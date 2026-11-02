# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Signed release downloads for update.sh.

A release is published on GitHub and on Gitea under tag v<version> with four
assets: the manifest, its Ed25519 signature and the server and web tarballs.
The manifest is checked against the pinned key below, every tarball against
the manifest while it streams to disk. There is no way to skip either check.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError
from urllib3.util import parse_url

RELEASE_PUBKEY_B64 = "9HiAMY1u6eJWqYsgbOXn4wPILIFM59YYNsoNbwL1FaY="
PRODUCT = "ulrmm"
VERSION_RE = re.compile(r"\d+\.\d{2}\.\d{2}\.\d{4}")
REPO_PART_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
MAX_REPOS = 10
SHA256_RE = re.compile(r"[0-9a-f]{64}")
API_TIMEOUT = 15
ASSET_TIMEOUT = (15, 600)
MAX_REDIRECTS = 5
CHUNK = 1 << 20
META_CHUNK = 64 << 10
# release JSON, manifest and signature of one source; slower counts as down
SOURCE_BUDGET = 40
PROGRESS_EVERY = 0.5
SOURCES_CACHE_KEY = "ulrmm_release_sources"
SOURCES_CACHE_TTL = 600
DEFAULT_SOURCES = [
    {"name": "github", "api": "https://api.github.com/repos/RiDDiX/ulrmm/releases"},
    {
        "name": "gitea",
        "api": "https://git.riddix.de/api/v1/repos/RiDDiX/ulrmm/releases",
    },
]


def builtin_sources() -> list[dict]:
    """ULRMM_RELEASE_SOURCES when local_settings.py sets it. Otherwise GitHub,
    and the developer's Gitea only for installations with its token."""
    configured = getattr(settings, "ULRMM_RELEASE_SOURCES", None)
    if configured is not None:
        return configured
    if getattr(settings, "ULRMM_RELEASE_GITEA_TOKEN", ""):
        return DEFAULT_SOURCES
    return [s for s in DEFAULT_SOURCES if s["name"] != "gitea"]


class ReleaseError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def key_id() -> str:
    return hashlib.sha256(base64.b64decode(RELEASE_PUBKEY_B64)).hexdigest()[:16]


def asset_names(version: str) -> tuple[str, str]:
    return f"ulrmm-server-{version}.tar.gz", f"ulrmm-web-{version}.tar.gz"


def version_key(version: str) -> tuple:
    """Sort key for N.DD.MM.YYYY: the date first, then the release of the day."""
    n, d, m, y = (int(x) for x in version.split("."))
    return y, m, d, n


def repo_api(repo_url: str) -> tuple[str, str]:
    """(kind, releases API) for https://host/owner/repository. github.com is
    GitHub, any other host is Gitea or Forgejo."""
    p = urlparse((repo_url or "").strip())
    parts = [x for x in p.path.split("/") if x]
    if (
        p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.params
        or p.query
        or p.fragment
        or len(parts) != 2
    ):
        raise ValueError("Enter the repository as https://host/owner/repository.")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    for part in (owner, repo):
        if not REPO_PART_RE.fullmatch(part) or not part.strip("."):
            raise ValueError("The owner or repository name has invalid characters.")
    if p.hostname in ("github.com", "www.github.com"):
        return "github", f"https://api.github.com/repos/{owner}/{repo}/releases"
    return "gitea", f"https://{p.netloc.lower()}/api/v1/repos/{owner}/{repo}/releases"


# --- http ------------------------------------------------------------------


def _source_hosts() -> set:
    """No public-address check for built-in sources from local_settings.py
    (a Gitea on the LAN) or ULRMM_RELEASE_TRUSTED_HOSTS. Dashboard
    repositories still get the check."""
    hosts = {urlparse(s["api"]).hostname for s in builtin_sources()}
    hosts.update(
        h.lower() for h in getattr(settings, "ULRMM_RELEASE_TRUSTED_HOSTS", ())
    )
    return hosts


def _netloc(url: str) -> str:
    p = parse_url(url)
    return f"{(p.host or '').strip('[]').lower()}:{p.port or 443}"


def _get(
    url: str,
    headers: dict,
    timeout,
    stream: bool = False,
    auth_netloc: str | None = None,
    deadline: float | None = None,
):
    """GET over https. Public-host check on every hop except trusted hosts.
    Authorization stays on auth_netloc, not on a redirect or another asset."""
    from deploy.tasks import _check_host, url_host

    trusted = _source_hosts()
    for _ in range(MAX_REDIRECTS + 1):
        if deadline and time.monotonic() > deadline:
            raise ReleaseError("no answer in time")
        try:
            host = url_host(url)
        except ValueError as e:
            raise ReleaseError(f"blocked: {e}")
        if urlparse(url).scheme != "https":
            raise ReleaseError("not https")
        if host not in trusted:
            try:
                _check_host(host)
            except ValueError as e:
                raise ReleaseError(f"blocked: {e}")
        send = dict(headers)
        if _netloc(url) != auth_netloc:
            send.pop("Authorization", None)
        r = requests.get(
            url, headers=send, timeout=timeout, stream=stream, allow_redirects=False
        )
        if r.status_code in (301, 302, 303, 307, 308):
            url = requests.compat.urljoin(url, r.headers.get("Location", ""))
            r.close()
            continue
        return r
    raise ReleaseError("too many redirects")


class ReleaseSource:
    def __init__(
        self,
        name: str,
        api: str,
        token: str = "",
        kind: str = "",
        needs_token: bool | None = None,
    ):
        self.name = name
        self.api = api.rstrip("/")
        self.kind = kind or name
        self.token = token or ""
        # set while the release metadata is read, see _resolve
        self.deadline = None
        # the built-in Gitea refuses anonymous API calls, added ones may not
        self.needs_token = self.kind == "gitea" if needs_token is None else needs_token

    @property
    def available(self) -> bool:
        return not self.needs_token or bool(self.token)

    def headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.token:
            scheme = "token" if self.kind == "gitea" else "Bearer"
            h["Authorization"] = f"{scheme} {self.token}"
        return h

    def fetch(self, version: str | None = None) -> dict:
        """The release JSON for the latest release or for tag v<version>."""
        if not self.available:
            raise ReleaseError("unavailable (no token)")
        url = f"{self.api}/tags/v{version}" if version else f"{self.api}/latest"
        body = self.read_asset(url, what="release JSON")
        try:
            data = json.loads(body)
        except ValueError:
            raise ReleaseError("invalid JSON")
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("tag_name"), str)
            or not isinstance(data.get("assets"), list)
        ):
            raise ReleaseError("invalid JSON")
        return data

    def _get(self, url: str, timeout, stream: bool = False, binary: bool = False):
        headers = self.headers()
        if binary:
            headers["Accept"] = "application/octet-stream"
        return _get(url, headers, timeout, stream, _netloc(self.api), self.deadline)

    def asset_url(self, asset: dict) -> str:
        """Where to fetch an asset: a private GitHub release only hands the
        file out through the asset API with a token."""
        if self.kind == "github" and self.token and isinstance(asset.get("url"), str):
            return asset["url"]
        return asset["browser_download_url"]

    def read_asset(self, url: str, limit: int = 1 << 20, what: str = "asset") -> bytes:
        try:
            r = self._get(url, API_TIMEOUT, stream=True, binary=what == "asset")
        except (requests.RequestException, ValueError) as e:
            raise ReleaseError(f"connection error: {e.__class__.__name__}")
        if r.status_code != 200:
            r.close()
            raise ReleaseError(f"HTTP {r.status_code}", r.status_code)
        body = b""
        try:
            with r:
                for chunk in r.iter_content(min(META_CHUNK, limit + 1)):
                    body += chunk
                    if len(body) > limit:
                        raise ReleaseError(f"{what} too large")
                    if self.deadline and time.monotonic() > self.deadline:
                        raise ReleaseError("no answer in time")
        except requests.RequestException as e:
            raise ReleaseError(f"connection error: {e.__class__.__name__}")
        return body


def _repo_sources() -> list[ReleaseSource]:
    """Enabled repositories from the Update Center."""
    from .models import ReleaseRepo

    try:
        rows = list(ReleaseRepo.objects.filter(enabled=True))
    except DatabaseError as e:
        # an update must not fail over the optional table (code ahead of
        # the database, a broken connection): the built-in sources remain
        from ulrmm.logger import logger

        logger.error(f"release repositories not read: {e.__class__.__name__}")
        return []
    out = []
    for row in rows:
        try:
            kind, api = repo_api(row.repo_url)
        except ValueError:
            continue
        out.append(ReleaseSource(row.name, api, row.token, kind, needs_token=False))
    return out


def sources() -> list[ReleaseSource]:
    tokens = {
        "github": getattr(settings, "ULRMM_RELEASE_GITHUB_TOKEN", ""),
        "gitea": getattr(settings, "ULRMM_RELEASE_GITEA_TOKEN", ""),
    }
    out = []
    for s in builtin_sources():
        kind = s.get("kind") or s["name"]
        out.append(ReleaseSource(s["name"], s["api"], tokens.get(kind, ""), kind))
    return out + _repo_sources()


def _newest(found: list) -> tuple:
    """(name, release) with the highest version; on a tie the earlier source."""
    return max(found, key=lambda f: version_key(f[1]["version"]))


# --- manifest ----------------------------------------------------------------


def verify_manifest(manifest_bytes: bytes, sig_b64: str) -> dict:
    """The manifest as dict once its signature and shape check out."""
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUBKEY_B64))
        key.verify(sig, manifest_bytes)
    except (ValueError, binascii.Error, InvalidSignature):
        raise ReleaseError("manifest signature does not verify")
    try:
        m = json.loads(manifest_bytes)
    except ValueError:
        raise ReleaseError("manifest is not JSON")
    if (
        not isinstance(m, dict)
        or m.get("v") != 1
        or m.get("product") != PRODUCT
        or not isinstance(m.get("version"), str)
        or not VERSION_RE.fullmatch(m["version"])
        or not isinstance(m.get("assets"), list)
    ):
        raise ReleaseError("manifest has an unexpected shape")
    names = set()
    for a in m["assets"]:
        if (
            not isinstance(a, dict)
            or not isinstance(a.get("name"), str)
            or "/" in a["name"]
            or not isinstance(a.get("sha256"), str)
            or not SHA256_RE.fullmatch(a["sha256"])
            or not isinstance(a.get("size"), int)
            or isinstance(a["size"], bool)
            or a["size"] < 0
        ):
            raise ReleaseError("manifest has an unexpected shape")
        names.add(a["name"])
    if not set(asset_names(m["version"])) <= names:
        raise ReleaseError("manifest lacks the server or web tarball")
    return m


def _resolve(source: ReleaseSource, version: str | None) -> dict:
    """One source's release with its verified manifest, ReleaseError otherwise."""
    source.deadline = time.monotonic() + SOURCE_BUDGET
    try:
        return _resolve_now(source, version)
    finally:
        source.deadline = None


def _resolve_all(srcs: list, version: str | None) -> list:
    """_resolve on every source at once, results in srcs order. Over the
    budget counts as down. The thread is a daemon; the socket timeout ends it."""
    results = [None] * len(srcs)

    def run(i, source):
        try:
            results[i] = _resolve(source, version)
        except ReleaseError as e:
            results[i] = e
        except Exception as e:
            results[i] = ReleaseError(f"failed: {e.__class__.__name__}")

    threads = [
        threading.Thread(target=run, args=(i, s), daemon=True)
        for i, s in enumerate(srcs)
    ]
    for t in threads:
        t.start()
    end = time.monotonic() + SOURCE_BUDGET + 1
    for t in threads:
        t.join(max(0, end - time.monotonic()))
    return [r if r is not None else ReleaseError("no answer in time") for r in results]


def _resolve_now(source: ReleaseSource, version: str | None) -> dict:
    data = source.fetch(version)
    tag = data["tag_name"]
    if version and tag != f"v{version}":
        raise ReleaseError(f"tag {tag} is not v{version}")
    if not tag.startswith("v") or not VERSION_RE.fullmatch(tag[1:]):
        raise ReleaseError(f"unexpected tag {tag}")
    ver = tag[1:]
    assets = {}
    for a in data["assets"]:
        if (
            isinstance(a, dict)
            and isinstance(a.get("name"), str)
            and isinstance(a.get("browser_download_url"), str)
        ):
            assets[a["name"]] = a
    try:
        manifest_bytes = source.read_asset(
            source.asset_url(assets[f"ulrmm-{ver}.manifest.json"])
        )
        sig_b64 = source.read_asset(
            source.asset_url(assets[f"ulrmm-{ver}.manifest.sig"]), 4096
        ).decode("ascii", errors="replace")
    except KeyError:
        raise ReleaseError("manifest or signature asset missing")
    manifest = verify_manifest(manifest_bytes, sig_b64)
    if manifest["version"] != ver:
        raise ReleaseError(f"manifest is for {manifest['version']}, tag is {tag}")
    missing = [a["name"] for a in manifest["assets"] if a["name"] not in assets]
    if missing:
        raise ReleaseError(f"release lacks {', '.join(missing)}")
    return {
        "source": source.name,
        # download_and_verify uses this source object, not a lookup by name
        "_source": source,
        "version": ver,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "sig": sig_b64,
        "assets": assets,
        "release": data,
    }


def discover(version: str | None = None, log=None) -> tuple[str, dict]:
    """(source name, release) with a verified manifest. All sources are asked
    at once. A pinned version is the first source in order that has it,
    otherwise the newest wins. log gets one line per source, in source order."""
    if version and not VERSION_RE.fullmatch(version):
        raise ReleaseError("invalid version")
    errors, found = [], []
    srcs = sources()
    for source, res in zip(srcs, _resolve_all(srcs, version)):
        if isinstance(res, ReleaseError):
            errors.append(f"source {source.name}: {res}")
            if log:
                log(errors[-1])
            continue
        if log:
            log(f"source {source.name}: ok {res['version']}")
        found.append((source.name, res))
    if found:
        return found[0] if version else _newest(found)
    raise ReleaseError("; ".join(errors) or "no release sources configured")


# --- download ----------------------------------------------------------------


def _stream(
    source: ReleaseSource, url: str, path: Path, size: int, cb
) -> tuple[str, int]:
    """Stream url to path, never more than the manifest size; (sha256, bytes)
    of what landed. cb(bytes) per chunk."""
    try:
        r = source._get(url, ASSET_TIMEOUT, stream=True, binary=True)
    except (requests.RequestException, ValueError) as e:
        raise ReleaseError(f"connection error: {e.__class__.__name__}")
    if r.status_code != 200:
        r.close()
        raise ReleaseError(f"HTTP {r.status_code} for {path.name}", r.status_code)
    length = r.headers.get("Content-Length", "")
    if length.isdigit() and int(length) > size:
        r.close()
        raise ReleaseError(
            f"{path.name}: Content-Length {length} exceeds the manifest size {size}"
        )
    h = hashlib.sha256()
    got = 0
    try:
        with r, open(path, "wb") as f:
            for chunk in r.iter_content(CHUNK):
                if not chunk:
                    continue
                got += len(chunk)
                if got > size:
                    raise ReleaseError(
                        f"{path.name}: stream exceeds the manifest size {size}"
                    )
                f.write(chunk)
                h.update(chunk)
                cb(len(chunk))
    except requests.RequestException as e:
        path.unlink(missing_ok=True)
        raise ReleaseError(f"download of {path.name} broke: {e.__class__.__name__}")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return h.hexdigest(), got


def download_and_verify(release: dict, dest: Path, progress_cb=None) -> Path:
    """Fetch the release into dest/<version>, verify every tarball against the
    manifest; the directory is removed again on any failure.

    progress_cb(phase, bytes, total) is called while streaming."""
    source = release.get("_source")
    if source is None:
        raise ReleaseError(f"source {release.get('source')} is gone")
    manifest = release["manifest"]
    version = manifest["version"]
    wanted = manifest["assets"]
    total = sum(a["size"] for a in wanted)
    target = Path(dest) / version
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    done = 0

    def tick(n):
        nonlocal done
        done += n
        if progress_cb:
            progress_cb("download", done, total)

    try:
        (target / "manifest.json").write_bytes(release["manifest_bytes"])
        (target / "manifest.sig").write_text(release["sig"].strip() + "\n")
        got = {}
        if progress_cb:
            progress_cb("download", 0, total)
        for a in wanted:
            asset = release["assets"].get(a["name"])
            if asset is None:
                raise ReleaseError(f"asset {a['name']} missing from the release")
            got[a["name"]] = _stream(
                source,
                source.asset_url(asset),
                target / a["name"],
                a["size"],
                tick,
            )
        if progress_cb:
            progress_cb("verify", done, total)
        for a in wanted:
            sha, size = got[a["name"]]
            if size != a["size"]:
                raise ReleaseError(
                    f"{a['name']}: size {size} does not match manifest {a['size']}"
                )
            if sha != a["sha256"]:
                raise ReleaseError(f"{a['name']}: sha256 does not match the manifest")
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return target


# --- progress file -----------------------------------------------------------


def write_progress(path, **fields) -> None:
    """update.progress.json, replaced atomically, world readable."""
    path = Path(path)
    data = {
        "phase": None,
        "percent": None,
        "bytes": 0,
        "total": 0,
        "rate_bps": 0,
        "source": None,
        "version": None,
        "message": "",
    }
    data.update(fields)
    data["updated_at"] = _now()
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def progress_writer(path, source: str | None = None, version: str | None = None):
    """A download_and_verify callback that writes path at most every 0.5 s,
    always on a phase change and at 100 percent."""
    started = time.monotonic()
    last = {"t": 0.0, "phase": None}

    def cb(phase, done, total, message=""):
        now = time.monotonic()
        throttled = phase == last["phase"] and now - last["t"] < PROGRESS_EVERY
        if throttled and done < total:
            return
        last["t"], last["phase"] = now, phase
        elapsed = now - started
        write_progress(
            path,
            phase=phase,
            percent=round(done * 100 / total) if total else None,
            bytes=done,
            total=total,
            rate_bps=int(done / elapsed) if elapsed > 0 else 0,
            source=source,
            version=version,
            message=message or f"{phase} {done}/{total} bytes",
        )

    return cb


# --- dashboard status --------------------------------------------------------


def _probe() -> dict:
    out = {"active": None, "latest": None, "key_id": key_id(), "sources": []}
    found = []
    srcs = sources()
    for source, res in zip(srcs, _resolve_all(srcs, None)):
        row = {
            "name": source.name,
            "kind": source.kind,
            "api": source.api,
            "ok": False,
            "status": None,
            "latest": None,
            "checked_at": _now(),
            "error": None,
        }
        if isinstance(res, ReleaseError):
            row.update(status=res.status, error=str(res))
        else:
            row.update(ok=True, status=200, latest=res["version"])
            found.append((source.name, res))
        out["sources"].append(row)
    if found:
        name, release = _newest(found)
        out["active"], out["latest"] = name, release["version"]
    return out


def forget_status() -> None:
    cache.delete(SOURCES_CACHE_KEY)


def sources_status(refresh: bool = False) -> dict:
    cached = cache.get(SOURCES_CACHE_KEY)
    if cached and not refresh:
        return cached
    # one request probes, the rest answer from the cache like get_latest_version
    # held for the worst case of one probe, so a slow one is not doubled
    if not cache.add(SOURCES_CACHE_KEY + "_inflight", 1, SOURCE_BUDGET + 30):
        return cached or {
            "active": None,
            "latest": None,
            "key_id": key_id(),
            "sources": [],
        }
    try:
        out = _probe()
    finally:
        cache.delete(SOURCES_CACHE_KEY + "_inflight")
    cache.set(SOURCES_CACHE_KEY, out, SOURCES_CACHE_TTL)
    return out

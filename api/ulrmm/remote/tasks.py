# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import hashlib
import json
import platform
import re
import subprocess
import tempfile
import time
from pathlib import Path

import requests
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone as djangotime
from django.utils.dateparse import parse_datetime

from logs.models import AuditLog, DebugLog
from ulrmm.celery import app
from ulrmm.constants import (
    AGENT_DEFER,
    AuditActionType,
    AuditObjType,
)
from ulrmm.middleware import get_debug_info
from ulrmm.utils import redis_lock

from .models import RustDeskPeer, RustDeskRelease, RustDeskSettings
from .utils import (
    _PLAIN_VERSION_RE,
    CLIENT_NAMES,
    DEPLOY_TIMEOUT,
    DeployError,
    config_string,
    get_rustdesk_settings,
    parse_deploy_output,
    pinned_client,
    read_public_key,
    render_deploy,
    server_version,
    unsupported_reason,
    update_available,
    version_key,
)

REPOS = {"server": "rustdesk-server", "client": "rustdesk"}
LATEST_URL = "https://api.github.com/repos/rustdesk/{}/releases/latest"
TAG_URL = "https://github.com/rustdesk/{}/releases/tag/{}"
DOWNLOAD_URL = "https://github.com/rustdesk/{}/releases/download/{}/{}"
# the client is AGPL-3.0, this sits next to the mirrored installers
SOURCE_TXT = """RustDesk client {version}
License: AGPL-3.0
Source: https://github.com/rustdesk/rustdesk/tree/{tag}
License text: https://github.com/rustdesk/rustdesk/blob/{tag}/LICENCE
"""
HEADERS = {"User-Agent": "UniversalLocal RMM"}
# platform.machine() -> rustdesk-server-linux-<arch>.zip
SERVER_ARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64v8",
    "arm64": "arm64v8",
}
DOWNLOAD_TIMEOUT = 900
SCRIPT_TIMEOUT = 600
# reserved for install-rustdesk-server.sh: restart, rollback if that fails
SCRIPT_MIN = 120
MAX_PEERS = 25
AUTO = "auto-update"


class UpdateError(Exception):
    pass


def audit(actor: str, message: str, agent=None, action=AuditActionType.EXEC_COMMAND):
    AuditLog.objects.create(
        username=actor,
        agent=agent.hostname if agent else None,
        agent_id=agent.agent_id if agent else None,
        object_type=AuditObjType.AGENT if agent else AuditObjType.CORE,
        action=action,
        message=message,
        debug_info=get_debug_info(),
    )


def _dist() -> Path:
    return Path(getattr(settings, "AGENTS_DIST_DIR", "/opt/ulrmm-agents/dist"))


def _script() -> Path:
    default = (
        settings.BASE_DIR.parent.parent / "riddix/rustdesk/install-rustdesk-server.sh"
    )
    return Path(getattr(settings, "RUSTDESK_INSTALL_SCRIPT", default))


def _https_only(r) -> None:
    # every hop: an http one in between could have sent us anywhere
    for hop in (*r.history, r):
        if not hop.url.startswith("https://"):
            raise UpdateError(f"redirected to {hop.url}")


def _tag(release) -> str:
    # the tag as GitHub has it, version drops a leading v
    tag = release.url.rsplit("/", 1)[-1]
    return tag if tag.removeprefix("v") == release.version else release.version


def _download(url: str, dest: Path, size=None, sha256="", seconds=DOWNLOAD_TIMEOUT):
    """url -> dest via dest.part, returns the sha256.
    TLS to github.com is the check. size and sha256 catch a truncated
    or swapped file."""
    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    deadline = time.monotonic() + seconds
    try:
        with requests.get(url, headers=HEADERS, stream=True, timeout=30) as r:
            r.raise_for_status()
            _https_only(r)
            with part.open("wb") as f:
                for chunk in r.iter_content(1 << 20):
                    if time.monotonic() > deadline:
                        raise UpdateError(f"{dest.name}: ran out of time")
                    f.write(chunk)
                    digest.update(chunk)
        got = part.stat().st_size
        if size is not None and got != size:
            raise UpdateError(f"{dest.name}: {got} bytes, the release lists {size}")
        if sha256 and digest.hexdigest() != sha256:
            raise UpdateError(f"{dest.name}: checksum mismatch")
        part.chmod(0o644)
        part.replace(dest)
    except Exception as e:
        part.unlink(missing_ok=True)
        if isinstance(e, UpdateError):
            raise
        raise UpdateError(f"{dest.name}: download failed: {e}") from e
    return digest.hexdigest()


def latest_release(component: str):
    releases = RustDeskRelease.objects.filter(component=component)
    return max(releases, key=lambda r: version_key(r.version) or (), default=None)


def _newer(release, have: str) -> bool:
    have = version_key(have)
    return bool(release and have) and version_key(release.version) > have


def outdated_peers(pinned: str) -> list:
    peers = (
        RustDeskPeer.objects.exclude(rustdesk_id="")
        .select_related("agent")
        .defer(*(f"agent__{f}" for f in AGENT_DEFER))
        .order_by("pk")
    )
    return [p for p in peers if update_available(p, pinned)]


def releases_payload() -> dict:
    rd = get_rustdesk_settings()
    installed = server_version()
    server, client = latest_release("server"), latest_release("client")
    pinned = RustDeskRelease.objects.filter(
        component="client", version=rd.pinned_client_version
    ).first()
    outdated = outdated_peers(rd.pinned_client_version)

    def info(r):
        if not r:
            return None
        return {
            "version": r.version,
            "published_at": r.published_at,
            "url": r.url,
            "notes": r.notes,
        }

    return {
        "server": {
            "installed": installed,
            "latest": info(server),
            "update_available": _newer(server, installed),
            "arch_supported": platform.machine().lower() in SERVER_ARCH,
        },
        "client": {
            "pinned": rd.pinned_client_version,
            "latest": info(client),
            "update_available": _newer(client, rd.pinned_client_version),
            "mirrored_at": pinned.mirrored_at if pinned else None,
            "outdated_peers": len(outdated),
            "online_outdated_peers": sum(p.agent.is_online for p in outdated),
        },
        "auto_update_server": rd.auto_update_server,
        "auto_update_clients": rd.auto_update_clients,
        "releases_checked_at": rd.releases_checked_at,
    }


@app.task
def rustdesk_check_releases_task() -> list[str]:
    """Store the latest server and client release. Errors are returned
    and written to the debug log."""
    errors = []
    for component, repo in REPOS.items():
        try:
            r = requests.get(LATEST_URL.format(repo), headers=HEADERS, timeout=20)
            r.raise_for_status()
            _https_only(r)
            data = r.json()
            tag = str(data["tag_name"])
            version = tag.removeprefix("v")
            if not _PLAIN_VERSION_RE.fullmatch(version):
                raise ValueError(f"unexpected tag {tag[:40]!r}")
            assets = [
                {
                    "name": str(a["name"]),
                    "url": str(a["browser_download_url"]),
                    "size": int(a["size"]),
                }
                for a in data.get("assets") or []
            ]
            RustDeskRelease.objects.update_or_create(
                component=component,
                version=version,
                defaults={
                    "published_at": parse_datetime(str(data.get("published_at"))),
                    "url": TAG_URL.format(repo, tag),
                    "notes": str(data.get("body") or "")[:20000],
                    "assets": assets,
                },
            )
        except (
            UpdateError,
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
        ) as e:
            errors.append(f"RustDesk {component} release check failed: {e}")
            DebugLog.warning(errors[-1])
    if not errors:
        RustDeskSettings.objects.update_or_create(
            pk=1, defaults={"releases_checked_at": djangotime.now()}
        )
    return errors


@app.task
def rustdesk_pin_client_task(
    version: str,
    actor: str = AUTO,
    timeout: int = len(CLIENT_NAMES) * DOWNLOAD_TIMEOUT,
) -> None:
    """Mirror that client release to <dist>/rustdesk/ and pin it.
    timeout covers all files; each download gets at most DOWNLOAD_TIMEOUT."""
    # rows only hold versions that passed _PLAIN_VERSION_RE
    release = RustDeskRelease.objects.filter(
        component="client", version=version
    ).first()
    if not release:
        raise UpdateError(f"RustDesk client {version} is not a known release.")
    out = _dist() / "rustdesk"
    before = get_rustdesk_settings().pinned_client_version
    deadline = time.monotonic() + timeout
    try:
        if not _dist().is_dir():
            raise UpdateError(f"{_dist()} is missing, run build_agents.sh first")
        sizes = {a["name"]: a["size"] for a in release.assets}
        names = [n.format(v=version) for n in CLIENT_NAMES]
        if missing := [n for n in names if n not in sizes and n not in release.files]:
            raise UpdateError(f"the release has no {', '.join(missing)}")
        with redis_lock("rustdesk-pin-lock", actor) as acquired:
            if not acquired:
                raise UpdateError("another client download is running")
            out.mkdir(exist_ok=True)
            files = {}
            try:
                for name in names:
                    files[name] = _download(
                        DOWNLOAD_URL.format("rustdesk", _tag(release), name),
                        out / name,
                        sizes.get(name),
                        release.files.get(name, ""),
                        seconds=min(DOWNLOAD_TIMEOUT, deadline - time.monotonic()),
                    )
            except Exception:
                # no half release next to the current pin
                for name in set(files) - set(pinned_client()[1]):
                    (out / name).unlink(missing_ok=True)
                raise
            source = out / "SOURCE.txt.part"
            source.write_text(SOURCE_TXT.format(version=version, tag=_tag(release)))
            source.chmod(0o644)
            source.replace(out / "SOURCE.txt")
            # install-rustdesk-server.sh leaves the mirror alone while this exists
            manifest = out / "manifest.json.part"
            manifest.write_text(json.dumps({"client_version": version, "files": files}))
            manifest.chmod(0o644)
            manifest.replace(out / "manifest.json")
            release.files = files
            release.mirrored_at = djangotime.now()
            release.save(update_fields=["files", "mirrored_at"])
            RustDeskSettings.objects.update_or_create(
                pk=1, defaults={"pinned_client_version": version}
            )
            for f in out.glob("rustdesk-*"):
                if f.name not in files:
                    f.unlink(missing_ok=True)
    except (UpdateError, OSError) as e:
        msg = f"{actor}: pinning the RustDesk client {before} -> {version} failed: {e}"
        DebugLog.warning(msg)
        audit(actor, msg, action=AuditActionType.MODIFY)
        raise UpdateError(str(e)) from e
    audit(
        actor,
        f"{actor} pinned the RustDesk client {before} -> {version}",
        action=AuditActionType.MODIFY,
    )


@app.task
def rustdesk_update_server_task(
    version: str, actor: str = AUTO, timeout: int = SCRIPT_TIMEOUT
) -> None:
    """Download that hbbs/hbbr release and install it with
    install-rustdesk-server.sh under sudo. timeout covers both."""
    # rows only hold versions that passed _PLAIN_VERSION_RE
    release = RustDeskRelease.objects.filter(
        component="server", version=version
    ).first()
    if not release:
        raise UpdateError(f"RustDesk server {version} is not a known release.")
    before = server_version() or "unknown"
    deadline = time.monotonic() + timeout
    try:
        arch = SERVER_ARCH.get(platform.machine().lower())
        if not arch:
            raise UpdateError(f"there is no build for {platform.machine()}")
        # same host update.sh passes, so the next run leaves the units alone
        host = getattr(settings, "RUSTDESK_HOST", "") or re.sub(
            r":[0-9]+$", "", get_rustdesk_settings().id_server
        )
        if not host:
            raise UpdateError("no ID server is set")
        name = f"rustdesk-server-linux-{arch}.zip"
        size = {a["name"]: a["size"] for a in release.assets}.get(name)
        with redis_lock("rustdesk-server-lock", actor) as acquired:
            if not acquired:
                raise UpdateError("another server update is running")
            with tempfile.TemporaryDirectory() as tmp:
                zip_file = Path(tmp) / name
                url = DOWNLOAD_URL.format("rustdesk-server", _tag(release), name)
                _download(url, zip_file, size, seconds=timeout - SCRIPT_MIN)
                cmd = ["sudo", "-n", "bash", str(_script()), "--host", host]
                cmd += ["--server-version", version, "--server-zip", str(zip_file)]
                try:
                    p = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=max(SCRIPT_MIN, deadline - time.monotonic()),
                    )
                except subprocess.TimeoutExpired:
                    raise UpdateError("the install script did not finish in time")
        tail = (p.stdout + p.stderr)[-2000:]
        if server_version() != version:
            DebugLog.warning(f"RustDesk server update to {version}:\n{tail}")
            last = "\n".join(tail.strip().splitlines()[-5:])
            raise UpdateError(f"install script exit code {p.returncode}: {last}")
        DebugLog.info(f"RustDesk server update to {version}:\n{tail}")
    except (UpdateError, OSError) as e:
        msg = f"{actor}: RustDesk server update {before} -> {version} failed: {e}"
        DebugLog.warning(msg)
        audit(actor, msg)
        raise UpdateError(str(e)) from e
    audit(actor, f"{actor} updated the RustDesk server {before} -> {version}")


def update_peer(agent, peer, actor: str, *, host: str, config: str):
    """Upgrade the client on agent to the pinned version. No password sent,
    the stored one stays. DeployError text is peer.last_error."""
    version = get_rustdesk_settings().pinned_client_version
    before = peer.client_version or "unknown"
    try:
        data = render_deploy(
            agent, host=host, config=config, mode="update", expect_id=peer.rustdesk_id
        )
        out = asyncio.run(agent.nats_cmd(data, timeout=DEPLOY_TIMEOUT + 10))
        rustdesk_id, got = parse_deploy_output(out)
        if (rustdesk_id, got) != (peer.rustdesk_id, version):
            raise DeployError(
                f"the endpoint reported ID {rustdesk_id} and version {got}, "
                f"expected {peer.rustdesk_id} and {version}"
            )
    except DeployError as e:
        peer.last_error = f"RustDesk update on {agent.hostname} failed: {e}"
        peer.save(update_fields=["last_error"])
        audit(actor, f"{actor}: {peer.last_error} ({before} -> {version})", agent)
        raise DeployError(peer.last_error) from e

    peer.client_version = got
    peer.last_error = ""
    peer.save(update_fields=["client_version", "last_error"])
    audit(
        actor,
        f"{actor} updated RustDesk {before} -> {got} on {agent.hostname}, "
        f"ID {rustdesk_id}",
        agent,
    )
    return rustdesk_id, got


@app.task
def rustdesk_update_clients_task(actor: str = AUTO) -> int:
    """Update outdated clients on online devices, at most MAX_PEERS per run.
    Returns how many succeeded."""
    rd = get_rustdesk_settings()
    key = read_public_key()
    if not (rd.enabled and rd.id_server and key):
        DebugLog.warning("RustDesk client updates skipped: off, no ID server or key")
        return 0
    config = config_string(rd.id_server, rd.relay_server, key)
    peers = [p for p in outdated_peers(rd.pinned_client_version) if p.agent.is_online]
    done = 0
    for peer in peers[:MAX_PEERS]:
        agent = peer.agent
        if reason := unsupported_reason(agent, probe=True):
            DebugLog.warning(f"RustDesk update skipped: {reason}", agent=agent)
            continue
        # same lock as the deploy and update views
        lock = f"rustdesk_deploy_{agent.agent_id}"
        if not cache.add(lock, 1, DEPLOY_TIMEOUT + 30):
            DebugLog.warning(f"RustDesk update on {agent.hostname} skipped: busy")
            continue
        try:
            # another run can have updated it since the list was built
            peer.refresh_from_db(fields=["rustdesk_id", "client_version"])
            if not update_available(peer, rd.pinned_client_version):
                continue
            update_peer(agent, peer, actor, host=rd.id_server, config=config)
            done += 1
        except DeployError as e:
            # an open session on the device ends up here too
            DebugLog.warning(str(e), agent=agent)
        finally:
            cache.delete(lock)
    return done


@app.task
def rustdesk_auto_update_task() -> str:
    rd = get_rustdesk_settings()
    if rd.auto_update_server:
        latest = latest_release("server")
        if _newer(latest, server_version()):
            try:
                rustdesk_update_server_task(latest.version)
            except UpdateError:
                pass  # audited and logged
    if not rd.auto_update_clients:
        return "ok"
    latest = latest_release("client")
    if _newer(latest, rd.pinned_client_version):
        try:
            rustdesk_pin_client_task(latest.version)
        except UpdateError:
            pass
    return f"{rustdesk_update_clients_task()} clients updated"

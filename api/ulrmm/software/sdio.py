# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
Driver pack indexes of Snappy Driver Installer Origin (SDIO). The update
torrent lists every index and pack with SHA1 piece hashes; files come from
its web seed over https and are checked against those pieces. Only the
index data is read here, the agent fetches a pack when a driver from it is
approved. Index layout: see sdioindex.py.
"""

import asyncio
import bisect
import datetime as dt
import hashlib
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone as djangotime

from logs.models import AuditLog
from packages.utils import SCRIPTS
from remote.utils import version_key
from ulrmm.constants import AGENT_DEFER, AgentPlat
from ulrmm.helpers import agent_ver

from . import catalog, sdioindex
from .catalog import CatalogError, fetch
from .models import InstalledDrivers, SdioApproval, SdioCatalog, SdioIndex, SdioJob

TORRENT_URL = "https://www.snappy-driver-installer.org/downloads/SDIO_Update.torrent"
TORRENT_HOSTS = ("www.snappy-driver-installer.org",)
SEED_HOSTS = ("www.glenn.delahoy.com",)
TIMEOUT = (10, 60)
MAX_TORRENT = 8 << 20
MAX_INDEX = 32 << 20
MIN_INDEXES = 50
INDEX_DIR = "indexes/SDIO/"
PACK_DIR = "drivers/"
NAME_RE = re.compile(r"DP_[A-Za-z0-9_.-]{1,120}")


PROGRESS_KEY = "sdio-progress"
PROGRESS_TTL = 2 * 60 * 60
PROGRESS_STALE = 10 * 60


def set_progress(phase: str, done: int = 0, total: int = 0) -> None:
    """What the refresh task is doing, for the dashboard."""
    cache.set(
        PROGRESS_KEY,
        {"phase": phase, "done": done, "total": total, "at": time.time()},
        PROGRESS_TTL,
    )


def get_progress() -> dict | None:
    """None when nothing runs. Every step writes it, so a value that sat
    for PROGRESS_STALE seconds belongs to a worker that died."""
    p = cache.get(PROGRESS_KEY)
    if not isinstance(p, dict) or time.time() - p.get("at", 0) > PROGRESS_STALE:
        return None
    return {k: p.get(k) for k in ("phase", "done", "total")}


def clear_progress() -> None:
    cache.delete(PROGRESS_KEY)


class SdioError(Exception):
    pass


class Missing(SdioError):
    """The web seed does not serve this file."""


def user_agent() -> str:
    return f"ulrmm/{settings.ULRMM_VERSION} (sdio index)"


def bdecode(data: bytes):
    """Bencoded value of data. Byte strings stay bytes."""

    def value(i: int, depth: int):
        if depth > 32:
            raise SdioError("torrent nested too deep")
        if i >= len(data):
            raise SdioError("torrent truncated")
        c = data[i : i + 1]
        if c == b"i":
            end = data.find(b"e", i)
            if end < 0:
                raise SdioError("torrent truncated")
            try:
                return int(data[i + 1 : end]), end + 1
            except ValueError:
                raise SdioError("torrent has a bad number") from None
        if c in (b"l", b"d"):
            items, i = [], i + 1
            while data[i : i + 1] != b"e":
                if i >= len(data):
                    raise SdioError("torrent truncated")
                item, i = value(i, depth + 1)
                items.append(item)
            if c == b"l":
                return items, i + 1
            if len(items) % 2 or not all(isinstance(k, bytes) for k in items[::2]):
                raise SdioError("torrent has a bad dictionary")
            return dict(zip(items[::2], items[1::2])), i + 1
        colon = data.find(b":", i, i + 21)
        if colon < 0 or not data[i:colon].isdigit():
            raise SdioError("torrent not understood")
        n = int(data[i:colon])
        if colon + 1 + n > len(data):
            raise SdioError("torrent truncated")
        return data[colon + 1 : colon + 1 + n], colon + 1 + n

    out, end = value(0, 0)
    if end != len(data):
        raise SdioError("torrent has trailing data")
    return out


@dataclass(frozen=True)
class File:
    path: str
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length


class Torrent:
    def __init__(self, data: bytes):
        meta = bdecode(data)
        info = meta.get(b"info") if isinstance(meta, dict) else None
        if not isinstance(info, dict):
            raise SdioError("torrent has no info")
        self.name = _text(info.get(b"name"))
        self.piece_length = info.get(b"piece length")
        pieces = info.get(b"pieces")
        files = info.get(b"files")
        if (
            not self.name
            or not isinstance(self.piece_length, int)
            or self.piece_length < 16384
            or not isinstance(pieces, bytes)
            or len(pieces) % 20
            or not isinstance(files, list)
        ):
            raise SdioError("torrent not understood")
        self.pieces = pieces
        self.files: list[File] = []
        offset = 0
        for f in files:
            length = f.get(b"length") if isinstance(f, dict) else None
            parts = f.get(b"path") if isinstance(f, dict) else None
            if not isinstance(length, int) or length < 0 or not isinstance(parts, list):
                raise SdioError("torrent has a bad file entry")
            path = "/".join(_text(p) for p in parts)
            if not path or any(p in ("", ".", "..") for p in path.split("/")):
                raise SdioError("torrent has a bad file path")
            self.files.append(File(path, offset, length))
            offset += length
        if -(-offset // self.piece_length) != len(pieces) // 20:
            raise SdioError("torrent pieces do not cover its files")
        self.size = offset
        self.created = meta.get(b"creation date")
        if not isinstance(self.created, int):
            self.created = None
        self.seed = _seed(meta.get(b"url-list"))
        self.by_path = {f.path: f for f in self.files}
        self._starts = [f.offset for f in self.files]

    def url(self, f: File) -> str:
        return self.seed + quote(f"{self.name}/{f.path}")

    def indexes(self) -> dict[str, File]:
        """name without .bin -> index file"""
        out = {}
        for f in self.files:
            name = f.path.removeprefix(INDEX_DIR)
            if name != f.path and name.endswith(".bin"):
                stem = name[:-4]
                if NAME_RE.fullmatch(stem) and f.length:
                    out[stem] = f
        return out

    def pack(self, stem: str) -> File | None:
        return self.by_path.get(f"{PACK_DIR}{stem}.7z")

    def segments(self, start: int, end: int) -> list[tuple[File, int, int]]:
        """(file, offset in file, length) covering stream bytes start..end."""
        out = []
        i = max(bisect.bisect_right(self._starts, start) - 1, 0)
        while start < end and i < len(self.files):
            f = self.files[i]
            if f.end > start and f.length:
                lo = max(start, f.offset)
                hi = min(end, f.end)
                out.append((f, lo - f.offset, hi - lo))
                start = hi
            i += 1
        if start < end:
            raise SdioError("torrent range out of bounds")
        return out

    def piece_span(self, f: File) -> tuple[int, int]:
        """first and last piece index of a non-empty file"""
        return f.offset // self.piece_length, (f.end - 1) // self.piece_length

    def piece_hash(self, n: int) -> bytes:
        return self.pieces[n * 20 : n * 20 + 20]

    def end_segments(self, f: File, split=False):
        """Bytes of other files in the first and last piece of f."""
        first, last = self.piece_span(f)
        stream_end = min((last + 1) * self.piece_length, self.size)
        head = self.segments(first * self.piece_length, f.offset)
        tail = self.segments(f.end, stream_end)
        return (head, tail) if split else head + tail

    def plan(self, f: File, served=lambda g: True) -> dict:
        """What the agent needs to fetch and check one file. The first and
        last piece are only checked when served() says the web seed has
        the neighbour files they share."""
        first, last = self.piece_span(f)
        head, tail = self.end_segments(f, split=True)

        def ranges(segs):
            return [
                {"url": self.url(g), "start": off, "length": n} for g, off, n in segs
            ]

        return {
            "name": f.path.rsplit("/", 1)[-1],
            "url": self.url(f),
            "size": f.length,
            "piece_length": self.piece_length,
            "head": ranges(head),
            "tail": ranges(tail),
            "head_check": all(served(g) for g, _, _ in head),
            "tail_check": all(served(g) for g, _, _ in tail),
            "hashes": [self.piece_hash(n).hex() for n in range(first, last + 1)],
        }


def _text(value) -> str:
    if not isinstance(value, bytes):
        return ""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _seed(value) -> str:
    """The web seed as https; the torrent lists it with http."""
    seeds = value if isinstance(value, list) else [value]
    for s in seeds:
        url = _text(s)
        if url.startswith("http://"):
            url = "https://" + url[7:]
        if url.startswith("https://") and any(
            url[8:].split("/", 1)[0].lower() == h for h in SEED_HOSTS
        ):
            return url if url.endswith("/") else url + "/"
    raise SdioError("torrent has no known web seed")


def _request(url: str, hosts, limit: int, headers=None) -> tuple[int, dict, bytes]:
    """(status, headers, body); the body is only read for a 2xx answer."""
    name = url.rsplit("/", 1)[-1]
    try:
        r = fetch(
            "GET",
            url,
            hosts,
            user_agent=user_agent(),
            headers=headers,
            timeout=TIMEOUT,
            stream=True,
        )
        with r:
            # the seed refuses some file types (403) and lacks most packs
            if r.status_code in (403, 404, 410):
                raise Missing(f"{name} is not on the web seed ({r.status_code})")
            if r.status_code >= 400:
                raise SdioError(f"{name} answered HTTP {r.status_code}")
            chunks, size = [], 0
            if 200 <= r.status_code < 300:
                for chunk in r.iter_content(1 << 16):
                    size += len(chunk)
                    if size > limit:
                        raise SdioError(f"{name} is larger than expected")
                    chunks.append(chunk)
            return r.status_code, r.headers, b"".join(chunks)
    except (CatalogError, OSError) as e:
        raise SdioError(str(e)) from None


def _get(url: str, hosts, limit: int, headers=None) -> bytes:
    status, _, body = _request(url, hosts, limit, headers)
    if not 200 <= status < 300:
        raise SdioError(f"{url.rsplit('/', 1)[-1]} answered HTTP {status}")
    return body


def _range(t: Torrent, f: File, off: int, n: int) -> bytes:
    data = _get(
        t.url(f), SEED_HOSTS, n, headers={"Range": f"bytes={off}-{off + n - 1}"}
    )
    if len(data) != n:
        raise SdioError(f"{f.path} range came back with {len(data)} bytes")
    return data


def verify(t: Torrent, have: dict[str, bytes], wanted: list[File]) -> int:
    """Checks every piece the wanted files touch. have: path -> whole file;
    other bytes of those pieces are fetched by Range. A piece that shares
    bytes with a file the web seed does not serve cannot be checked; the
    number of those is returned."""
    pieces = set()
    for f in wanted:
        first, last = t.piece_span(f)
        pieces.update(range(first, last + 1))
    unchecked = 0
    for i, n in enumerate(sorted(pieces)):
        set_progress("verify", i, len(pieces))
        start = n * t.piece_length
        end = min(start + t.piece_length, t.size)
        h = hashlib.sha1()
        try:
            for f, off, length in t.segments(start, end):
                data = have.get(f.path)
                h.update(
                    data[off : off + length]
                    if data is not None
                    else _range(t, f, off, length)
                )
        except Missing:
            unchecked += 1
            continue
        if h.digest() != t.piece_hash(n):
            raise SdioError(f"piece {n} does not match the torrent")
    return unchecked


def root() -> str:
    return settings.SDIO_DIR


def index_dir() -> str:
    return os.path.join(root(), "indexes")


def torrent_path() -> str:
    return os.path.join(root(), "SDIO_Update.torrent")


def load_torrent() -> Torrent | None:
    try:
        with open(torrent_path(), "rb") as fh:
            return Torrent(fh.read())
    except (OSError, SdioError):
        return None


def refresh() -> str:
    """Fetches the torrent and the index files that changed. On any error the
    files from the last good refresh stay."""
    row = SdioIndex.load()
    row.checked = djangotime.now()
    try:
        text = _refresh(row)
        row.error = ""
    except (SdioError, OSError) as e:
        text = row.error = str(e)[:255]
    if (t := load_torrent()) and (http := http_packs(t)) is not None:
        row.http_packs = http
        served = served_by(set(http))
        row.full_packs = [
            n
            for n in http
            if all(served(g) for g, _, _ in t.end_segments(t.pack(n[:-3])))
        ]
        text += f", {len(http)} packs on the mirror"
    else:
        text += ", pack list kept"
    row.save()
    return text


def http_packs(t: Torrent) -> list[str] | None:
    """Packs the web seed serves. It has every index but only some packs,
    the others are in the BitTorrent swarm only. None when the mirror did
    not answer cleanly, so a short outage keeps the last list."""
    out = []
    stems = sorted(t.indexes())
    for i, stem in enumerate(stems):
        set_progress("packs", i, len(stems))
        if (f := t.pack(stem)) is None or not f.length:
            continue
        try:
            status, _, body = _request(
                t.url(f), SEED_HOSTS, 1, headers={"Range": "bytes=0-0"}
            )
        except Missing:
            continue
        except SdioError:
            return None
        if status == 206 and len(body) == 1:
            out.append(f"{stem}.7z")
    return out


def served_by(http: set):
    """Whether the web seed has a file of the torrent: the packs in http and
    every index, which the last refresh fetched from it."""

    def served(g: File) -> bool:
        name = g.path.rsplit("/", 1)[-1]
        if g.path.startswith(PACK_DIR):
            return name in http
        return g.path.startswith(INDEX_DIR) and name.endswith(".bin")

    return served


def _refresh(row: SdioIndex) -> str:
    set_progress("torrent")
    unchanged = os.path.isdir(index_dir()) and load_torrent() is not None
    headers = {"If-None-Match": row.etag} if row.etag and unchanged else {}
    status, answer, body = _request(TORRENT_URL, TORRENT_HOSTS, MAX_TORRENT, headers)
    if status == 304:
        return "torrent unchanged"
    if status != 200:
        raise SdioError(f"the torrent answered HTTP {status}")
    etag = answer.get("ETag", "")[:128]
    t = Torrent(body)
    listed = t.indexes()
    if len(listed) < MIN_INDEXES:
        raise SdioError("index list not understood")

    old = index_dir()
    have: dict[str, bytes] = {}
    fetched = []

    def download(f: File) -> bytes:
        data = _get(t.url(f), SEED_HOSTS, f.length)
        if len(data) != f.length:
            raise SdioError(f"{f.path} came back with {len(data)} bytes")
        fetched.append(f)
        return data

    for i, (stem, f) in enumerate(sorted(listed.items())):
        set_progress("indexes", i, len(listed))
        if f.length > MAX_INDEX:
            raise SdioError(f"{stem}.bin is larger than expected")
        try:
            with open(os.path.join(old, f"{stem}.bin"), "rb") as fh:
                data = fh.read(MAX_INDEX + 1)
        except OSError:
            data = None
        have[f.path] = data if data and len(data) == f.length else download(f)
    # files kept from the last refresh are checked too, they share pieces;
    # when they no longer fit, all of them are fetched again
    try:
        unchecked = verify(t, have, list(listed.values()))
    except SdioError:
        kept = [f for f in listed.values() if f not in fetched]
        if not kept:
            raise
        for f in kept:
            have[f.path] = download(f)
        unchecked = verify(t, have, list(listed.values()))

    os.makedirs(root(), exist_ok=True)
    new = old + ".new"
    shutil.rmtree(new, ignore_errors=True)
    os.makedirs(new)
    for f in listed.values():
        with open(os.path.join(new, f.path.rsplit("/", 1)[-1]), "wb") as fh:
            fh.write(have[f.path])
    with open(torrent_path() + ".new", "wb") as fh:
        fh.write(body)
    gone = old + ".old"
    shutil.rmtree(gone, ignore_errors=True)
    if os.path.isdir(old):
        os.rename(old, gone)
    os.rename(new, old)
    os.replace(torrent_path() + ".new", torrent_path())
    shutil.rmtree(gone, ignore_errors=True)

    row.etag = etag
    row.torrent_time = t.created
    row.files = len(listed)
    row.updated = djangotime.now()
    text = f"{len(listed)} indexes, {len(fetched)} downloaded"
    return f"{text}, {unchecked} pieces not checkable" if unchecked else text


# matching


_HWID_PREFIXES = ("PCI\\", "USB\\", "HDAUDIO\\", "ACPI\\", "HID\\")
_KEY_RE = re.compile(r"[A-Z0-9_&\\.-]{3,200}")
_DECOR_RE = re.compile(
    r"nt(amd64|x86|arm64|ia64|arm)?"
    r"(?:\.(\d*)(?:\.(\d*)(?:\.(\w*)(?:\.(\w*)(?:\.(\d*))?)?)?)?)?",
    re.IGNORECASE,
)
# entries kept per hardware id, newest first
MAX_ENTRIES = 40
MAX_OFFER_DEVICES = 200


def device_keys(device_id) -> list[str]:
    """Hardware ids Windows derives from an instance path, most specific
    first: PCI\\VEN_1&DEV_2&SUBSYS_3&REV_4 gives the full id, the id
    without SUBSYS, without REV, and VEN&DEV alone."""
    if not isinstance(device_id, str) or "\\" not in device_id:
        return []
    hwid = device_id.rsplit("\\", 1)[0].upper()
    if not hwid.startswith(_HWID_PREFIXES) or hwid.startswith(catalog._ACPI_INBOX):
        return []
    bus, _, rest = hwid.partition("\\")
    parts = rest.split("&")
    keys = []
    for n in range(len(parts), 0, -1):
        head = parts[:n]
        keys.append(head)
        if n > 2 and any(p.startswith("SUBSYS_") for p in head):
            keys.append([p for p in head if not p.startswith("SUBSYS_")])
    out = []
    for p in keys:
        # a bus\vendor id alone matches everything of that vendor
        if len(p) < 2 and bus not in ("ACPI", "HID"):
            continue
        k = f"{bus}\\{'&'.join(p)}"
        if _KEY_RE.fullmatch(k) and k not in out:
            out.append(k)
    return out


def os_info(agent) -> tuple[str, tuple[int, int], int | None, bool]:
    """(arch, (major, minor), build, server) of a Windows agent."""
    _, build = catalog.os_target(agent.operating_system)
    server = "server" in (agent.operating_system or "").lower()
    arch = {"ARM64": "arm64", "AMD64": "amd64", "X86": "x86"}.get(
        catalog.agent_arch(agent), ""
    )
    if build is None or build >= 10240:
        ver = (10, 0)
    elif build >= 9600:
        ver = (6, 3)
    elif build >= 9200:
        ver = (6, 2)
    else:
        ver = (6, 1)
    return arch, ver, build, server


def decor_rank(decor: str, arch: str, ver, build, server: bool) -> tuple | None:
    """INF decoration NT[arch][.major[.minor[.product[.suite[.build]]]]]
    against the agent: None when it does not apply, else a key where the
    more specific decoration is higher. 64-bit Windows only takes sections
    decorated with its architecture; no architecture means x86."""
    m = _DECOR_RE.fullmatch(decor or "nt")
    if not m or not arch:
        return None
    d_arch, major, minor, product, _, d_build = m.groups()
    if (d_arch or "x86").lower() != arch:
        return None
    os_ver = (int(major or 0), int(minor or 0))
    if os_ver > ver:
        return None
    try:
        kind = int(product, 0) if product else 0
    except ValueError:
        return None
    if kind and kind not in ((2, 3) if server else (1,)):
        return None
    need = int(d_build or 0)
    if need and build is not None and need > build:
        return None
    return bool(d_arch), os_ver, need, bool(kind)


# SDIO folders that only fit with checks of the laptop vendor, the USB
# root hub or the OS that are not made here
_SKIP_PATHS = (
    "_nb/",
    "touchpad_mouse/",
    "matchver/",
    "matchmarker/",
    "l/realtek/",
    "l/r/",
    "intel_2nd/",
    "intel_4th/",
    "intel_sdi_",
    "tweak",
)


def applies(entry: dict, arch: str, ver, build, server: bool) -> bool:
    """The entry is an INF hardware id from the best section of its
    manufacturer line for this OS, with a catalog that covers the OS."""
    if entry.get("pos") != 0:
        return False
    path = f"{entry.get('folder', '')}{entry.get('inf', '')}".lower()
    if any(p in path for p in _SKIP_PATHS):
        return False
    rank = decor_rank(str(entry.get("decor") or ""), arch, ver, build, server)
    if rank is None:
        return False
    for alt in entry.get("alts") or []:
        other = decor_rank(str(alt or ""), arch, ver, build, server)
        if other is not None and other > rank:
            return False
    cats = entry.get("cats") if isinstance(entry.get("cats"), dict) else {}
    return f"2:{ver[0]}.{ver[1]}" in str(cats.get(arch) or "").split(",")


def newer(entry: dict, driver: dict) -> bool:
    """Windows ranks by date first, then by version."""
    have_date = str(driver.get("date") or "")
    date = str(entry.get("date") or "")
    ver = version_key(str(entry.get("version") or ""))
    have = version_key(str(driver.get("version") or ""))
    if ver is None:
        return False
    if have_date and date:
        if date != have_date:
            return date > have_date
        return have is not None and ver > have
    return have is not None and ver > have


def _order(e: dict):
    return str(e.get("date") or ""), version_key(str(e.get("version") or "")) or ()


def _drivers(data) -> list[dict]:
    drivers = data.get("drivers") if isinstance(data, dict) else None
    return [d for d in drivers or [] if isinstance(d, dict)]


def offers(agent, driver, cached, os_=None) -> list[dict]:
    """Applicable pack entries newer than the installed driver, best first;
    for equal date and version the more specific hardware id wins."""
    os_ = os_ or os_info(agent)
    out = []
    for rank, key in enumerate(device_keys(driver.get("device_id"))):
        row = cached.get(key)
        for e in row.entries if row else []:
            if isinstance(e, dict) and applies(e, *os_) and newer(e, driver):
                out.append((_order(e), -rank, e))
    out.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [e for *_, e in out]


def pick(found: list, http) -> dict | None:
    """The entry shown for a device: an installable one first, else the
    newest for information."""
    return next((e for e in found if e.get("pack") in http), None) or next(
        iter(found), None
    )


def fleet_offers(agents) -> list[dict]:
    """The shown entry of every device of these agents, grouped by hardware
    id and version, devices with the most first."""
    index = SdioIndex.load()
    http, full = set(index.http_packs), set(index.full_packs)
    approved = approval_keys()
    rows = list(
        InstalledDrivers.objects.filter(agent__plat=AgentPlat.WINDOWS, agent__in=agents)
        .select_related("agent")
        .defer(*(f"agent__{f}" for f in AGENT_DEFER))
    )
    fleet = [(row.agent, _drivers(row.data)) for row in rows]
    cached = cached_for([d for _, drivers in fleet for d in drivers])
    groups: dict[tuple, dict] = {}
    for agent, drivers in fleet:
        os_ = os_info(agent)
        for d in drivers:
            best = pick(offers(agent, d, cached, os_), http)
            if best is None:
                continue
            key = (best["hwid"].upper(), best.get("version"))
            group = groups.get(key)
            # the same version in a pack the mirror serves wins the row
            if group is None or (not group["pack_http"] and best.get("pack") in http):
                group = groups[key] = {
                    **{f: best.get(f) for f in SHOWN},
                    "approved": key in approved,
                    "pack_http": best.get("pack") in http,
                    "pack_verified": best.get("pack") in full,
                    "device_count": group["device_count"] if group else 0,
                    "devices": group["devices"] if group else [],
                }
            group["device_count"] += 1
            if len(group["devices"]) < MAX_OFFER_DEVICES:
                group["devices"].append(
                    {
                        "agent_id": agent.agent_id,
                        "hostname": agent.hostname,
                        "device": d.get("device"),
                        "class": d.get("class"),
                        "version": d.get("version"),
                        "date": d.get("date"),
                    }
                )
    return sorted(
        groups.values(), key=lambda g: (-g["device_count"], str(g["desc"]).lower())
    )


def cached_for(drivers) -> dict:
    names = {k for d in drivers for k in device_keys(d.get("device_id"))}
    return {c.hwid: c for c in SdioCatalog.objects.filter(hwid__in=names)}


def approval_keys() -> set[tuple[str, str]]:
    return set(SdioApproval.objects.values_list("hwid", "version"))


def fleet_keys() -> set[str]:
    keys = set()
    rows = InstalledDrivers.objects.filter(agent__plat=AgentPlat.WINDOWS)
    for data in rows.values_list("data", flat=True).iterator(chunk_size=200):
        for d in _drivers(data):
            keys.update(device_keys(d.get("device_id")))
    return keys


def scan() -> str:
    """Pack entries for every hardware id of the fleet, from the indexes on disk."""
    t = load_torrent()
    if t is None:
        raise SdioError("no SDIO index has been downloaded yet")
    found: dict[str, list] = {k: [] for k in fleet_keys()}
    listed = sorted(t.indexes().items())
    for i, (stem, f) in enumerate(listed):
        set_progress("scan", i, len(listed))
        pack = t.pack(stem)
        if pack is None:
            continue
        path = os.path.join(index_dir(), f"{stem}.bin")
        for e in sdioindex.read(path, set(found)):
            hits = found.get(e["hwid"].upper())
            if hits is not None:
                hits.append({**e, "pack": f"{stem}.7z", "pack_size": pack.length})
    now = djangotime.now()
    with transaction.atomic():
        SdioCatalog.objects.all().delete()
        SdioCatalog.objects.bulk_create(
            [
                SdioCatalog(
                    hwid=k,
                    checked=now,
                    entries=sorted(v, key=_order, reverse=True)[:MAX_ENTRIES],
                )
                for k, v in found.items()
            ],
            batch_size=500,
        )
    return f"{len(found)} hardware ids, {sum(1 for v in found.values() if v)} with pack drivers"


SHOWN = (
    "hwid",
    "version",
    "date",
    "provider",
    "desc",
    "pack",
    "pack_size",
    "folder",
    "inf",
)


def driver_fields(agent, drivers: list) -> list[dict]:
    """sdio, sdio_checked and sdio_job per driver row."""
    cached = cached_for(drivers)
    approved = approval_keys()
    index = SdioIndex.load()
    http, full = set(index.http_packs), set(index.full_packs)
    os_ = os_info(agent)
    since = djangotime.now() - dt.timedelta(days=30)
    jobs = list(
        SdioJob.objects.filter(agent=agent, created__gte=since).order_by("-created")
    )
    out = []
    for d in drivers:
        keys = device_keys(d.get("device_id"))
        best = pick(offers(agent, d, cached, os_), http)
        checks = [cached[k].checked for k in keys if k in cached]
        job = next(
            (
                j
                for j in jobs
                if any(
                    isinstance(i, dict) and i.get("device_id") == d.get("device_id")
                    for i in j.items
                )
            ),
            None,
        )
        out.append(
            {
                "sdio": (
                    {
                        **{f: best.get(f) for f in SHOWN},
                        "approved": (best["hwid"].upper(), best.get("version"))
                        in approved,
                        "pack_http": best.get("pack") in http,
                        # both end pieces checked against the torrent
                        "pack_verified": best.get("pack") in full,
                    }
                    if best
                    else None
                ),
                "sdio_checked": (
                    min(checks) if keys and len(checks) == len(keys) else None
                ),
                "sdio_job": (
                    {
                        "id": job.id,
                        "state": job.state,
                        "detail": job.detail,
                        "updated": job.updated,
                        "done": job.done,
                        "total": job.total,
                    }
                    if job
                    else None
                ),
            }
        )
    return out


# install jobs

ACTIVE = ("queued", "downloading", "installing")
JOB_STALE = dt.timedelta(hours=6)
RETRY_FAILED = dt.timedelta(days=7)
DEADLINE = 4 * 60 * 60
SCRIPT_TIMEOUT = 1800


def _close_stale(agent) -> None:
    SdioJob.objects.filter(
        agent=agent, state__in=ACTIVE, updated__lt=djangotime.now() - JOB_STALE
    ).update(
        state="failed",
        detail="no result from the agent within 6 hours",
        # counts as an attempt: a device that crashed in the install is not
        # sent the same driver again within the week
        results=[{"result": "fail", "msg": "no result from the agent"}],
    )


def _tried(agent) -> tuple[set, set]:
    """(done, failed recently) as (device_id, hwid, version) sets."""
    done, failed = set(), set()
    since = djangotime.now() - RETRY_FAILED
    for state, items, results, created in SdioJob.objects.filter(
        agent=agent, state__in=("done", "failed")
    ).values_list("state", "items", "results", "created"):
        # a job the agent never ran does not count as an attempt
        if state == "failed" and (not results or created < since):
            continue
        for i in items if isinstance(items, list) else []:
            if isinstance(i, dict):
                key = (
                    i.get("device_id"),
                    str(i.get("hwid", "")).upper(),
                    i.get("version"),
                )
                (done if state == "done" else failed).add(key)
    return done, failed


def wanted_items(agent, drivers, approved, http) -> list[dict]:
    cached = cached_for(drivers)
    os_ = os_info(agent)
    done, failed = _tried(agent)
    items = []
    for d in drivers:
        for e in offers(agent, d, cached, os_):
            key = (e["hwid"].upper(), e.get("version"))
            if key not in approved or e.get("pack") not in http:
                continue
            if (d.get("device_id"), *key) in done | failed:
                break
            items.append(
                {
                    "device_id": d.get("device_id"),
                    "device": str(d.get("device") or "")[:255],
                    "hwid": e["hwid"],
                    "version": e.get("version"),
                    "desc": e.get("desc"),
                    "pack": e.get("pack"),
                    "folder": e.get("folder"),
                    "inf": e.get("inf"),
                }
            )
            break
    return items


def _eligible(agent) -> bool:
    return (
        agent.plat == AgentPlat.WINDOWS
        and agent.is_online
        and agent_ver(agent.version) >= agent_ver(settings.SDIO_MIN_AGENT)
        and agent.get_patch_policy().drivers != "exclude"
    )


def apply_approvals(agent_pks=None) -> str:
    approved = approval_keys()
    if not approved:
        return "no approved pack drivers"
    http = set(SdioIndex.load().http_packs)
    authors = dict(
        ((h.upper(), v), by)
        for h, v, by in SdioApproval.objects.values_list(
            "hwid", "version", "created_by"
        )
    )
    rows = InstalledDrivers.objects.filter(
        agent__plat=AgentPlat.WINDOWS
    ).select_related("agent")
    if agent_pks is not None:
        rows = rows.filter(agent__pk__in=agent_pks)
    sent = 0
    total = rows.count() if agent_pks is None else 0
    for i, row in enumerate(rows.iterator(chunk_size=100)):
        if total:
            set_progress("apply", i, total)
        agent = row.agent
        _close_stale(agent)
        if not _eligible(agent) or agent.sdio_jobs.filter(state__in=ACTIVE).exists():
            continue
        items = wanted_items(agent, _drivers(row.data), approved, http)
        if items and start_job(agent, items, authors):
            sent += 1
    return f"{sent} install jobs sent"


def start_job(agent, items, authors) -> bool:
    job = SdioJob.objects.create(
        id=uuid.uuid4().hex, agent=agent, state="queued", items=items
    )
    by = sorted(
        {authors.get((i["hwid"].upper(), i["version"]), "") for i in items} - {""}
    )
    AuditLog.audit_raw_command(
        username=", ".join(by)[:255] or "system",
        agent=agent,
        cmd="approved SDIO drivers: "
        + "; ".join(f"{i['desc']} {i['version']} for {i['device']}" for i in items),
        shell="sdio",
        debug_info={"job": job.id},
    )
    answer = asyncio.run(
        agent.nats_cmd({"func": "sdiodriver", "payload": {"job": job.id}}, timeout=5)
    )
    if answer == "ok":
        return True
    job.state = "failed"
    job.detail = f"the agent did not take the job: {answer}"[:500]
    job.save(update_fields=["state", "detail", "updated"])
    return False


def job_plan(job: SdioJob) -> dict:
    """The plan the agent fetches: per pack its download and piece check and
    the approved folders to take from it."""
    t = load_torrent()
    if t is None:
        raise SdioError("the SDIO index is gone from the server")
    folders: dict[str, list] = {}
    for i in job.items:
        folders.setdefault(i["pack"], [])
        if i["folder"] not in folders[i["pack"]]:
            folders[i["pack"]].append(i["folder"])
    served = served_by(set(SdioIndex.load().http_packs))
    packs = []
    for name, wanted in folders.items():
        f = t.pack(name.removesuffix(".7z"))
        if f is None:
            raise SdioError(
                f"{name} is no longer listed, it is tried again after the next scan"
            )
        packs.append({**t.plan(f, served), "folders": wanted})
    return {
        "job": job.id,
        "deadline": DEADLINE,
        "script": SCRIPTS[AgentPlat.WINDOWS].read_text(),
        "script_timeout": SCRIPT_TIMEOUT,
        "packs": packs,
    }

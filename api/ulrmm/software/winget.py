# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
The winget community index (source2.msix, the format winget itself reads
since 1.8): packages(id, name, latest_version) in Public/index.db. The older
source.msix is 22 MB and needs winget's version ordering for the latest.
"""

import base64
import hashlib
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile

import requests
from django.utils import timezone as djangotime

from .catalog import CatalogError, fetch
from .models import WingetCatalog

SOURCE_URL = "https://cdn.winget.microsoft.com/cache/source2.msix"
SOURCE_HOSTS = ("cdn.winget.microsoft.com",)
TIMEOUT = (10, 60)
MAX_MSIX = 32 << 20
MAX_INDEX = 128 << 20
MIN_ROWS = 1000
INDEX_MEMBER = "Public/index.db"
# winget runs without a shell, the server also requires catalog membership
ID_RE = re.compile(r"[^\W_][\w.+&!,@-]{0,127}")


class IndexProblem(Exception):
    pass


def _download(r, dest: str) -> tuple[str, str]:
    """Body -> dest with the size cap, returns (sha256 hex, md5 base64)."""
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with open(dest, "wb") as fh:
        for chunk in r.iter_content(1 << 20):
            size += len(chunk)
            if size > MAX_MSIX:
                raise IndexProblem(f"source2.msix is larger than {MAX_MSIX >> 20} MiB")
            sha.update(chunk)
            md5.update(chunk)
            fh.write(chunk)
    return sha.hexdigest(), base64.b64encode(md5.digest()).decode()


def _extract(msix: str, dest: str) -> None:
    with zipfile.ZipFile(msix) as z:
        try:
            info = z.getinfo(INDEX_MEMBER)
        except KeyError:
            raise IndexProblem(f"{INDEX_MEMBER} is missing") from None
        if info.file_size > MAX_INDEX:
            raise IndexProblem(f"{INDEX_MEMBER} is larger than {MAX_INDEX >> 20} MiB")
        # the header size could lie, the copy counts again
        with z.open(info) as src, open(dest, "wb") as out:
            copied = 0
            while chunk := src.read(1 << 20):
                copied += len(chunk)
                if copied > MAX_INDEX:
                    raise IndexProblem(
                        f"{INDEX_MEMBER} is larger than {MAX_INDEX >> 20} MiB"
                    )
                out.write(chunk)


def read_index(path: str) -> tuple[list, int | None]:
    """([[id, name, version], ...] sorted by id, lastwritetime)."""
    db = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        meta = dict(db.execute("SELECT name, value FROM metadata").fetchall())
        if str(meta.get("majorVersion")) != "2":
            raise IndexProblem(f"index format {meta.get('majorVersion')!r}, expected 2")
        rows = db.execute("SELECT id, name, latest_version FROM packages").fetchall()
    except sqlite3.Error as e:
        raise IndexProblem(f"index.db: {e}") from e
    finally:
        db.close()
    packages = [
        [i, n[:128], v[:64]]
        for i, n, v in rows
        if isinstance(i, str)
        and isinstance(n, str)
        and isinstance(v, str)
        and ID_RE.fullmatch(i)
    ]
    if len(packages) < MIN_ROWS:
        raise IndexProblem(f"only {len(packages)} usable packages in the index")
    packages.sort(key=lambda p: p[0].casefold())
    try:
        stamp = int(meta.get("lastwritetime"))
    except (TypeError, ValueError):
        stamp = None
    return packages, stamp


def refresh() -> str:
    """Downloads the index when it changed. The last good list stays on any error."""
    cat = WingetCatalog.load()
    now = djangotime.now()
    headers = {"If-None-Match": cat.etag} if cat.etag and cat.packages else {}
    tmp = tempfile.mkdtemp(prefix="winget-")
    try:
        try:
            with fetch(
                "GET",
                SOURCE_URL,
                SOURCE_HOSTS,
                headers=headers,
                timeout=TIMEOUT,
                stream=True,
            ) as r:
                if r.status_code == 304:
                    WingetCatalog.objects.filter(pk=cat.pk).update(
                        checked=now, error=""
                    )
                    return "winget catalog unchanged"
                if r.status_code != 200:
                    raise IndexProblem(f"HTTP {r.status_code}")
                length = r.headers.get("Content-Length", "")
                if length.isdigit() and int(length) > MAX_MSIX:
                    raise IndexProblem(
                        f"source2.msix is larger than {MAX_MSIX >> 20} MiB"
                    )
                msix = os.path.join(tmp, "source2.msix")
                sha, md5 = _download(r, msix)
                sent = r.headers.get("Content-MD5", "")
                etag = r.headers.get("ETag", "")[:128]
            if sent and sent != md5:
                raise IndexProblem("Content-MD5 does not match the download")
            index = os.path.join(tmp, "index.db")
            _extract(msix, index)
            packages, stamp = read_index(index)
        except (requests.RequestException, CatalogError, OSError) as e:
            raise IndexProblem(str(e) or type(e).__name__) from e
        except zipfile.BadZipFile as e:
            raise IndexProblem(f"source2.msix: {e}") from e
    except IndexProblem as e:
        WingetCatalog.objects.filter(pk=cat.pk).update(checked=now, error=str(e)[:255])
        return f"winget catalog not updated: {e}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    WingetCatalog.objects.filter(pk=cat.pk).update(
        packages=packages,
        etag=etag,
        sha256=sha,
        index_time=stamp,
        checked=now,
        updated=now,
        error="",
    )
    return f"winget catalog has {len(packages)} packages"


def find(package_id: str) -> list | None:
    """The catalog row of an id, ignoring case like winget does."""
    wanted = package_id.casefold()
    packages = WingetCatalog.load().packages
    return next(
        (p for p in packages if isinstance(p, list) and p[0].casefold() == wanted),
        None,
    )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import glob
import ipaddress
import itertools
import os
import socket
import time
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone as djangotime

from agents.models import Agent
from packages.utils import remove_stale_uploads
from ulrmm.celery import app
from ulrmm.constants import ONLINE_AGENTS, AgentPlat

from .models import BaseIso, SecurityEvent

SECURITY_EVENT_DAYS = 90
# the largest base image an upload or a URL download may write; Windows 11
# media runs past 8 GiB
MAX_DOWNLOAD = 14 * 1024**3
ISO_JOB_TTL = 24 * 3600


def _online(pk: int):
    agent = Agent.objects.filter(pk=pk).only(*ONLINE_AGENTS, "site").first()
    return agent if agent and agent.is_online else None


@app.task
def enrolled_laps_task(pk: int) -> str:
    """LAPS rotation soon after enrollment; an agent that is not online yet
    is left to the hourly laps_rotate_task."""
    from laps.tasks import rotate_agent_task

    if _online(pk) is None:
        return "not online"
    return rotate_agent_task(pk)


@app.task
def enrolled_keys_task(pk: int) -> str:
    """BitLocker recovery keys of a freshly enrolled Windows agent; the
    nightly collect_recovery_keys_task covers it otherwise."""
    from encryption.utils import COLLECT_TIMEOUT, collect_payload, parse_collect, store

    agent = _online(pk)
    if agent is None or agent.plat != AgentPlat.WINDOWS:
        return "skipped"
    out = asyncio.run(
        agent.nats_cmd(collect_payload(AgentPlat.WINDOWS), timeout=COLLECT_TIMEOUT + 10)
    )
    rep = parse_collect(AgentPlat.WINDOWS, out)
    store(agent, rep)
    return rep.error or "ok"


@app.task
def prune_security_events() -> int:
    """Security events older than 90 days."""
    cutoff = djangotime.now() - dt.timedelta(days=SECURITY_EVENT_DAYS)
    deleted, _ = SecurityEvent.objects.filter(last_seen__lt=cutoff).delete()
    return deleted


@app.task
def promote_command_keys() -> str:
    from .signing import promote_command_keys as promote

    return promote()


def iso_job_key(job_id: str) -> str:
    return f"iso:job:{job_id}"


def iso_job_set(job_id: str, **fields) -> None:
    rec = cache.get(iso_job_key(job_id)) or {}
    rec.update(fields)
    cache.set(iso_job_key(job_id), rec, ISO_JOB_TTL)


def iso_path(filename: str) -> str:
    return os.path.join(settings.ISO_DIR, filename)


def iso_dir() -> str:
    path = settings.ISO_DIR
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        # nginx (www-data) reads the images through X-Accel
        os.chmod(path, 0o755)
    return path


def iso_uploads_dir() -> str:
    path = os.path.join(iso_dir(), ".uploads")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _inspect(row: BaseIso, sha: str | None = None) -> None:
    from . import iso

    row.status = BaseIso.Status.INSPECTING
    row.error = ""
    row.save(update_fields=["status", "error"])
    path = iso_path(row.filename)
    row.sha256 = sha or iso.sha256_of(path)
    info = iso.inspect(path)
    row.size = info.get("size") or os.path.getsize(path)
    row.label = (info.get("label") or "")[:32]
    row.os = info.get("os") or ""
    row.bios = bool(info.get("bios"))
    row.efi = bool(info.get("efi"))
    row.udf = bool(info.get("udf"))
    row.status = BaseIso.Status.READY
    row.save()


def _fail(row: BaseIso, e: Exception) -> None:
    row.status = BaseIso.Status.ERROR
    row.error = (str(e) or e.__class__.__name__)[:500]
    row.save(update_fields=["status", "error"])


@app.task
def inspect_base_iso(pk: int) -> str:
    """Hash and inspect a base image, then mark it ready."""
    row = BaseIso.objects.filter(pk=pk).first()
    if row is None:
        return "gone"
    try:
        _inspect(row)
    except Exception as e:
        _fail(row, e)
        return "error"
    return "ready"


def dl_key(pk) -> str:
    return f"iso:dl:{pk}"


def dl_progress(pk) -> dict | None:
    return cache.get(dl_key(pk))


def dl_set(pk, **fields) -> None:
    rec = cache.get(dl_key(pk)) or {}
    rec.update(fields)
    cache.set(dl_key(pk), rec, ISO_JOB_TTL)


def dl_cancel(pk) -> None:
    cache.set(f"iso:dl:cancel:{pk}", 1, 3600)


def url_host(url: str) -> str | None:
    """Host the request connects to. Refuse a URL that urlparse and urllib3
    read differently (a backslash before @)."""
    from urllib3.util import parse_url

    if "\\" in url:
        raise ValueError("the url contains a backslash")
    try:
        ours = urlparse(url).hostname
        theirs = parse_url(url).host
    except ValueError:
        raise ValueError("the url cannot be parsed")
    theirs = theirs.strip("[]").lower() if theirs else None
    if ours != theirs:
        raise ValueError("the url names two different hosts")
    return ours


def _check_host(hostname: str | None) -> None:
    if not hostname:
        raise ValueError("the url has no host")
    try:
        infos = socket.getaddrinfo(hostname, 443)
    except socket.gaierror:
        raise ValueError("the host does not resolve")
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise ValueError("the host resolves to a private address")


def _open(url: str, have: int):
    """GET url with https and public-host checks on every redirect hop."""
    for _ in range(6):
        if urlparse(url).scheme != "https":
            raise ValueError("a redirect left https")
        _check_host(url_host(url))
        headers = {"Range": f"bytes={have}-"} if have else {}
        r = requests.get(
            url, stream=True, timeout=30, headers=headers, allow_redirects=False
        )
        if r.status_code in (301, 302, 303, 307, 308):
            url = requests.compat.urljoin(url, r.headers.get("Location", ""))
            r.close()
            continue
        return r
    raise ValueError("too many redirects")


@app.task
def download_base_iso(pk: int) -> str:
    """Fetch source_url (https only, public hosts, size capped, resumable)
    into ISO_DIR, verify the checksum, then inspect."""
    from . import iso

    row = BaseIso.objects.filter(pk=pk).first()
    if row is None:
        return "gone"
    if not cache.add(f"iso:dl:lock:{pk}", 1, ISO_JOB_TTL):
        return "busy"
    dest = iso_path(row.filename)
    part = dest + ".part"
    cancel_key = f"iso:dl:cancel:{pk}"
    try:
        if urlparse(row.source_url).scheme != "https":
            raise ValueError("only https downloads are allowed")
        have = os.path.getsize(part) if os.path.exists(part) else 0
        r = _open(row.source_url, have)
        with r:
            if getattr(r, "status_code", 200) == 416:
                os.remove(part)
                raise ValueError("the partial file was stale, retry")
            r.raise_for_status()
            resumed = have > 0 and getattr(r, "status_code", 200) == 206
            if not resumed:
                have = 0
            length = int(r.headers.get("Content-Length") or 0)
            total = 0
            if resumed:
                tail = (r.headers.get("Content-Range") or "").rpartition("/")[2]
                total = (
                    int(tail) if tail.isdigit() else (have + length if length else 0)
                )
            elif length:
                total = length
            if total > MAX_DOWNLOAD:
                raise ValueError("the file is larger than the 14 GiB limit")
            done = have
            t0, b0 = time.monotonic(), done
            speed, last = 0.0, 0.0

            def report(status="downloading"):
                pct = round(done / total * 100, 1) if total else 0.0
                eta = round((total - done) / speed) if speed > 0 and total else None
                dl_set(
                    pk,
                    status=status,
                    progressPercent=pct,
                    downloadedBytes=done,
                    totalBytes=total,
                    speedBytesPerSec=round(speed),
                    etaSeconds=eta,
                    error="",
                )

            report()
            with open(part, "ab" if resumed else "wb") as f:
                for chunk in r.iter_content(1024 * 1024):
                    if cache.get(cancel_key):
                        cache.delete(cancel_key)
                        row.status = BaseIso.Status.ERROR
                        row.error = "cancelled"
                        row.save(update_fields=["status", "error"])
                        dl_set(pk, status="error", error="cancelled")
                        return "cancelled"
                    done += len(chunk)
                    if done > MAX_DOWNLOAD:
                        f.close()
                        os.remove(part)
                        raise ValueError("the file is larger than the 14 GiB limit")
                    f.write(chunk)
                    now = time.monotonic()
                    if now - t0 >= 1:
                        speed = (done - b0) / (now - t0)
                        if now - t0 >= 2:
                            t0, b0 = now, done
                    if now - last >= 0.5:
                        last = now
                        report()
            report()
        if total and done != total:
            raise ValueError("the download ended early")
        os.replace(part, dest)
        row.status = BaseIso.Status.VERIFYING
        row.error = ""
        row.save(update_fields=["status", "error"])
        dl_set(pk, status="verifying", progressPercent=100.0, etaSeconds=None)
        vlast = [0.0]

        def verify_cb(n, size):
            now = time.monotonic()
            if now - vlast[0] >= 0.5:
                vlast[0] = now
                dl_set(pk, verifiedBytes=n, totalBytes=size)

        sha = iso.sha256_of(dest, progress=verify_cb)
        want = row.expected_sha256.strip().lower()
        if want and want != sha.lower():
            os.remove(dest)
            raise ValueError("SHA-256 mismatch")
        _inspect(row, sha)
        dl_set(pk, status="ready", progressPercent=100.0, etaSeconds=None, error="")
    except Exception as e:
        _fail(row, e)
        dl_set(pk, status="error", error=str(e)[:500])
        return "error"
    finally:
        cache.delete(f"iso:dl:lock:{pk}")
    return "ready"


@app.task
def build_iso_task(job_id: str, body: dict, username: str) -> str:
    """Build the ISO of one job into ISO_DIR/jobs/<job_id>.iso, then move it
    into the library as a built image."""
    from accounts.models import User

    from . import iso, iso_layout
    from .iso_views import _register, _taken, iso_name, render_for

    iso_job_set(job_id, state="running", pct=0, text="Rendering")
    try:
        user = User.objects.get(username=username)
        deployment, target_id, _clean, files, family = render_for(user, body)
        base = BaseIso.objects.get(pk=body.get("base"))
        base_path = iso_path(base.filename)
        agent = iso_layout.agent_payload(deployment, family, target_id)
        layout = iso_layout.full(
            target_id, deployment, files, agent, base=iso.inspect(base_path)
        )
        jobs = os.path.join(iso_dir(), "jobs")
        os.makedirs(jobs, exist_ok=True)
        out = os.path.join(jobs, f"{job_id}.iso")
        last = [-1]

        def progress(done, total):
            pct = int(85 * done / total) if total else 0
            if pct != last[0]:
                last[0] = pct
                iso_job_set(job_id, pct=pct, text="Writing the image")

        try:
            with open(out, "w+b") as f:
                res = iso.inject(
                    base_path, f, layout.files, edits=layout.edits, progress=progress
                )
            info = iso.inspect(out)
        except BaseException:
            if os.path.exists(out):
                os.remove(out)
            raise
        # client and site names can be long, a file name has 255 bytes. The
        # row is made before the move: its unique filename settles two builds
        # that finish at the same moment
        stem = iso_name(deployment, target_id)[:200]
        label = layout.label or base.label
        for n in itertools.count(1):
            name = f"{stem}.iso" if n == 1 else f"{stem}-{n}.iso"
            if _taken(name):
                continue
            try:
                with transaction.atomic():
                    row = _register(
                        name,
                        kind=BaseIso.Kind.BUILT,
                        status=BaseIso.Status.READY,
                        size=res["size"],
                        sha256=res["sha256"],
                        label=(info.get("label") or label)[:32],
                        os=info.get("os") or base.os,
                        bios=bool(info.get("bios")),
                        efi=bool(info.get("efi")),
                        udf=bool(info.get("udf")),
                        built_by=username,
                        target=target_id,
                        deployment=deployment,
                    )
            except IntegrityError:
                continue
            break
        dest = iso_path(name)
        os.replace(out, dest)
        os.chmod(dest, 0o644)
        iso_job_set(
            job_id,
            state="done",
            pct=100,
            text="Done",
            name=name,
            size=res["size"],
            sha256=res["sha256"],
            label=label,
            notes=layout.notes
            + (
                []
                if res.get("mbr_kept", True)
                else [
                    "The MBR and GPT of the base image are not carried over: boot "
                    "the result as a CD/DVD or virtual media, or write it to USB "
                    "with Rufus or Ventoy."
                ]
            ),
            path=dest,
            iso=row.pk,
        )
    except Exception as e:
        iso_job_set(job_id, state="error", text="Failed", error=str(e)[:500])
        return "error"
    return "done"


@app.task
def prune_iso_jobs() -> int:
    """Unfinished build leftovers and staged ISO uploads older than 24 hours."""
    cutoff = time.time() - ISO_JOB_TTL
    n = 0
    for path in glob.glob(os.path.join(settings.ISO_DIR, "jobs", "*.iso")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                n += 1
        except OSError:
            pass
    return n + remove_stale_uploads(os.path.join(settings.ISO_DIR, ".uploads"))

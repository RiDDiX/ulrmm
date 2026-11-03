# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import os
import tempfile
import time
from contextlib import suppress

import requests
from django.core.cache import cache
from django.db import IntegrityError, transaction

from agents.models import Agent
from logs.models import DebugLog
from ulrmm.celery import app
from ulrmm.constants import AGENT_DEFER, AgentPlat
from ulrmm.utils import redis_lock

from . import baselines, catalog, sdio, sdioindex, winget
from .catalog import CatalogError
from .models import InstalledDrivers, SdioIndex

SCAN_LOCK = "driver-catalog"
SCAN_MAX = 300
SCAN_FRESH = dt.timedelta(days=7)
SCAN_FRESH_ERROR = dt.timedelta(days=1)
CHECK_MAX = 100
CHECK_FRESH = dt.timedelta(hours=1)

JOB_TTL = 2 * 60 * 60
MAX_CAB = 1 << 30
DOWNLOAD_SECONDS = 25 * 60


@app.task(bind=True)
def refresh_winget_task(self) -> str:
    with redis_lock("winget-catalog", self.app.oid) as acquired:
        if not acquired:
            return "winget catalog refresh already running"
        return winget.refresh()


def _summary(stats: dict) -> str:
    text = f"{stats['requests']} catalog searches, {stats['errors']} failed"
    return f"{text}, stopped: {stats['stopped']}" if stats["stopped"] else text


@app.task(bind=True)
def scan_driver_catalog_task(self) -> str:
    with redis_lock(SCAN_LOCK, self.app.oid) as acquired:
        if not acquired:
            return "driver catalog scan already running"
        keys = {}
        rows = InstalledDrivers.objects.filter(agent__plat=AgentPlat.WINDOWS)
        for data in rows.values_list("data", flat=True).iterator(chunk_size=200):
            keys.update(dict.fromkeys(catalog.inventory_keys(data)))
        stats = catalog.scan(list(keys), SCAN_MAX, SCAN_FRESH, SCAN_FRESH_ERROR)
        if stats["stopped"]:
            DebugLog.warning(f"Driver catalog scan: {_summary(stats)}")
        return _summary(stats)


@app.task(bind=True)
def check_agent_catalog_task(self, agent_pk: int) -> str:
    with redis_lock(SCAN_LOCK, self.app.oid) as acquired:
        if not acquired:
            return "driver catalog scan already running"
        row = InstalledDrivers.objects.filter(agent_id=agent_pk).first()
        keys = catalog.inventory_keys(row.data) if row else []
        key = check_progress_key(agent_pk)

        def step(done, total):
            cache.set(key, {"done": done, "total": total}, CHECK_PROGRESS_TTL)

        try:
            stats = catalog.scan(keys, CHECK_MAX, CHECK_FRESH, CHECK_FRESH, step=step)
        finally:
            cache.delete(key)
        return _summary(stats)


CHECK_PROGRESS_TTL = 60 * 60


def check_progress_key(agent_pk: int) -> str:
    return f"drvcat_check_{agent_pk}"


def job_key(job: str) -> str:
    return f"drvcat_job_{job}"


def agent_job_key(agent_id: str) -> str:
    return f"drvcat_{agent_id}"


def set_job(job: str, **fields) -> None:
    data = cache.get(job_key(job)) or {}
    cache.set(job_key(job), {**data, **fields}, JOB_TTL)


def _fetch_cab(url: str, sha256: str, size: int) -> str:
    """Download into PACKAGES_DIR, checked against the dialog's sha256."""
    from packages.utils import packages_dir

    fd, path = tempfile.mkstemp(prefix=".incoming-", dir=packages_dir())
    os.fchmod(fd, 0o644)
    digest, got, head = hashlib.sha256(), 0, b""
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    try:
        with os.fdopen(fd, "wb") as fh, catalog.fetch(
            "GET", url, catalog.DOWNLOAD_HOSTS, stream=True, timeout=(10, 60)
        ) as r:
            if r.status_code != 200:
                raise CatalogError(f"download: HTTP {r.status_code}")
            for chunk in r.iter_content(1 << 20):
                got += len(chunk)
                if got > MAX_CAB:
                    raise CatalogError(f"the cab is larger than {MAX_CAB >> 30} GiB")
                if time.monotonic() > deadline:
                    raise CatalogError("the download ran out of time")
                head += chunk[: max(0, 4 - len(head))]
                digest.update(chunk)
                fh.write(chunk)
        if size and got != size:
            raise CatalogError(f"downloaded {got} bytes, the catalog lists {size}")
        if digest.hexdigest() != sha256:
            raise CatalogError("the download does not match the catalog's sha256")
        if head != b"MSCF":
            raise CatalogError("the download is not a cab file")
    except BaseException as e:
        with suppress(FileNotFoundError):
            os.unlink(path)
        if isinstance(e, requests.RequestException):
            raise CatalogError(f"download failed: {type(e).__name__}") from e
        raise
    return path


def _package(entry: dict, info: dict, path: str, size: int, username: str):
    """A driver package for the cab, the existing one for the same sha256."""
    from packages.models import PackageKind, SoftwarePackage
    from packages.utils import clean_filename

    sha = info["sha256"]
    if pkg := SoftwarePackage.objects.filter(sha256=sha).first():
        os.unlink(path)
        return pkg
    try:
        filename, kind = clean_filename(info["name"])
    except ValueError:
        filename, kind = "", ""
    if kind != PackageKind.DRIVER or not filename.lower().endswith(".cab"):
        os.unlink(path)
        raise CatalogError(f"unexpected file name {info['name'][:100]}")
    title = entry["title"][:255]
    name = title
    if SoftwarePackage.objects.filter(name=name).exists():
        name = f"{title[:246]} {entry['update_id'][:8]}"
    try:
        with transaction.atomic():
            pkg = SoftwarePackage.objects.create(
                name=name,
                filename=filename,
                kind=PackageKind.DRIVER,
                plat=AgentPlat.WINDOWS,
                sha256=sha,
                size=size,
                allow_unsigned=False,
                timeout=1800,
                created_by=username,
            )
            os.replace(path, pkg.file_path)
    except IntegrityError:
        os.unlink(path)
        if pkg := SoftwarePackage.objects.filter(sha256=sha).first():
            return pkg
        raise CatalogError(f"A package named {name} exists already.") from None
    return pkg


def install_from_catalog(job, agent, device_id: str, update_id: str, user) -> dict:
    from packages.models import RunAs
    from packages.services import start_installs

    row = InstalledDrivers.objects.filter(agent=agent).first()
    drivers = row.data.get("drivers") if row and isinstance(row.data, dict) else []
    driver = next(
        (
            d
            for d in drivers or []
            if isinstance(d, dict) and d.get("device_id") == device_id
        ),
        None,
    )
    tries = catalog.candidates(agent, driver) if driver else []
    if not tries or tries[0].get("update_id") != update_id:
        raise CatalogError("The catalog no longer offers this update for the device.")

    fetcher = catalog.Fetcher()
    wanted = catalog.agent_arch(agent)
    entry = next(
        (e for e in tries if catalog.arch_ok(fetcher.arch(e["update_id"]), wanted)),
        None,
    )
    if entry is None:
        raise CatalogError(
            f"No catalog entry of version {tries[0].get('version')} is for {wanted}."
        )
    info = fetcher.download(entry["update_id"])
    set_job(job, state="downloading")
    size = entry.get("size") if isinstance(entry.get("size"), int) else 0
    path = _fetch_cab(info["url"], info["sha256"], size)
    package = _package(entry, info, path, os.path.getsize(path), user.username)
    try:
        result = start_installs(
            user,
            package,
            [agent],
            RunAs.SYSTEM,
            {"source": "catalog", "update_id": entry["update_id"]},
        )
    except ValueError as e:
        raise CatalogError(str(e)) from e
    return {"batch": result["batch"], "package": package.pk}


@app.task
def catalog_install_task(
    job: str, agent_pk: int, device_id: str, update_id: str, user_pk: int
) -> str:
    from accounts.models import User

    agent = Agent.objects.defer(*AGENT_DEFER).filter(pk=agent_pk).first()
    try:
        user = User.objects.filter(pk=user_pk).first()
        if agent is None or user is None:
            raise CatalogError("the agent or the user is gone")
        done = install_from_catalog(job, agent, device_id, update_id, user)
    except (CatalogError, OSError) as e:
        set_job(job, state="failed", detail=str(e)[:500])
        DebugLog.warning(f"Driver install from the catalog failed: {e}", agent=agent)
        return f"failed: {e}"
    finally:
        if agent is not None:
            cache.delete(agent_job_key(agent.agent_id))
    set_job(job, state="queued", detail="", **done)
    return f"queued batch {done['batch']}"


SDIO_LOCK = "sdio-index"
APPLY_LOCK = "sdio-apply"


@app.task(bind=True)
def refresh_sdio_task(self) -> str:
    with redis_lock(SDIO_LOCK, self.app.oid) as acquired:
        if not acquired:
            return "SDIO index refresh already running"
        try:
            return _refresh_sdio(self)
        finally:
            sdio.clear_progress()


def _refresh_sdio(task) -> str:
    text = sdio.refresh()
    try:
        text += "; " + sdio.scan()
    except (sdio.SdioError, sdioindex.IndexError_, OSError) as e:
        row = SdioIndex.load()
        row.error = f"scan: {e}"[:255]
        row.save(update_fields=["error"])
        DebugLog.warning(f"SDIO index scan failed: {e}")
        return f"{text}; scan failed: {e}"
    with redis_lock(APPLY_LOCK, task.app.oid) as acquired:
        if not acquired:
            return f"{text}; approvals are being applied already"
        return f"{text}; {sdio.apply_approvals()}"


@app.task(bind=True, max_retries=10)
def apply_sdio_task(self, agent_pks=None) -> str:
    with redis_lock(APPLY_LOCK, self.app.oid) as acquired:
        if acquired:
            return sdio.apply_approvals(agent_pks)
    # a driver push of one agent must not get lost behind another run
    if agent_pks is not None:
        raise self.retry(countdown=60)
    return "SDIO approvals are being applied already"


@app.task(bind=True)
def baseline_tick_task(self) -> str:
    with redis_lock("software-baselines", self.app.oid) as acquired:
        if not acquired:
            return "baseline round already running"
        return baselines.tick()


@app.task
def baseline_agent_task(agent_pk: int) -> str:
    lock = f"baseline_agent_{agent_pk}"
    if not cache.add(lock, 1, baselines.AGENT_LOCK_TTL):
        return "another baseline round runs on this agent"
    try:
        agent = (
            Agent.objects.defer(*AGENT_DEFER)
            .select_related("site__client")
            .filter(pk=agent_pk)
            .first()
        )
        if agent is None or not agent.is_online:
            return "offline"
        return baselines.step(agent)
    finally:
        cache.delete(lock)


@app.task
def baseline_linux_pkg_task(state_pk: int) -> str:
    return baselines.install_linux_pkg(state_pk)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import logging
import secrets
from contextlib import suppress

from asgiref.sync import async_to_sync, sync_to_async
from django.core.cache import cache
from django.utils import timezone as djangotime

from logs.models import DebugLog
from ulrmm.celery import app
from ulrmm.constants import DebugLogType

from . import jobs
from .models import InstallState, PackageInstall, PackageKind
from .utils import (
    BATCH_ALIVE_TTL,
    agent_lock,
    batch_key,
    download_key,
    hide,
    install_payload,
    parse_result,
    release_job,
    remove_stale_uploads,
)

logger = logging.getLogger("ulrmm")

CONCURRENCY = 20
# a busy agent is tried again every LOCK_WAIT seconds, LOCK_TRIES times
LOCK_WAIT = 60
LOCK_TRIES = 30
HEARTBEAT = 60
BUSY = "busy"


def finish(install: PackageInstall, state: str, **fields) -> None:
    install.state = state
    install.finished = djangotime.now()
    for key, value in fields.items():
        setattr(install, key, value)
    # never package_id, the package can be gone by now
    install.save(update_fields=["state", "finished", *fields])

    agent = install.agent
    message = f"{install.package_name} on {agent.hostname} ({install.run_as}): {state}"
    if install.detail:
        message += f", {install.detail}"
    if state in (InstallState.SUCCEEDED, InstallState.REBOOT_REQUIRED):
        DebugLog.info(message, agent=agent, log_type=DebugLogType.SCRIPTING)
    else:
        DebugLog.warning(message, agent=agent, log_type=DebugLogType.SCRIPTING)


def _lock(install: PackageInstall) -> str:
    return agent_lock(install.agent.agent_id)


def _claim(pk: int):
    """Queued row with the agent lock held. BUSY if another install has the
    agent. None if there is nothing to run."""
    install = (
        PackageInstall.objects.select_related("package", "agent")
        .filter(pk=pk, state=InstallState.QUEUED)
        .first()
    )
    if not install:
        return None
    if not install.package:
        finish(install, InstallState.FAILED, detail="the package was deleted")
        return None
    # one at a time per agent, msiexec and dpkg would block each other anyway
    if not cache.add(_lock(install), pk, install.package.timeout + 60):
        return BUSY
    return install


def _give_up(pk: int) -> None:
    if install := (
        PackageInstall.objects.select_related("agent")
        .filter(pk=pk, state=InstallState.QUEUED)
        .first()
    ):
        finish(
            install,
            InstallState.FAILED,
            detail="another package install is still running",
        )


def _mark_running(install: PackageInstall, token: str) -> dict:
    cache.set(download_key(token), install.pk, install.package.timeout + 300)
    install.state = InstallState.RUNNING
    install.started = djangotime.now()
    install.save(update_fields=["state", "started"])
    return install_payload(install.package, install.run_as, token)


def _release(install: PackageInstall, token: str) -> None:
    if token:
        cache.delete(download_key(token))
    cache.delete(_lock(install))


async def after_install(install: PackageInstall, state: str) -> None:
    if install.package.kind == PackageKind.DRIVER and state in (
        InstallState.SUCCEEDED,
        InstallState.REBOOT_REQUIRED,
    ):
        # the agent pushes its driver inventory again, best effort
        with suppress(Exception):
            await install.agent.nats_cmd({"func": "drivers"}, wait=False)


async def _start_job(install: PackageInstall) -> bool:
    """Hands the install to the agent. True when the agent took it: the row
    stays running and the lock held until the agent reports, see jobs.py."""
    await sync_to_async(jobs.start)(install)
    out = await install.agent.nats_cmd(
        {"func": "pkgjob", "payload": {"job": str(install.pk)}}, timeout=10
    )
    if out == "ok":
        return True
    await sync_to_async(release_job)(install)
    # agents before PKGJOB_MIN_AGENT do not answer
    reason = "no answer" if out == "timeout" else str(out)[:200]
    await sync_to_async(finish)(
        install, InstallState.FAILED, detail=f"the agent did not take the job: {reason}"
    )
    return False


async def _run(install: PackageInstall) -> None:
    package, agent = install.package, install.agent
    token = ""
    taken = False
    try:
        if not agent.is_online:
            await sync_to_async(finish)(install, InstallState.SKIPPED, detail="offline")
            return
        if jobs.uses_job(package, agent, install.run_as):
            taken = await _start_job(install)
            return

        token = secrets.token_urlsafe(32)
        data = await sync_to_async(_mark_running)(install, token)
        out = await agent.nats_cmd(data, timeout=package.timeout + 30)
        state, fields = parse_result(out, package.timeout, token)
        await sync_to_async(finish)(install, state, **fields)
        await after_install(install, state)
    except Exception as e:
        taken = False
        await sync_to_async(finish)(
            install,
            InstallState.FAILED,
            detail=hide(f"server error: {e}", token)[:500],
        )
    finally:
        if not taken:
            await sync_to_async(_release)(install, token)


async def _install(pk: int, sem: asyncio.Semaphore) -> None:
    for attempt in range(LOCK_TRIES + 1):
        if attempt:
            # waiting for the agent does not take a slot
            await asyncio.sleep(LOCK_WAIT)
        async with sem:
            install = await sync_to_async(_claim)(pk)
            if install is BUSY:
                continue
            if install:
                await _run(install)
            return
    await sync_to_async(_give_up)(pk)


async def _heartbeat(batch: str) -> None:
    while True:
        # one redis hiccup must not end it, the open rows would expire
        try:
            await cache.aset(batch_key(batch), 1, BATCH_ALIVE_TTL)
        except Exception as e:
            logger.error(f"package batch {batch} heartbeat: {e}")
        await asyncio.sleep(HEARTBEAT)


async def _run_batch(batch: str) -> None:
    pks = await sync_to_async(list)(
        PackageInstall.objects.filter(batch=batch, state=InstallState.QUEUED)
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    sem = asyncio.Semaphore(CONCURRENCY)
    beat = asyncio.ensure_future(_heartbeat(batch))
    try:
        results = await asyncio.gather(
            *(_install(pk, sem) for pk in pks), return_exceptions=True
        )
    finally:
        beat.cancel()
    for pk, result in zip(pks, results):
        if isinstance(result, Exception):
            logger.error(f"package install {pk} failed: {result}")


@app.task
def install_batch_task(batch: str) -> None:
    # one worker for the batch, not one worker per agent.
    # async_to_sync keeps the orm on this thread and its connection
    try:
        async_to_sync(_run_batch)(batch)
    finally:
        # open rows of a batch without this key expire, see expire_stale
        cache.delete(batch_key(batch))


@app.task
def remove_stale_uploads_task() -> str:
    return f"{remove_stale_uploads()} stale upload files removed"

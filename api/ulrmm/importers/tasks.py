# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import time

from django.utils import timezone as djangotime

from logs.models import DebugLog
from ulrmm.celery import app
from ulrmm.utils import redis_lock

from . import migrate, removal
from .models import ImportedDevice, ImportSource
from .sources import SourceError, for_source, validate
from .sources.base import FETCH_SECONDS

# the views answer it, the tasks store it when they find the lock held
BUSY = (
    "The source is being read, imported or its installers are being sent. "
    "Try again when that is done."
)


def lock_id(pk: int) -> str:
    return f"importers-source-{pk}"


def _busy(pk: int) -> str:
    # the view answered 202 before the lock was taken by someone else
    ImportSource.objects.filter(pk=pk).update(last_error=BUSY)
    return "busy"


def fetch(source) -> None:
    """Reads the source and stores the checked snapshot, or the error."""
    ImportSource.objects.filter(pk=source.pk).update(last_error="")
    try:
        client = for_source(source)
        client.deadline = time.monotonic() + FETCH_SECONDS
        snapshot = validate(client.fetch())
    except SourceError as e:
        ImportSource.objects.filter(pk=source.pk).update(last_error=str(e)[:500])
        return
    except Exception as e:
        DebugLog.error(message=f"import from {source.name}: {e!r}"[:1000])
        ImportSource.objects.filter(pk=source.pk).update(
            last_error=f"unexpected error: {type(e).__name__}"
        )
        return
    ImportSource.objects.filter(pk=source.pk).update(
        snapshot=snapshot, last_fetch=djangotime.now(), last_error=""
    )


@app.task(bind=True)
def fetch_task(self, pk: int) -> str:
    with redis_lock(lock_id(pk), self.app.oid) as acquired:
        if not acquired:
            return _busy(pk)
        # a file source has no server: it is read by the upload
        if source := ImportSource.objects.filter(pk=pk, from_file=False).first():
            fetch(source)
    return "ok"


@app.task(bind=True)
def migrate_task(self, pk: int, device_ids: list[int]) -> dict | str:
    with redis_lock(lock_id(pk), self.app.oid) as acquired:
        if not acquired:
            return _busy(pk)
        source = ImportSource.objects.filter(pk=pk).first()
        if source is None:
            return "gone"
        try:
            return migrate.send(source, device_ids)
        except migrate.MigrateError as e:
            ImportSource.objects.filter(pk=pk).update(last_error=str(e)[:500])
            return str(e)


@app.task
def remove_task() -> str:
    """Runs every few minutes; does nothing while no removal waits."""
    removal.end_stale_claims()
    for pk in removal.recover_due():
        try:
            recover_task.delay(pk)
        except Exception as e:
            DebugLog.error(message=f"remote-control recovery of {pk}: {e!r}"[:1000])
            ImportedDevice.objects.filter(pk=pk).update(recovery_at=None)
    waiting = ImportedDevice.objects.filter(remove_state__in=removal.WAITING)
    if not waiting.exists():
        return "idle"
    for source in ImportSource.objects.filter(
        pk__in=waiting.values("source_id"), from_file=False
    ):
        try:
            client = for_source(source)
        except SourceError as e:
            ImportSource.objects.filter(pk=source.pk).update(last_error=str(e)[:500])
            continue
        for device in waiting.filter(source=source).select_related("source"):
            # one device that fails never ends the round for the others
            try:
                removal.step(device, client)
            except Exception as e:
                DebugLog.error(
                    message=f"removal of the old agent on {device}: {e!r}"[:1000]
                )
    return "ok"


@app.task
def recover_task(pk: int) -> str:
    """One recovery for a device remove_task claimed, see removal.recover_due."""
    # without a claim (a task queued by an older release) nothing is sent
    device = (
        ImportedDevice.objects.filter(pk=pk, recovery_at__isnull=False)
        .select_related("agent")
        .first()
    )
    if device is None:
        return "unclaimed"
    result = removal.recover(device)
    row = ImportedDevice.objects.filter(pk=pk)
    if not result:
        # not online here: the next sweep looks again
        row.update(recovery_at=None)
        return "offline"
    if result.startswith("failed"):
        # the claim stays: due again after removal.RECOVERY_RETRY
        row.update(recovery=result[:500])
    else:
        # done, given up or nothing linked: the claim ends
        row.update(recovery=result[:500], recovery_at=None)
    return result

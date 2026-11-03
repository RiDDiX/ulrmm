# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.utils import timezone as djangotime

from logs.models import DebugLog
from ulrmm.celery import app
from ulrmm.utils import redis_lock

from . import migrate
from .models import ImportSource
from .sources import SourceError, for_source, validate


def lock_id(pk: int) -> str:
    return f"importers-source-{pk}"


def fetch(source) -> None:
    """Reads the source and stores the checked snapshot, or the error."""
    try:
        snapshot = validate(for_source(source).fetch())
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
            return "busy"
        if source := ImportSource.objects.filter(pk=pk).first():
            fetch(source)
    return "ok"


@app.task(bind=True)
def migrate_task(self, pk: int, device_ids: list[int]) -> dict | str:
    with redis_lock(lock_id(pk), self.app.oid) as acquired:
        if not acquired:
            return "busy"
        source = ImportSource.objects.filter(pk=pk).first()
        if source is None:
            return "gone"
        try:
            return migrate.send(source, device_ids)
        except migrate.MigrateError as e:
            ImportSource.objects.filter(pk=pk).update(last_error=str(e)[:500])
            return str(e)

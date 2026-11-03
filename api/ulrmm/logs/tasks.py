# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta

from django.utils import timezone as djangotime

from ulrmm.celery import app

BATCH = 10_000


def _prune(model, older_than_days: int) -> None:
    if older_than_days < 0:
        return
    cutoff = djangotime.now() - timedelta(days=older_than_days)
    old = model.objects.filter(entry_time__lt=cutoff).order_by("pk")
    # batches keep each DELETE short on big tables
    while ids := list(old.values_list("pk", flat=True)[:BATCH]):
        model.objects.filter(pk__in=ids).delete()


@app.task
def prune_debug_log(older_than_days: int) -> str:
    from .models import DebugLog

    _prune(DebugLog, older_than_days)
    return "ok"


@app.task
def prune_audit_log(older_than_days: int) -> str:
    from .models import AuditLog

    _prune(AuditLog, older_than_days)
    return "ok"

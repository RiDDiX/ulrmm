# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db.models import Subquery, OuterRef, Value
from django.db.models.functions import Coalesce
from django.utils import timezone as djangotime

from ulrmm.celery import app


@app.task
def prune_patch_events(older_than_days: int) -> str:
    from .models import PatchEvent

    cutoff = djangotime.now() - djangotime.timedelta(days=older_than_days)

    # the chain is hashed per record, so only a contiguous oldest first prefix
    # can go: everything before the first event young enough to keep
    first_kept = Subquery(
        PatchEvent.objects.filter(patch_device_id=OuterRef("patch_device_id"))
        .filter(at__gte=cutoff)
        .order_by("id")
        .values("id")[:1]
    )
    PatchEvent.objects.filter(
        at__lt=cutoff, id__lt=Coalesce(first_kept, Value(9223372036854775807))
    ).delete()

    return "ok"


@app.task(bind=True)
def maintenance_schedule_task(self) -> str:
    from ulrmm.utils import redis_lock

    from .maintenance import run_pass

    with redis_lock("maintenance-schedule-lock", self.app.oid) as acquired:
        if not acquired:
            return "still running"
        run_pass(djangotime.now())
    return "ok"

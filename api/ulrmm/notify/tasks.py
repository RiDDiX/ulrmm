# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.utils import timezone as djangotime

from ulrmm.celery import app
from ulrmm.utils import redis_lock

from . import dispatch, tamper


@app.task
def send_notifications_task(ids: list[int]) -> str:
    dispatch.deliver(ids)
    return "ok"


@app.task(bind=True)
def escalate_task(self) -> str:
    with redis_lock("notify-escalate-lock", self.app.oid) as acquired:
        if not acquired:
            return "already running"
        now = djangotime.now()
        dispatch.flush_held(now)
        dispatch.escalate(now)
        dispatch.prune(now)
    return "ok"


@app.task(bind=True)
def tamper_watch_task(self) -> str:
    with redis_lock("tamper-watch-lock", self.app.oid) as acquired:
        if not acquired:
            return "already running"
        return tamper.watch(djangotime.now())

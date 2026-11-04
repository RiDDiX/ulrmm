# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from typing import Optional

from django.utils import timezone as djangotime

from alerts.models import Alert
from alerts.tasks import notify_once
from checks.models import CheckHistory, CheckResult
from ulrmm.celery import app
from ulrmm.logger import logger


def _notify(pk: int, field: str, send: str, alert_interval=None) -> str:
    alert = (
        Alert.objects.select_related("assigned_check", "agent").filter(pk=pk).first()
    )
    if alert is None:
        return "alert not found"

    result = (
        CheckResult.objects.select_related("assigned_check", "agent")
        .filter(assigned_check=alert.assigned_check, agent=alert.agent)
        .first()
    )
    if result is None:
        return "check result not found"
    return notify_once(alert, field, getattr(result, send), alert_interval)


@app.task
def handle_check_email_alert_task(
    pk: int, alert_interval: Optional[float] = None
) -> str:
    return _notify(pk, "email_sent", "send_email", alert_interval)


@app.task
def handle_check_sms_alert_task(pk: int, alert_interval: Optional[float] = None) -> str:
    return _notify(pk, "sms_sent", "send_sms", alert_interval)


@app.task
def handle_resolved_check_sms_alert_task(pk: int) -> str:
    return _notify(pk, "resolved_sms_sent", "send_resolved_sms")


@app.task
def handle_resolved_check_email_alert_task(pk: int) -> str:
    return _notify(pk, "resolved_email_sent", "send_resolved_email")


@app.task
def prune_check_history(older_than_days: int) -> str:
    cutoff = djangotime.now() - dt.timedelta(days=older_than_days)
    deleted, _ = CheckHistory.objects.filter(x__lt=cutoff).delete()
    logger.info(f"Pruned {deleted} check history objects")
    return "ok"

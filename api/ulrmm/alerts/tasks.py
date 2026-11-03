# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db.models import Q
from django.utils import timezone as djangotime

from agents.models import Agent
from ulrmm.celery import app

from .models import Alert


@app.task
def unsnooze_alerts() -> str:
    expired = Alert.objects.filter(snooze_until__lte=djangotime.now(), snoozed=True)
    expired.update(snooze_until=None, snoozed=False)
    return "ok"


@app.task
def cache_agents_alert_template() -> str:
    related = ("site", "policy", "alert_template")
    for each in Agent.objects.select_related(*related).only("pk", *related):
        each.set_alert_template()
    return "ok"


@app.task
def prune_resolved_alerts(older_than_days: int) -> str:
    cutoff = djangotime.now() - djangotime.timedelta(days=older_than_days)
    # age counts from the resolution; rows resolved before it was recorded use their creation
    Alert.objects.filter(resolved=True).filter(
        Q(resolved_on__lt=cutoff) | Q(resolved_on__isnull=True, alert_time__lt=cutoff)
    ).delete()
    return "ok"


@app.task
def run_alert_action_task(alert_pk: int, resolved: bool = False) -> str:
    """Runs an alert's failure or resolved action outside the agent's request."""
    alert = Alert.objects.filter(pk=alert_pk).first()
    if alert is None:
        return "alert not found"
    alert.run_action(resolved=resolved)
    return "ok"

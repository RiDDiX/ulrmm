# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from time import sleep

from django.db.models import Q
from django.utils import timezone as djangotime

from agents.models import Agent
from ulrmm.celery import app
from ulrmm.constants import AGENT_DEFER
from ulrmm.helpers import rand_range

from .models import Alert


def notify_once(alert: Alert, field: str, send, alert_interval=None) -> str:
    """Calls send unless the notification went out already.

    The stamp is claimed on the alert first, so two workers never both send;
    a failed send (an exception or a (message, False) answer of
    CoreSettings.send_mail / send_sms) hands it back for the next run.
    """
    previous = getattr(alert, field)
    stamp = Alert.claim_notification(alert.pk, field, alert_interval)
    if stamp is None:
        return "ok"

    # spread a burst of notifications out a little
    sleep(rand_range(100, 1500))
    try:
        result = send()
    except Exception:
        Alert.release_notification(alert.pk, field, stamp, previous)
        raise
    if isinstance(result, tuple) and result[1] is False:
        Alert.release_notification(alert.pk, field, stamp, previous)
        return "send failed"
    return "ok"


@app.task
def unsnooze_alerts() -> str:
    expired = Alert.objects.filter(snooze_until__lte=djangotime.now(), snoozed=True)
    expired.update(snooze_until=None, snoozed=False)
    return "ok"


@app.task
def cache_agents_alert_template() -> str:
    agents = Agent.objects.defer(*AGENT_DEFER).select_related("site__client", "policy")
    for each in agents:
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

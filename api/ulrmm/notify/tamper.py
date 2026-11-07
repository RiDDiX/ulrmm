# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Agent protection: a service stopped by hand or an agent gone without a
shutdown, reboot or sleep sent from this server or announced by the agent."""

import datetime as dt

from django.db.models import F, Q

from core.utils import get_core_settings
from ulrmm.constants import AlertSeverity

from .dispatch import dispatch, notify_alert

ALERT_TYPE = "agent"
MESSAGE = "agent stopped or unreachable without a shutdown"
POWER_MODES = ("shutdown", "reboot", "suspend")
# around last_seen: a shutdown is sent a moment before the agent goes quiet
SLACK = dt.timedelta(minutes=10)
# older outages are no news, also keeps the first run after switching it on quiet
LOOKBACK = dt.timedelta(hours=24)


def raise_tamper(agent, detail: str):
    from alerts.models import Alert

    alert = Alert.objects.create(
        agent=agent,
        alert_type=ALERT_TYPE,
        severity=AlertSeverity.WARNING,
        message=MESSAGE,
    )
    dispatch(
        {
            "source": "tamper",
            "severity": AlertSeverity.WARNING,
            "title": f"{agent.hostname}: {MESSAGE}",
            "body": detail,
            "agent": agent,
            "alert": alert,
            "dedupe_key": f"alert:{alert.pk}:{alert.severity}",
            "dedupe_hours": 0,
        }
    )
    return alert


def report_stop(agent, reason) -> None:
    """stop_reason from the agent's check-in after a restart."""
    # the agent is back already: the alert records the stop until someone resolves it
    if reason == "manual" and get_core_settings().tamper_watch:
        raise_tamper(agent, "The agent service was stopped by hand.")


def expected_offline(agent) -> bool:
    from logs.models import AuditLog
    from patches.maintenance import ACTIVE
    from patches.models import RunState, ScheduleRun

    if agent.power_event_applies:
        return True
    since = agent.last_seen - SLACK
    power = Q(after_value__mode__in=POWER_MODES, entry_time__gte=since)
    # agent_id None: a bulk action, it names no single agent
    if AuditLog.objects.filter(
        power, Q(agent_id=agent.agent_id) | Q(agent_id=None)
    ).exists():
        return True
    return ScheduleRun.objects.filter(
        Q(state__in=ACTIVE)
        | Q(state__in=(RunState.SLEPT, RunState.REBOOTING), changed__gte=since),
        agent=agent,
    ).exists()


def watch(now) -> str:
    from agents.models import Agent
    from alerts.models import Alert

    # back online: re-arm and close the alert of this outage, also after
    # the watch was switched off
    back = Agent.objects.filter(
        tamper_alerted_at__isnull=False, last_seen__gt=F("tamper_alerted_at")
    ).only("pk", "agent_id", "hostname", "tamper_alerted_at")
    for agent in back:
        alert = (
            Alert.objects.filter(
                agent=agent,
                alert_type=ALERT_TYPE,
                resolved=False,
                alert_time__gte=agent.tamper_alerted_at,
            )
            .order_by("alert_time")
            .first()
        )
        Agent.objects.filter(pk=agent.pk).update(tamper_alerted_at=None)
        if alert:
            alert.resolve()
            notify_alert(alert, resolved=True)

    core = get_core_settings()
    if not core.tamper_watch:
        return "off"

    cutoff = now - dt.timedelta(minutes=core.tamper_offline_minutes)
    gone = Agent.objects.filter(
        tamper_alerted_at__isnull=True,
        maintenance_mode=False,
        last_seen__lt=cutoff,
        last_seen__gte=cutoff - LOOKBACK,
    ).only(
        "pk",
        "agent_id",
        "hostname",
        "last_seen",
        "maintenance_mode",
        "site",
        "power_event",
        "power_event_at",
    )
    raised = 0
    for agent in gone:
        if expected_offline(agent):
            continue
        Agent.objects.filter(pk=agent.pk).update(tamper_alerted_at=now)
        minutes = int((now - agent.last_seen).total_seconds() // 60)
        raise_tamper(
            agent,
            f"Offline for {minutes} minutes, last seen {agent.last_seen:%Y-%m-%d %H:%M} UTC.",
        )
        raised += 1
    return f"{raised} raised"

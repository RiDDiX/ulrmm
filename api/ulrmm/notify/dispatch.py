# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Matching events to routes, delivery, quiet hours, rate limit, escalation.

dispatch() only writes rows and queues a celery task, so callers inside a
request never wait for a chat service.
"""

import datetime as dt
import re
from contextlib import suppress
from zoneinfo import ZoneInfo

from cryptography.fernet import InvalidToken
from django.db import connection, transaction
from django.db.models import Exists, OuterRef
from django.utils import timezone as djangotime

from core.utils import get_core_settings
from logs.models import DebugLog
from remote.utils import decrypt_secret
from ulrmm.constants import AlertSeverity

from . import senders
from .models import HKDF_INFO, Channel, Notification, Route, State

RANK = {AlertSeverity.INFO: 0, AlertSeverity.WARNING: 1, AlertSeverity.ERROR: 2}
RATE_LIMIT = 60
# this many failed sends in a row within PAUSE_FOR pause the channel
PAUSE_AFTER = 5
PAUSE_FOR = dt.timedelta(minutes=5)
PAUSED = "channel paused after repeated failures"
GONE = "the channel is gone or disabled"
# rows still queued after this lost their task (worker restart, broker loss)
STALE = dt.timedelta(minutes=10)
REQUEUE_BATCH = 500
# pg_advisory_xact_lock(int4, int4) namespace for the dedupe check
_DEDUPE_LOCK_SPACE = 0x4E_4F_54
DIGEST_LINES = 40
KEEP = dt.timedelta(days=90)
ALERT_SOURCES = {
    "availability": "agent",
    "check": "check",
    "task": "task",
    # notify.tamper alerts
    "agent": "tamper",
}
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def _line(value, size: int) -> str:
    return _CTRL.sub(" ", str(value or "")).strip()[:size]


def _rank(severity: str) -> int:
    # anything unknown counts as error, better too loud than lost
    return RANK.get(severity, 2)


def in_maintenance(agent) -> bool:
    from patches.maintenance import ACTIVE
    from patches.models import ScheduleKind, ScheduleRun

    return agent.maintenance_mode or (
        ScheduleRun.objects.filter(
            agent=agent, state__in=ACTIVE, schedule__kind=ScheduleKind.MAINTENANCE
        ).exists()
    )


def _log(message: str, agent=None) -> None:
    with suppress(Exception):
        DebugLog.error(message=f"Notifications: {message}"[:1000], agent=agent)


def dispatch(event: dict) -> int:
    """Queue an event for the channels of every matching route.

    event: source, severity (info|warning|error), title, body, and optional
    agent, alert, dedupe_key, dedupe_hours. An event whose dedupe_key was
    queued within dedupe_hours (default 24, 0 = as long as the history is
    kept) is dropped. Returns the number of queued notifications. Never
    raises, no routes or channels is not an error.
    """
    try:
        return _dispatch(event)
    except Exception as e:
        _log(f"{type(e).__name__}: {e}")
        return 0


def _dispatch(event: dict) -> int:
    from .tasks import send_notifications_task

    source = event["source"]
    severity = event.get("severity") or AlertSeverity.INFO
    alert = event.get("alert")
    routes = [
        r
        for r in Route.objects.prefetch_related("channels").order_by("pk")
        if (not r.sources or source in r.sources)
        and (not r.severities or severity in r.severities)
    ]
    if not routes:
        return 0
    key = _line(event.get("dedupe_key"), 200)
    with transaction.atomic():
        if key:
            # two workers with the same event: the second waits and sees the rows
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                    [_DEDUPE_LOCK_SPACE, key],
                )
            seen = Notification.objects.filter(dedupe_key=key)
            if hours := event.get("dedupe_hours", 24):
                seen = seen.filter(
                    created__gte=djangotime.now() - dt.timedelta(hours=hours)
                )
            if seen.exists():
                return 0
        rows = _queue(event, routes, severity, alert, source, key)
    if rows:
        pks = [r.pk for r in rows]
        # inside a caller's transaction the rows are visible only after commit
        transaction.on_commit(lambda: send_notifications_task.delay(pks))
    return len(rows)


def _queue(event, routes, severity, alert, source, key) -> list:
    agent = event.get("agent") or (alert.agent if alert else None)
    muted = agent is not None and in_maintenance(agent)
    targets: dict[int, tuple] = {}
    for route in routes:
        if muted and route.mute_in_maintenance:
            continue
        for channel in route.channels.all():
            if channel.enabled and _rank(severity) >= _rank(channel.min_severity):
                targets.setdefault(channel.pk, (channel, route))
    if not targets:
        return []

    return Notification.objects.bulk_create(
        Notification(
            route=route,
            channel=channel,
            alert=alert,
            source=source,
            severity=severity,
            title=_line(event.get("title"), 200),
            body=str(event.get("body") or "")[:4000],
            dedupe_key=key,
        )
        for channel, route in targets.values()
    )


def notify_alert(alert, resolved: bool = False) -> int:
    """Hook of Alert.handle_alert_failure and handle_alert_resolve."""
    if alert.snoozed and not resolved:
        return 0
    try:
        failure = f"alert:{alert.pk}:{alert.severity}"
        if (
            resolved
            and not Notification.objects.filter(
                alert=alert, escalation_level=0
            ).exists()
        ):
            # nobody heard about the failure, the recovery is no news either
            return 0
        source = (
            "netmon"
            if alert.network_device_id
            else ALERT_SOURCES.get(alert.alert_type, "agent")
        )
        where = ", ".join(
            _line(x, 80) for x in (alert.client, alert.site, alert.hostname) if x
        )
        message = _line(alert.message, 180)
        # what failed on a network device, low printer supplies included
        if alert.network_device_id and not resolved:
            if detail := alert.network_device.summary():
                where = f"{where}\n{detail}" if where else detail
    except Exception as e:
        _log(f"{type(e).__name__}: {e}")
        return 0
    return dispatch(
        {
            "source": source,
            "severity": alert.severity,
            "title": f"Resolved: {message}" if resolved else message,
            "body": where,
            "alert": alert,
            "dedupe_key": f"alert:{alert.pk}:resolved" if resolved else failure,
            "dedupe_hours": 0,
        }
    )


def _secret(channel) -> str:
    return decrypt_secret(channel.secret, HKDF_INFO) if channel.secret else ""


def send(channel, n: dict) -> None:
    """Raises senders.SendError."""
    try:
        secret = _secret(channel)
    except InvalidToken:
        raise senders.SendError("the stored token can no longer be read, set it again")
    getattr(senders, channel.kind)(channel.config or {}, secret, n)


def _payload(row) -> dict:
    alert = row.alert
    agent = alert.agent if alert else None
    return {
        "source": row.source,
        "severity": row.severity,
        "title": row.title,
        "body": row.body,
        "alert": row.alert_id,
        "agent_id": agent.agent_id if agent else None,
        "escalation_level": row.escalation_level,
    }


def _tz():
    with suppress(Exception):
        return ZoneInfo(get_core_settings().default_time_zone)
    return dt.timezone.utc


def in_quiet_hours(channel, now) -> bool:
    start, end = channel.quiet_start, channel.quiet_end
    if not start or not end or start == end:
        return False
    t = now.astimezone(_tz()).time()
    return start <= t < end if start < end else (t >= start or t < end)


def _send_row(channel, row, n: dict, now) -> None:
    try:
        send(channel, n)
        row.state, row.sent_at, row.error = State.SENT, now, ""
        channel.last_sent, channel.last_error = now, ""
    except Exception as e:
        reason = str(e) if isinstance(e, senders.SendError) else type(e).__name__
        row.state, row.error = State.FAILED, reason[:500]
        channel.last_error = reason[:500]
        _log(f"{channel.name} ({channel.kind}): {reason}")
    row.save(update_fields=["state", "sent_at", "error"])
    Channel.objects.filter(pk=channel.pk).update(
        last_sent=channel.last_sent, last_error=channel.last_error
    )


def _failures(channel, now) -> int:
    """Failed sends in a row of the channel within PAUSE_FOR, at most PAUSE_AFTER."""
    last = (
        Notification.objects.filter(
            channel=channel,
            created__gte=now - PAUSE_FOR,
            state__in=(State.SENT, State.FAILED),
        )
        .exclude(error__in=(PAUSED, GONE))
        .order_by("-pk")
        .values_list("state", flat=True)[:PAUSE_AFTER]
    )
    n = 0
    for state in last:
        if state != State.FAILED:
            break
        n += 1
    return n


def deliver(ids: list[int]) -> None:
    now = djangotime.now()
    rows = (
        Notification.objects.filter(pk__in=ids, state=State.QUEUED)
        .select_related("channel", "alert__agent")
        .order_by("pk")
    )
    sent: dict[int, int] = {}
    failures: dict[int, int] = {}
    for row in rows:
        # a requeued row can be in two tasks, only one of them takes it
        claimed = Notification.objects.filter(pk=row.pk, state=State.QUEUED)
        if not claimed.update(state=State.SENDING):
            continue
        channel = row.channel
        if not channel or not channel.enabled:
            row.state, row.error = State.FAILED, GONE
            row.save(update_fields=["state", "error"])
            continue
        if in_quiet_hours(channel, now):
            row.state = State.HELD
            row.save(update_fields=["state"])
            continue
        if channel.pk not in sent:
            sent[channel.pk] = Notification.objects.filter(
                channel=channel,
                state=State.SENT,
                sent_at__gte=now - dt.timedelta(hours=1),
            ).count()
            failures[channel.pk] = _failures(channel, now)
        # a recovery must not get lost, it clears what the failure said
        recovery = row.dedupe_key.endswith(":resolved")
        if failures[channel.pk] >= PAUSE_AFTER:
            # stays queued, requeue_stale() tries it again after the pause
            row.state, row.error = State.QUEUED, PAUSED
            row.save(update_fields=["state", "error"])
        elif sent[channel.pk] >= RATE_LIMIT and not recovery:
            row.state, row.error = State.DROPPED, "over 60 messages in one hour"
            row.save(update_fields=["state", "error"])
            if sent[channel.pk] == RATE_LIMIT:
                _summary(
                    channel,
                    now,
                    "Rate limit reached",
                    "More than 60 notifications in the last hour. Further ones "
                    "are kept in the notification history only.",
                )
                sent[channel.pk] += 1
        else:
            _send_row(channel, row, _payload(row), now)
            if row.state == State.SENT:
                sent[channel.pk] += 1
                failures[channel.pk] = 0
            else:
                failures[channel.pk] += 1


def _summary(channel, now, title: str, body: str, held=None) -> None:
    row = Notification.objects.create(
        channel=channel, source="notify", severity="warning", title=title, body=body
    )
    n = {
        "source": "notify",
        "severity": "warning",
        "title": title,
        "body": body,
        "escalation_level": 0,
    }
    _send_row(channel, row, n, now)
    if held is not None:
        held.update(state=row.state, sent_at=row.sent_at, error=row.error)


def flush_held(now) -> None:
    """One digest per channel once its quiet hours are over."""
    for channel in Channel.objects.filter(notifications__state=State.HELD).distinct():
        if in_quiet_hours(channel, now):
            continue
        held = Notification.objects.filter(channel=channel, state=State.HELD)
        rows = list(held.order_by("pk").values_list("severity", "title")[:DIGEST_LINES])
        total = held.count()
        lines = [f"[{sev}] {title}" for sev, title in rows]
        if total > len(rows):
            lines.append(f"and {total - len(rows)} more")
        pks = list(held.values_list("pk", flat=True))
        _summary(
            channel,
            now,
            f"{total} notifications from quiet hours",
            "\n".join(lines),
            held=Notification.objects.filter(pk__in=pks),
        )


def escalate(now) -> None:
    """Unresolved alerts past a route's escalate_after_minutes go to its
    escalate_to channels, once per route."""
    from alerts.models import Alert

    from .tasks import send_notifications_task

    routes = Route.objects.filter(escalate_after_minutes__gt=0).prefetch_related(
        "escalate_to"
    )
    for route in routes:
        channels = [c for c in route.escalate_to.all() if c.enabled]
        if not channels:
            continue
        cutoff = now - dt.timedelta(minutes=route.escalate_after_minutes)
        first = Notification.objects.filter(
            alert=OuterRef("pk"), route=route, escalation_level=0, created__lte=cutoff
        )
        done = Notification.objects.filter(
            alert=OuterRef("pk"), route=route, escalation_level=1
        )
        alerts = (
            Alert.objects.filter(resolved=False, snoozed=False)
            .filter(Exists(first))
            .exclude(Exists(done))
            .select_related("agent")
        )
        new = []
        for alert in alerts:
            if (
                alert.agent
                and route.mute_in_maintenance
                and in_maintenance(alert.agent)
            ):
                continue
            src = Notification.objects.filter(
                alert=alert, route=route, escalation_level=0
            ).first()
            new += [
                Notification(
                    route=route,
                    channel=c,
                    alert=alert,
                    source=src.source,
                    severity=alert.severity,
                    title=_line(f"Escalated: {src.title}", 200),
                    body=src.body,
                    escalation_level=1,
                )
                for c in channels
                if _rank(alert.severity) >= _rank(c.min_severity)
            ]
        if new:
            rows = Notification.objects.bulk_create(new)
            send_notifications_task.delay([r.pk for r in rows])


def requeue_stale(now) -> int:
    """Queued rows whose task got lost go out again, oldest first."""
    from .tasks import send_notifications_task

    # a worker that died while sending left its row claimed.
    # shortcut: aged by created, a row sent right now can go out twice; add a
    # claimed_at column if that shows up
    Notification.objects.filter(state=State.SENDING, created__lt=now - STALE).update(
        state=State.QUEUED
    )
    ids = list(
        Notification.objects.filter(state=State.QUEUED, created__lt=now - STALE)
        .order_by("pk")
        .values_list("pk", flat=True)[:REQUEUE_BATCH]
    )
    if ids:
        send_notifications_task.delay(ids)
    return len(ids)


def prune(now) -> None:
    Notification.objects.filter(created__lt=now - KEEP).delete()

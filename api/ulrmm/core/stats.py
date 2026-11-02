# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta

from django.db.models import Count, DurationField, ExpressionWrapper, F, Q
from django.utils import timezone as djangotime

from alerts.models import Alert
from checks.models import CheckResult
from ulrmm.constants import AgentMonType, CheckStatus
from winupdate.models import WinUpdate


def _offline_q() -> Q:
    now = djangotime.now()
    threshold = ExpressionWrapper(
        F("offline_time") * timedelta(minutes=1), output_field=DurationField()
    )
    # a never-seen agent is offline, matching Agent.status
    return Q(last_seen__lt=now - threshold) | Q(last_seen__isnull=True)


def _overdue_q() -> Q:
    now = djangotime.now()
    threshold = ExpressionWrapper(
        F("overdue_time") * timedelta(minutes=1), output_field=DurationField()
    )
    return (
        _offline_q()
        & Q(last_seen__lt=now - threshold)
        & _monitored_q()
        & ~power_event_q()
    )


def power_event_q() -> Q:
    # Agent.power_event_applies in SQL
    from agents.models import POWER_EVENT_SLACK

    return (
        ~Q(power_event="")
        & Q(power_event_at__isnull=False)
        & (
            Q(last_seen__isnull=True)
            | Q(power_event_at__gte=F("last_seen") - POWER_EVENT_SLACK)
        )
    )


def _monitored_q() -> Q:
    # SQL form of Agent.should_create_alert(agent.alert_template)
    t = "alert_template__"
    actions = Q(**{f"{t}agent_script_actions": True})
    return (
        Q(overdue_email_alert=True)
        | Q(overdue_text_alert=True)
        | Q(overdue_dashboard_alert=True)
        | Q(**{f"{t}agent_always_alert": True})
        | Q(**{f"{t}agent_always_email": True})
        | Q(**{f"{t}agent_always_text": True})
        | (
            actions
            & (
                Q(**{f"{t}action_rest__isnull": False})
                | Q(**{f"{t}resolved_action_rest__isnull": False})
                | Q(**{f"{t}action__isnull": False})
                | Q(**{f"{t}resolved_action__isnull": False})
            )
        )
    )


def fleet_stats(agents) -> dict:
    now = djangotime.now()
    day1 = now - timedelta(days=1)
    day7 = now - timedelta(days=7)

    counts = agents.aggregate(
        total=Count("pk"),
        offline=Count("pk", filter=_offline_q()),
        overdue=Count("pk", filter=_overdue_q()),
        servers=Count("pk", filter=Q(monitoring_type=AgentMonType.SERVER)),
        workstations=Count("pk", filter=Q(monitoring_type=AgentMonType.WORKSTATION)),
        needs_reboot=Count("pk", filter=Q(needs_reboot=True)),
        maintenance_mode=Count("pk", filter=Q(maintenance_mode=True)),
        under_1d=Count("pk", filter=Q(last_seen__gte=day1)),
        d1_7=Count("pk", filter=Q(last_seen__lt=day1, last_seen__gte=day7)),
        over_7d=Count("pk", filter=Q(last_seen__lt=day7)),
        never=Count("pk", filter=Q(last_seen__isnull=True)),
    )

    offline = counts["offline"]
    overdue = counts["overdue"]

    by_plat = [
        {"plat": r["plat"], "count": r["count"]}
        for r in agents.values("plat")
        .annotate(count=Count("pk"))
        .order_by("-count", "plat")
    ]
    by_version = [
        {"version": r["version"], "count": r["count"]}
        for r in agents.values("version")
        .annotate(count=Count("pk"))
        .order_by("-count")[:10]
    ]

    check_results = CheckResult.objects.filter(agent__in=agents)
    failing_by_type = [
        {"check_type": r["assigned_check__check_type"], "count": r["count"]}
        for r in check_results.filter(status=CheckStatus.FAILING)
        .values("assigned_check__check_type")
        .annotate(count=Count("pk"))
        .order_by("-count")
    ]

    pending = WinUpdate.objects.filter(
        agent__in=agents, action="approve", installed=False
    )
    patches_pending_agents = pending.values("agent").distinct().count()
    patches_failed_agents = (
        pending.filter(result="failed").values("agent").distinct().count()
    )

    alerts = [
        {"severity": r["severity"], "count": r["count"]}
        for r in Alert.objects.filter(agent__in=agents, resolved=False, hidden=False)
        .values("severity")
        .annotate(count=Count("pk"))
        .order_by("-count")
    ]

    return {
        "agents": {
            "total": counts["total"],
            "online": counts["total"] - offline,
            "offline": offline - overdue,
            "overdue": overdue,
            "servers": counts["servers"],
            "workstations": counts["workstations"],
            "needs_reboot": counts["needs_reboot"],
            "maintenance_mode": counts["maintenance_mode"],
        },
        "by_plat": by_plat,
        "by_version": by_version,
        "last_seen_buckets": {
            "under_1d": counts["under_1d"],
            "1d_7d": counts["d1_7"],
            "over_7d": counts["over_7d"],
            "never": counts["never"],
        },
        "checks": {
            "failing": check_results.filter(status=CheckStatus.FAILING).count(),
            "passing": check_results.filter(status=CheckStatus.PASSING).count(),
        },
        "failing_checks_by_type": failing_by_type,
        "patches_pending_agents": patches_pending_agents,
        "patches_failed_agents": patches_failed_agents,
        "alerts": alerts,
    }

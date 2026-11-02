# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Overview page widgets.

A widget is a role flag (or None), a settings serializer and a data
function. The function reads that app's role-filtered querysets. The
number of queries stays fixed as rows grow.
"""

import copy
import datetime as dt
from urllib.parse import urlencode

from django.db.models import (
    BooleanField,
    Case,
    Count,
    ExpressionWrapper,
    F,
    Q,
    Value,
    When,
)
from django.db.models.functions import Coalesce
from django.http import QueryDict
from django.utils import timezone as djangotime
from rest_framework import serializers
from rest_framework.response import Response

from agents.models import Agent
from alerts.models import Alert
from logs.models import PendingAction
from checks.models import CheckResult
from core.stats import _offline_q, _overdue_q
from discovery.models import DeviceState, DiscoveredDevice, Scan
from encryption.utils import fleet_summary
from groups.models import DeviceGroup
from metrics import views as metrics_views
from netmon.models import DeviceStatus, NetworkDevice
from timeline.sources import LIST_FLAGS, SOURCES, collect
from ulrmm.constants import AgentMonType, AlertSeverity, CheckStatus, PAStatus
from ulrmm.permissions import _has_perm
from vulns import views as vulns_views
from winupdate.models import WinUpdate

ROWS = 10
MAX_GROUPS = 20
# completed actions counted in the actions widget
ACTIONS_RECENT = dt.timedelta(days=1)


def _agents(request):
    return Agent.objects.filter_by_role(request.user)


def _get(view, request, params=None) -> Response:
    """Call another app's GET as this user.

    The counts and the permission checks stay in that view.
    """
    sub = copy.copy(request._request)
    sub.GET = QueryDict(urlencode(params or {}))
    # pass this user through. otherwise DRF reads the token again
    sub._force_auth_user, sub._force_auth_token = request.user, request.auth
    r = view(sub)
    return Response(r.data, status=r.status_code)


def _by_severity(field="severity") -> dict:
    return {
        s: Count("pk", filter=Q(**{field: s}))
        for s in (AlertSeverity.ERROR, AlertSeverity.WARNING, AlertSeverity.INFO)
    }


def fleet(request, s) -> dict:
    agents = _agents(request)
    c = agents.aggregate(
        total=Count("pk"),
        offline=Count("pk", filter=_offline_q()),
        overdue=Count("pk", filter=_overdue_q()),
        servers=Count("pk", filter=Q(monitoring_type=AgentMonType.SERVER)),
        workstations=Count("pk", filter=Q(monitoring_type=AgentMonType.WORKSTATION)),
        needs_reboot=Count("pk", filter=Q(needs_reboot=True)),
        maintenance_mode=Count("pk", filter=Q(maintenance_mode=True)),
    )
    # matches core.stats.fleet_stats
    c["online"] = c["total"] - c["offline"]
    c["offline"] -= c["overdue"]
    c["by_plat"] = list(
        agents.values("plat").annotate(count=Count("pk")).order_by("-count", "plat")
    )
    return c


def alerts(request, s) -> dict:
    # open alerts, counted the same way as the alerts icon
    qs = Alert.objects.filter_by_role(request.user).filter(
        resolved=False, snoozed=False, hidden=False
    )
    c = qs.aggregate(total=Count("pk"), **_by_severity())
    rows = qs.order_by("-alert_time", "-pk").values(
        "id",
        "severity",
        "message",
        "alert_time",
        "alert_type",
        "agent__agent_id",
        "agent__hostname",
        "agent__display_name",
        "network_device__name",
    )[:ROWS]
    c["latest"] = [
        {
            "id": r["id"],
            "severity": r["severity"],
            "message": (r["message"] or "")[:300],
            "alert_time": r["alert_time"],
            "alert_type": r["alert_type"],
            "agent_id": r["agent__agent_id"],
            "name": r["agent__display_name"]
            or r["agent__hostname"]
            or r["network_device__name"]
            or "",
        }
        for r in rows
    ]
    return c


def offline(request, s) -> dict:
    agents = _agents(request)
    c = agents.aggregate(
        offline=Count("pk", filter=_offline_q()),
        overdue=Count("pk", filter=_overdue_q()),
    )
    c["offline"] -= c["overdue"]
    rows = (
        agents.filter(_offline_q())
        .annotate(is_overdue=ExpressionWrapper(_overdue_q(), BooleanField()))
        .order_by("-last_seen", "hostname")
        .values(
            "agent_id",
            "hostname",
            "display_name",
            "plat",
            "last_seen",
            "is_overdue",
            "site__name",
            "site__client__name",
        )[:ROWS]
    )
    c["agents"] = [
        {
            "agent_id": r["agent_id"],
            "hostname": r["hostname"],
            "display_name": r["display_name"],
            "client": r["site__client__name"],
            "site": r["site__name"],
            "plat": r["plat"],
            "last_seen": r["last_seen"],
            "overdue": r["is_overdue"],
        }
        for r in rows
    ]
    return c


def patches(request, s) -> dict:
    # approved and not installed, as in core.stats and the agent table
    return WinUpdate.objects.filter(
        agent__in=_agents(request), action="approve", installed=False
    ).aggregate(
        pending_agents=Count("agent", distinct=True),
        failed_agents=Count("agent", distinct=True, filter=Q(result="failed")),
        pending_updates=Count("pk"),
        failed_updates=Count("pk", filter=Q(result="failed")),
    )


def checks(request, s) -> dict:
    qs = CheckResult.objects.filter(
        agent__in=_agents(request), status=CheckStatus.FAILING
    ).annotate(sev=Coalesce("alert_severity", "assigned_check__alert_severity"))
    c = qs.aggregate(failing=Count("pk"), **_by_severity("sev"))
    rows = (
        qs.select_related("agent", "assigned_check__script")
        .only(
            "last_run",
            "more_info",
            "agent",
            "agent__agent_id",
            "agent__hostname",
            "agent__display_name",
            "assigned_check",
            "assigned_check__check_type",
            "assigned_check__name",
            "assigned_check__disk",
            "assigned_check__warning_threshold",
            "assigned_check__error_threshold",
            "assigned_check__svc_display_name",
            "assigned_check__script",
            "assigned_check__script__name",
        )
        .order_by(F("last_run").desc(nulls_last=True), "-pk")[:ROWS]
    )
    c["items"] = [
        {
            "id": r.pk,
            "check_id": r.assigned_check_id,
            "agent_id": r.agent.agent_id,
            "hostname": r.agent.hostname,
            "display_name": r.agent.display_name,
            "check": r.assigned_check.readable_desc,
            "check_type": r.assigned_check.check_type,
            "severity": r.sev,
            "last_run": r.last_run,
            "more_info": (r.more_info or "")[:200],
        }
        for r in rows
    ]
    return c


def activity(request, s) -> dict:
    # each type checks the permission flag its own view uses
    allowed = {t for t, flag in LIST_FLAGS.items() if _has_perm(request, flag)}
    before = djangotime.now() + djangotime.timedelta(seconds=1)
    items = collect(
        _agents(request), before, s["limit"], s["types"], allowed, LIST_FLAGS
    )
    return {"items": items}


def vulns(request, s) -> Response:
    return _get(vulns_views.summary, request)


def netmon(request, s) -> dict:
    devices = NetworkDevice.objects.filter_by_role(request.user)
    on = Q(enabled=True)
    c = devices.aggregate(
        total=Count("pk"),
        disabled=Count("pk", filter=~on),
        maintenance=Count("pk", filter=on & Q(maintenance_mode=True)),
        **{st: Count("pk", filter=on & Q(status=st)) for st in DeviceStatus.values},
    )
    bad = (DeviceStatus.DOWN, DeviceStatus.ERROR, DeviceStatus.DEGRADED)
    rows = (
        devices.filter(on, status__in=bad)
        .annotate(
            rank=Case(
                *[When(status=st, then=Value(i)) for i, st in enumerate(bad)],
            )
        )
        .order_by("rank", "name")
        .values(
            "id",
            "name",
            "host",
            "status",
            "last_checked",
            "site__name",
            "site__client__name",
        )[:ROWS]
    )
    c["problems"] = [
        {
            "id": r["id"],
            "name": r["name"],
            "host": r["host"],
            "status": r["status"],
            "last_checked": r["last_checked"],
            "client": r["site__client__name"],
            "site": r["site__name"],
        }
        for r in rows
    ]
    return c


def _top(metric):
    def top(request, s) -> Response:
        return _get(metrics_views.fleet, request, {**s, "metric": metric})

    return top


def discovery(request, s) -> dict:
    c = DiscoveredDevice.objects.aggregate(
        total=Count("pk"),
        **{st: Count("pk", filter=Q(state=st)) for st in DeviceState.values},
    )
    c["last_scan"] = (
        Scan.objects.order_by("-pk")
        .values(
            "id",
            "status",
            "networks",
            "started_at",
            "finished_at",
            "hosts_total",
            "hosts_up",
        )
        .first()
    )
    return c


def groups(request, s) -> dict:
    qs = DeviceGroup.objects.only("name", "kind", "rules")
    if s["group_ids"]:
        qs = qs.filter(pk__in=s["group_ids"])
    found = list(qs.order_by("name")[:MAX_GROUPS])
    if not found:
        return {"groups": []}

    # one query: a filtered count per group, over this user's agents
    counts = {}
    for g in found:
        member = Q(pk__in=g.agents().values("pk"))
        counts[f"m{g.pk}"] = Count("pk", filter=member)
        counts[f"o{g.pk}"] = Count("pk", filter=member & _offline_q())
    c = _agents(request).aggregate(**counts)
    return {
        "groups": [
            {
                "id": g.pk,
                "name": g.name,
                "kind": g.kind,
                "members": c[f"m{g.pk}"],
                "offline": c[f"o{g.pk}"],
            }
            for g in found
        ]
    }


def encryption(request, s) -> dict:
    return fleet_summary(_agents(request))


def notes(request, s) -> dict:
    return {"text": s["text"]}


def _action_row(a: PendingAction) -> dict:
    return {
        "id": a.pk,
        "agent_id": a.agent.agent_id,
        "hostname": a.agent.hostname,
        "client": a.agent.site.client.name,
        "action_type": a.action_type,
        "description": a.description,
        "status": a.status,
        "entry_time": a.entry_time,
    }


def actions(request, s) -> dict:
    qs = PendingAction.objects.filter_by_role(request.user)
    if s["client_ids"]:
        qs = qs.filter(agent__site__client_id__in=s["client_ids"])
    since = djangotime.now() - ACTIONS_RECENT
    counts = qs.aggregate(
        pending=Count("pk", filter=Q(status=PAStatus.PENDING)),
        completed=Count(
            "pk", filter=Q(status=PAStatus.COMPLETED, entry_time__gte=since)
        ),
    )
    rows = qs.select_related("agent__site__client").only(
        "entry_time",
        "action_type",
        "status",
        "details",
        "agent__agent_id",
        "agent__hostname",
        "agent__site__client__name",
    )
    pending = rows.filter(status=PAStatus.PENDING).order_by("entry_time", "pk")
    # actions keep their queue time only, so "completed" means queued in the
    # last day and done by now, for the count and the list alike
    done = rows.filter(status=PAStatus.COMPLETED, entry_time__gte=since).order_by(
        "-entry_time", "-pk"
    )
    return {
        **counts,
        "pending_rows": [_action_row(a) for a in pending[: s["limit"]]],
        "completed_rows": [_action_row(a) for a in done[: s["limit"]]],
    }


class NoSettings(serializers.Serializer):
    pass


class ActivitySettings(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=50, default=20)
    types = serializers.ListField(
        child=serializers.ChoiceField(choices=sorted(SOURCES)),
        max_length=len(SOURCES),
        default=list,
    )


class TopSettings(serializers.Serializer):
    range = serializers.ChoiceField(choices=list(metrics_views.RANGES), default="24h")
    limit = serializers.IntegerField(min_value=1, max_value=50, default=10)


class GroupSettings(serializers.Serializer):
    # empty: the first groups by name
    group_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        max_length=MAX_GROUPS,
        default=list,
    )

    def validate_group_ids(self, value):
        return list(dict.fromkeys(value))


class ActionSettings(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=50, default=10)
    # empty: every client the user sees
    client_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1), max_length=200, default=list
    )

    def validate_client_ids(self, value):
        return list(dict.fromkeys(value))


class NoteSettings(serializers.Serializer):
    text = serializers.CharField(
        max_length=2000, allow_blank=True, default="", trim_whitespace=False
    )


WIDGETS = {
    "fleet": (None, NoSettings, fleet),
    "alerts": ("can_list_alerts", NoSettings, alerts),
    "offline": ("can_list_agents", NoSettings, offline),
    "patches": (None, NoSettings, patches),
    "checks": ("can_list_checks", NoSettings, checks),
    "activity": ("can_list_agents", ActivitySettings, activity),
    "vulns": ("can_view_vulnerabilities", NoSettings, vulns),
    "netmon": ("can_list_network_devices", NoSettings, netmon),
    "top_cpu": ("can_list_agents", TopSettings, _top("cpu")),
    "top_mem": ("can_list_agents", TopSettings, _top("mem")),
    "discovery": ("can_run_network_discovery", NoSettings, discovery),
    "groups": ("can_list_agents", GroupSettings, groups),
    "encryption": ("can_view_recovery_keys", NoSettings, encryption),
    "notes": (None, NoteSettings, notes),
    "actions": ("can_list_pendingactions", ActionSettings, actions),
}


def allowed(request, kind: str) -> bool:
    flag = WIDGETS[kind][0]
    return not request.user.is_installer_user and (
        flag is None or bool(_has_perm(request, flag))
    )


def _flat(errors) -> str:
    if isinstance(errors, dict):
        return "; ".join(f"{k}: {_flat(v)}" for k, v in errors.items())
    if isinstance(errors, list):
        return " ".join(_flat(e) for e in errors)
    return str(errors)


def clean_settings(kind: str, data) -> dict:
    cls = WIDGETS[kind][1]
    if not isinstance(data, dict):
        raise serializers.ValidationError("settings must be an object")
    if unknown := sorted(set(data) - set(cls().fields)):
        raise serializers.ValidationError(f"unknown settings: {', '.join(unknown)}")
    s = cls(data=data)
    if not s.is_valid():
        raise serializers.ValidationError(_flat(s.errors))
    return dict(s.validated_data)


def query_settings(kind: str, params) -> dict:
    """settings from the query string, lists comma separated"""
    fields = WIDGETS[kind][1]().fields
    return {
        k: (
            [i for i in v.split(",") if i]
            if isinstance(fields.get(k), serializers.ListField)
            else v
        )
        for k, v in params.items()
    }

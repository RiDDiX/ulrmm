# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db.models import Case, F, Q, When

from agents.models import Agent, AgentHistory
from alerts.models import Alert
from logs.models import AuditLog, DebugLog, PendingAction
from packages.models import PackageInstall
from patches.models import PatchEvent, ScheduleRun
from ulrmm.constants import AgentHistoryType, PAAction

DETAIL_MAX = 500

# type -> permission flag needed on the role, None = open to anyone in scope
GATED = {"audit": "can_view_auditlogs", "debug": "can_view_debuglogs"}
# the flags that guard the same rows in their own views
LIST_FLAGS = {
    **GATED,
    "script": "can_list_agent_history",
    "command": "can_list_agent_history",
    "task": "can_list_agent_history",
    "app_update": "can_list_agent_history",
    "alert": "can_list_alerts",
    "pending": "can_list_pendingactions",
    "patch": "can_view_patches",
    "package": "can_install_packages",
}

AGENT_ONLY = ("agent__agent_id", "agent__hostname", "agent__display_name")


def _cut(value, size=DETAIL_MAX) -> str:
    return (value or "")[:size]


def _agent(a) -> dict:
    return {"agent_id": a.agent_id, "name": a.display_name or a.hostname}


def _item(ts, kind, title, detail, user, severity, ref_kind, ref_id, agent, pk=None):
    return {
        # row pk for the page order, removed by collect()
        "_pk": ref_id if pk is None else pk,
        "ts": ts,
        "type": kind,
        "title": _cut(title, 120),
        "detail": _cut(detail),
        "user": user or "",
        "severity": severity,
        "ref": {"kind": ref_kind, "id": ref_id},
        "agent": agent,
    }


def _by_agent(agent, field: str) -> Q:
    # agent is one Agent or a queryset of them (fleet feed)
    if isinstance(agent, Agent):
        return Q(**{field: agent})
    return Q(**{f"{field}__in": agent.values("pk")})


HISTORY_TYPES = {
    "script": AgentHistoryType.SCRIPT_RUN,
    "command": AgentHistoryType.CMD_RUN,
    "task": AgentHistoryType.TASK_RUN,
    "app_update": AgentHistoryType.APP_UPDATE,
}


def history(agent, before, limit, kinds=None) -> list:
    rows = (
        AgentHistory.objects.filter(_by_agent(agent, "agent"), time__lte=before)
        .filter(type__in=[HISTORY_TYPES[k] for k in (kinds or HISTORY_TYPES)])
        .select_related("agent", "script")
        .only("time", "type", "command", "username", "script__name", *AGENT_ONLY)
        .annotate(retcode=F("script_results__retcode"))
        .defer("script_results")
        .order_by("-time", "-pk")[:limit]
    )
    names = {v: k for k, v in HISTORY_TYPES.items()}
    out = []
    for h in rows:
        kind = names.get(h.type, "command")
        if kind == "script":
            title = h.script.name if h.script_id else "Script run"
        elif kind == "task":
            title = h.command or "Task run"
        elif kind == "app_update":
            title = h.command or "App update"
        else:
            title = "Command run"
        failed = isinstance(h.retcode, int) and h.retcode != 0
        detail = f"exit code {h.retcode}" if isinstance(h.retcode, int) else ""
        out.append(
            _item(
                h.time,
                kind,
                title,
                detail,
                h.username,
                "error" if failed else "info",
                "history",
                h.pk,
                _agent(h.agent),
            )
        )
    return out


def audit(agent, before, limit) -> list:
    if isinstance(agent, Agent):
        q = Q(agent_id=agent.agent_id)
    else:
        q = Q(agent_id__in=agent.values("agent_id"))
    rows = (
        AuditLog.objects.filter(q, entry_time__lte=before)
        .only("entry_time", "action", "username", "message", "agent", "agent_id")
        .order_by("-entry_time", "-pk")[:limit]
    )
    return [
        _item(
            r.entry_time,
            "audit",
            r.get_action_display(),
            r.message,
            r.username,
            "info",
            "audit",
            r.pk,
            {"agent_id": r.agent_id, "name": r.agent or ""},
        )
        for r in rows
    ]


def debug(agent, before, limit) -> list:
    sev = {"warning": "warning", "error": "error", "critical": "error"}
    rows = (
        DebugLog.objects.filter(_by_agent(agent, "agent"), entry_time__lte=before)
        .select_related("agent")
        .only("entry_time", "log_level", "log_type", "message", *AGENT_ONLY)
        .order_by("-entry_time", "-pk")[:limit]
    )
    return [
        _item(
            r.entry_time,
            "debug",
            r.get_log_type_display(),
            r.message,
            "",
            sev.get(r.log_level, "info"),
            "debuglog",
            r.pk,
            _agent(r.agent),
        )
        for r in rows
    ]


def alerts(agent, before, limit) -> list:
    # one alert is up to two items: created and resolved
    rows = (
        Alert.objects.filter(
            _by_agent(agent, "agent"),
            Q(alert_time__lte=before) | Q(resolved=True, resolved_on__lte=before),
        )
        .select_related("agent")
        .only(
            "alert_time",
            "resolved",
            "resolved_on",
            "severity",
            "message",
            "alert_type",
            *AGENT_ONLY,
        )
        # the newest item of the row that this page can show
        .annotate(
            last=Case(
                When(resolved=True, resolved_on__lte=before, then="resolved_on"),
                default="alert_time",
            )
        )
        .order_by(F("last").desc(nulls_last=True), "-pk")[:limit]
    )
    out = []
    for a in rows:
        who = _agent(a.agent)
        if a.alert_time and a.alert_time <= before:
            out.append(
                _item(
                    a.alert_time,
                    "alert",
                    "Alert created",
                    a.message,
                    "",
                    a.severity,
                    "alert",
                    a.pk,
                    who,
                )
            )
        if a.resolved and a.resolved_on and a.resolved_on <= before:
            out.append(
                _item(
                    a.resolved_on,
                    "alert",
                    "Alert resolved",
                    a.message,
                    "",
                    "info",
                    "alert",
                    a.pk,
                    who,
                )
            )
    return out


def pending(agent, before, limit) -> list:
    # values(): model init has a signal that rewrites reboot rows
    rows = (
        PendingAction.objects.filter(_by_agent(agent, "agent"), entry_time__lte=before)
        .order_by("-entry_time", "-pk")
        .values(
            "pk",
            "entry_time",
            "action_type",
            "status",
            "agent__agent_id",
            "agent__hostname",
            "agent__display_name",
        )[:limit]
    )
    names = dict(PAAction.choices)
    return [
        _item(
            r["entry_time"],
            "pending",
            names.get(r["action_type"]) or "Pending action",
            r["status"],
            "",
            "info",
            "pendingaction",
            r["pk"],
            {
                "agent_id": r["agent__agent_id"],
                "name": r["agent__display_name"] or r["agent__hostname"],
            },
        )
        for r in rows
    ]


def patch(agent, before, limit) -> list:
    rows = (
        PatchEvent.objects.filter(
            _by_agent(agent, "patch_device__agent"), at__lte=before
        )
        .select_related("patch_device__agent", "patch_device__patch")
        .only(
            "at",
            "event_type",
            "actor",
            "to_state",
            "candidate_version",
            "patch_device__patch__package",
            "patch_device__agent__agent_id",
            "patch_device__agent__hostname",
            "patch_device__agent__display_name",
        )
        .order_by("-at", "-pk")[:limit]
    )
    out = []
    for e in rows:
        pd = e.patch_device
        bad = e.event_type in (
            "verification_failed",
            "retry_exhausted",
            "rollout_halted",
        )
        out.append(
            _item(
                e.at,
                "patch",
                f"{e.get_event_type_display()}: {pd.patch.package}",
                " ".join(p for p in (e.to_state, e.candidate_version) if p),
                e.actor,
                "error" if bad else "info",
                "patch",
                pd.patch_id,
                _agent(pd.agent),
                e.pk,
            )
        )
    return out


def schedule(agent, before, limit) -> list:
    sev = {"failed": "error", "timeout": "warning", "refused": "warning"}
    rows = (
        ScheduleRun.objects.filter(_by_agent(agent, "agent"), changed__lte=before)
        .select_related("agent", "schedule")
        .only("changed", "state", "detail", "schedule__name", *AGENT_ONLY)
        .order_by("-changed", "-pk")[:limit]
    )
    return [
        _item(
            r.changed,
            "schedule",
            f"{r.schedule.name}: {r.get_state_display()}",
            r.detail,
            "",
            sev.get(r.state, "info"),
            "schedulerun",
            r.pk,
            _agent(r.agent),
        )
        for r in rows
    ]


def package(agent, before, limit) -> list:
    sev = {"failed": "error", "refused": "error", "reboot_required": "warning"}
    rows = (
        PackageInstall.objects.filter(_by_agent(agent, "agent"), created__lte=before)
        .select_related("agent")
        .only("created", "package_name", "state", "detail", "requested_by", *AGENT_ONLY)
        .order_by("-created", "-pk")[:limit]
    )
    return [
        _item(
            r.created,
            "package",
            f"{r.package_name}: {r.get_state_display()}",
            r.detail,
            r.requested_by,
            sev.get(r.state, "info"),
            "packageinstall",
            r.pk,
            _agent(r.agent),
        )
        for r in rows
    ]


SOURCES = {
    "script": history,
    "command": history,
    "task": history,
    "app_update": history,
    "audit": audit,
    "debug": debug,
    "alert": alerts,
    "pending": pending,
    "patch": patch,
    "schedule": schedule,
    "package": package,
}


def collect(agent, before, limit, types, allowed, gates=GATED, skip=0) -> list:
    """Merge the requested sources, newest first, at or before `before`.

    `allowed` is the gated types this caller can see. `types` is what was
    asked for (empty means all). `skip` is how many items at exactly
    `before` the previous page already returned.
    """
    wanted = {
        t
        for t in (types or SOURCES)
        if t in SOURCES and (t not in gates or t in allowed)
    }
    items = []
    n = limit + skip
    hist = sorted(wanted & set(HISTORY_TYPES))
    if hist:
        items += history(agent, before, n, hist)
    for t in sorted(wanted - set(HISTORY_TYPES)):
        items += SOURCES[t](agent, before, n)
    # each source orders and limits by (ts, pk). the next page starts where this one stopped
    items.sort(key=lambda i: (i["ts"], i["ref"]["kind"], i["_pk"]), reverse=True)
    shown = 0
    while shown < min(skip, len(items)) and items[shown]["ts"] == before:
        shown += 1
    page = items[shown : shown + limit]
    for i in page:
        del i["_pk"]
    return page

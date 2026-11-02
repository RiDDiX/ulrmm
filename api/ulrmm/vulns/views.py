# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db.models import (
    BooleanField,
    Case,
    Count,
    ExpressionWrapper,
    F,
    Func,
    IntegerField,
    JSONField,
    Max,
    Q,
    Value,
    When,
)
from django.db.models.functions import Concat
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from agents.models import Agent
from logs.models import AuditLog
from ulrmm.constants import (
    AGENT_DEFER,
    ONLINE_AGENTS,
    AgentPlat,
    AuditActionType,
    AuditObjType,
)
from winupdate.tasks import posix_refresh_task
from ulrmm.helpers import notify_error
from remote.utils import version_key
from ulrmm.permissions import _has_perm, _has_perm_on_agent

from .models import AgentScan, Finding, FindingStatus, Level, Source
from .tasks import SCANNED, ecosystem, scan_vulnerabilities_task

MAX_ROWS = 1000

LEVEL_ORDER = Case(
    *[
        When(advisory__level=level, then=Value(i))
        for i, level in enumerate(("critical", "high", "medium", "low"))
    ],
    default=Value(4),
    output_field=IntegerField(),
)

UNKNOWN = Q(advisory=None) | Q(advisory__level=Level.UNKNOWN)

# first fixed version for the finding's own <ecosystem>|<package> key, NULL when
# there is no advisory, no key, an empty list or something other than a list
FIX0 = Func(
    F("advisory__fixed"),
    Concat("ecosystem", Value("|"), "package"),
    Value("0"),
    function="jsonb_extract_path",
    output_field=JSONField(),
)
NEEDS_UPDATE = Q(status=FindingStatus.OPEN, fix0__isnull=False)
NO_FIX = Q(status=FindingStatus.OPEN, fix0__isnull=True)

VIEWS = {
    "needs_update": NEEDS_UPDATE,
    "no_fix": NO_FIX,
    "open": Q(status=FindingStatus.OPEN),
    "ignored": Q(status=FindingStatus.IGNORED),
    "fixed": Q(status=FindingStatus.FIXED),
}

SEVERITIES = {
    "critical": Q(advisory__level=Level.CRITICAL),
    "high": Q(advisory__level=Level.HIGH),
    "medium": Q(advisory__level=Level.MEDIUM),
    "low": Q(advisory__level=Level.LOW),
    "unknown": UNKNOWN,
}

URLS = {
    Source.OSV: "https://osv.dev/vulnerability/{}",
    Source.MSRC: "https://msrc.microsoft.com/update-guide/vulnerability/{}",
    Source.NVD: "https://nvd.nist.gov/vuln/detail/{}",
    Source.VUXML: "https://vuxml.FreeBSD.org/freebsd/{}.html",
}

COVERAGE = (
    "Linux package inventories of Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux "
    "and openSUSE Leap/Tumbleweed are checked against OSV. Pending Windows "
    "security updates are matched to CVEs through MSRC. Common Windows and macOS "
    "apps are checked against NVD by name and version, apps without a known CPE "
    "mapping are counted, not checked. FreeBSD devices check their packages "
    "with pkg audit (VuXML) during each package scan; VuXML has no severity "
    "scores, so these findings show as unknown. Other distributions, flatpak "
    "and snap are not checked."
)


class VulnPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_view_vulnerabilities")

        # ignore uses can_approve_patches. there is no flag of its own
        return _has_perm(r, "can_view_vulnerabilities") and _has_perm(
            r, "can_approve_patches"
        )


def _agent(request, agent_id: str) -> Agent:
    agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
    if not _has_perm_on_agent(request.user, agent_id):
        raise PermissionDenied()
    return agent


def with_fix(qs):
    return qs.annotate(fix0=FIX0)


def fixed_version(source: str, installed: str, fixed_in) -> str | None:
    if not isinstance(fixed_in, list) or not fixed_in:
        return None
    entries = [str(e) for e in fixed_in]
    if source != Source.NVD:
        return entries[-1]

    # NVD lists are sorted as strings and can hold versions below the installed one
    def key(v):
        return version_key(v) or ()

    have = key(installed)
    newer = [e for e in entries if key(e) > have]
    return min(newer, key=key) if newer else max(entries, key=key)


def _rows(qs) -> list[dict]:
    qs = qs.annotate(
        fix_available=ExpressionWrapper(
            Q(fix0__isnull=False), output_field=BooleanField()
        )
    )
    rows = qs.order_by(LEVEL_ORDER, "-last_seen", "vuln_id", "pk").values(
        "id",
        "package",
        "version",
        "ecosystem",
        "vuln_id",
        "status",
        "source",
        "first_seen",
        "last_seen",
        "agent__agent_id",
        "agent__hostname",
        "agent__display_name",
        "agent__plat",
        "advisory__summary",
        "advisory__severity",
        "advisory__score",
        "advisory__level",
        "advisory__fixed",
        "fix_available",
    )[:MAX_ROWS]
    out = []
    for r in rows:
        fixed_in = (r["advisory__fixed"] or {}).get(
            f"{r['ecosystem']}|{r['package']}", []
        )
        out.append(
            {
                "id": r["id"],
                "agent_id": r["agent__agent_id"],
                "hostname": r["agent__hostname"],
                "display_name": r["agent__display_name"],
                "plat": r["agent__plat"],
                "package": r["package"],
                "version": r["version"],
                "ecosystem": r["ecosystem"],
                "vuln_id": r["vuln_id"],
                "url": URLS.get(r["source"], URLS[Source.OSV]).format(r["vuln_id"]),
                "status": r["status"],
                "source": r["source"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "summary": r["advisory__summary"] or "",
                "severity": r["advisory__severity"] or "",
                "score": r["advisory__score"],
                "level": r["advisory__level"] or Level.UNKNOWN,
                "fixed_in": fixed_in,
                "fix_available": r["fix_available"],
                "fixed_version": (
                    fixed_version(r["source"], r["version"], fixed_in)
                    if r["fix_available"]
                    else None
                ),
            }
        )
    return out


def _page(qs) -> dict:
    count = qs.count()
    return {"count": count, "truncated": count > MAX_ROWS, "findings": _rows(qs)}


def _filter(qs, params):
    """status, severity, source and search, shared by the fleet and agent views.
    Returns the filtered queryset or an error response."""
    if severity := params.get("severity"):
        if severity not in Level.values:
            return notify_error(f"severity must be one of {', '.join(Level.values)}")
        qs = qs.filter(SEVERITIES[severity])

    if source := params.get("source"):
        if source not in Source.values:
            return notify_error(f"source must be one of {', '.join(Source.values)}")
        qs = qs.filter(source=source)

    if status := params.get("status"):
        if status not in VIEWS:
            return notify_error(f"status must be one of {', '.join(VIEWS)}")
        qs = qs.filter(VIEWS[status])

    if search := params.get("search", "").strip()[:100]:
        qs = qs.filter(
            Q(package__icontains=search)
            | Q(vuln_id__icontains=search)
            | Q(advisory__summary__icontains=search)
            | Q(agent__hostname__icontains=search)
            | Q(agent__display_name__icontains=search)
        )
    return qs


@api_view(["GET"])
@permission_classes([IsAuthenticated, VulnPerms])
def findings(request):
    qs = with_fix(Finding.objects.filter_by_role(request.user))
    params = request.query_params

    if agent_id := params.get("agent"):
        qs = qs.filter(agent__agent_id=agent_id)

    qs = _filter(qs, params)
    if isinstance(qs, Response):
        return qs
    return Response(_page(qs))


@api_view(["GET"])
@permission_classes([IsAuthenticated, VulnPerms])
def summary(request):
    agents = Agent.objects.filter_by_role(request.user)
    open_ = with_fix(
        Finding.objects.filter(agent__in=agents, status=FindingStatus.OPEN)
    )
    # severities and affected devices count what an update can fix
    counts = open_.aggregate(
        open=Count("id"),
        needs_update=Count("id", filter=NEEDS_UPDATE),
        no_fix=Count("id", filter=NO_FIX),
        **{
            level: Count("id", filter=NEEDS_UPDATE & q)
            for level, q in SEVERITIES.items()
        },
        agents_affected=Count("agent", distinct=True, filter=NEEDS_UPDATE),
    )
    last_scan = AgentScan.objects.filter(agent__in=agents).aggregate(
        last=Max("scanned_at")
    )["last"]
    return Response({**counts, "last_scan": last_scan, "coverage": COVERAGE})


@api_view(["GET"])
@permission_classes([IsAuthenticated, VulnPerms])
def agent_findings(request, agent_id: str):
    agent = _agent(request, agent_id)
    all_ = with_fix(Finding.objects.filter(agent=agent))
    qs = _filter(all_, request.query_params)
    if isinstance(qs, Response):
        return qs
    totals = all_.aggregate(
        **{view: Count("id", filter=q) for view, q in VIEWS.items()},
        all=Count("id"),
        **{
            f"sev_{level}": Count("id", filter=NEEDS_UPDATE & q)
            for level, q in SEVERITIES.items()
        },
    )
    by_severity = {level: totals.pop(f"sev_{level}") for level in SEVERITIES}
    counts = {k: totals[k] for k in (*VIEWS, "all")}

    eco, reason = ecosystem(agent)
    scan = AgentScan.objects.filter(agent=agent).first()
    if eco and not scan:
        reason = "Not checked yet."
    elif eco and not scan.packages:
        reason = "No package inventory yet, refresh the device's software list first."

    return Response(
        {
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ecosystem": eco,
            "supported": eco is not None,
            "reason": reason,
            "last_scan": scan.scanned_at if scan else None,
            "packages": scan.packages if scan else 0,
            "unchecked": scan.unchecked if scan else 0,
            "unmapped": scan.unmapped if scan else 0,
            "plat": agent.plat,
            "counts": counts,
            "by_severity": by_severity,
            **_page(qs),
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated, VulnPerms])
def scan_fleet(request):
    agents = Agent.objects.filter_by_role(request.user)
    pks = list(agents.filter(plat__in=SCANNED).values_list("pk", flat=True))
    scan_vulnerabilities_task.delay(agent_pks=pks)
    # FreeBSD devices run pkg audit in their package scan; offline ones would
    # only log a failed scan
    bsd = [
        agent.pk
        for agent in agents.filter(plat=AgentPlat.FREEBSD).only(*ONLINE_AGENTS)
        if agent.is_online
    ]
    for pk in bsd:
        posix_refresh_task.delay(pk, "scan")
    return Response(f"Vulnerability check queued for {len(pks) + len(bsd)} agents")


@api_view(["POST"])
@permission_classes([IsAuthenticated, VulnPerms])
def scan_agent(request, agent_id: str):
    agent = _agent(request, agent_id)
    eco, reason = ecosystem(agent)
    if not eco:
        return notify_error(reason)
    if agent.plat == AgentPlat.FREEBSD:
        posix_refresh_task.delay(agent.pk, "scan")
        return Response(f"Vulnerability check queued for {agent.hostname}")
    scan_vulnerabilities_task.delay(agent_pks=[agent.pk])
    return Response(f"Vulnerability check queued for {agent.hostname}")


@api_view(["POST"])
@permission_classes([IsAuthenticated, VulnPerms])
def toggle_ignore(request, pk: int):
    finding = get_object_or_404(Finding, pk=pk)
    agent = _agent(
        request,
        Agent.objects.values_list("agent_id", flat=True).get(pk=finding.agent_id),
    )
    if finding.status == FindingStatus.FIXED:
        return notify_error("This finding is fixed already.")

    ignored = finding.status == FindingStatus.OPEN
    finding.status = FindingStatus.IGNORED if ignored else FindingStatus.OPEN
    finding.save(update_fields=["status"])

    username = request.user.username
    verb = "ignored" if ignored else "reopened"
    entry = AuditLog(username=username, agent=agent.hostname, agent_id=agent.agent_id)
    entry.object_type, entry.action = AuditObjType.AGENT, AuditActionType.MODIFY
    entry.after_value = {"finding": finding.pk, "status": finding.status}
    entry.message = (
        f"{username} {verb} {finding.vuln_id} "
        f"in {finding.package} {finding.version} on {agent.hostname}"
    )
    entry.save()
    return Response({"id": finding.pk, "status": finding.status})

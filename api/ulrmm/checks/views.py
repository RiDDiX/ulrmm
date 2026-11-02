# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from datetime import timedelta

from django.db.models import Prefetch, prefetch_related_objects
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from alerts.models import Alert
from automation.models import Policy
from metrics.models import AgentState
from ulrmm.constants import AGENT_DEFER, AgentPlat, CheckStatus, CheckType
from ulrmm.exceptions import NatsDown
from ulrmm.helpers import notify_error
from ulrmm.nats_utils import abulk_nats_command
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_item,
    _has_perm_on_policy,
    _may_manage_policy_pk,
)

from .models import Check, CheckHistory, CheckResult
from .permissions import BulkRunChecksPerms, ChecksPerms, RunChecksPerms
from .serializers import CheckHistorySerializer, CheckSerializer

WINDOWS_ONLY = (CheckType.WINSVC, CheckType.EVENT_LOG)
# these need the state push or the runner of a current agent
STATE_TYPES = (CheckType.SYSTEMD, CheckType.CONTAINER, CheckType.METRIC)
# systemd units, rc.d services on FreeBSD
SERVICE_PLATS = (AgentPlat.LINUX, AgentPlat.FREEBSD)
MAX_HISTORY_DAYS = 3650
# the checks table needs the agent's alert template, not its inventory
AGENT_DETAIL_DEFER = tuple(f"agent__{field}" for field in AGENT_DEFER)


def _context(request) -> dict:
    return {"reveal_env_vars": _has_perm(request, "can_manage_checks")}


def _checks_with_agent():
    return Check.objects.select_related("agent__alert_template", "script").defer(
        *AGENT_DETAIL_DEFER
    )


def _check_or_404(pk: int) -> Check:
    return get_object_or_404(_checks_with_agent().select_related("policy"), pk=pk)


def _body(request) -> dict:
    if not isinstance(request.data, dict):
        raise ValidationError("Expected a JSON object.")
    return request.data.copy()


def _require_agent_scope(request, agent) -> None:
    if agent and not _has_perm_on_agent(request.user, agent.agent_id):
        raise PermissionDenied()


def _require_item_scope(request, check: Check, *, manage: bool = False) -> None:
    if not _has_perm_on_item(request.user, check, manage=manage):
        raise PermissionDenied()


def _require_script_perm(request, data: dict, current=None) -> None:
    # a check runs its script on the endpoint as SYSTEM/root, attaching one is
    # running it
    script = data.get("script")
    changed = script and str(script) != str(current)
    if changed and not _has_perm(request, "can_run_scripts"):
        raise PermissionDenied("Attaching a script needs the run scripts permission.")


def _wildcard_event_id(data: dict, check_type) -> None:
    if check_type == CheckType.EVENT_LOG and data.get("event_id_is_wildcard"):
        data["event_id"] = 0


def _resolve_open_alert(result: CheckResult) -> None:
    # a manual reset acknowledges silently, no resolved notification is sent
    alert = Alert.create_or_return_check_alert(
        result.assigned_check, agent=result.agent, skip_create=True
    )
    if alert:
        alert.resolve()


def _reset(result: CheckResult) -> None:
    result.status = CheckStatus.PASSING
    result.fail_count = 0
    result.save(update_fields=["status", "fail_count"])
    _resolve_open_alert(result)


class GetAddChecks(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    def get(self, request, agent_id=None, policy=None):
        if agent_id:
            with_scripts = Prefetch(
                "agentchecks", queryset=Check.objects.select_related("script")
            )
            owner = get_object_or_404(
                Agent.objects.select_related("alert_template")
                .prefetch_related(with_scripts)
                .defer(*AGENT_DEFER),
                agent_id=agent_id,
            )
            checks = owner.get_checks_with_policies()
        elif policy:
            policy = get_object_or_404(Policy, id=policy)
            if not _has_perm_on_policy(request.user, policy):
                raise PermissionDenied()
            checks = (
                Check.objects.filter(policy=policy)
                .select_related("script")
                .order_by("pk")
            )
        else:
            checks = _checks_with_agent().filter_by_role(request.user)

        checks = list(checks)
        prefetch_related_objects(checks, "assignedtasks")
        return Response(
            CheckSerializer(checks, many=True, context=_context(request)).data
        )

    def post(self, request):
        data = _body(request)
        check_type = data.get("check_type")

        if data.get("agent"):
            agent = get_object_or_404(Agent, agent_id=data["agent"])
            _require_agent_scope(request, agent)
            data["agent"] = agent.pk
            # the posix agent answers these with an empty status or log
            if check_type in WINDOWS_ONLY and agent.plat != AgentPlat.WINDOWS:
                return notify_error(
                    f"{check_type} checks are only supported on Windows agents"
                )
            if check_type == CheckType.SYSTEMD and agent.plat not in SERVICE_PLATS:
                return notify_error(
                    "Service checks are only supported on Linux and FreeBSD agents"
                )
        else:
            agent = None
            if not _may_manage_policy_pk(request.user, data.get("policy")):
                raise PermissionDenied()

        _wildcard_event_id(data, check_type)
        _require_script_perm(request, data)

        serializer = CheckSerializer(data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        new_check = serializer.save()

        message = f"{new_check.readable_desc} was added!"
        if agent and (
            (
                new_check.check_type in (CheckType.SECURITY, CheckType.HW_HEALTH)
                and "health" not in (agent.wmi_detail or {})
            )
            or (
                new_check.check_type in STATE_TYPES
                and not AgentState.objects.filter(agent=agent).exists()
            )
        ):
            message += " Agent update required before it runs."
        return Response(message)


class GetUpdateDeleteCheck(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    def get(self, request, pk):
        check = _check_or_404(pk)
        _require_item_scope(request, check)
        return Response(CheckSerializer(check, context=_context(request)).data)

    def put(self, request, pk):
        check = _check_or_404(pk)
        _require_item_scope(request, check, manage=True)

        data = _body(request)
        # owner and kind are fixed, audit fields belong to the server
        for name in (
            *Check.non_editable_fields(),
            "agent",
            "policy",
            "managed_by_policy",
        ):
            data.pop(name, None)
        if "event_id_is_wildcard" in data:
            _wildcard_event_id(data, check.check_type)
        _require_script_perm(request, data, current=check.script_id)

        form = CheckSerializer(check, data=data, partial=True)
        form.is_valid(raise_exception=True)
        return Response(f"{form.save().readable_desc} was edited!")

    def delete(self, request, pk):
        check = _check_or_404(pk)
        _require_item_scope(request, check, manage=True)
        label = check.readable_desc
        check.delete()
        return Response(f"{label} was deleted!")


class ResetCheck(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    def post(self, request, pk):
        result = get_object_or_404(
            CheckResult.objects.select_related("agent", "assigned_check"), pk=pk
        )
        _require_agent_scope(request, result.agent)
        _reset(result)
        return Response("The check status was reset")


class ResetAllChecksStatus(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    def post(self, request, agent_id):
        results = CheckResult.objects.select_related("assigned_check")
        candidates = (
            Agent.objects.select_related(
                "alert_template", "policy", "policy__alert_template"
            )
            .prefetch_related("agentchecks", Prefetch("checkresults", queryset=results))
            .defer(*AGENT_DEFER)
        )
        agent = get_object_or_404(candidates, agent_id=agent_id)
        _require_agent_scope(request, agent)

        for check in agent.get_checks_with_policies():
            # checks that never ran have no result to reset
            if isinstance(check.check_result, CheckResult):
                _reset(check.check_result)

        return Response("All checks status were reset")


class GetCheckHistory(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    def patch(self, request, pk):
        result = get_object_or_404(CheckResult.objects.select_related("agent"), pk=pk)
        _require_agent_scope(request, result.agent)

        days = (
            request.data.get("timeFilter", 0) if isinstance(request.data, dict) else 0
        )
        if isinstance(days, str) and days.isdigit():
            days = int(days)
        if (
            isinstance(days, bool)
            or not isinstance(days, int)
            or not 0 <= days <= MAX_HISTORY_DAYS
        ):
            return notify_error(
                f"timeFilter must be a number of days from 0 to {MAX_HISTORY_DAYS}"
            )

        # one agent never sees another's points of a shared policy check
        history = CheckHistory.objects.filter(
            check_id=result.assigned_check_id, agent_id=result.agent.agent_id
        )
        if days:
            now = djangotime.now()
            history = history.filter(x__lte=now, x__gt=now - timedelta(days=days))

        return Response(CheckHistorySerializer(history.order_by("-x"), many=True).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated, RunChecksPerms])
def run_checks(request, agent_id):
    agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
    reply = asyncio.run(agent.nats_cmd({"func": "runchecks"}, timeout=15))
    if reply == "busy":
        return notify_error(f"Checks are already running on {agent.hostname}")
    if reply != "ok":
        return notify_error("Unable to contact the agent")
    return Response("Checks will now be run on " + agent.hostname)


@api_view(["POST"])
@permission_classes([IsAuthenticated, BulkRunChecksPerms])
def bulk_run_checks(request, target, pk):
    scope = {"client": "site__client__id", "site": "site__id"}.get(target)
    if scope is None:
        return notify_error("Checks run for a client or a site")

    agent_ids = (
        Agent.objects.only("agent_id", "site")
        .filter_by_role(request.user)
        .filter(**{scope: pk})
        .values_list("agent_id", flat=True)
    )
    items = [(agent_id, {"func": "runchecks"}) for agent_id in agent_ids]
    if not items:
        return notify_error("No agents matched query")

    try:
        asyncio.run(abulk_nats_command(items=items))
    except NatsDown as e:
        return notify_error(str(e))

    return Response(f"Checks will now be run on {len(items)} agents")

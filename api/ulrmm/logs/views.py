# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from datetime import timedelta

from django.core.cache import cache
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import MethodNotAllowed, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from agents.models import Agent
from ulrmm.constants import (
    AGENT_DEFER,
    AuditActionType,
    AuditObjType,
    PAAction,
    PAStatus,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _audit_log_filter, _has_perm_on_agent, _is_restricted

from .models import AuditLog, DebugLog, PendingAction
from .permissions import AuditLogPerms, DebugLogPerms, PendingActionPerms
from .serializers import (
    AuditLogSerializer,
    DebugLogSerializer,
    PendingActionSerializer,
)

# sortBy values the audit table accepts; the web sends column names
AUDIT_SORT = {
    "entry_time": "entry_time",
    "username": "username",
    "agent": "agent",
    "agent_id": "agent_id",
    "action": "action",
    "object_type": "object_type",
    "message": "message",
    "client_ip": "debug_info__ip",
}
AUDIT_LIST_FILTERS = (
    "agentFilter",
    "clientFilter",
    "userFilter",
    "actionFilter",
    "objectFilter",
)
MAX_ROWS = 1000
# counting every match of a big log is slow, past this the total is a floor
COUNT_CAP = 10_000
MAX_DAYS = 36500


class BadInput(Exception):
    pass


def _number(value, name: str) -> int:
    # numeric strings were accepted before and stay accepted
    # isdecimal: "²" passes isdigit() but int() rejects it
    if isinstance(value, str) and value.isdecimal():
        if len(value) > 20:
            raise BadInput(f"{name} must be a whole number")
        try:
            return int(value)
        except ValueError:
            raise BadInput(f"{name} must be a whole number")
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadInput(f"{name} must be a whole number")
    return value


def _audit_query(data, user):
    if not isinstance(data, dict):
        raise BadInput("The search must be a JSON object")
    pagination = data.get("pagination")
    if not isinstance(pagination, dict):
        raise BadInput("pagination is required")

    # the web table always sends all four
    for key in ("sortBy", "descending", "page", "rowsPerPage"):
        if key not in pagination:
            raise BadInput(f"pagination.{key} is required")

    rows = _number(pagination["rowsPerPage"], "rowsPerPage")
    rows = min(max(rows, 1), MAX_ROWS)
    page = _number(pagination["page"], "page")
    if page < 1:
        raise BadInput("page must be a whole number of at least 1")
    descending = pagination["descending"]
    if not isinstance(descending, bool):
        raise BadInput("descending must be a boolean")
    sort_by = pagination.get("sortBy")
    column = (
        AUDIT_SORT.get(sort_by, "entry_time")
        if isinstance(sort_by, str)
        else "entry_time"
    )
    direction = "-" if descending else ""

    for key in AUDIT_LIST_FILTERS:
        if key in data:
            values = data[key]
            if not isinstance(values, list) or not all(
                isinstance(v, (str, int)) and not isinstance(v, bool) for v in values
            ):
                raise BadInput(f"{key} must be a list")

    qs = AuditLog.objects.filter(_audit_log_filter(user))
    if "agentFilter" in data:
        qs = qs.filter(agent_id__in=data["agentFilter"])
    elif "clientFilter" in data:
        try:
            client_pks = [int(pk) for pk in data["clientFilter"]]
        except ValueError:
            raise BadInput("clientFilter must list client ids")
        agent_ids = Agent.objects.filter(site__client_id__in=client_pks).values(
            "agent_id"
        )
        qs = qs.filter(agent_id__in=agent_ids)
    if "userFilter" in data:
        qs = qs.filter(username__in=data["userFilter"])
    if "actionFilter" in data:
        qs = qs.filter(action__in=data["actionFilter"])
    if "objectFilter" in data:
        types = list(data["objectFilter"])
        # base audit rows of the key store carry the model name
        if AuditObjType.KEYSTORE in types:
            types.append("globalkvstore")
        qs = qs.filter(object_type__in=types)

    days = _number(data.get("timeFilter", 0), "timeFilter")
    if not 0 <= days <= MAX_DAYS:
        raise BadInput(f"timeFilter must be between 0 and {MAX_DAYS}")
    if days:
        now = djangotime.now()
        qs = qs.filter(entry_time__lte=now, entry_time__gt=now - timedelta(days=days))

    qs = qs.order_by(f"{direction}{column}", f"{direction}id")
    return qs, rows, page


class GetAuditLogs(APIView):
    permission_classes = [IsAuthenticated, AuditLogPerms]

    def patch(self, request):
        try:
            qs, rows, page = _audit_query(request.data, request.user)
        except BadInput as e:
            return notify_error(str(e))

        paginator = Paginator(qs, rows)
        total = qs.order_by()[: COUNT_CAP + 1].count()
        paginator.count = min(total, COUNT_CAP)
        entries = list(paginator.get_page(page))
        agent_ids = {e.agent_id for e in entries if e.agent_id}
        agents = (
            Agent.objects.defer(*AGENT_DEFER)
            .select_related("site__client")
            .filter(agent_id__in=agent_ids)
        )
        sites = {agent.agent_id: agent.site for agent in agents}

        return Response(
            {
                "audit_logs": AuditLogSerializer(
                    entries, many=True, context={"sites": sites}
                ).data,
                "total": paginator.count,
                "total_capped": total > COUNT_CAP,
            }
        )


class GetDebugLog(APIView):
    permission_classes = [IsAuthenticated, DebugLogPerms]

    def patch(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        qs = (
            DebugLog.objects.filter_by_role(request.user)
            .select_related("agent")
            .only(
                "id",
                "entry_time",
                "log_level",
                "log_type",
                "message",
                "agent",
                "agent__hostname",
            )
        )
        if "logTypeFilter" in data:
            qs = qs.filter(log_type=data["logTypeFilter"])
        if "logLevelFilter" in data:
            qs = qs.filter(log_level=data["logLevelFilter"])
        if "agentFilter" in data:
            qs = qs.filter(agent__agent_id=data["agentFilter"])

        lines = qs.order_by("-entry_time")[:1000]
        return Response(DebugLogSerializer(lines, many=True).data)


class CancelThrottle(UserRateThrottle):
    # a cancel can hold a worker for the 10 s NATS timeout
    scope = "pendingaction_cancel"


@api_view(["GET"])
@permission_classes([IsAuthenticated, PendingActionPerms])
def pending_count(request):
    """For the menu: pending actions the user may see."""
    qs = PendingAction.objects.filter_by_role(request.user)
    return Response({"pending": qs.filter(status=PAStatus.PENDING).count()})


class PendingActions(APIView):
    permission_classes = [IsAuthenticated, PendingActionPerms]

    def get_throttles(self):
        if self.request.method == "DELETE":
            return [CancelThrottle()]
        return super().get_throttles()

    def get(self, request, agent_id=None, pk=None):
        if pk is not None:
            raise MethodNotAllowed(request.method)

        if agent_id is not None:
            agent = get_object_or_404(
                Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id
            )
            actions = PendingAction.objects.filter(agent=agent)
        else:
            actions = PendingAction.objects.filter_by_role(request.user)

        actions = (
            actions.select_related("agent__site__client")
            .defer("agent__services", "agent__wmi_detail")
            .order_by("pk")
        )
        # the list without page stays for older web builds
        if "page" not in request.query_params:
            return Response(PendingActionSerializer(actions, many=True).data)
        try:
            rows = min(
                max(_number(request.query_params.get("rows", "50"), "rows"), 1),
                MAX_ROWS,
            )
            page = _number(request.query_params["page"], "page")
        except BadInput as e:
            return notify_error(str(e))
        paginator = Paginator(actions, rows)
        return Response(
            {
                "actions": PendingActionSerializer(
                    paginator.get_page(page), many=True
                ).data,
                "total": paginator.count,
            }
        )

    def delete(self, request, pk=None, agent_id=None):
        if pk is None:
            raise MethodNotAllowed(request.method)

        actions = PendingAction.objects.select_related("agent")
        # a restricted role cannot tell a missing action from a foreign one
        if _is_restricted(request.user) and not actions.filter(pk=pk).exists():
            raise PermissionDenied()
        action = get_object_or_404(actions, pk=pk)
        agent = action.agent
        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()

        lock = f"pendingaction_cancel:{action.pk}"
        if not cache.add(lock, True, 15):
            return notify_error("A cancel for this pending action is already running.")
        try:
            return self._cancel(request, action, agent)
        finally:
            cache.delete(lock)

    def _cancel(self, request, action, agent):
        # a reboot that is done has no Windows task left to remove
        if (
            action.action_type == PAAction.SCHED_REBOOT
            and action.status != PAStatus.COMPLETED
        ):
            details = action.details if isinstance(action.details, dict) else {}
            taskname = details.get("taskname")
            if not taskname:
                return notify_error("This pending action has no scheduled task name.")
            nats_data = {
                "func": "delschedtask",
                "schedtaskpayload": {"name": taskname},
            }
            r = asyncio.run(agent.nats_cmd(nats_data, timeout=10))
            if r != "ok":
                return notify_error(r)

        description = action.description
        snapshot = {
            "id": action.pk,
            "action_type": action.action_type,
            "status": action.status,
            "details": action.details,
        }
        action.delete()

        username = request.user.username
        what = description or action.action_type
        AuditLog._agent_entry(
            username,
            agent,
            get_debug_info(),
            action=AuditActionType.DELETE,
            before_value=snapshot,
            message=f"{username} cancelled pending action {what} on {agent.hostname}",
        )
        return Response(f"{agent.hostname}: {description} was cancelled")

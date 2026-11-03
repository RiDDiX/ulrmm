# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from agents.models import Agent
from clients.models import Site
from core.permissions import CoreSettingsPerms
from logs.models import AuditLog
from ulrmm.constants import (
    AGENT_DEFER,
    AppUpdatePolicy,
    AuditActionType,
    AuditObjType,
)
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm, _has_perm_on_agent, _has_perm_on_site

from .models import AppUpdate, AppUpdateScan, AppUpdateSettings, State
from .tasks import (
    ID_RE,
    LIST,
    LIST_TIMEOUT,
    OPEN,
    PLATS,
    apply_app_updates_task,
    effective,
    parse_list,
    store,
)

MAX_EXCLUSIONS = 500


class AppUpdatePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_list_software") or _has_perm(
                r, "can_manage_app_updates"
            )
        return _has_perm(r, "can_manage_app_updates")


class AgentPolicyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_edit_agent")


class SitePolicyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_manage_sites")


class SettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppUpdateSettings
        fields = ("enabled", "hour", "max_per_run", "exclusions")

    def validate_exclusions(self, value):
        if (
            not isinstance(value, list)
            or len(value) > MAX_EXCLUSIONS
            or not all(isinstance(v, str) and ID_RE.fullmatch(v) for v in value)
        ):
            raise serializers.ValidationError(
                f"At most {MAX_EXCLUSIONS} app ids of letters, digits and . _ + & ! @ -"
            )
        return sorted(set(value))


def _agent(request, agent_id: str) -> Agent:
    agent = get_object_or_404(
        Agent.objects.defer(*AGENT_DEFER).select_related("site"), agent_id=agent_id
    )
    if not _has_perm_on_agent(request.user, agent_id):
        raise PermissionDenied()
    return agent


def _policy(agent: Agent, s: AppUpdateSettings) -> dict:
    on, origin = effective(agent, s.enabled)
    return {
        "policy": agent.app_updates,
        "site_policy": agent.site.app_updates,
        "global_enabled": s.enabled,
        "effective": on,
        "effective_from": origin,
        "hour": s.hour,
    }


def _payload(agent: Agent) -> dict:
    s = AppUpdateSettings.load()
    scan = AppUpdateScan.objects.filter(agent=agent).first()
    rows, pending = [], 0
    for u in AppUpdate.objects.filter(agent=agent).order_by("name", "pk"):
        excluded_globally = u.app_id in s.exclusions
        if u.state in OPEN and u.available and not excluded_globally:
            pending += 1
        rows.append(
            {
                "id": u.pk,
                "source": u.source,
                "app_id": u.app_id,
                "name": u.name,
                "installed": u.installed,
                "available": u.available,
                "state": u.state,
                "last_error": u.last_error,
                "seen_at": u.seen_at,
                "excluded_globally": excluded_globally,
            }
        )
    return {
        "agent_id": agent.agent_id,
        "supported": agent.plat in PLATS,
        **_policy(agent, s),
        "collected_at": scan.collected_at if scan else None,
        "error": scan.error if scan else "",
        "pending": pending,
        "updates": rows,
    }


def _audit(request, agent: Agent, action: str, message: str, after: dict) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        agent=agent.hostname,
        agent_id=agent.agent_id,
        action=action,
        object_type=AuditObjType.AGENT,
        message=message,
        after_value=after,
    )


def _ready(agent: Agent) -> Response | None:
    if agent.plat not in PLATS:
        return notify_error("App updates need a Windows or macOS agent.")
    if not agent.is_online:
        return notify_error(f"{agent.hostname} is offline.")
    return None


@api_view(["GET"])
@permission_classes([IsAuthenticated, AppUpdatePerms])
def agent_updates(request, agent_id: str):
    return Response(_payload(_agent(request, agent_id)))


@api_view(["POST"])
@permission_classes([IsAuthenticated, AppUpdatePerms])
def collect(request, agent_id: str):
    agent = _agent(request, agent_id)
    if error := _ready(agent):
        return error
    try:
        rows = parse_list(asyncio.run(agent.nats_cmd(LIST, timeout=LIST_TIMEOUT)))
    except ValueError as e:
        store(agent, {}, str(e))
        return notify_error(str(e))
    store(agent, rows)
    return Response(_payload(agent))


@api_view(["POST"])
@permission_classes([IsAuthenticated, AppUpdatePerms])
def apply(request, agent_id: str):
    agent = _agent(request, agent_id)
    ids = request.data.get("ids")
    if (
        not isinstance(ids, list)
        or not ids
        or not all(isinstance(i, str) and ID_RE.fullmatch(i) for i in ids)
    ):
        return notify_error("Choose the apps to update.")
    if error := _ready(agent):
        return error

    rows = list(
        AppUpdate.objects.filter(agent=agent, app_id__in=ids, state__in=OPEN)
        .exclude(available="")
        .exclude(app_id__in=AppUpdateSettings.load().exclusions)
    )
    if not rows:
        return notify_error("None of these apps has an update to install.")

    pks = [u.pk for u in rows]
    queued = sorted({u.app_id for u in rows})
    AppUpdate.objects.filter(pk__in=pks).update(state=State.UPDATING, last_error="")
    apply_app_updates_task.delay(pks=pks, username=request.user.username)
    _audit(
        request,
        agent,
        AuditActionType.EXEC_COMMAND,
        f"{request.user.username} started app updates on {agent.hostname}: "
        f"{', '.join(queued)}",
        {"app_ids": queued},
    )
    return Response({"queued": queued, "skipped": sorted(set(ids) - set(queued))})


@api_view(["PUT"])
@permission_classes([IsAuthenticated, AppUpdatePerms])
def exclude(request, agent_id: str):
    agent = _agent(request, agent_id)
    app_id, excluded = request.data.get("app_id"), request.data.get("excluded")
    if not isinstance(app_id, str) or not ID_RE.fullmatch(app_id):
        return notify_error("app_id is not valid.")
    if not isinstance(excluded, bool):
        return notify_error("excluded must be true or false.")

    rows = AppUpdate.objects.filter(agent=agent, app_id=app_id)
    if not rows.exists():
        return notify_error("No update is listed for this app.")
    if rows.filter(state=State.UPDATING).exists():
        return notify_error("This app is being updated right now.")
    if excluded:
        rows.update(state=State.EXCLUDED)
    else:
        # an excluded row without a pending version was only the marker
        rows.filter(state=State.EXCLUDED, available="").delete()
        rows.filter(state=State.EXCLUDED).update(state=State.AVAILABLE)

    _audit(
        request,
        agent,
        AuditActionType.MODIFY,
        f"{request.user.username} {'excluded' if excluded else 'included'} "
        f"{app_id} in app updates on {agent.hostname}",
        {"app_id": app_id, "excluded": excluded},
    )
    return Response(_payload(agent))


@api_view(["PATCH"])
@permission_classes([IsAuthenticated, AgentPolicyPerms])
def agent_policy(request, agent_id: str):
    agent = _agent(request, agent_id)
    value = request.data.get("app_updates")
    if value not in AppUpdatePolicy.values:
        return notify_error(
            f"app_updates must be one of {', '.join(AppUpdatePolicy.values)}"
        )
    agent.app_updates = value
    agent.save(update_fields=["app_updates"])
    return Response(_policy(agent, AppUpdateSettings.load()))


@api_view(["PATCH"])
@permission_classes([IsAuthenticated, SitePolicyPerms])
def site_policy(request, pk: int):
    site = get_object_or_404(Site, pk=pk)
    if not _has_perm_on_site(request.user, site.pk):
        raise PermissionDenied()
    value = request.data.get("app_updates")
    if value not in AppUpdatePolicy.values:
        return notify_error(
            f"app_updates must be one of {', '.join(AppUpdatePolicy.values)}"
        )
    site.app_updates = value
    site.save(update_fields=["app_updates"])
    return Response({"id": site.pk, "app_updates": site.app_updates})


@api_view(["GET", "PUT"])
@permission_classes([IsAuthenticated, CoreSettingsPerms])
def settings_view(request):
    s = AppUpdateSettings.load()
    if request.method == "PUT":
        serializer = SettingsSerializer(s, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        s = serializer.save()

    sites = (
        Site.objects.filter_by_role(request.user)
        .exclude(app_updates=AppUpdatePolicy.INHERIT)
        .select_related("client")
        .order_by("client__name", "name")
    )
    return Response(
        {
            **SettingsSerializer(s).data,
            "sites": [
                {
                    "id": site.pk,
                    "name": site.name,
                    "client_name": site.client.name,
                    "app_updates": site.app_updates,
                }
                for site in sites
            ],
        }
    )

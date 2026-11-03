# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from assets.views import _unrestricted
from clients.models import Site
from core.utils import stepup_denied
from logs.models import AuditLog
from ulrmm.constants import AGENT_DEFER, AuditActionType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm, _has_perm_on_agent, _has_perm_on_site

from .models import LapsPolicy, LapsState
from .serializers import LapsPolicySerializer, LapsStateSerializer
from .tasks import library_script, rotate_agent_task

STEPUP = "Local admin passwords change on the devices."


class LapsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_manage_laps")


def _agent(request, agent_id) -> Agent:
    agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
    if not _has_perm_on_agent(request.user, agent.agent_id):
        raise PermissionDenied()
    return agent


class Policies(APIView):
    """The global policy and the site policies that replace it."""

    permission_classes = [IsAuthenticated, LapsPerms]

    def get(self, request):
        default = LapsPolicy.objects.filter(site__isnull=True).first() or LapsPolicy()
        sites = [
            p
            for p in LapsPolicy.objects.filter(site__isnull=False)
            .select_related("site__client")
            .order_by("site__client__name", "site__name")
            if _has_perm_on_site(request.user, p.site_id)
        ]
        return Response(
            {
                "global": LapsPolicySerializer(default).data,
                "sites": LapsPolicySerializer(sites, many=True).data,
            }
        )

    def put(self, request):
        site = request.data.get("site")
        if site is not None:
            if type(site) is not int or not Site.objects.filter(pk=site).exists():
                return notify_error("Unknown site.")
            if not _has_perm_on_site(request.user, site):
                raise PermissionDenied()
        elif not _unrestricted(request.user):
            # the global policy reaches devices of every client
            raise PermissionDenied()
        if denied := stepup_denied(request, STEPUP):
            return denied
        policy = LapsPolicy.objects.filter(site_id=site).first()
        s = LapsPolicySerializer(instance=policy, data=request.data)
        s.is_valid(raise_exception=True)
        return Response(LapsPolicySerializer(s.save()).data)


class SitePolicy(APIView):
    permission_classes = [IsAuthenticated, LapsPerms]

    def delete(self, request, site_id):
        policy = get_object_or_404(LapsPolicy, site_id=site_id)
        if not _has_perm_on_site(request.user, site_id):
            raise PermissionDenied()
        if denied := stepup_denied(request, STEPUP):
            return denied
        policy.delete()
        return Response("The site follows the global policy again.")


class AgentLaps(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, agent_id):
        if not _has_perm(request, "can_view_credentials"):
            raise PermissionDenied()
        agent = _agent(request, agent_id)
        policy = LapsPolicy.for_site(agent.site_id)
        state = LapsState.objects.filter(agent=agent).first()
        effective = None
        if policy:
            effective = LapsPolicySerializer(policy).data
            effective["scope"] = "site" if policy.site_id else "global"
        return Response(
            {
                "supported": library_script(agent.plat) is not None,
                "policy": effective,
                "state": LapsStateSerializer(state).data if state else None,
                "can_rotate": bool(_has_perm(request, "can_manage_laps")),
            }
        )


class RotateNow(APIView):
    permission_classes = [IsAuthenticated, LapsPerms]

    def post(self, request, agent_id):
        agent = _agent(request, agent_id)
        if denied := stepup_denied(request, STEPUP):
            return denied
        policy = LapsPolicy.for_site(agent.site_id)
        if not (policy and policy.enabled):
            return notify_error("Local admin rotation is off for this device's site.")
        if not library_script(agent.plat):
            return notify_error(
                "The script library has no rotation script for this platform."
            )
        if not agent.is_online:
            return notify_error("The device is offline.")

        actor = request.user.username
        AuditLog._agent_entry(
            actor,
            agent,
            get_debug_info(),
            action=AuditActionType.EXEC_SCRIPT,
            after_value={"account": policy.account},
            message=f"{actor} rotated the local admin password "
            f"({policy.account}) of {agent.hostname}",
        )
        rotate_agent_task.delay(agent.pk, username=request.user.username, force=True)
        return Response("The password is being rotated.")

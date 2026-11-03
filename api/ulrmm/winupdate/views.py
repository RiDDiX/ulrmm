# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm, _has_perm_on_agent
from ulrmm.utils import get_default_timezone

from .installing import SCAN_CMD, get_installing, mark_installing
from .models import WinUpdate
from .permissions import AgentWinUpdatePerms
from .posix import managed_reason
from .serializers import WinUpdateSerializer
from .tasks import posix_install_updates_task, posix_refresh_task

NO_APPROVED_UPDATES = "There are no approved updates to install"


class GetWindowsUpdates(APIView):
    permission_classes = [IsAuthenticated, AgentWinUpdatePerms]

    def get(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        ctx = dict(default_tz=get_default_timezone())
        ctx["installing_guids"] = get_installing(agent.pk)
        rows = WinUpdate.objects.filter(agent=agent).order_by("-id", "installed")
        return Response(WinUpdateSerializer(rows, many=True, context=ctx).data)


class ScanWindowsUpdates(APIView):
    permission_classes = [IsAuthenticated, AgentWinUpdatePerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if reason := managed_reason(agent):
            return notify_error(reason)
        if agent.is_posix:
            posix_refresh_task.delay(agent.pk, "scan")
            return Response(f"A package update scan was queued on {agent.hostname}")

        agent.delete_superseded_updates()
        asyncio.run(agent.nats_cmd(SCAN_CMD, wait=False))
        return Response(f"Windows update scan queued for {agent.hostname}.")


class InstallWindowsUpdates(APIView):
    permission_classes = [IsAuthenticated, AgentWinUpdatePerms]

    def post(self, request, agent_id):
        if not _has_perm(request, "can_install_patches_now"):
            raise PermissionDenied()

        agent = get_object_or_404(Agent, agent_id=agent_id)
        if reason := managed_reason(agent):
            return notify_error(reason)
        agent.delete_superseded_updates()
        agent.approve_updates()
        guids = agent.get_approved_update_guids()
        # an empty run would still end in the policy's reboot
        if not guids:
            return notify_error(NO_APPROVED_UPDATES)

        if agent.is_posix:
            mark_installing(agent.pk, guids)
            posix_install_updates_task.delay(agent.pk, guids, request.user.username)
            return Response(
                f"Approved package updates will now be installed on {agent.hostname}"
            )

        result = asyncio.run(
            agent.nats_cmd({"func": "installwinupdates", "guids": guids}, wait=False)
        )
        if agent.is_online and result != "natsdown":
            mark_installing(agent.pk, guids)
        return Response(f"Approved patches will now be installed on {agent.hostname}")


class EditWindowsUpdates(APIView):
    permission_classes = [IsAuthenticated, AgentWinUpdatePerms]

    def put(self, request, pk):
        if not _has_perm(request, "can_approve_patches"):
            raise PermissionDenied()

        update = get_object_or_404(WinUpdate.objects.select_related("agent"), pk=pk)
        if not _has_perm_on_agent(request.user, update.agent.agent_id):
            raise PermissionDenied()

        # only the decision is editable, never what the agent reported
        action = request.data.get("action") if hasattr(request.data, "get") else None
        serializer = WinUpdateSerializer(
            instance=update, data={"action": action}, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            f"Windows update {update.kb or update.title} was changed to {update.action}"
        )

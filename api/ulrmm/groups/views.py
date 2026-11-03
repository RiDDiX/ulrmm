# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import AgentPerms
from agents.views import GetAgents
from logs.models import AuditLog
from ulrmm.constants import AuditObjType
from ulrmm.middleware import get_debug_info

from .models import DeviceGroup, Tag
from .permissions import GroupPerms, PreviewGroupPerms
from .rules import clean_rules, rules_q
from .serializers import AgentTagsSerializer, DeviceGroupSerializer, TagSerializer

PREVIEW_HOSTNAMES = 25


class GetAddTags(APIView):
    permission_classes = [IsAuthenticated, GroupPerms]

    def get(self, request):
        return Response(TagSerializer(Tag.objects.all(), many=True).data)

    def post(self, request):
        serializer = TagSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(TagSerializer(serializer.save()).data)


class EditDeleteTag(APIView):
    permission_classes = [IsAuthenticated, GroupPerms]

    def put(self, request, pk):
        tag = get_object_or_404(Tag, pk=pk)
        serializer = TagSerializer(instance=tag, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        return Response(TagSerializer(serializer.save()).data)

    def delete(self, request, pk):
        tag = get_object_or_404(Tag, pk=pk)
        tag.delete()
        return Response(f"{tag.name} was deleted")


class AgentTags(APIView):
    # PUT: can_edit_agent and the agent in scope
    permission_classes = [IsAuthenticated, AgentPerms]

    def put(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        serializer = AgentTagsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        before = sorted(agent.tags.values_list("name", flat=True))
        agent.tags.set(serializer.validated_data["tags"])
        after = sorted(agent.tags.values_list("name", flat=True))
        if before != after:
            ident = {"hostname": agent.hostname, "agent_id": agent.agent_id}
            AuditLog.audit_object_changed(
                request.user.username,
                AuditObjType.AGENT,
                {**ident, "tags": before},
                {**ident, "tags": after},
                agent.hostname,
                debug_info=get_debug_info(),
            )
        return Response(TagSerializer(agent.tags.all(), many=True).data)


class GetAddGroups(APIView):
    permission_classes = [IsAuthenticated, GroupPerms]

    def get(self, request):
        groups = DeviceGroup.objects.all()
        return Response(
            DeviceGroupSerializer(groups, many=True, context={"request": request}).data
        )

    def post(self, request):
        serializer = DeviceGroupSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            DeviceGroupSerializer(serializer.save(), context={"request": request}).data
        )


class GetEditDeleteGroup(APIView):
    permission_classes = [IsAuthenticated, GroupPerms]

    def get(self, request, pk):
        group = get_object_or_404(DeviceGroup, pk=pk)
        return Response(DeviceGroupSerializer(group, context={"request": request}).data)

    def put(self, request, pk):
        group = get_object_or_404(DeviceGroup, pk=pk)
        serializer = DeviceGroupSerializer(
            instance=group,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            DeviceGroupSerializer(serializer.save(), context={"request": request}).data
        )

    def delete(self, request, pk):
        group = get_object_or_404(DeviceGroup, pk=pk)
        group.delete()
        return Response(f"{group.name} was deleted")


class GroupAgents(GetAgents):
    """Agent table for this group. Query params and rows match GetAgents."""

    def get(self, request, pk):
        self.group = get_object_or_404(DeviceGroup, pk=pk)
        return super().get(request)

    def base_queryset(self, request):
        return self.group.agents().filter_by_role(request.user)


class PreviewGroup(APIView):
    permission_classes = [IsAuthenticated, PreviewGroupPerms]

    def post(self, request):
        agents = Agent.objects.filter_by_role(request.user).filter(  # type: ignore
            rules_q(clean_rules(request.data))
        )
        return Response(
            {
                "count": agents.count(),
                "agents": list(
                    agents.order_by("hostname").values_list("hostname", flat=True)[
                        :PREVIEW_HOSTNAMES
                    ]
                ),
            }
        )

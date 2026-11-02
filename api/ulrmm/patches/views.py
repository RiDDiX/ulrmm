# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from zoneinfo import ZoneInfo

from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from clients.models import Client, Site
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
)
from ulrmm.utils import get_default_timezone

from .maintenance import kind_allowed
from .models import MaintenanceSchedule, ScheduleKind
from .recurrence import upcoming
from .serializers import MaintenanceScheduleSerializer

PREVIEW_RUNS = 10


class SchedulePerms(permissions.BasePermission):
    # writes also need the permission of the kind, checked in the views
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_list_agents")


def _in_scope(user, schedule) -> bool:
    # a whole client needs the client, the sites of one are not enough
    return (
        all(
            _has_perm_on_agent(user, i)
            for i in Agent.objects.filter(agent_id__in=schedule.agents).values_list(
                "agent_id", flat=True
            )
        )
        and all(
            _has_perm_on_site(user, pk)
            for pk in Site.objects.filter(pk__in=schedule.sites).values_list(
                "pk", flat=True
            )
        )
        and all(
            _has_perm_on_client(user, pk, manage=True)
            for pk in Client.objects.filter(pk__in=schedule.clients).values_list(
                "pk", flat=True
            )
        )
    )


def _check(request, schedule) -> None:
    if not kind_allowed(request, schedule.kind):
        label = ScheduleKind(schedule.kind).label.lower()
        raise PermissionDenied(f"You cannot manage {label} schedules.")
    if not _in_scope(request.user, schedule):
        raise PermissionDenied("A target of this schedule is outside your scope.")


def _next_runs(schedule, tz, limit: int) -> list[dict]:
    span = dt.timedelta(minutes=schedule.duration)
    now = dt.datetime.now(dt.timezone.utc)
    return [
        {
            "start": s.astimezone(tz).isoformat(),
            "end": (s + span).astimezone(tz).isoformat(),
        }
        for s in upcoming(schedule, tz, now, span, limit)
    ]


class GetAddSchedules(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def get(self, request):
        tz = get_default_timezone()
        ret = []
        for s in MaintenanceSchedule.objects.order_by("name"):
            if _in_scope(request.user, s):
                data = MaintenanceScheduleSerializer(s).data
                data["next_runs"] = _next_runs(s, tz, 1)
                data["timezone"] = str(tz)
                ret.append(data)
        return Response(ret)

    def post(self, request):
        serializer = MaintenanceScheduleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _check(request, MaintenanceSchedule(**serializer.validated_data))
        user = request.user.username
        serializer.save(created_by=user, modified_by=user)
        return Response("ok")


class GetUpdateDeleteSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def get_schedule(self, request, pk) -> MaintenanceSchedule:
        schedule = get_object_or_404(MaintenanceSchedule, pk=pk)
        if not _in_scope(request.user, schedule):
            raise PermissionDenied("A target of this schedule is outside your scope.")
        return schedule

    def get(self, request, pk):
        return Response(
            MaintenanceScheduleSerializer(self.get_schedule(request, pk)).data
        )

    def put(self, request, pk):
        schedule = self.get_schedule(request, pk)
        _check(request, schedule)
        serializer = MaintenanceScheduleSerializer(instance=schedule, data=request.data)
        serializer.is_valid(raise_exception=True)
        _check(request, MaintenanceSchedule(**serializer.validated_data))
        # the schedule runs on behalf of whoever saved it last
        serializer.save(modified_by=request.user.username)
        return Response("ok")

    def delete(self, request, pk):
        schedule = self.get_schedule(request, pk)
        _check(request, schedule)
        schedule.delete()
        return Response("ok")


class PreviewSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    # next runs of the schedule in the form, in the default time zone
    def post(self, request):
        serializer = MaintenanceScheduleSerializer(
            data=request.data, context={"preview": True}
        )
        serializer.is_valid(raise_exception=True)
        schedule = MaintenanceSchedule(**serializer.validated_data)
        tz = get_default_timezone()
        return Response(
            {"timezone": str(tz), "runs": _next_runs(schedule, tz, PREVIEW_RUNS)}
        )


class AgentSchedules(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    # schedules that reach this agent, without their other targets
    def get(self, request, agent_id):
        agent = get_object_or_404(
            Agent.objects.select_related("site"), agent_id=agent_id
        )
        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()

        tz = ZoneInfo(agent.timezone)
        schedules = MaintenanceSchedule.objects.filter(
            Q(agents__contains=[agent.agent_id])
            | Q(sites__contains=[agent.site_id])
            | Q(clients__contains=[agent.site.client_id])
        ).order_by("name")
        ret = []
        for s in schedules:
            last = s.runs.filter(agent=agent).order_by("-occurrence").first()
            ret.append(
                {
                    "id": s.pk,
                    "name": s.name,
                    "kind": s.kind,
                    "enabled": s.enabled,
                    "timezone": str(tz),
                    "next_runs": _next_runs(s, tz, 1) if s.enabled else [],
                    "last_run": last
                    and {
                        "occurrence": last.occurrence,
                        "state": last.state,
                        "detail": last.detail,
                        "changed": last.changed,
                        "woke": last.woke,
                    },
                }
            )
        return Response(ret)

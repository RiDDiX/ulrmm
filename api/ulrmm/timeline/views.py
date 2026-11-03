# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from ulrmm.permissions import _has_perm, _has_perm_on_agent

from .sources import LIST_FLAGS, SOURCES, collect

# next_before is "<iso>~<n>": n items at exactly that time were already shown
MAX_SKIP = 10000


def _params(request, default_limit, max_limit):
    before = request.query_params.get("before")
    skip = 0
    if before:
        before, _, shown = before.partition("~")
        try:
            before = parse_datetime(before)
        except ValueError:
            before = None
        if shown:
            if not (shown.isdecimal() and len(shown) <= 5) or int(shown) > MAX_SKIP:
                before = None
            else:
                skip = int(shown)
        if before is None:
            raise ValidationError("Invalid before")
        if djangotime.is_naive(before):
            before = djangotime.make_aware(before)
    else:
        before = djangotime.now() + djangotime.timedelta(seconds=1)

    try:
        limit = int(request.query_params.get("limit", default_limit))
    except ValueError:
        raise ValidationError("Invalid limit")
    limit = max(1, min(limit, max_limit))

    types = [t for t in request.query_params.get("types", "").split(",") if t]
    unknown = [t for t in types if t not in SOURCES]
    if unknown:
        raise ValidationError(f"Unknown types: {', '.join(unknown)}")
    return before, skip, limit, types


def _feed(request, agents, default_limit, max_limit):
    before, skip, limit, types = _params(request, default_limit, max_limit)
    allowed = {t for t, flag in LIST_FLAGS.items() if _has_perm(request, flag)}
    items = collect(agents, before, limit, types, allowed, LIST_FLAGS, skip)
    cursor = None
    if items:
        last = items[-1]["ts"]
        same = sum(i["ts"] == last for i in items) + (skip if last == before else 0)
        cursor = f"{last.isoformat()}~{same}"
    for i in items:
        i["ts"] = i["ts"].isoformat()
    return Response({"items": items, "next_before": cursor})


class AgentTimeline(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, agent_id):
        if not _has_perm(request, "can_list_agents") or not _has_perm_on_agent(
            request.user, agent_id
        ):
            return Response(status=403)
        agent = get_object_or_404(
            Agent.objects.only("pk", "agent_id"), agent_id=agent_id
        )
        return _feed(request, agent, 100, 500)


class FleetTimeline(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_installer_user or not _has_perm(request, "can_list_agents"):
            return Response(status=403)
        agents = Agent.objects.filter_by_role(request.user)
        return _feed(request, agents, 50, 200)

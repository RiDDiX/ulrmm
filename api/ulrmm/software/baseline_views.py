# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from clients.models import Deployment
from deploy.models import Enrollment
from logs.models import AuditLog
from ulrmm.constants import (
    AGENT_DEFER,
    AuditActionType,
    AuditObjType,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm_on_policy, _has_perm_on_site

from .baselines import baseline_ids, effective_items, forget_cache, summary
from .models import Baseline, BaselineItem, BaselineState, BaselineStatus
from .permissions import AgentBaselinePerms, BaselinePerms, DeploymentBaselinePerms
from .serializers import BaselineSerializer

# a changed rule or source means the item is checked again everywhere
RECHECK_FIELDS = ("source", "ref", "detection")


def _queryset():
    items = Prefetch("items", queryset=BaselineItem.objects.order_by("order", "pk"))
    return Baseline.objects.prefetch_related(items, "policies", "deployments")


def _out_of_scope(user, policies, deployments) -> bool:
    """A scoped role changes a baseline only when it may change every policy
    and owns every deployment it reaches."""
    return any(not _has_perm_on_policy(user, p, manage=True) for p in policies) or any(
        not _has_perm_on_site(user, d.site_id) for d in deployments
    )


def _write_items(baseline, items: list[dict]) -> None:
    existing = {i.pk: i for i in baseline.items.all()}
    keep, recheck = [], []
    for data in items:
        pk = data.pop("id", None)
        item = existing.get(pk)
        if item is None:
            keep.append(BaselineItem.objects.create(baseline=baseline, **data).pk)
            continue
        if any(getattr(item, k) != data[k] for k in RECHECK_FIELDS if k in data):
            recheck.append(item.pk)
        for key, value in data.items():
            setattr(item, key, value)
        item.save()
        keep.append(item.pk)
    baseline.items.exclude(pk__in=keep).delete()
    if recheck:
        BaselineState.objects.filter(item__in=recheck).exclude(
            status=BaselineStatus.INSTALLING
        ).update(
            status=BaselineStatus.PENDING,
            attempts=0,
            detail="",
            updated=djangotime.now(),
        )


def _state_row(state) -> dict:
    return {
        "id": state.pk,
        "item": state.item_id,
        "status": state.status,
        "attempts": state.attempts,
        "detail": state.detail,
        "started_at": state.started_at,
        "verified_at": state.verified_at,
        "detected_version": state.detected_version,
        "updated": state.updated,
    }


class GetAddBaselines(APIView):
    permission_classes = [IsAuthenticated, BaselinePerms]

    def get(self, request):
        baselines = _queryset().order_by("name")
        return Response(BaselineSerializer(baselines, many=True).data)

    def post(self, request):
        serializer = BaselineSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)
        items = data.pop("items", [])
        policies = data.pop("policies", [])
        deployments = data.pop("deployments", [])
        if _out_of_scope(request.user, policies, deployments):
            raise PermissionDenied()
        with transaction.atomic():
            baseline = Baseline(**data)
            baseline.save()
            before = Baseline.serialize(baseline)
            _write_items(baseline, items)
            baseline.policies.set(policies)
            baseline.deployments.set(deployments)
            # the add row has no items yet, this one names them
            baseline.save(old_model=before)
        forget_cache()
        return Response(BaselineSerializer(_queryset().get(pk=baseline.pk)).data, 201)


class BaselineDetail(APIView):
    permission_classes = [IsAuthenticated, BaselinePerms]

    def get(self, request, pk):
        return Response(BaselineSerializer(get_object_or_404(_queryset(), pk=pk)).data)

    def put(self, request, pk):
        baseline = get_object_or_404(_queryset(), pk=pk)
        serializer = BaselineSerializer(
            instance=baseline, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)
        items = data.pop("items", None)
        policies = data.pop("policies", None)
        deployments = data.pop("deployments", None)
        reach_p = [*baseline.policies.all(), *(policies or [])]
        reach_d = [*baseline.deployments.all(), *(deployments or [])]
        if _out_of_scope(request.user, reach_p, reach_d):
            raise PermissionDenied()
        with transaction.atomic():
            before = Baseline.serialize(baseline)
            for key, value in data.items():
                setattr(baseline, key, value)
            if items is not None:
                _write_items(baseline, items)
            if policies is not None:
                baseline.policies.set(policies)
            if deployments is not None:
                baseline.deployments.set(deployments)
            baseline.save(old_model=before)
        forget_cache()
        return Response(BaselineSerializer(_queryset().get(pk=pk)).data)

    def delete(self, request, pk):
        baseline = get_object_or_404(_queryset(), pk=pk)
        if _out_of_scope(
            request.user, baseline.policies.all(), baseline.deployments.all()
        ):
            raise PermissionDenied()
        baseline.delete()
        forget_cache()
        return Response(f"{baseline.name} was deleted")


class BaselineStatusView(APIView):
    """A row per agent the baseline reaches, Policy Status style: agents
    without a state yet come as pending rows."""

    permission_classes = [IsAuthenticated, BaselinePerms]

    def get(self, request, pk):
        baseline = get_object_or_404(Baseline, pk=pk)
        visible = Agent.objects.filter_by_role(request.user)
        states = (
            BaselineState.objects.filter(item__baseline=baseline, agent__in=visible)
            .select_related("agent", "item")
            .defer(*(f"agent__{f}" for f in AGENT_DEFER))
            .order_by("agent__hostname", "item__order", "item__pk")
        )
        rows: dict[int, dict] = {}
        for state in states:
            row = rows.setdefault(
                state.agent_id,
                {
                    "id": state.agent_id,
                    "agent": state.agent_id,
                    "agent_id": state.agent.agent_id,
                    "hostname": state.agent.hostname,
                    "pairs": [],
                    "items": [],
                },
            )
            row["pairs"].append((state.status, state.item.required))
            row["items"].append(_state_row(state))
        for row in rows.values():
            row["status"] = summary(row.pop("pairs"))

        reach = set(
            Enrollment.objects.filter(deployment__baselines=baseline).values_list(
                "agent_id", flat=True
            )
        )
        for policy in baseline.policies.filter(active=True):
            reach |= set(policy.related_agents().values_list("pk", flat=True))
        waiting = (
            visible.filter(pk__in=reach - set(rows), plat=baseline.plat)
            .defer(*AGENT_DEFER)
            .select_related("site__client")
            .order_by("hostname")
        )
        pending = [
            {
                "id": f"agent-{agent.pk}",
                "agent": agent.pk,
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "status": BaselineStatus.PENDING,
                "items": [],
            }
            for agent in waiting
            if baseline.pk in baseline_ids(agent)
        ]
        return Response([*rows.values(), *pending])


def _agent(agent_id: str):
    return get_object_or_404(
        Agent.objects.defer(*AGENT_DEFER).select_related("site__client"),
        agent_id=agent_id,
    )


class AgentBaseline(APIView):
    """The agent's baseline items with their state."""

    permission_classes = [IsAuthenticated, AgentBaselinePerms]

    def get(self, request, agent_id):
        agent = _agent(agent_id)
        states = {s.item_id: s for s in BaselineState.objects.filter(agent=agent)}
        rows = []
        for item in effective_items(agent):
            state = states.get(item.pk)
            row = (
                _state_row(state)
                if state
                else {
                    "id": None,
                    "item": item.pk,
                    "status": BaselineStatus.PENDING,
                    "attempts": 0,
                    "detail": "",
                    "started_at": None,
                    "verified_at": None,
                    "detected_version": "",
                    "updated": None,
                }
            )
            row.update(
                baseline=item.baseline_id,
                baseline_name=item.baseline.name,
                name=item.name or item.ref,
                source=item.source,
                ref=item.ref,
                required=item.required,
            )
            rows.append(row)
        return Response(
            {
                "status": summary([(r["status"], r["required"]) for r in rows]),
                "items": rows,
            }
        )


class RetryAgentBaseline(APIView):
    """Failed items of the agent start over: pending, no attempts."""

    permission_classes = [IsAuthenticated, AgentBaselinePerms]

    def post(self, request, agent_id):
        from .tasks import baseline_agent_task

        agent = _agent(agent_id)
        states = BaselineState.objects.filter(agent=agent, status=BaselineStatus.FAILED)
        item = request.data.get("item") if hasattr(request.data, "get") else None
        if item is not None:
            if isinstance(item, bool) or not isinstance(item, int):
                return notify_error("item must be the id of a baseline item.")
            states = states.filter(item_id=item)
        items = list(states.values_list("item_id", flat=True))
        count = states.update(
            status=BaselineStatus.PENDING,
            attempts=0,
            detail="",
            updated=djangotime.now(),
        )
        if count:
            username = request.user.username
            text = (
                f"{username} retries {count} failed baseline items on {agent.hostname}"
            )
            AuditLog._agent_entry(
                username,
                agent,
                get_debug_info(),
                action=AuditActionType.EXEC_COMMAND,
                after_value={"items": items},
                message=text[:255],
            )
            if agent.is_online:
                baseline_agent_task.delay(agent.pk)
        return Response(f"{count} failed items are tried again on {agent.hostname}")


class DeploymentBaselines(APIView):
    """The baselines an agent installs when it enrolls through the deployment."""

    permission_classes = [IsAuthenticated, DeploymentBaselinePerms]

    def _deployment(self, request, pk):
        deployment = get_object_or_404(
            Deployment.objects.select_related("site__client"), pk=pk
        )
        if not _has_perm_on_site(request.user, deployment.site_id):
            raise PermissionDenied()
        return deployment

    def get(self, request, pk):
        deployment = self._deployment(request, pk)
        ids = sorted(deployment.baselines.values_list("pk", flat=True))
        return Response({"baselines": ids})

    def put(self, request, pk):
        deployment = self._deployment(request, pk)
        ids = request.data.get("baselines") if hasattr(request.data, "get") else None
        if not isinstance(ids, list) or not all(
            isinstance(i, int) and not isinstance(i, bool) for i in ids
        ):
            return Response({"baselines": "Give a list of baseline ids."}, status=400)
        found = set(Baseline.objects.filter(pk__in=ids).values_list("pk", flat=True))
        if missing := sorted(set(ids) - found):
            return Response(
                {"baselines": f"No baseline has the id {missing[0]}."}, status=400
            )
        before = sorted(deployment.baselines.values_list("pk", flat=True))
        deployment.baselines.set(found)
        username = request.user.username
        # the uid is the public link, never write it into the audit log
        name = deployment.name or f"#{deployment.pk}"
        AuditLog.objects.create(
            username=username,
            object_type=AuditObjType.SITE,
            action=AuditActionType.MODIFY,
            message=f"{username} set the software baselines of deployment {name} "
            f"for site {deployment.site.name}"[:255],
            before_value={"baselines": before},
            after_value={"baselines": sorted(found)},
            debug_info=get_debug_info(),
        )
        return Response({"baselines": sorted(found)})

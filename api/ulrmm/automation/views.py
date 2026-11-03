# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from typing import Any, NamedTuple, Optional

from django.db import transaction
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from autotasks.models import AutomatedTask, TaskResult
from checks.models import Check, CheckResult
from clients.models import Client, Site
from ulrmm.constants import AGENT_DEFER
from ulrmm.helpers import notify_error
from ulrmm.permissions import (
    _assigned_in_scope,
    _has_perm,
    _has_perm_on_client,
    _has_perm_on_site,
    _is_super,
    _restrictions,
    _role,
    _scope_q,
)
from winupdate.models import WinUpdatePolicy
from winupdate.serializers import WinUpdatePolicySerializer

from .models import Policy
from .permissions import AutomationPolicyPerms, PatchPolicyPerms
from .serializers import (
    EXCLUSIONS,
    PolicyCheckStatusSerializer,
    PolicyOverviewSerializer,
    PolicyRelatedSerializer,
    PolicySerializer,
    PolicyTableSerializer,
    PolicyTaskStatusSerializer,
)

INHERIT_FIELDS = ("critical", "important", "moderate", "low", "other", "drivers")
INHERIT_FIELDS += ("run_time_frequency", "reboot_after_install")


# A client/site-scoped role reaches a policy through the agents it applies to.
# Reading needs one of them in scope, or none at all and every assignment in
# scope (a policy nobody uses yet, so the role can build one before assigning
# it). Changing, deleting, copying or running needs every agent and every
# assignment in scope.


class Scope(NamedTuple):
    agents: Q
    clients: Any
    sites: Any


def _scope(user) -> Optional[Scope]:
    """What the role may see, None for an unrestricted user."""
    role = _role(user)
    if _is_super(user, role) or not role:
        return None
    clients, sites, restricted = _restrictions(role)
    return Scope(_scope_q(clients, sites), clients, sites) if restricted else None


def _readable(policy: Policy, scope: Optional[Scope]) -> bool:
    if scope is None:
        return True
    reach = policy.related_agents()
    if reach.filter(scope.agents).exists():
        return True
    return not reach.exists() and _assigned_in_scope(policy, scope.clients, scope.sites)


def _require_readable(policy: Policy, scope: Optional[Scope]) -> None:
    if not _readable(policy, scope):
        raise PermissionDenied()


def _require_writable(policy: Optional[Policy], scope: Optional[Scope]) -> None:
    if scope is None or policy is None:
        return
    if policy.related_agents().exclude(scope.agents).exists():
        raise PermissionDenied()
    if not _assigned_in_scope(policy, scope.clients, scope.sites):
        raise PermissionDenied()


def _visible(user, scope: Optional[Scope]) -> Optional[dict[str, set]]:
    """pks a scoped role may see in the excluded_* lists."""
    if scope is None:
        return None
    return {
        "excluded_agents": set(
            Agent.objects.filter(scope.agents).values_list("pk", flat=True)
        ),
        "excluded_sites": set(
            Site.objects.filter_by_role(user).values_list("pk", flat=True)
        ),
        "excluded_clients": set(
            Client.objects.filter_by_role(user).values_list("pk", flat=True)
        ),
    }


def _save_scoped(serializer, visible, policy: Optional[Policy] = None) -> Policy:
    """A scoped role names only exclusions it can see; the ones it cannot see
    stay on the policy, since the web sends back the list it was shown. The
    check runs on the objects the serializer resolved, so every pk spelling
    it accepts is checked."""
    if visible is not None:
        for field in EXCLUSIONS:
            submitted = serializer.initial_data.get(field, [])
            if not isinstance(submitted, list):
                # DRF iterates any iterable here, a dict would pass as its keys
                raise ValidationError({field: ["Expected a list of pks."]})
    serializer.is_valid(raise_exception=True)
    if visible is not None:
        chosen = serializer.validated_data
        for field in EXCLUSIONS:
            if field not in chosen:
                continue
            if {obj.pk for obj in chosen[field]} - visible[field]:
                raise PermissionDenied()
            if policy is not None:
                hidden = getattr(policy, field).exclude(pk__in=visible[field])
                chosen[field] = [*chosen[field], *hidden]
    return serializer.save()


def _pk(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


def _body(request) -> dict:
    data = request.data
    if not isinstance(data, dict):
        raise ValidationError("Expected a JSON object.")
    if hasattr(data, "getlist"):
        # form bodies carry repeated keys; flatten so the exclusion checks see lists
        return {
            k: data.getlist(k) if k in EXCLUSIONS else data.get(k) for k in data.keys()
        }
    return data.copy()


def _context(request, scope) -> dict:
    return {
        "user": request.user,
        "scope": scope.agents if scope is not None else None,
        "visible": _visible(request.user, scope),
    }


class GetAddPolicies(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request):
        scope = _scope(request.user)
        policies = (
            Policy.objects.select_related("alert_template")
            .prefetch_related("excluded_sites", "excluded_clients", "excluded_agents")
            .prefetch_related("winupdatepolicy")
            .order_by("pk")
        )
        context = _context(request, scope)
        if scope is not None:
            # one reach evaluation per policy serves the filter and the count
            counts = {}
            for p in policies:
                reach = p.related_agents()
                n = reach.filter(scope.agents).count()
                # same rule as _readable
                if n or (
                    not reach.exists()
                    and _assigned_in_scope(p, scope.clients, scope.sites)
                ):
                    counts[p.pk] = n
            policies = [p for p in policies if p.pk in counts]
            context["agents_count"] = counts
        return Response(
            PolicyTableSerializer(policies, many=True, context=context).data
        )

    def post(self, request):
        data = _body(request)
        scope = _scope(request.user)

        source = None
        if data.get("copyId") is not None:
            copy_id = _pk(data["copyId"])
            if copy_id is None:
                return notify_error("copyId must be a policy id")
            source = get_object_or_404(Policy, pk=copy_id)
            # copying hands over the checks and tasks of the source
            _require_writable(source, scope)

        serializer = PolicySerializer(data=data)
        with transaction.atomic():
            policy = _save_scoped(serializer, _visible(request.user, scope))
            if source:
                # pk order: the copies and their audit entries follow the source
                for check in source.policychecks.order_by("pk"):
                    check.create_policy_check(policy=policy)
                # tasks of a check came along with it
                for task in source.autotasks.filter(
                    assigned_check__isnull=True
                ).order_by("pk"):
                    task.create_policy_task(policy)

        return Response("ok")


class GetUpdateDeletePolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request, pk):
        scope = _scope(request.user)
        policy = get_object_or_404(Policy, pk=pk)
        _require_readable(policy, scope)
        return Response(PolicySerializer(policy, context=_context(request, scope)).data)

    def put(self, request, pk):
        policy = self.get_policy(request, pk)
        scope = _scope(request.user)
        _require_writable(policy, scope)

        data = _body(request)
        serializer = PolicySerializer(instance=policy, data=data, partial=True)
        _save_scoped(serializer, _visible(request.user, scope), policy)

        # Policy.save sees active/enforced; exclusions land after it
        if any(key in data for key in (*EXCLUSIONS, "alert_template")):
            Policy.forget_cached_policies()

        return Response("ok")

    def delete(self, request, pk):
        policy = self.get_policy(request, pk)
        _require_writable(policy, _scope(request.user))
        policy.delete()

        return Response("ok")

    @staticmethod
    def get_policy(request, pk) -> Policy:
        policy = get_object_or_404(Policy, pk=pk)
        # activating, excluding from or deleting it swaps the patch policy of
        # every agent it applies to
        if policy.winupdatepolicy.exists() and not _has_perm(
            request, "can_manage_patch_policies"
        ):
            raise PermissionDenied("You cannot change patch policies.")
        return policy


class GetRelated(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request, pk):
        policy = get_object_or_404(Policy, pk=pk)
        _require_readable(policy, _scope(request.user))
        related = PolicyRelatedSerializer(policy, context={"user": request.user})
        return Response(related.data)


class OverviewPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request):
        user = request.user
        sites = Site.objects.filter_by_role(user).select_related(
            "workstation_policy", "server_policy"
        )
        clients = (
            Client.objects.filter_by_role(user)
            .select_related("workstation_policy", "server_policy")
            .prefetch_related(
                Prefetch("sites", queryset=sites, to_attr="filtered_sites")
            )
        )
        context = {"visible": _visible(user, _scope(user))}
        return Response(
            PolicyOverviewSerializer(clients, many=True, context=context).data
        )


def _not_run_rows(request, item, results, own) -> list[dict]:
    """A row per agent the policy check or task applies to that has no result
    yet, so the dialog lists them before their first run. own(agent) is the
    agent's policy checks or tasks: the same answer as its own list."""
    if item is None:
        return []
    have = {r.agent_id for r in results}
    agents = (
        item.policy.related_agents()
        .filter_by_role(request.user)
        .defer(*AGENT_DEFER)
        .select_related("site__client")
        .exclude(pk__in=have)
        .order_by("hostname")
    )
    # one policy lookup per agent, cached per agent like its own check list
    return [
        {
            "id": f"agent-{agent.pk}",
            "agent": agent.pk,
            "hostname": agent.hostname,
            "status": "pending",
            "last_run": None,
        }
        for agent in agents
        if any(i.pk == item.pk for i in own(agent))
    ]


class PolicyCheck(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request, check):
        # a scoped role sees the results of its own agents only
        results = (
            CheckResult.objects.filter_by_role(request.user)
            .filter(assigned_check=check, assigned_check__policy__isnull=False)
            .select_related("agent", "assigned_check")
            .order_by("pk")
        )
        item = (
            Check.objects.select_related("policy")
            .filter(pk=check, policy__isnull=False)
            .first()
        )
        rows = _not_run_rows(
            request, item, results, lambda a: a.get_checks_from_policies()
        )
        if item is not None:
            for row in rows:
                row.update(
                    check_type=item.check_type,
                    readable_desc=item.readable_desc,
                    history_info=None,
                    more_info="",
                )
        return Response(PolicyCheckStatusSerializer(results, many=True).data + rows)


class PolicyAutoTask(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    def get(self, request, task):
        # a scoped role sees the results of its own agents only
        results = (
            TaskResult.objects.filter_by_role(request.user)
            .filter(task=task, task__policy__isnull=False)
            .select_related("agent")
            .order_by("pk")
        )
        item = (
            AutomatedTask.objects.select_related("policy")
            .filter(pk=task, policy__isnull=False)
            .first()
        )
        rows = _not_run_rows(
            request, item, results, lambda a: a.get_tasks_from_policies()
        )
        return Response(PolicyTaskStatusSerializer(results, many=True).data + rows)

    def post(self, request, task):
        from .tasks import run_win_policy_autotasks_task

        # the same flag that runs a task on a single agent
        if not _has_perm(request, "can_run_autotasks"):
            raise PermissionDenied()
        policy_task = get_object_or_404(
            AutomatedTask.objects.select_related("policy"),
            pk=task,
            policy__isnull=False,
        )
        # the run reaches every agent of the policy
        _require_writable(policy_task.policy, _scope(request.user))

        run_win_policy_autotasks_task.delay(task=policy_task.pk)
        return Response("Affected agent tasks will run shortly")


def _policy_row_or_404(pk) -> WinUpdatePolicy:
    # agent rows are edited on the agent, where the site scope is checked
    return get_object_or_404(
        WinUpdatePolicy.objects.select_related("policy"),
        pk=pk,
        agent__isnull=True,
        policy__isnull=False,
    )


class UpdatePatchPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms, PatchPolicyPerms]

    def post(self, request):
        data = _body(request)
        if data.get("policy") is None:
            return notify_error("policy is required")
        policy_pk = _pk(data["policy"])
        if policy_pk is None:
            return notify_error("policy must be a policy id")
        policy = get_object_or_404(Policy, pk=policy_pk)
        _require_writable(policy, _scope(request.user))

        serializer = WinUpdatePolicySerializer(data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            # the policy row lock keeps two posts from adding a second row
            Policy.objects.select_for_update().filter(pk=policy.pk).first()
            if WinUpdatePolicy.objects.filter(policy=policy).exists():
                return notify_error("This policy already has a patch policy.")
            serializer.save(policy=policy)

        return Response("ok")

    def put(self, request, pk):
        row = _policy_row_or_404(pk)
        _require_writable(row.policy, _scope(request.user))

        serializer = WinUpdatePolicySerializer(
            instance=row, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    def delete(self, request, pk):
        row = _policy_row_or_404(pk)
        _require_writable(row.policy, _scope(request.user))
        row.delete()

        return Response("ok")


class ResetPatchPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms, PatchPolicyPerms]

    def post(self, request):
        data = _body(request)
        agents = Agent.objects.filter_by_role(request.user)

        for key in ("client", "site"):
            if key not in data:
                continue
            pk = _pk(data[key])
            if pk is None:
                return notify_error(f"{key} must be a {key} id")
            if key == "client":
                if not _has_perm_on_client(request.user, pk):
                    raise PermissionDenied()
                agents = agents.filter(site__client_id=pk)
            else:
                if not _has_perm_on_site(request.user, pk):
                    raise PermissionDenied()
                agents = agents.filter(site_id=pk)
            break

        with transaction.atomic():
            for agent in agents.only("pk"):
                row = agent.winupdatepolicy.order_by("pk").first()
                if row is None:
                    row = WinUpdatePolicy(agent=agent)
                for field in INHERIT_FIELDS:
                    setattr(row, field, "inherit")
                row.reprocess_failed_inherit = True
                if row.pk:
                    row.save(
                        update_fields=[*INHERIT_FIELDS, "reprocess_failed_inherit"]
                    )
                else:
                    row.save()

        return Response("The patch policy on the affected agents has been reset.")

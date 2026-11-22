# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import AGENT_POLICY_PATHS, Agent
from automation.models import Policy
from automation.views import _readable, _require_writable, _scope
from ulrmm.constants import AGENT_DEFER, TaskSyncStatus, TaskType
from ulrmm.helpers import agent_ver, notify_error
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_item,
    _has_perm_on_policy,
    _may_manage_policy_pk,
    agent_perm_check,
)

from .models import AutomatedTask
from .permissions import AutoTaskPerms, RunAutoTaskPerms
from .serializers import TaskSerializer

ONBOARDING_MIN_AGENT = "2.6.0"
# the task table needs the agent's alert template, not its inventory
AGENT_DETAIL_DEFER = tuple(f"agent__{field}" for field in AGENT_DEFER)


def _context(request) -> dict:
    return {"reveal_env_vars": _has_perm(request, "can_manage_autotasks")}


def _tasks():
    return AutomatedTask.objects.select_related(
        "agent__alert_template", "assigned_check"
    ).defer(*AGENT_DETAIL_DEFER)


def _task_or_404(pk: int) -> AutomatedTask:
    return get_object_or_404(
        _tasks()
        .select_related("policy")
        .prefetch_related(
            Prefetch("additional_agents", queryset=Agent.objects.only("pk")),
            Prefetch("additional_policies", queryset=Policy.objects.only("pk")),
        ),
        pk=pk,
    )


def _body(request) -> dict:
    if not isinstance(request.data, dict):
        raise ValidationError("Expected a JSON object.")
    return request.data.copy()


def _require_agent_scope(request, agent) -> None:
    if agent and not _has_perm_on_agent(request.user, agent.agent_id):
        raise PermissionDenied()


def _has_policy_placement(policy: Policy) -> bool:
    return any(
        getattr(policy, name).exists()
        for name in (
            "workstation_sites",
            "server_sites",
            "workstation_clients",
            "server_clients",
            "agents",
            "default_server_policy",
            "default_workstation_policy",
        )
    )


def _require_item_scope(request, task: AutomatedTask, *, manage: bool = False) -> None:
    scope = _scope(request.user)
    if (
        manage
        and not _has_perm(request, "can_manage_automation_policies")
        and task.additional_policies.exists()
    ):
        raise PermissionDenied()
    if task.policy_id:
        if scope is not None and not _has_policy_placement(task.policy):
            raise PermissionDenied()
        if manage:
            # the policy check rule (every agent it reaches is in scope), or
            # the policy page rule, which also covers the role's own empty site
            if not _has_perm_on_policy(request.user, task.policy, manage=True):
                _require_writable(task.policy, scope)
        elif not _readable(task.policy, scope):
            raise PermissionDenied()
    elif task.agent_id and not _has_perm_on_item(request.user, task, manage=manage):
        raise PermissionDenied()
    elif (
        not task.agent_id
        and scope is not None
        and not (
            task.additional_agents.filter(scope.agents).exists()
            or any(
                _has_policy_placement(policy) and _readable(policy, scope)
                for policy in task.additional_policies.all()
            )
        )
    ):
        raise PermissionDenied()
    if manage:
        if scope is not None:
            if task.additional_agents.exclude(scope.agents).exists():
                raise PermissionDenied()
            for policy in task.additional_policies.all():
                _require_writable(policy, scope)


def _action_keys(actions, kind: str) -> set:
    if not isinstance(actions, list):
        return set()
    if kind == "script":
        return {
            str(a.get("script"))
            for a in actions
            if isinstance(a, dict) and a.get("type") == "script"
        }
    return {
        (str(a.get("command")), str(a.get("shell")))
        for a in actions
        if isinstance(a, dict) and a.get("type") == "cmd"
    }


def _require_action_perms(request, actions, current=None) -> None:
    # a task runs its actions on the endpoint as SYSTEM/root: adding one is
    # running it, so it needs the same permission as running it by hand
    if _action_keys(actions, "script") - _action_keys(
        current, "script"
    ) and not _has_perm(request, "can_run_scripts"):
        raise PermissionDenied(
            "Adding a script action needs the run scripts permission."
        )
    if _action_keys(actions, "cmd") - _action_keys(current, "cmd") and not _has_perm(
        request, "can_send_cmd"
    ):
        raise PermissionDenied(
            "Adding a command action needs the send command permission."
        )


TASK_CREATED = "The task has been created. It will show up on the agent on next checkin"


class GetAddAutoTasks(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    def get(self, request, agent_id=None, policy=None):
        if agent_id:
            owner = get_object_or_404(
                Agent.objects.select_related("alert_template").defer(*AGENT_DEFER),
                agent_id=agent_id,
            )
            tasks = owner.get_tasks_with_policies()
        elif policy:
            policy = get_object_or_404(Policy, id=policy)
            if not _has_perm_on_policy(request.user, policy):
                # A scoped role can prepare a policy already assigned to its
                # own empty site or client. Completely unassigned policies
                # keep the task list's existing visibility rule.
                if not _readable(
                    policy, _scope(request.user)
                ) or not _has_policy_placement(policy):
                    raise PermissionDenied()
            tasks = (
                _tasks()
                .filter(
                    Q(policy=policy, owner_assigned=True)
                    | Q(additional_policies=policy)
                )
                .distinct()
                .order_by("pk")
            )
        else:
            tasks = _tasks().filter_by_role(request.user)

        context = _context(request)
        if agent_id:
            context["agent"] = owner
        if context["reveal_env_vars"]:
            rows = []
            for task in tasks:
                try:
                    _require_item_scope(request, task, manage=True)
                except PermissionDenied:
                    task_context = {**context, "reveal_env_vars": False}
                else:
                    task_context = context
                rows.append(TaskSerializer(task, context=task_context).data)
            return Response(rows)
        return Response(TaskSerializer(tasks, many=True, context=context).data)

    def post(self, request, agent_id=None, policy=None):
        data = _body(request)
        # the agent and policy aliases decide the owner themselves
        if agent_id:
            data["agent"] = agent_id
            data.pop("policy", None)
        elif policy:
            data["policy"] = policy
            data.pop("agent", None)

        if data.get("agent"):
            agent = get_object_or_404(Agent, agent_id=data["agent"])
            _require_agent_scope(request, agent)
            if data.get("task_type") == TaskType.ONBOARDING and agent_ver(
                agent.version
            ) < agent_ver(ONBOARDING_MIN_AGENT):
                return notify_error(
                    f"Onboarding tasks require agent >= {ONBOARDING_MIN_AGENT}"
                )
            data["agent"] = agent.pk
        elif not _may_manage_policy_pk(request.user, data.get("policy")):
            raise PermissionDenied()

        _require_action_perms(request, data.get("actions"))

        serializer = TaskSerializer(data=data, context=_context(request))
        serializer.is_valid(raise_exception=True)
        task = serializer.save()

        # policy tasks reach their agents through the sync job
        if task.agent_id:
            from .tasks import create_win_task_schedule

            create_win_task_schedule.delay(pk=task.pk)

        return Response(TASK_CREATED)


class GetEditDeleteAutoTask(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    def get(self, request, pk):
        task = _task_or_404(pk)
        _require_assignment_read(request, task)
        context = _context(request)
        try:
            _require_item_scope(request, task, manage=True)
        except PermissionDenied:
            context = {"reveal_env_vars": False}
        return Response(TaskSerializer(task, context=context).data)

    @transaction.atomic
    def put(self, request, pk):
        task = get_object_or_404(AutomatedTask.objects.select_for_update(), pk=pk)
        _require_item_scope(request, task, manage=True)

        data = _body(request)
        if "actions" in data:
            _require_action_perms(request, data["actions"], current=task.actions)

        serializer = TaskSerializer(
            instance=task, data=data, partial=True, context=_context(request)
        )
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get("assigned_check") and (
            task.additional_agents.exists() or task.additional_policies.exists()
        ):
            raise ValidationError(
                "A check-triggered task belongs to its check's scope."
            )
        # the endpoint copy follows through the sync job once save() marks it
        serializer.save()
        return Response("The task was updated")

    @transaction.atomic
    def delete(self, request, pk):
        task = get_object_or_404(AutomatedTask.objects.select_for_update(), pk=pk)
        _require_item_scope(request, task, manage=True)

        from .tasks import delete_win_task_schedule, remove_orphaned_win_tasks

        if (
            not task.agent_id
            or not task.owner_assigned
            or task.agent.is_posix
            or task.additional_agents.exists()
            or task.additional_policies.exists()
        ):
            # copies on the endpoints are swept up by the orphan cleanup
            task.delete()
            transaction.on_commit(remove_orphaned_win_tasks.delay)
            return Response(f"{task.name} was deleted")

        result = task._result_on(task.agent)
        task._set_sync(result, TaskSyncStatus.PENDING_DELETION)
        task.owner_assigned = False
        task.save(update_fields=["owner_assigned"])
        transaction.on_commit(lambda: delete_win_task_schedule.delay(pk=task.pk))
        return Response(f"{task.name} will be deleted shortly")


class RunAutoTask(APIView):
    permission_classes = [IsAuthenticated, RunAutoTaskPerms]

    def post(self, request, pk):
        task = _task_or_404(pk)
        agent_id = (
            request.data.get("agent_id") if isinstance(request.data, dict) else None
        )
        private = (
            task.agent_id
            and task.owner_assigned
            and not task.additional_agents.exists()
            and not task.additional_policies.exists()
        )
        if private or (not agent_id and task.agent_id and task.owner_assigned):
            _require_item_scope(request, task)
            agent_id = None
        elif agent_id:
            if not _has_perm_on_agent(request.user, agent_id):
                raise PermissionDenied()
            agent = get_object_or_404(Agent, agent_id=agent_id)
            if not task.applies_to(agent):
                _require_item_scope(request, task)
                return notify_error(f"{task.name} does not apply to {agent.hostname}")
        else:
            _require_item_scope(request, task)
            label = "policy task" if task.policy_id else "task"
            return notify_error(f"Choose the agent to run this {label} on")
        if not task.enabled:
            return notify_error(f"{task.name} is disabled")

        from .tasks import run_win_task

        if agent_id is None:
            run_win_task.delay(pk=task.pk)
        else:
            run_win_task.delay(pk=task.pk, agent_id=agent_id)

        return Response(f"{task.name} will now be run.")


class TaskCatalog(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    def get(self, request):
        tasks = AutomatedTask.objects.order_by("name", "pk")
        scope = _scope(request.user)
        if scope is not None:
            agents = Agent.objects.filter(scope.agents).values("pk")
            policies = (
                Policy.objects.filter(
                    Q(autotasks__isnull=False) | Q(additional_autotasks__isnull=False)
                )
                .only("pk")
                .distinct()
            )
            readable = [
                policy.pk
                for policy in policies
                if _readable(policy, scope) and _has_policy_placement(policy)
            ]
            linked = AutomatedTask.objects.filter(
                Q(additional_agents__in=agents) | Q(additional_policies__in=readable)
            ).values("pk")
            tasks = tasks.filter(
                Q(agent_id__in=agents, policy__isnull=True)
                | Q(policy_id__in=readable)
                | Q(pk__in=linked)
            )
        return Response(
            [
                {
                    "id": task.pk,
                    "name": task.name,
                    "enabled": task.enabled,
                    "schedule": task.schedule,
                }
                for task in tasks
            ]
        )


def _policy_editable(request, policy, scope) -> bool:
    if not _has_perm(request, "can_manage_automation_policies"):
        return False
    try:
        _require_writable(policy, scope)
    except PermissionDenied:
        return False
    return True


def _require_assignment_read(request, task):
    try:
        _require_item_scope(request, task)
    except PermissionDenied:
        scope = _scope(request.user)
        if scope is None:
            raise
        if not (
            task.additional_agents.filter(scope.agents).exists()
            or any(
                _has_policy_placement(policy) and _readable(policy, scope)
                for policy in task.additional_policies.all()
            )
        ):
            raise


class TaskAssignments(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    @staticmethod
    def _representation(request, task):
        scope = _scope(request.user)
        can_manage = _has_perm(request, "can_manage_autotasks")
        can_add = can_manage
        try:
            _require_item_scope(request, task, manage=True)
        except PermissionDenied:
            can_add = False
        published = {p.pk for p in task.additional_policies.all()}
        if task.owner_assigned and task.policy_id:
            published.add(task.policy_id)
        policies = [
            {
                "id": p.pk,
                "name": p.name,
                "assigned": p.pk in published,
                "editable": can_manage
                and (p.pk in published or can_add)
                and (not task.assigned_check_id or p.pk == task.policy_id)
                and _policy_editable(request, p, scope),
            }
            for p in Policy.objects.order_by("name", "pk")
            if _readable(p, scope)
        ]
        visible_policy_ids = {policy["id"] for policy in policies}
        agents = (
            Agent.objects.filter_by_role(request.user)
            .select_related(*AGENT_POLICY_PATHS)
            .defer(*AGENT_DEFER)
            .order_by("hostname", "pk")
        )
        devices = []
        for agent in agents:
            direct = (task.owner_assigned and task.agent_id == agent.pk) or (
                task.additional_agents.contains(agent)
            )
            member_policies = (
                Policy._active_policies(agent)
                if agent.plat in task.task_supported_platforms
                else []
            )
            sources = task.assignment_sources(agent, policies=member_policies)
            devices.append(
                {
                    "id": agent.pk,
                    "agent_id": agent.agent_id,
                    "hostname": agent.hostname,
                    "timezone": agent.timezone,
                    "schedule": task.schedule_for(agent),
                    "direct": direct,
                    "direct_effective": sources["direct"],
                    "effective": any(sources.values()),
                    "policy_ids": [p["id"] for p in sources["policies"]],
                    "member_policy_ids": [
                        p.pk for p in member_policies if p.pk in visible_policy_ids
                    ],
                    "editable": can_manage
                    and (not task.assigned_check_id or agent.pk == task.agent_id)
                    and (
                        direct
                        or (
                            can_add
                            and (
                                agent.pk == task.agent_id
                                or agent.plat in task.task_supported_platforms
                            )
                        )
                    ),
                }
            )
        return {
            "devices": devices,
            "policies": policies,
            "schedule": task.schedule,
            "can_delete_definition": can_add,
        }

    def get(self, request, pk):
        task = _task_or_404(pk)
        _require_assignment_read(request, task)
        return Response(self._representation(request, task))

    def patch(self, request, pk):
        self._change(request, pk)
        # listed after the commit, the row locks are not held while it renders
        return Response(self._representation(request, _task_or_404(pk)))

    @transaction.atomic
    def _change(self, request, pk) -> None:
        task = get_object_or_404(AutomatedTask.objects.select_for_update(), pk=pk)
        _require_assignment_read(request, task)
        data = _body(request)
        changes = {}
        for kind in ("agents", "policies"):
            for action in ("add", "remove"):
                key = f"{action}_{kind}"
                values = data.pop(key, [])
                if not isinstance(values, list) or any(
                    type(value) is not int or not 0 < value <= 2**63 - 1
                    for value in values
                ):
                    raise ValidationError(
                        {key: "Expected a list of positive integer IDs."}
                    )
                changes[key] = set(values)
            if changes[f"add_{kind}"] & changes[f"remove_{kind}"]:
                raise ValidationError(f"Cannot add and remove the same {kind}.")
        if data:
            raise ValidationError("Unknown assignment fields.")
        if changes["add_agents"] or changes["add_policies"]:
            _require_item_scope(request, task, manage=True)
            if task.taskresults.filter(
                sync_status=TaskSyncStatus.PENDING_DELETION
            ).exists():
                raise ValidationError("The task is being deleted.")
            additions = len(changes["add_agents"]) + len(changes["add_policies"])
            if additions > 1 and not _has_perm(request, "can_run_bulk"):
                raise PermissionDenied()
            _require_action_perms(request, task.actions)
            if task.assigned_check_id and (
                changes["add_agents"] - {task.agent_id}
                or changes["add_policies"] - {task.policy_id}
            ):
                raise ValidationError(
                    "A check-triggered task belongs to its check's scope."
                )

        agent_ids = changes["add_agents"] | changes["remove_agents"]
        agents = (
            Agent.objects.select_for_update(of=("self",))
            .filter(pk__in=agent_ids)
            .defer(*AGENT_DEFER)
            .select_related("site")
            .order_by("pk")
        )
        can_reach_agent = agent_perm_check(request.user)
        if {agent.pk for agent in agents} != agent_ids:
            raise PermissionDenied()
        for agent in agents:
            if not can_reach_agent(agent):
                raise PermissionDenied()
            if (
                agent.pk in changes["add_agents"]
                and agent.pk != task.agent_id
                and agent.plat not in task.task_supported_platforms
            ):
                raise ValidationError("A device platform is unsupported by this task.")
        policy_ids = changes["add_policies"] | changes["remove_policies"]
        policies = (
            Policy.objects.select_for_update().filter(pk__in=policy_ids).order_by("pk")
        )
        scope = _scope(request.user)
        if {policy.pk for policy in policies} != policy_ids or any(
            not _policy_editable(request, policy, scope) for policy in policies
        ):
            raise PermissionDenied()

        for kind, owner in (("agents", task.agent_id), ("policies", task.policy_id)):
            add = changes[f"add_{kind}"]
            remove = changes[f"remove_{kind}"]
            if owner in add | remove:
                task.owner_assigned = owner in add
                task.save(update_fields=["owner_assigned"])
            relation = getattr(task, f"additional_{kind}")
            relation.add(*(add - {owner}))
            relation.remove(*remove)

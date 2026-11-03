# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from automation.models import Policy
from ulrmm.constants import AGENT_DEFER, TaskType
from ulrmm.helpers import agent_ver, notify_error
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_item,
    _has_perm_on_policy,
    _may_manage_policy_pk,
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
    return get_object_or_404(_tasks().select_related("policy"), pk=pk)


def _body(request) -> dict:
    if not isinstance(request.data, dict):
        raise ValidationError("Expected a JSON object.")
    return request.data.copy()


def _require_agent_scope(request, agent) -> None:
    if agent and not _has_perm_on_agent(request.user, agent.agent_id):
        raise PermissionDenied()


def _require_item_scope(request, task: AutomatedTask, *, manage: bool = False) -> None:
    if not _has_perm_on_item(request.user, task, manage=manage):
        raise PermissionDenied()


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
                raise PermissionDenied()
            tasks = _tasks().filter(policy=policy).order_by("pk")
        else:
            tasks = _tasks().filter_by_role(request.user)

        return Response(
            TaskSerializer(tasks, many=True, context=_context(request)).data
        )

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
        _require_item_scope(request, task)
        return Response(TaskSerializer(task, context=_context(request)).data)

    def put(self, request, pk):
        task = _task_or_404(pk)
        _require_item_scope(request, task, manage=True)

        data = _body(request)
        if "actions" in data:
            _require_action_perms(request, data["actions"], current=task.actions)

        serializer = TaskSerializer(
            instance=task, data=data, partial=True, context=_context(request)
        )
        serializer.is_valid(raise_exception=True)
        # the endpoint copy follows through the sync job once save() marks it
        serializer.save()
        return Response("The task was updated")

    def delete(self, request, pk):
        task = _task_or_404(pk)
        _require_item_scope(request, task, manage=True)

        from .tasks import delete_win_task_schedule, remove_orphaned_win_tasks

        reply = f"{task.name} will be deleted shortly"
        if not task.agent_id:
            # copies on the endpoints are swept up by the orphan cleanup
            task.delete()
            remove_orphaned_win_tasks.delay()
        else:
            delete_win_task_schedule.delay(pk=task.pk)
        return Response(reply)


class RunAutoTask(APIView):
    permission_classes = [IsAuthenticated, RunAutoTaskPerms]

    def post(self, request, pk):
        task = _task_or_404(pk)
        _require_item_scope(request, task)

        if not task.enabled:
            return notify_error(f"{task.name} is disabled")

        from .tasks import run_win_task

        agent_id = (
            request.data.get("agent_id") if isinstance(request.data, dict) else None
        )
        if task.agent_id:
            run_win_task.delay(pk=task.pk)
        elif not task.policy_id:
            return notify_error(f"{task.name} has no agent to run on")
        elif not agent_id:
            return notify_error("Choose the agent to run this policy task on")
        else:
            if not _has_perm_on_agent(request.user, agent_id):
                raise PermissionDenied()
            agent = get_object_or_404(Agent, agent_id=agent_id)
            if task.pk not in {t.pk for t in agent.get_tasks_with_policies()}:
                return notify_error(f"{task.name} does not apply to {agent.hostname}")
            run_win_task.delay(pk=task.pk, agent_id=agent_id)

        return Response(f"{task.name} will now be run.")

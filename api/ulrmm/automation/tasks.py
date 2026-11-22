# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from automation.models import Policy
from autotasks.models import AutomatedTask
from ulrmm.celery import app


@app.task
def run_win_policy_autotasks_task(
    task: int, policy_id: int | None = None, agent_pks: list[int] | None = None
) -> str:
    policy_task = AutomatedTask.objects.select_related("policy").filter(pk=task).first()
    if policy_task is None:
        return "AutomatedTask not found"
    selected = policy_id if policy_id is not None else policy_task.policy_id
    if selected is None or not policy_task.assigned_to_policy(selected):
        return "AutomatedTask must be a policy"
    policy = Policy.objects.filter(pk=selected).first()

    # an inactive policy hands its tasks to no agent
    if not policy or not policy.active or not policy_task.enabled:
        return "ok"
    targets = policy.related_agents()
    if agent_pks is not None:
        targets = targets.filter(pk__in=agent_pks)
    for agent in targets:
        if agent.plat in policy_task.task_supported_platforms:
            policy_task.run_win_task(agent)
    return "ok"

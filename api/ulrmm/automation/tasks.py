# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from autotasks.models import AutomatedTask
from ulrmm.celery import app


@app.task
def run_win_policy_autotasks_task(task: int) -> str:
    policy_task = AutomatedTask.objects.select_related("policy").filter(pk=task).first()
    if policy_task is None:
        return "AutomatedTask not found"
    policy = policy_task.policy
    if policy is None:
        return "AutomatedTask must be a policy"

    # an inactive policy hands its tasks to no agent
    if not policy.active:
        return "ok"
    for agent in policy.related_agents():
        if agent.plat in policy_task.task_supported_platforms:
            policy_task.run_win_task(agent)
    return "ok"

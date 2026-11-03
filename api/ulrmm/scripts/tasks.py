# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from typing import Optional

from django.conf import settings

from agents.models import Agent, AgentHistory
from scripts.models import Script
from ulrmm.celery import app
from ulrmm.constants import AgentHistoryType, CustomFieldModel
from ulrmm.logger import logger
from ulrmm.nats_utils import abulk_nats_command


def _history_for(agents, **fields):
    rows = [AgentHistory(agent=agent, **fields) for agent in agents]
    return AgentHistory.objects.bulk_create(rows)


def _dispatch(agent_pks, history_fields, build_message) -> None:
    """Writes one history row per agent and sends each agent its nats message."""
    agents = list(Agent.objects.filter(pk__in=agent_pks))
    rows = _history_for(agents, **history_fields)
    batch = []
    for agent, row in zip(agents, rows):
        batch.append((agent.agent_id, build_message(agent, row.pk)))
    asyncio.run(abulk_nats_command(items=batch))


@app.task
def bulk_command_task(
    *,
    username: str,
    agent_pks: list[int],
    shell: str,
    cmd: str,
    run_as_user: bool = False,
    timeout: int,
) -> None:
    def message(agent, history_pk):
        return {
            "func": "rawcmd",
            "timeout": timeout,
            "payload": {"command": cmd, "shell": shell},
            "run_as_user": run_as_user,
            "id": history_pk,
        }

    _dispatch(
        agent_pks,
        {"type": AgentHistoryType.CMD_RUN, "command": cmd, "username": username},
        message,
    )


def _agent_field(pk: Optional[int]):
    from core.models import CustomField

    if pk is None:
        return None
    field = CustomField.objects.filter(pk=pk).first()
    if field is None or field.model != CustomFieldModel.AGENT:
        # deleted since the run was queued, or not a field results can go to
        logger.error(f"bulk script: custom field {pk} is not an agent field, ignored")
        return None
    return field


@app.task
def bulk_script_task(
    *,
    username: str,
    script_pk: int,
    agent_pks: list[int],
    custom_field_pk: Optional[int],
    timeout: int,
    args: list[str] = [],
    env_vars: list[str] = [],
    run_as_user: bool = False,
    collector_all_output: bool = False,
    save_to_agent_note: bool = False,
) -> None:
    script = Script.objects.get(pk=script_pk)
    shell = script.shell
    as_user = run_as_user or script.run_as_user

    def message(agent, history_pk):
        return {
            "func": "runscriptfull",
            "id": history_pk,
            "timeout": timeout,
            "script_args": script.parse_script_args(agent, shell, args),
            "payload": {"code": script.code, "shell": shell},
            "run_as_user": as_user,
            "env_vars": script.parse_script_env_vars(agent, shell, env_vars),
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }

    history_fields = {
        "type": AgentHistoryType.SCRIPT_RUN,
        "script": script,
        "username": username,
        "custom_field": _agent_field(custom_field_pk),
        "collector_all_output": collector_all_output,
        "save_to_agent_note": save_to_agent_note,
    }
    _dispatch(agent_pks, history_fields, message)

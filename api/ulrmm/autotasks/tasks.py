# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from contextlib import suppress
from time import sleep
from typing import Optional, Union

import msgpack
import nats
from django.db.models import Q

from agents.models import Agent
from alerts.models import Alert
from deploy import envelope
from ulrmm.agent_ident import agent_task_prefix
from ulrmm.celery import app
from ulrmm.constants import ORPHANED_WIN_TASK_LOCK
from ulrmm.helpers import rand_range, setup_nats_options
from ulrmm.logger import logger
from ulrmm.utils import redis_lock

from .models import AutomatedTask, TaskResult

LIST_TASKS_TIMEOUT = 5


def _on_agent(pk: int, agent_id: Optional[str], method: str) -> str:
    try:
        task = AutomatedTask.objects.select_related("agent", "policy").get(pk=pk)
        if agent_id:
            getattr(task, method)(Agent.objects.get(agent_id=agent_id))
        else:
            getattr(task, method)()
    except (AutomatedTask.DoesNotExist, Agent.DoesNotExist):
        pass
    return "ok"


@app.task
def create_win_task_schedule(pk: int, agent_id: Optional[str] = None) -> str:
    return _on_agent(pk, agent_id, "create_task_on_agent")


@app.task
def modify_win_task(pk: int, agent_id: Optional[str] = None) -> str:
    return _on_agent(pk, agent_id, "modify_task_on_agent")


@app.task
def delete_win_task_schedule(pk: int, agent_id: Optional[str] = None) -> str:
    return _on_agent(pk, agent_id, "delete_task_on_agent")


@app.task
def run_win_task(pk: int, agent_id: Optional[str] = None) -> str:
    return _on_agent(pk, agent_id, "run_win_task")


async def _remove_orphans(known: dict[str, set[str]]) -> None:
    try:
        nc = await nats.connect(**setup_nats_options())
    except Exception as e:
        logger.error(f"Orphaned task cleanup could not reach NATS: {e}")
        return

    prefix = agent_task_prefix()
    reboot_prefix = f"{prefix}SchedReboot"

    async def sweep(agent_id: str, names: set[str]) -> None:
        try:
            raw = await envelope.request(
                nc,
                agent_id,
                msgpack.dumps({"func": "listschedtasks"}),
                LIST_TASKS_TIMEOUT,
            )
            listed = msgpack.loads(raw)
        except Exception:
            # offline since the snapshot, or an answer that is not msgpack
            return
        if not isinstance(listed, list):
            return

        for name in listed:
            if (
                not isinstance(name, str)
                or not prefix
                or not name.startswith(prefix)
                or name.startswith(reboot_prefix)
                or name in names
            ):
                continue
            # created after the snapshot was taken
            if await AutomatedTask.objects.filter(
                Q(agent__agent_id=agent_id) | Q(policy__isnull=False),
                win_task_name=name,
            ).aexists():
                continue
            logger.info(f"Deleting orphaned task: {name} on agent {agent_id}")
            with suppress(envelope.Refused):
                await envelope.publish(
                    nc,
                    agent_id,
                    msgpack.dumps(
                        {"func": "delschedtask", "schedtaskpayload": {"name": name}}
                    ),
                )

    try:
        await asyncio.gather(*(sweep(a, n) for a, n in known.items()))
    finally:
        await nc.flush()
        await nc.close()


@app.task(bind=True)
def remove_orphaned_win_tasks(self) -> str:
    with redis_lock(ORPHANED_WIN_TASK_LOCK, self.app.oid) as got_lock:
        if not got_lock:
            return f"{self.app.oid} still running"

        from core.tasks import _get_agent_qs

        known = {
            agent.agent_id: {t.win_task_name for t in agent.get_tasks_with_policies()}
            for agent in _get_agent_qs()
            if not agent.is_posix and agent.is_online
        }
        if known:
            asyncio.run(_remove_orphans(known))
        return "completed"


def _notify(
    pk: int, field: str, send: str, alert_interval: Union[float, None] = None
) -> str:
    """Sends one task notification unless it went out already.

    The stamp is claimed on the alert before sending so two workers never both
    send; a failed send hands it back for the next run.
    """
    alert = Alert.objects.select_related("assigned_task", "agent").filter(pk=pk).first()
    if alert is None:
        return "alert not found"

    result = (
        TaskResult.objects.select_related("task", "agent")
        .filter(task=alert.assigned_task, agent=alert.agent)
        .first()
    )
    if result is None:
        return "task result not found"

    previous = getattr(alert, field)
    stamp = Alert.claim_notification(pk, field, alert_interval)
    if stamp is None:
        return "ok"

    # spread a burst of alerts out a little
    sleep(rand_range(100, 1500))
    try:
        getattr(result, send)()
    except Exception:
        Alert.release_notification(pk, field, stamp, previous)
        raise
    return "ok"


@app.task
def handle_task_email_alert(pk: int, alert_interval: Union[float, None] = None) -> str:
    return _notify(pk, "email_sent", "send_email", alert_interval)


@app.task
def handle_task_sms_alert(pk: int, alert_interval: Union[float, None] = None) -> str:
    return _notify(pk, "sms_sent", "send_sms", alert_interval)


@app.task
def handle_resolved_task_email_alert(pk: int) -> str:
    return _notify(pk, "resolved_email_sent", "send_resolved_email")


@app.task
def handle_resolved_task_sms_alert(pk: int) -> str:
    return _notify(pk, "resolved_sms_sent", "send_resolved_sms")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import logging

from asgiref.sync import async_to_sync, sync_to_async

from agents.models import Agent
from ulrmm.celery import app
from ulrmm.constants import ONLINE_AGENTS, AgentPlat
from ulrmm.utils import redis_lock

from .utils import COLLECT_TIMEOUT, collect_payload, parse_collect, store

logger = logging.getLogger("ulrmm")

CONCURRENCY = 10
COLLECT_LOCK = "encryption-collect-lock"


async def _collect(agents: list[Agent]) -> None:
    data = collect_payload(AgentPlat.WINDOWS)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(agent: Agent) -> None:
        async with sem:
            out = await agent.nats_cmd(data, timeout=COLLECT_TIMEOUT + 10)
        await sync_to_async(store)(agent, parse_collect(AgentPlat.WINDOWS, out))

    results = await asyncio.gather(*(one(a) for a in agents), return_exceptions=True)
    for agent, result in zip(agents, results):
        if isinstance(result, Exception):
            logger.error(f"recovery key collection on {agent.agent_id}: {result}")


@app.task
def collect_recovery_keys_task() -> None:
    """BitLocker keys from online Windows agents.

    macOS and Linux report a status. That is read when the device page is opened.
    """
    with redis_lock(COLLECT_LOCK, collect_recovery_keys_task.app.oid) as acquired:
        if not acquired:
            return
        agents = [
            a
            for a in Agent.objects.filter(plat=AgentPlat.WINDOWS).only(*ONLINE_AGENTS)
            if a.is_online
        ]
        # async_to_sync keeps the orm on this thread and its connection
        async_to_sync(_collect)(agents)

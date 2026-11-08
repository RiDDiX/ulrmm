# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.utils import timezone as djangotime

from agents.models import Agent
from agents.perf import parse_perf, perf_command
from core.stats import _offline_q
from core.utils import get_core_settings
from logs.tasks import BATCH
from ulrmm.celery import app
from ulrmm.constants import MINUTE_LOCK_EXPIRE
from ulrmm.utils import redis_lock

from .models import Sample

SAMPLE_LOCK = "metrics-sample-lock"
CONCURRENCY = 20
AGENT_TIMEOUT = 15
MAX_DISKS = 16
MB = 1024 * 1024
# agents that pushed their state this recently already have a sample
STATE_FRESH = 15 * 60


def disk_usage(disks) -> dict:
    """{mount: used percent} from the disk list the agent reports on check-in."""
    ret = {}
    for disk in disks[:MAX_DISKS] if isinstance(disks, list) else []:
        if not isinstance(disk, dict):
            continue
        device, percent = disk.get("device"), disk.get("percent")
        if isinstance(device, str) and isinstance(percent, (int, float)):
            ret[device[:64]] = percent
    return ret


def build_sample(agent: "Agent", perf: dict | None, ts) -> "Sample | None":
    if not perf:
        return None
    total, used = perf["mem_total"], perf["mem_used"]
    if total is None or used is None or total < MB:
        total = used = None
    if perf["cpu_percent"] is None and total is None:
        return None
    return Sample(
        agent=agent,
        ts=ts,
        cpu=perf["cpu_percent"],
        mem_total=total // MB if total else None,
        mem_used=used // MB if total else None,
        disks=disk_usage(agent.disks),
    )


async def _perf(agent: "Agent", sem: asyncio.Semaphore):
    shell, command = perf_command(agent.plat)
    data = {
        "func": "rawcmd",
        "timeout": 10,
        "payload": {"command": command, "shell": shell},
        "run_as_user": False,
    }
    async with sem:
        try:
            output = await asyncio.wait_for(
                agent.nats_cmd(data, timeout=AGENT_TIMEOUT), AGENT_TIMEOUT
            )
        except Exception:
            return None, None
    if not isinstance(output, str) or output in ("timeout", "natsdown"):
        return None, None
    return parse_perf(agent.plat, output), djangotime.now()


async def _collect(agents: list["Agent"]):
    sem = asyncio.Semaphore(CONCURRENCY)
    return await asyncio.gather(*(_perf(agent, sem) for agent in agents))


@app.task
def sample_metrics_task() -> str:
    lock = redis_lock(SAMPLE_LOCK, sample_metrics_task.app.oid, MINUTE_LOCK_EXPIRE)
    with lock as acquired:
        if not acquired:
            return "already running"

        fresh = djangotime.now() - djangotime.timedelta(seconds=STATE_FRESH)
        online = (
            Agent.objects.exclude(last_seen=None)
            .exclude(_offline_q())
            .exclude(state__received__gte=fresh)
            .only("pk", "agent_id", "plat", "disks")
        )
        agents = [agent for agent in online if perf_command(agent.plat)]
        samples = [
            sample
            for agent, (perf, ts) in zip(agents, asyncio.run(_collect(agents)))
            if (sample := build_sample(agent, perf, ts))
        ]
        Sample.objects.bulk_create(samples)
        return f"{len(samples)} of {len(agents)} agents sampled"


@app.task
def prune_metrics_task() -> str:
    days = min(max(get_core_settings().metric_history_days or 30, 1), 365)
    cutoff = djangotime.now() - djangotime.timedelta(days=days)
    old = Sample.objects.filter(ts__lt=cutoff).order_by("pk")
    deleted = 0
    # batches keep each DELETE short on big tables
    while ids := list(old.values_list("pk", flat=True)[:BATCH]):
        deleted += Sample.objects.filter(pk__in=ids).delete()[0]
    return f"{deleted} samples removed"

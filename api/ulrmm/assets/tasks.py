# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import time

from asgiref.sync import async_to_sync
from django.db.models import F
from django.utils import timezone as djangotime

from agents.models import Agent
from notify.dispatch import dispatch
from ulrmm.celery import app
from ulrmm.constants import ONLINE_AGENTS, REDIS_LOCK_EXPIRE, AgentPlat
from ulrmm.utils import redis_lock

from . import activation, warranty
from .models import Activation, License

NOTICE = dt.timedelta(days=30)
# a run stops before its lock expires; the devices it did not reach come
# first next time, they have the oldest lookup
WARRANTY_RUN_CAP = REDIS_LOCK_EXPIRE - 10 * 60


@app.task(bind=True)
def warranty_lookup_task(self) -> str:
    with redis_lock("assets-warranty-lock", self.app.oid) as acquired:
        if not acquired:
            return "already running"
        tokens: dict = {}
        done = 0
        stop = time.monotonic() + WARRANTY_RUN_CAP
        agents = Agent.objects.only(
            "pk", "agent_id", "hostname", "plat", "wmi_detail", "warranty_end"
        ).order_by(F("warranty_status__fetched_at").asc(nulls_first=True), "pk")
        # one request per device in sequence. Dell takes up to 100 service
        # tags per call if this gets slow
        for agent in agents.iterator(chunk_size=100):
            if time.monotonic() > stop:
                break
            if warranty.maker(agent) in ("dell", "lenovo"):
                warranty.refresh(agent, tokens)
                done += 1
    return f"{done} looked up"


@app.task(bind=True)
def activation_collect_task(self) -> str:
    """Activation state of online Windows devices. Offline ones keep the last."""
    with redis_lock("assets-activation-lock", self.app.oid) as acquired:
        if not acquired:
            return "already running"
        agents = [
            a
            for a in Agent.objects.filter(plat=AgentPlat.WINDOWS).only(*ONLINE_AGENTS)
            if a.is_online
        ]
        # async_to_sync keeps the orm on this thread and its connection
        replies = async_to_sync(activation.collect)(agents)
        now = djangotime.now()
        done = 0
        for agent, products in zip(agents, replies):
            if products is not None:
                Activation.objects.update_or_create(
                    agent=agent, defaults={"products": products, "collected_at": now}
                )
                done += 1
    return f"{done} of {len(agents)} collected"


@app.task
def expiry_notify_task() -> str:
    """Warranty and license ends within 30 days, one notification each."""
    today = djangotime.localdate()
    soon = today + NOTICE
    sent = 0
    for agent in Agent.objects.filter(
        warranty_end__gte=today, warranty_end__lte=soon
    ).only("pk", "agent_id", "hostname", "maintenance_mode", "warranty_end"):
        sent += dispatch(
            {
                "source": "license",
                "severity": "info",
                "title": f"{agent.hostname}: warranty ends {agent.warranty_end}",
                "body": "Renew the warranty or plan the replacement.",
                "agent": agent,
                "dedupe_key": f"warranty:{agent.pk}:{agent.warranty_end}",
                "dedupe_hours": 0,
            }
        )
    for lic in License.objects.filter(expires__gte=today, expires__lte=soon):
        sent += dispatch(
            {
                "source": "license",
                "severity": "info",
                "title": f"License {lic.name} expires {lic.expires}",
                "body": f"{lic.vendor}".strip(),
                "dedupe_key": f"license:{lic.pk}:{lic.expires}",
                "dedupe_hours": 0,
            }
        )
    return f"{sent} queued"

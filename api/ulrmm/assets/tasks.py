# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt

from django.utils import timezone as djangotime

from agents.models import Agent
from notify.dispatch import dispatch
from ulrmm.celery import app
from ulrmm.utils import redis_lock

from . import warranty
from .models import License

NOTICE = dt.timedelta(days=30)


@app.task(bind=True)
def warranty_lookup_task(self) -> str:
    with redis_lock("assets-warranty-lock", self.app.oid) as acquired:
        if not acquired:
            return "already running"
        tokens: dict = {}
        done = 0
        agents = Agent.objects.only(
            "pk", "agent_id", "hostname", "plat", "wmi_detail", "warranty_end"
        )
        # one request per device in sequence. Dell takes up to 100 service
        # tags per call if this gets slow
        for agent in agents.iterator(chunk_size=100):
            if warranty.maker(agent) in ("dell", "lenovo"):
                warranty.refresh(agent, tokens)
                done += 1
    return f"{done} looked up"


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

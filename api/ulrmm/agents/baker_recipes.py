# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import random
import string
from datetime import timedelta
from functools import lru_cache
from itertools import cycle

from django.conf import settings
from django.utils import timezone as djangotime
from model_bakery.recipe import Recipe, foreign_key, seq

from ulrmm.constants import AgentMonType, AgentPlat


def generate_agent_id() -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(39))


@lru_cache(maxsize=None)
def _test_data(name: str) -> str:
    with open(settings.BASE_DIR / "ulrmm" / "test_data" / name, encoding="utf-8") as f:
        return f.read()


def _json(name: str):
    # parsed per agent, so no two agents share one mutable dict
    return lambda: json.loads(_test_data(name))


def _seen(**ago):
    return lambda: djangotime.now() - timedelta(**ago)


SAMPLE_SERVICES = [
    {
        "name": "Spooler",
        "display_name": "Print Spooler",
        "description": "Queues print jobs for local and network printers.",
        "status": "running",
        "start_type": "automatic",
        "pid": 2316,
        "username": "LocalSystem",
        "binpath": "C:\\Windows\\System32\\spoolsv.exe",
    },
    {
        "name": "W32Time",
        "display_name": "Windows Time",
        "description": "Keeps the system clock in step with a time server.",
        "status": "stopped",
        "start_type": "manual",
        "pid": 0,
        "username": "NT AUTHORITY\\LocalService",
        "binpath": "C:\\Windows\\system32\\svchost.exe -k LocalService",
    },
]

# default: a Windows agent last seen five days ago, in a fresh site
agent = Recipe(
    "agents.Agent",
    last_seen=_seen(days=5),
    site=foreign_key(Recipe("clients.Site")),
    hostname="DESKTOP-TEST123",
    version="1.3.0",
    plat=AgentPlat.WINDOWS,
    agent_ident="ulrmm-agent",
    monitoring_type=cycle(AgentMonType.values),
    agent_id=seq(generate_agent_id()),
)

server_agent = agent.extend(monitoring_type=AgentMonType.SERVER)

workstation_agent = agent.extend(monitoring_type=AgentMonType.WORKSTATION)

online_agent = agent.extend(
    last_seen=djangotime.now,
    services=_json("winsvcs.json"),
    wmi_detail=_json("wmi_python_agent.json"),
)

offline_agent = agent.extend(last_seen=_seen(minutes=7))

# overdue needs outage monitoring, a silent unmonitored agent stays offline
overdue_agent = agent.extend(last_seen=_seen(minutes=35), overdue_dashboard_alert=True)

agent_with_services = agent.extend(
    services=lambda: json.loads(json.dumps(SAMPLE_SERVICES))
)

agent_with_wmi = agent.extend(wmi_detail=_json("wmi_python_agent.json"))

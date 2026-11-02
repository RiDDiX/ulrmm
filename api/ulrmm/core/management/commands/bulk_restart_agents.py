# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from time import sleep

from django.core.management.base import BaseCommand

from agents.utils import get_agent_url
from core.utils import get_mesh_ws_url


class Command(BaseCommand):
    help = "Restart the RMM and Mesh agent services on every agent"

    def handle(self, *args, **options):
        from agents.models import Agent
        from ulrmm.constants import AGENT_DEFER

        agents = list(Agent.objects.defer(*AGENT_DEFER).order_by("pk"))
        uri = get_mesh_ws_url()

        for agent in agents:
            self.stdout.write(
                f"Restarting UniversalLocal RMM Agent Service on {agent.hostname}"
            )
            try:
                agent_url = get_agent_url(agent=agent)
            except ValueError as e:
                self.stdout.write(str(e))
                continue
            agent.recover("agent", uri, wait=False, agent_url=agent_url)

        self.stdout.write(self.style.WARNING("Waiting 10 seconds..."))
        sleep(10)

        for agent in agents:
            self.stdout.write(f"Restarting MeshAgent Service on {agent.hostname}")
            agent.recover("mesh", "", wait=False)

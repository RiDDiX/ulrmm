# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.core.management.base import BaseCommand

from agents.models import Agent
from ulrmm.constants import ONLINE_AGENTS


class Command(BaseCommand):
    help = "List online agents that do not run the latest version"

    def handle(self, *args, **kwargs):
        agents = (
            Agent.objects.only(*ONLINE_AGENTS, "hostname")
            .exclude(version=settings.LATEST_AGENT_VER)
            .order_by("hostname")
        )
        for agent in agents:
            if agent.is_online:
                self.stdout.write(
                    self.style.SUCCESS(f"{agent.hostname} - v{agent.version}")
                )

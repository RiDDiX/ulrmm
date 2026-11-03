# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from agents.models import Agent
from ulrmm.constants import AGENT_DEFER


class Command(BaseCommand):
    help = "Find agents with a service whose name or display name contains a text"

    def add_arguments(self, parser):
        parser.add_argument("name", type=str)

    def handle(self, *args, **kwargs):
        search = kwargs["name"].lower()
        fields = [f for f in AGENT_DEFER if f != "services"]
        for agent in Agent.objects.defer(*fields).order_by("hostname"):
            if not isinstance(agent.services, list):
                continue
            for svc in agent.services:
                try:
                    name, display = svc["name"], svc["display_name"]
                    if search in name.lower() or search in display.lower():
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"{agent.hostname} - {name} ({display}) - "
                                f"{svc['status']}"
                            )
                        )
                except (KeyError, TypeError, AttributeError):
                    continue

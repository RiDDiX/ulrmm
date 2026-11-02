# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.core.management.base import BaseCommand

from agents.models import Agent
from agents.tasks import send_agent_update_task
from core.utils import get_core_settings
from ulrmm.helpers import agent_ver


class Command(BaseCommand):
    help = "Queue the self-update of every outdated agent"

    def handle(self, *args, **kwargs):
        if not get_core_settings().agent_auto_update:
            return

        latest = settings.LATEST_AGENT_VER
        candidates = (
            Agent.objects.exclude(version=latest)
            .only("pk", "agent_id", "version")
            .order_by("pk")
        )
        # dated versions order by date, old MAJOR.MINOR.PATCH ones sort below
        ids = [
            a.agent_id for a in candidates if agent_ver(a.version) < agent_ver(latest)
        ]
        send_agent_update_task.delay(agent_ids=ids, force=False)

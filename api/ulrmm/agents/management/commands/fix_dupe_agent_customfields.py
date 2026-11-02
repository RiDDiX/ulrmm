# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand
from django.db.models import Count, Max

from agents.models import AgentCustomField


class Command(BaseCommand):
    help = "Keep only the newest value when an agent has a custom field twice"

    def handle(self, *args, **kwargs):
        dupes = (
            AgentCustomField.objects.values("agent_id", "field__name")
            .annotate(rows=Count("pk"), newest=Max("pk"))
            .filter(rows__gt=1)
            .order_by()
        )
        for dupe in dupes:
            AgentCustomField.objects.filter(
                agent_id=dupe["agent_id"], field__name=dupe["field__name"]
            ).exclude(pk=dupe["newest"]).delete()

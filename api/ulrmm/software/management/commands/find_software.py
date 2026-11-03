# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from software.models import InstalledSoftware


class Command(BaseCommand):
    help = "Lists the agents whose software inventory has a name containing NAME"

    def add_arguments(self, parser):
        parser.add_argument("name", help="case-insensitive part of the program name")

    def handle(self, *args, **options):
        search = options["name"].lower()
        rows = InstalledSoftware.objects.select_related("agent__site__client")
        for row in rows.iterator(chunk_size=20):
            # the inventory comes from the agent, anything but a list of named
            # entries is skipped
            items = row.software if isinstance(row.software, list) else []
            for sw in items:
                name = sw.get("name") if isinstance(sw, dict) else None
                if isinstance(name, str) and search in name.lower():
                    agent = row.agent
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Found {name} installed on: {agent.site.client.name}"
                            f"\\{agent.site.name}\\{agent.hostname}"
                        )
                    )
                    break

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.core.management.base import BaseCommand
from django.utils import timezone as djangotime
from packaging.version import Version

from agents.models import Agent
from ulrmm.constants import AGENT_DEFER
from ulrmm.helpers import agent_ver
from ulrmm.utils import reload_nats


class Command(BaseCommand):
    help = "Delete agents that match the given filters (dry run without --delete)"

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, help="Not seen for this many days")
        parser.add_argument("--agentver", type=str, help="This version or older")
        parser.add_argument("--site", type=str, help="Site name")
        parser.add_argument("--client", type=str, help="Client name")
        parser.add_argument("--hostname", type=str, help="Hostname starts with")
        parser.add_argument(
            "--delete", action="store_true", help="Delete instead of listing"
        )

    def handle(self, *args, **kwargs):
        days, version = kwargs["days"], kwargs["agentver"]
        site, client, hostname = kwargs["site"], kwargs["client"], kwargs["hostname"]
        if not any((days, version, site, client, hostname)):
            self.stdout.write(
                self.style.ERROR(
                    "Must have at least one parameter: days, agentver, site, "
                    "client or hostname"
                )
            )
            return

        ceiling = None
        if version:
            ceiling = agent_ver(version)
            # agent_ver maps anything unparsable to 0
            if ceiling == Version("0"):
                self.stdout.write(self.style.ERROR(f"{version} is not a version"))
                return

        agents = Agent.objects.select_related("site__client").defer(*AGENT_DEFER)
        if days:
            cutoff = djangotime.now() - djangotime.timedelta(days=days)
            agents = agents.filter(last_seen__lt=cutoff)
        if site:
            agents = agents.filter(site__name=site)
        if client:
            agents = agents.filter(site__client__name=client)
        if hostname:
            agents = agents.filter(hostname__istartswith=hostname)

        matched = [
            a
            for a in agents.order_by("pk")
            if ceiling is None or agent_ver(a.version) <= ceiling
        ]
        if not matched:
            self.stdout.write(self.style.ERROR("No agents matched"))
            return

        def line(agent):
            return (
                f"{agent.hostname} | Version {agent.version} | "
                f"Last Seen {agent.last_seen} | "
                f"{agent.site.client.name} > {agent.site.name}"
            )

        if not kwargs["delete"]:
            for agent in matched:
                self.stdout.write(line(agent))
            self.stdout.write(
                self.style.WARNING(
                    "The above agents would be deleted. Run again with --delete "
                    "to actually delete them."
                )
            )
            return

        deleted = 0
        for agent in matched:
            self.stdout.write(self.style.SUCCESS(f"Deleting {line(agent)}"))
            asyncio.run(agent.nats_cmd({"func": "uninstall"}, wait=False))
            try:
                agent.delete()
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed to delete agent {agent.hostname}: {e}")
                )
            else:
                deleted += 1

        # the deleted agents lose their NATS credentials
        reload_nats()
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} agents"))

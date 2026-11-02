# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from agents.models import Agent
from clients.models import Client, Site


class Command(BaseCommand):
    help = "Bulk update agent offline and overdue times"

    def add_arguments(self, parser):
        parser.add_argument("time", type=int, help="Time in minutes")
        parser.add_argument("--client", type=str, help="Only agents of this client")
        parser.add_argument("--site", type=str, help="Only agents of this site")
        parser.add_argument("--offline", action="store_true", help="Set offline time")
        parser.add_argument("--overdue", action="store_true", help="Set overdue time")
        parser.add_argument("--all", action="store_true", help="Every agent")

    def handle(self, *args, **kwargs):
        minutes = kwargs["time"]
        if kwargs["offline"] and minutes < 2:
            self.stdout.write(self.style.ERROR("Minimum offline time is 2 minutes"))
            return
        if kwargs["overdue"] and minutes < 3:
            self.stdout.write(self.style.ERROR("Minimum overdue time is 3 minutes"))
            return

        if kwargs["client"]:
            client = Client.objects.filter(name=kwargs["client"]).first()
            if client is None:
                self.stdout.write(
                    self.style.ERROR(f"Client {kwargs['client']} doesn't exist")
                )
                return
            agents = Agent.objects.filter(site__client=client)
        elif kwargs["site"]:
            site = Site.objects.filter(name=kwargs["site"]).first()
            if site is None:
                self.stdout.write(
                    self.style.ERROR(f"Site {kwargs['site']} doesn't exist")
                )
                return
            agents = Agent.objects.filter(site=site)
        elif kwargs["all"]:
            agents = Agent.objects.all()
        else:
            return

        if not agents.exists():
            return

        if kwargs["offline"]:
            count = agents.update(offline_time=minutes)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Changed offline time on {count} agents to {minutes} minutes"
                )
            )
        if kwargs["overdue"]:
            count = agents.update(overdue_time=minutes)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Changed overdue time on {count} agents to {minutes} minutes"
                )
            )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import os
from contextlib import suppress

from django.core.management.base import BaseCommand, CommandError

STATE_FILE = os.path.expanduser("~/agents_maint_mode.json")


class Command(BaseCommand):
    help = "Put every agent into or out of maintenance mode"

    def add_arguments(self, parser):
        # exactly one mode per run; argparse reports a usage error otherwise
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--enable", action="store_true")
        mode.add_argument("--disable", action="store_true")
        mode.add_argument("--force-enable", action="store_true")
        mode.add_argument("--force-disable", action="store_true")

    def _write_state(self, pks):
        with open(STATE_FILE, "w") as fh:
            json.dump(pks, fh)
        os.chmod(STATE_FILE, 0o600)

    def _read_state(self):
        with open(STATE_FILE) as fh:
            return json.load(fh)

    def handle(self, *args, **options):
        from agents.models import Agent

        if options["enable"]:
            # keep an earlier snapshot so a later --disable restores it
            if os.path.exists(STATE_FILE):
                self.stdout.write(
                    self.style.WARNING(
                        "maintenance state file already exists; leaving it in place"
                    )
                )
            else:
                already = list(
                    Agent.objects.filter(maintenance_mode=True).values_list(
                        "pk", flat=True
                    )
                )
                self._write_state(already)
            Agent.objects.update(maintenance_mode=True)

        elif options["disable"]:
            if not os.path.exists(STATE_FILE):
                raise CommandError(
                    "no maintenance state file found; use --force-disable to "
                    "clear maintenance for every agent"
                )
            already = set(self._read_state())
            Agent.objects.exclude(pk__in=already).update(maintenance_mode=False)
            with suppress(OSError):
                os.remove(STATE_FILE)

        elif options["force_enable"]:
            Agent.objects.update(maintenance_mode=True)

        elif options["force_disable"]:
            with suppress(OSError):
                os.remove(STATE_FILE)
            Agent.objects.update(maintenance_mode=False)

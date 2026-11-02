# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from contextlib import suppress

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Tasks to run before applying migrations on update"

    def handle(self, *args, **options):
        from core.utils import clear_entire_cache

        write = self.stdout.write
        write(self.style.WARNING("Cleaning the cache"))
        clear_entire_cache()
        write(self.style.SUCCESS("Cache was cleared!"))

        with suppress(Exception):
            call_command("fix_dupe_agent_customfields")

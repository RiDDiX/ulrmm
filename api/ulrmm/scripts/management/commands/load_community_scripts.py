# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.cache import cache
from django.core.management.base import BaseCommand

from scripts.models import Script
from scripts.views import LIBRARY_SYNC_LOCK


class Command(BaseCommand):
    help = "Loads community scripts into the database"

    def handle(self, *args, **kwargs):
        self.stdout.write("Syncing community scripts...")
        # a dashboard sync loading at the same time would race on the rows;
        # without a cache the load goes ahead
        try:
            locked = cache.add(LIBRARY_SYNC_LOCK, "manage.py", 600)
        except Exception:
            locked = None
        if locked is False:
            self.stdout.write(
                self.style.WARNING("The script library is being synced already.")
            )
            return
        try:
            result = Script.load_community_scripts()
        finally:
            if locked:
                cache.delete(LIBRARY_SYNC_LOCK)

        if "error" in result:
            self.stdout.write(
                self.style.WARNING(
                    f"Community scripts not loaded, nothing changed: {result['error']}"
                )
            )
            return
        counts = ", ".join(
            f"{result[k]} {k}"
            for k in ("added", "updated", "removed", "retired", "skipped")
        )
        self.stdout.write(self.style.SUCCESS(f"Community scripts synced: {counts}"))

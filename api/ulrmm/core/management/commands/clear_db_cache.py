# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Clear the entire RMM cache"

    def handle(self, *args, **options):
        from core.utils import clear_entire_cache

        clear_entire_cache()
        self.stdout.write(self.style.SUCCESS("Cache was cleared!"))

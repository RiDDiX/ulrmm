# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Populate the initial CoreSettings singleton"

    def handle(self, *args, **options):
        from core.models import CoreSettings

        try:
            CoreSettings().save()
        except ValidationError:
            # the singleton already exists; nothing to do
            pass
        self.stdout.write("Core db populated")

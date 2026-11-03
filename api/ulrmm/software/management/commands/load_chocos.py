# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from software.models import ChocoSoftware


class Command(BaseCommand):
    help = "Loads the bundled chocolatey package list into the database"

    def handle(self, *args, **options):
        source = Path(settings.BASE_DIR) / "software" / "chocos.json"
        packages = json.loads(source.read_text())

        # a failed insert keeps the previous list
        with transaction.atomic():
            ChocoSoftware.objects.all().delete()
            ChocoSoftware.objects.create(chocos=packages)

        self.stdout.write(self.style.SUCCESS("Chocos saved to db"))

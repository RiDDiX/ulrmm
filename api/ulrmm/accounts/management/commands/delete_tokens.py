# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt

from django.core.management.base import BaseCommand
from django.utils import timezone as djangotime
from knox.models import AuthToken


class Command(BaseCommand):
    help = "Signs out every dashboard session (run on update)"

    def handle(self, *args, **kwargs):
        # install credentials (deployments, generated install commands) stay
        AuthToken.objects.filter(
            deploytokens__isnull=True,
            installertokens__isnull=True,
            expiry__lt=djangotime.now() + dt.timedelta(hours=23),
        ).delete()
        self.stdout.write("All web tokens have been deleted!")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import pyotp
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Prints a new random TOTP secret"

    def handle(self, *args, **kwargs):
        self.stdout.write(pyotp.random_base32())

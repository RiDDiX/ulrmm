# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Reload the NATS server configuration"

    def handle(self, *args, **options):
        from ulrmm.utils import reload_nats

        self.stdout.write("Reloading NATs configuration...")
        reload_nats()
        self.stdout.write("NATs configuration reloaded")

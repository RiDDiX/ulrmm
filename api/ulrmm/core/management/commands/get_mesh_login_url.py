# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Print a one-time MeshCentral login URL"

    def handle(self, *args, **options):
        from core.meshtoken import get_login_token
        from core.models import CoreSettings

        core = CoreSettings.objects.first()
        token = get_login_token(key=core.mesh_token, user=f"user//{core.mesh_username}")
        self.stdout.write(self.style.SUCCESS(f"{core.mesh_site}/?login={token}&"))

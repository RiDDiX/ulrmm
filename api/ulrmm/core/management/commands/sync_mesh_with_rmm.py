# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sync RMM users and permissions with MeshCentral"

    def handle(self, *args, **options):
        from core.tasks import sync_mesh_perms_task

        self.stdout.write(
            self.style.SUCCESS(
                "Syncing RMM users/permissions with meshcentral, this might take "
                "a long time...please wait..."
            )
        )
        sync_mesh_perms_task()

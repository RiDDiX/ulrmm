# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Troubleshoot the MeshCentral connection"

    def handle(self, *args, **options):
        from core.meshtoken import get_auth_token
        from core.models import CoreSettings
        from core.utils import (
            MeshDeviceGroupNotFound,
            get_mesh_device_id,
            get_mesh_ws_url,
        )

        core = CoreSettings.objects.first()
        self.stdout.write(self.style.WARNING(f"Mesh site: {core.mesh_site}"))
        self.stdout.write(self.style.WARNING(f"Mesh username: {core.mesh_username}"))
        self.stdout.write(
            self.style.WARNING(f"Mesh device group: {core.mesh_device_group}")
        )

        try:
            get_auth_token(core.mesh_api_superuser, core.mesh_token)
            # the token is a live superuser credential, so it is never printed
            self.stdout.write(self.style.SUCCESS("Auth token ok"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting auth token: {e}"))
            return

        try:
            uri = get_mesh_ws_url()
            self.stdout.write(self.style.SUCCESS("Mesh url ok"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting mesh url: {e}"))
            return

        try:
            mesh_id = asyncio.run(get_mesh_device_id(uri, core.mesh_device_group))
            self.stdout.write(self.style.SUCCESS(f"Mesh device id ok: {mesh_id}"))
        except MeshDeviceGroupNotFound as e:
            self.stdout.write(self.style.ERROR(str(e)))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting mesh device id: {e}"))

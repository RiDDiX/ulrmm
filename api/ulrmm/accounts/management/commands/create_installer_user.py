# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid

from django.core.management.base import BaseCommand

from accounts.models import User
from ulrmm.helpers import make_random_password


class Command(BaseCommand):
    help = "Creates the account install links and deployments authenticate as"

    def handle(self, *args, **kwargs):
        self.stdout.write("Checking if installer user has been created...")
        if User.objects.filter(is_installer_user=True).exists():
            self.stdout.write("Installer user already exists")
            return

        # random name and a long throwaway password, the account never logs in
        flags = {"is_installer_user": True, "block_dashboard_login": True}
        User.objects.create_user(
            password=make_random_password(len=60), username=uuid.uuid4().hex, **flags
        )
        self.stdout.write("Installer user has been created")

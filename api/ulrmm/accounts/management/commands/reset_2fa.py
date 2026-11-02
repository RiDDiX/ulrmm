# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import pyotp
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from accounts.utils import clear_pending_totp_key, end_other_sessions
from ulrmm.util_settings import get_webdomain

from .generate_barcode import print_qr


class Command(BaseCommand):
    help = "Gives a user a new TOTP secret and ends its sessions"

    def add_arguments(self, parser):
        parser.add_argument("username", type=str)

    def handle(self, *args, **kwargs):
        username = kwargs["username"]
        user = User.objects.filter(username=username).first()
        if user is None:
            raise CommandError(f"User {username} doesn't exist")

        code = pyotp.random_base32()
        user.totp_key = code
        user.save(update_fields=["totp_key"])
        clear_pending_totp_key(user)
        end_other_sessions(user)

        domain = get_webdomain(settings.CORS_ORIGIN_WHITELIST[0])
        url = pyotp.totp.TOTP(code).provisioning_uri(username, issuer_name=domain)
        print_qr(self, url)
        for hint in (
            "Scan the barcode above with your authenticator app",
            f"If that doesn't work you may manually enter the setup key: {code}",
        ):
            self.stdout.write(self.style.WARNING(hint))
        self.stdout.write(f"Other sessions and API keys of {username} were ended")
        self.stdout.write(
            self.style.SUCCESS(f"2fa was successfully reset for user {username}")
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os
import shutil
import subprocess
import sys

import pyotp
from django.core.management.base import BaseCommand, CommandError

from accounts.models import User


def print_qr(command, url: str) -> None:
    """Draws the provisioning URI with the qr tool from the venv."""
    qr = shutil.which("qr", path=os.path.dirname(sys.executable)) or "qr"
    command.stdout.flush()
    try:
        subprocess.run([qr, url], check=False)
    except OSError:
        command.stdout.write(command.style.WARNING("qr is not available"))


class Command(BaseCommand):
    help = "Stores a TOTP secret for a user and prints its QR code"

    def add_arguments(self, parser):
        for name in ("code", "username", "domain"):
            parser.add_argument(name, type=str)

    def handle(self, *args, **kwargs):
        code, username = kwargs["code"], kwargs["username"]
        user = User.objects.filter(username=username).first()
        if user is None:
            raise CommandError(f"User {username} doesn't exist")

        # first admin at install time: committed directly, no pending step
        user.totp_key = code
        user.save(update_fields=["totp_key"])

        url = pyotp.totp.TOTP(code).provisioning_uri(
            username, issuer_name=kwargs["domain"]
        )
        print_qr(self, url)
        hints = (
            "Scan the barcode above with your authenticator app",
            f"If that doesn't work you may manually enter the setup key: {code}",
        )
        for hint in hints:
            self.stdout.write(self.style.SUCCESS(hint))

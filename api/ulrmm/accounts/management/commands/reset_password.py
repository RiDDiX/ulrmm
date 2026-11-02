# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from getpass import getpass

from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from accounts.utils import clear_pending_totp_key, end_other_sessions


class Command(BaseCommand):
    help = "Sets a new password for a user and ends its sessions"

    def add_arguments(self, parser):
        parser.add_argument("username", type=str)

    def handle(self, *args, **kwargs):
        username = kwargs["username"]
        user = User.objects.filter(username=username).first()
        if user is None:
            raise CommandError(f"User {username} doesn't exist")

        # operator tool: no password rules here
        while True:
            password = getpass()
            if password == getpass(prompt="Confirm Password:"):
                break
            self.stdout.write(self.style.ERROR("Passwords don't match"))

        user.set_password(password)
        user.save()
        clear_pending_totp_key(user)
        end_other_sessions(user)
        self.stdout.write(f"Other sessions and API keys of {username} were ended")
        self.stdout.write(self.style.SUCCESS(f"Password for {username} was reset!"))

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Agent command keys. list shows them; rotate creates the next key, which "
        "becomes current once every agent knows it (at the latest after 24 h); "
        "promote runs that check now."
    )

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("list", "rotate", "promote"))

    def handle(self, *args, **options):
        from deploy import signing
        from deploy.models import CommandKey

        action = options["action"]
        if action == "rotate":
            row = signing.rotate_command_key()
            self.stdout.write(f"next command key {row.kid}")
        elif action == "promote":
            self.stdout.write(signing.promote_command_keys())
        signing.current_command_key()
        for row in CommandKey.objects.order_by("created", "pk"):
            self.stdout.write(f"{row.kid} {row.state} {row.created:%Y-%m-%d %H:%M}")

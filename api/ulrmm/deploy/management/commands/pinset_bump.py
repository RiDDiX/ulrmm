# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Max

from deploy import signing
from deploy.models import PinSet
from deploy.pki import security_settings

# far above anything an agent can have stored since the backup was made
BUMP = 1000


class Command(BaseCommand):
    help = (
        "Stores the current pin set with a seq 1000 above the highest one, "
        "for after a database restore: agents that stored a pin set newer "
        "than the backup accept the pin document again."
    )

    def handle(self, *args, **kwargs):
        primary = signing.spki_pins()
        if not primary:
            raise CommandError(signing.NO_PINS)
        sec = security_settings()
        top = PinSet.objects.aggregate(top=Max("seq"))["top"] or 0
        pins = PinSet.objects.create(
            seq=top + BUMP,
            primary=primary,
            backup=list(sec.backup_pins or []),
            cmd=signing.command_claim(),
            sec2=sec.sec2_mode,
        )
        self.stdout.write(f"pin set {pins.seq}")

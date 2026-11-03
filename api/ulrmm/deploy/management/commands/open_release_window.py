# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone as djangotime

from deploy import events
from deploy.identity import RELEASE_TIME
from deploy.models import (
    AgentIdentity,
    IdentityState,
    SecurityEventKind,
    SecurityEventSeverity,
)


class Command(BaseCommand):
    help = (
        "For after a database restore: every active identity may fetch one new "
        "token family with its identity signature alone within 24 h, because "
        "the agents hold tokens newer than the backup."
    )

    def add_arguments(self, parser):
        parser.add_argument("--all-active", action="store_true")

    def handle(self, *args, **kwargs):
        if not kwargs["all_active"]:
            raise CommandError("pass --all-active")
        until = djangotime.now() + RELEASE_TIME
        count = (
            AgentIdentity.objects.filter(state=IdentityState.ACTIVE)
            .exclude(ed25519="")
            .update(release_until=until)
        )
        events.record(
            SecurityEventKind.RELEASED,
            SecurityEventSeverity.WARNING,
            detail=f"release window for {count} active identities after a restore",
        )
        self.stdout.write(
            f"release window for {count} identities until {until:%Y-%m-%d %H:%M} UTC"
        )

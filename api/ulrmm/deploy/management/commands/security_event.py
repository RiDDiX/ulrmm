# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from deploy import events
from deploy.models import SecurityEventKind, SecurityEventSeverity


class Command(BaseCommand):
    help = "Records a security event, for shell scripts such as backup.sh"

    def add_arguments(self, parser):
        parser.add_argument("kind", choices=SecurityEventKind.values)
        parser.add_argument("severity", choices=SecurityEventSeverity.values)
        parser.add_argument("--detail", default="", help="at most 500 characters")

    def handle(self, *args, **kwargs):
        events.record(kwargs["kind"], kwargs["severity"], detail=kwargs["detail"])
        self.stdout.write(f"{kwargs['kind']} {kwargs['severity']}")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from checks.models import Check
from ulrmm.constants import AgentPlat, CheckType


class Command(BaseCommand):
    help = (
        "Lists service and event log checks on agents other than Windows, which "
        "those agents cannot run. Changes nothing: removing someone's checks "
        "during an update would be the worse surprise."
    )

    def handle(self, *args, **kwargs):
        unsupported = (
            Check.objects.select_related("agent")
            .filter(
                check_type__in=(CheckType.WINSVC, CheckType.EVENT_LOG),
                agent__isnull=False,
            )
            .exclude(agent__plat=AgentPlat.WINDOWS)
            .order_by("pk")
        )
        if not unsupported:
            self.stdout.write(self.style.SUCCESS("No unsupported checks found"))
            return

        for check in unsupported:
            agent = check.agent
            self.stdout.write(
                self.style.WARNING(
                    f"pk={check.pk} {check.check_type} on {agent.hostname} "
                    f"({agent.plat}): {check.readable_desc}"
                )
            )
        self.stdout.write(
            self.style.WARNING(
                f"\n{len(unsupported)} unsupported check(s). Remove them in the "
                "dashboard, or with: python manage.py shell -c "
                '"from checks.models import Check; '
                'Check.objects.filter(pk__in=[...]).delete()"'
            )
        )

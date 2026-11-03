# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from autotasks.tasks import remove_orphaned_win_tasks


class Command(BaseCommand):
    help = "Removes scheduled tasks on online agents that the server no longer knows"

    def handle(self, *args, **options):
        # runs here, not on a worker, under the same lock as the beat job
        self.stdout.write(remove_orphaned_win_tasks())

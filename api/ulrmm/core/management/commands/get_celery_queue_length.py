# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Print the current Celery queue length"

    def handle(self, *args, **options):
        from ulrmm.utils import get_celery_queue_len

        self.stdout.write(str(get_celery_queue_len()))

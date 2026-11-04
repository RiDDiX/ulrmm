# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.cache import cache
from django.core.management.base import BaseCommand

from ulrmm import constants as c


class Command(BaseCommand):
    help = "Clear the distributed task locks (run only with celery/beat stopped)"

    def handle(self, *args, **options):
        for lock in (
            c.AGENT_OUTAGES_LOCK,
            c.ORPHANED_WIN_TASK_LOCK,
            c.RESOLVE_ALERTS_LOCK,
            c.SYNC_SCHED_TASK_LOCK,
            c.SYNC_MESH_PERMS_TASK_LOCK,
            c.CACHE_DB_FIELDS_TASK_LOCK,
            c.SCHED_TASK_RUNNER_LOCK,
        ):
            cache.delete(lock)

        cache.delete_many_pattern("posix-packages-*")

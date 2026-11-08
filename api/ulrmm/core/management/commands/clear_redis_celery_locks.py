# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.cache import cache
from django.core.management.base import BaseCommand

from ulrmm import constants as c

# every task lock; core/test_commands.py checks the redis_lock calls against it
LOCKS = (
    c.AGENT_OUTAGES_LOCK,
    c.ORPHANED_WIN_TASK_LOCK,
    c.RESOLVE_ALERTS_LOCK,
    c.SYNC_SCHED_TASK_LOCK,
    c.SYNC_MESH_PERMS_TASK_LOCK,
    c.CACHE_DB_FIELDS_TASK_LOCK,
    c.SCHED_TASK_RUNNER_LOCK,
    c.NETMON_POLL_LOCK,
    "appupdates-apply",
    "appupdates-collect",
    "assets-activation-lock",
    "assets-warranty-lock",
    "discovery-scan-lock-key",
    "driver-catalog",
    "encryption-collect-lock",
    "integrations-sync-lock",
    "laps-rotate-lock",
    "maintenance-schedule-lock",
    "metrics-sample-lock",
    "notify-escalate-lock",
    "rustdesk-pin-lock",
    "rustdesk-server-lock",
    "sdio-apply",
    "sdio-index",
    "software-baselines",
    "tamper-watch-lock",
    "vulns-scan",
    "winget-catalog",
)
# locks per agent or object
LOCK_PATTERNS = (
    "posix-packages-*",
    "laps-rotate-*",
    "importers-source-*",
    "appupdates-applying-*",
)


class Command(BaseCommand):
    help = "Clear the distributed task locks (run only with celery/beat stopped)"

    def handle(self, *args, **options):
        cache.delete_many(LOCKS)
        for pattern in LOCK_PATTERNS:
            cache.delete_many_pattern(pattern)

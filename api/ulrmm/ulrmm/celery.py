# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import absolute_import, unicode_literals

import os
from datetime import timedelta

from celery import Celery
from celery.schedules import crontab
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ulrmm.settings")

broker_url = settings.REDIS_URL
app = Celery("ulrmm", backend=broker_url, broker=broker_url)
app.conf.update(
    accept_content=["json"],
    result_serializer="json",
    task_serializer="json",
    task_track_started=True,
    worker_proc_alive_timeout=30,
    worker_max_tasks_per_child=2,
    broker_connection_retry_on_startup=True,
)
app.autodiscover_tasks()

every_minute = crontab()
every_five_minutes = crontab(minute="*/5")

# (beat entry name, task path, schedule)
BEAT_TABLE = (
    (
        "auto-approve-win-updates",
        "winupdate.tasks.auto_approve_updates_task",
        crontab(minute=2, hour="*/8"),
    ),
    (
        "install-scheduled-win-updates",
        "winupdate.tasks.check_agent_update_schedule_task",
        crontab(minute=5, hour="*"),
    ),
    (
        "agent-auto-update",
        "agents.tasks.auto_self_agent_update_task",
        crontab(minute=35, hour="*"),
    ),
    (
        "remove-orphaned-tasks",
        "autotasks.tasks.remove_orphaned_win_tasks",
        crontab(minute=50, hour="*/2"),
    ),
    ("agent-outages-task", "agents.tasks.agent_outages_task", timedelta(seconds=150.0)),
    ("unsnooze-alerts", "alerts.tasks.unsnooze_alerts", crontab(minute=10, hour="*")),
    (
        "core-maintenance-tasks",
        "core.tasks.core_maintenance_tasks",
        crontab(minute=15, hour="*"),
    ),
    (
        "cache-db-fields-task",
        "core.tasks.cache_db_fields_task",
        crontab(minute="*/3", hour="*"),
    ),
    (
        "sync-scheduled-tasks",
        "core.tasks.sync_scheduled_tasks",
        crontab(minute="*/2", hour="*"),
    ),
    (
        "sync-mesh-perms-task",
        "core.tasks.sync_mesh_perms_task",
        crontab(minute="*/4", hour="*"),
    ),
    (
        "resolve-pending-actions",
        "core.tasks.resolve_pending_actions",
        timedelta(seconds=100.0),
    ),
    ("resolve-alerts-task", "core.tasks.resolve_alerts_task", timedelta(seconds=80.0)),
    ("ulrmm-scheduler", "core.tasks.scheduled_task_runner", every_minute),
    ("metrics-sample", "metrics.tasks.sample_metrics_task", every_five_minutes),
    ("metrics-prune", "metrics.tasks.prune_metrics_task", crontab(minute=40, hour=2)),
    (
        "discovery-prune",
        "discovery.tasks.prune_discovery_task",
        crontab(minute=50, hour=2),
    ),
    ("vulns-scan", "vulns.tasks.scan_vulnerabilities_task", crontab(minute=20, hour=3)),
    (
        "encryption-collect",
        "encryption.tasks.collect_recovery_keys_task",
        crontab(minute=10, hour=4),
    ),
    (
        "rustdesk-check-releases",
        "remote.tasks.rustdesk_check_releases_task",
        crontab(minute=20, hour=5),
    ),
    (
        "rustdesk-auto-update",
        "remote.tasks.rustdesk_auto_update_task",
        crontab(minute=40, hour=5),
    ),
    ("netmon-poll", "netmon.tasks.poll_network_devices", every_minute),
    ("maintenance-schedules", "patches.tasks.maintenance_schedule_task", every_minute),
    (
        "ulrmm-reports-scheduler",
        "reporting.tasks.scheduled_reports_runner",
        every_minute,
    ),
    # MSRC/NVD lookups run inside vulns-scan
    (
        "appupdates-collect",
        "appupdates.tasks.collect_app_updates_task",
        crontab(minute=0, hour=6),
    ),
    ("appupdates-apply", "appupdates.tasks.apply_app_updates_task", crontab(minute=30)),
    ("notify-escalate", "notify.tasks.escalate_task", every_five_minutes),
    ("tamper-watch", "notify.tasks.tamper_watch_task", every_five_minutes),
    (
        "assets-warranty",
        "assets.tasks.warranty_lookup_task",
        crontab(minute=30, hour=4, day_of_week=1),
    ),
    ("assets-expiry", "assets.tasks.expiry_notify_task", crontab(minute=0, hour=7)),
    (
        "assets-activation",
        "assets.tasks.activation_collect_task",
        crontab(minute=50, hour=4),
    ),
    ("laps-rotate", "laps.tasks.laps_rotate_task", crontab(minute=15)),
    (
        "integrations-sync",
        "integrations.tasks.sync_integrations_task",
        crontab(minute=25),
    ),
    (
        "winget-catalog",
        "software.tasks.refresh_winget_task",
        crontab(minute=50, hour=5),
    ),
    # at most 300 searches, 2 s apart
    (
        "driver-catalog",
        "software.tasks.scan_driver_catalog_task",
        crontab(minute=35, hour=4),
    ),
    # torrent check, changed indexes only, then the approvals
    ("sdio-index", "software.tasks.refresh_sdio_task", crontab(minute=20, hour=5)),
    # one baseline item per agent at a time, see software/baselines.py
    ("software-baselines", "software.tasks.baseline_tick_task", every_five_minutes),
    ("package-uploads", "packages.tasks.remove_stale_uploads_task", crontab(minute=40)),
    # NATS permissions of agents that updated themselves, reload on change only
    ("nats-config", "core.tasks.refresh_nats_config_task", every_five_minutes),
    (
        "security-events-prune",
        "deploy.tasks.prune_security_events",
        crontab(minute=45, hour=2),
    ),
    ("iso-jobs-prune", "deploy.tasks.prune_iso_jobs", crontab(minute=20)),
    (
        "command-keys-promote",
        "deploy.tasks.promote_command_keys",
        crontab(minute="*/15"),
    ),
)
app.conf.beat_schedule = {
    name: {"task": task, "schedule": when} for name, task, when in BEAT_TABLE
}


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")

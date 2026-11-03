# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Trigger every periodic task once"

    def handle(self, *args, **options):
        from agents import tasks as agents
        from alerts import tasks as alerts
        from autotasks import tasks as autotasks
        from core import tasks as core
        from winupdate import tasks as winupdate

        for task in (
            agents.auto_self_agent_update_task,
            agents.agent_outages_task,
            alerts.unsnooze_alerts,
            core.cache_db_fields_task,
            core.core_maintenance_tasks,
            core.resolve_pending_actions,
            core.resolve_alerts_task,
            core.sync_scheduled_tasks,
            autotasks.remove_orphaned_win_tasks,
            winupdate.auto_approve_updates_task,
            winupdate.check_agent_update_schedule_task,
            core.sync_mesh_perms_task,
        ):
            task.delay()

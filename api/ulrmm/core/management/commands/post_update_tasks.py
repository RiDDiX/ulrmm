# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64

from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import BaseCommand

from ulrmm.constants import ULRMM_LATEST_VER_CACHE_KEY, ScriptType


class Command(BaseCommand):
    help = "Tasks to run after applying migrations on update"

    def handle(self, *args, **options):
        self.stdout.write("Running post update tasks")

        from accounts.models import User
        from agents.models import Agent
        from autotasks.models import AutomatedTask
        from checks.models import Check, CheckHistory
        from core.models import CoreSettings
        from core import tasks as core_tasks
        from scripts.models import Script

        # the command takes the library sync lock, so a dashboard sync cannot race it
        call_command("load_community_scripts")

        for user in User.objects.filter(is_installer_user=True):
            user.block_dashboard_login = True
            user.save()

        for script in Script.objects.exclude(script_type=ScriptType.BUILT_IN).filter(
            script_body=""
        ):
            encoded = getattr(script, "code_base64", "")
            if encoded:
                raw = base64.b64decode(encoded.encode("ascii", "ignore"))
                script.script_body = raw.decode("ascii", "ignore")
                script.save(update_fields=["script_body"])

        for model in (AutomatedTask, Check):
            model.objects.filter(managed_by_policy=True).delete()
        CheckHistory.objects.filter(agent_id__isnull=True).delete()

        for agent in Agent.objects.filter(goarch=""):
            agent.goarch = "386" if agent.arch == "32" else "amd64"
            agent.save(update_fields=["goarch"])

        self.stdout.write(
            self.style.SUCCESS("Checking for orphaned history results...")
        )
        removed = core_tasks.remove_orphaned_history_results()
        if removed > 0:
            self.stdout.write(f"Removed {removed} orphaned history results.")

        core = CoreSettings.objects.first()
        if core and core.sync_mesh_with_rmm:
            self.stdout.write(
                self.style.SUCCESS(
                    "Syncing RMM users/permissions with meshcentral, this might "
                    "take a long time...please wait..."
                )
            )
            core_tasks.sync_mesh_perms_task()

        cache.delete(ULRMM_LATEST_VER_CACHE_KEY)
        self.stdout.write("Post update tasks finished")

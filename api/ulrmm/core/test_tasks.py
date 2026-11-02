# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import AsyncMock, patch

import time_machine
from django.conf import settings
from model_bakery import baker

from autotasks.models import TaskResult
from core.tasks import cache_db_fields_task, resolve_alerts_task, scheduled_task_runner
from ulrmm.constants import AgentPlat, AlertType, TaskRunStatus, TaskType
from ulrmm.test import ULRMMTestCase

MONDAY_1030 = dt.datetime(2026, 3, 2, 10, 30, tzinfo=dt.timezone.utc)


class TestCoreTasks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_cache_db_fields_marks_sites_and_clients(self):
        bad_site, good_site = baker.make("clients.Site", _quantity=2)
        baker.make_recipe(
            "agents.overdue_agent", site=bad_site, overdue_email_alert=True
        )
        baker.make_recipe("agents.online_agent", site=good_site)

        self.assertEqual(cache_db_fields_task(), "ok")
        for obj, error in (
            (bad_site, True),
            (good_site, False),
            (bad_site.client, True),
        ):
            obj.refresh_from_db()
            self.assertEqual(obj.failing_checks, {"error": error, "warning": False})

    def test_cache_db_fields_counts_every_agent(self):
        site = baker.make("clients.Site")
        # the error agent is read first; its error must not hide the warning
        for severity in ("error", "warning"):
            agent = baker.make_recipe("agents.online_agent", site=site)
            check = baker.make(
                "checks.Check",
                agent=agent,
                check_type="ping",
                alert_severity=severity,
            )
            baker.make(
                "checks.CheckResult",
                agent=agent,
                assigned_check=check,
                status="failing",
                alert_severity=severity,
            )

        cache_db_fields_task()
        site.refresh_from_db()
        self.assertEqual(site.failing_checks, {"error": True, "warning": True})

    @patch("alerts.models.Alert.handle_alert_resolve")
    def test_resolve_alerts_only_for_online_agents_with_open_alerts(self, resolve):
        back = baker.make_recipe(
            "agents.online_agent", version=settings.LATEST_AGENT_VER
        )
        baker.make("alerts.Alert", agent=back, alert_type=AlertType.AVAILABILITY)
        down = baker.make_recipe(
            "agents.overdue_agent", version=settings.LATEST_AGENT_VER
        )
        baker.make("alerts.Alert", agent=down, alert_type=AlertType.AVAILABILITY)
        baker.make_recipe("agents.online_agent", version=settings.LATEST_AGENT_VER)

        self.assertEqual(resolve_alerts_task(), "completed")
        resolve.assert_called_once()
        self.assertEqual(resolve.call_args.args[0].pk, back.pk)

    @time_machine.travel(MONDAY_1030, tick=False)
    @patch("core.tasks.abulk_nats_command", new_callable=AsyncMock)
    def test_runner_starts_due_posix_tasks(self, bulk):
        due = None
        for plat in (AgentPlat.LINUX, AgentPlat.WINDOWS):
            agent = baker.make_recipe("agents.online_agent", plat=plat, time_zone="UTC")
            for minute in (30, 31):
                task = baker.make(
                    "autotasks.AutomatedTask",
                    agent=agent,
                    task_type=TaskType.DAILY,
                    run_time_date=MONDAY_1030.replace(minute=minute),
                )
                result = baker.make("autotasks.TaskResult", agent=agent, task=task)
                if plat == AgentPlat.LINUX and minute == 30:
                    due = (agent, task, result)

        agent, task, result = due
        expected = [(agent.agent_id, {"func": "runtask", "taskpk": task.pk})]
        self.assertEqual(scheduled_task_runner(), expected)
        bulk.assert_awaited_once_with(items=expected)
        result.refresh_from_db()
        self.assertEqual(result.run_status, TaskRunStatus.RUNNING)
        self.assertEqual(
            TaskResult.objects.filter(run_status=TaskRunStatus.RUNNING).count(), 1
        )
        # a second tick inside the same minute does not start it again
        self.assertEqual(scheduled_task_runner(), [])

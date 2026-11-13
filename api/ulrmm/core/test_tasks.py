# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import AsyncMock, patch

import time_machine
from django.conf import settings
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker

from autotasks.models import TaskResult
from checks.models import CheckHistory
from core.tasks import (
    NO_INSTALL_RESULT,
    cache_db_fields_task,
    remove_orphaned_history_results,
    resolve_alerts_task,
    resolve_pending_actions,
    scheduled_task_runner,
)
from logs.models import PendingAction
from ulrmm.constants import AgentPlat, AlertType, PAAction, PAStatus, TaskRunStatus
from ulrmm.constants import TaskType
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

    def test_cache_db_fields_skips_heavy_agent_fields(self):
        baker.make_recipe("agents.online_agent", site=baker.make("clients.Site"))
        with CaptureQueriesContext(connection) as ctx:
            cache_db_fields_task()
        agent_sql = [q["sql"] for q in ctx if '"agents_agent"' in q["sql"]]
        self.assertTrue(agent_sql)
        self.assertFalse([sql for sql in agent_sql if "wmi_detail" in sql])

    def test_orphaned_history_removed_in_batches(self):
        agent = baker.make_recipe("agents.agent")
        keep = baker.make(CheckHistory, agent_id=agent.agent_id)
        unowned = baker.make(CheckHistory, agent_id=None)
        baker.make(CheckHistory, agent_id="gone", _quantity=3)
        with patch("core.tasks.ORPHAN_BATCH", 2), CaptureQueriesContext(
            connection
        ) as ctx:
            self.assertEqual(remove_orphaned_history_results(), 3)
        self.assertCountEqual(
            CheckHistory.objects.values_list("pk", flat=True), [keep.pk, unowned.pk]
        )
        # NOT EXISTS, no list of every agent id in the statement
        self.assertTrue(any("NOT (EXISTS" in q["sql"] for q in ctx))
        self.assertNotIn(agent.agent_id, " ".join(q["sql"] for q in ctx))

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

    @time_machine.travel(MONDAY_1030, tick=False)
    @patch("core.tasks.abulk_nats_command", new_callable=AsyncMock)
    def test_runner_sends_only_the_rows_it_claims(self, bulk):
        agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, time_zone="UTC"
        )
        taken, free = (
            baker.make(
                "autotasks.TaskResult",
                agent=agent,
                task=baker.make(
                    "autotasks.AutomatedTask",
                    agent=agent,
                    task_type=TaskType.DAILY,
                    run_time_date=MONDAY_1030,
                ),
                locked_at=MONDAY_1030 - dt.timedelta(seconds=70),
            )
            for _ in range(2)
        )

        def due(task, agent, now):
            # another run locks the row after this one has read it
            TaskResult.objects.filter(pk=taken.pk).update(
                locked_at=now - dt.timedelta(seconds=10)
            )
            return True

        with patch("ulrmm.scheduler.should_run_daily_task", side_effect=due):
            ran = scheduled_task_runner()
        expected = [(agent.agent_id, {"func": "runtask", "taskpk": free.task_id})]
        self.assertEqual(ran, expected)
        bulk.assert_awaited_once_with(items=expected)
        taken.refresh_from_db()
        self.assertIsNone(taken.run_status)

    def test_cache_db_fields_reads_the_agents_once(self):
        for site in baker.make("clients.Site", _quantity=3):
            baker.make_recipe("agents.online_agent", site=site)
        with CaptureQueriesContext(connection) as ctx:
            cache_db_fields_task()
        agent_reads = [q for q in ctx if 'FROM "agents_agent"' in q["sql"]]
        self.assertEqual(len(agent_reads), 1)

    def test_installs_without_a_result_fail_after_two_hours(self):
        agent = baker.make_recipe("agents.agent")
        old = djangotime.now() - dt.timedelta(hours=2, minutes=1)
        rows = {}
        for name, kind, age in (
            ("winget", PAAction.WINGET_INSTALL, old),
            ("choco", PAAction.CHOCO_INSTALL, old),
            ("fresh", PAAction.WINGET_INSTALL, None),
            ("other", PAAction.RUN_CMD, old),
        ):
            row = baker.make(
                "logs.PendingAction",
                agent=agent,
                action_type=kind,
                details={"name": name, "installed": False, "output": None},
            )
            if age:
                PendingAction.objects.filter(pk=row.pk).update(entry_time=age)
            rows[name] = row

        resolve_pending_actions()

        for name, expired in (
            ("winget", True),
            ("choco", True),
            ("fresh", False),
            ("other", False),
        ):
            row = PendingAction.objects.get(pk=rows[name].pk)
            done = row.status == PAStatus.COMPLETED
            self.assertEqual(done, expired, name)
            if expired:
                self.assertEqual(row.details["output"], NO_INSTALL_RESULT)
                self.assertFalse(row.details["installed"])

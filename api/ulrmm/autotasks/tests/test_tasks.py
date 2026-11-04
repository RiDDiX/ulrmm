# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import AsyncMock, MagicMock, patch

import msgpack
from model_bakery import baker

from autotasks.tasks import (
    create_win_task_schedule,
    delete_win_task_schedule,
    handle_resolved_task_email_alert,
    handle_resolved_task_sms_alert,
    handle_task_email_alert,
    handle_task_sms_alert,
    remove_orphaned_win_tasks,
)
from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase


class TestAutotaskTasks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent")
        self.task = baker.make(
            "autotasks.AutomatedTask", agent=self.agent, name="Cleanup"
        )

    def test_schedule_tasks_call_the_model_and_skip_missing_rows(self):
        for celery_task, method in (
            (create_win_task_schedule, "create_task_on_agent"),
            (delete_win_task_schedule, "delete_task_on_agent"),
        ):
            with self.subTest(method), patch(
                f"autotasks.models.AutomatedTask.{method}"
            ) as call:
                self.assertEqual(celery_task(self.task.pk), "ok")
                call.assert_called_once_with()
                self.assertEqual(celery_task(self.task.pk, self.agent.agent_id), "ok")
                self.assertEqual(call.call_args.args[0].pk, self.agent.pk)
                self.assertEqual(celery_task(self.task.pk + 100), "ok")
                self.assertEqual(call.call_count, 2)

    @patch("alerts.tasks.sleep")
    def test_task_notifications_go_out_once(self, _):
        baker.make("autotasks.TaskResult", agent=self.agent, task=self.task)
        alert = baker.make(
            "alerts.Alert",
            agent=self.agent,
            assigned_task=self.task,
            alert_type=AlertType.TASK,
        )
        cases = (
            (handle_task_email_alert, "send_email", "email_sent"),
            (handle_task_sms_alert, "send_sms", "sms_sent"),
            (
                handle_resolved_task_email_alert,
                "send_resolved_email",
                "resolved_email_sent",
            ),
            (handle_resolved_task_sms_alert, "send_resolved_sms", "resolved_sms_sent"),
        )
        for task, method, stamp in cases:
            with self.subTest(task.name), patch(
                f"autotasks.models.TaskResult.{method}"
            ) as send:
                self.assertEqual(task(alert.pk), "ok")
                task(alert.pk)
                send.assert_called_once()
                alert.refresh_from_db()
                self.assertIsNotNone(getattr(alert, stamp))

    # the late-creation lookup would open a second connection from the async thread
    @patch(
        "django.db.models.QuerySet.aexists", new_callable=AsyncMock, return_value=False
    )
    @patch("autotasks.tasks.nats.connect", new_callable=AsyncMock)
    def test_orphan_sweep_deletes_only_unknown_rmm_tasks(self, connect, _):
        listed = [
            self.task.win_task_name,
            "ULRMM_gone",
            "ULRMM_SchedReboot_x",
            "OtherVendorTask",
        ]
        nc = MagicMock(
            request=AsyncMock(return_value=MagicMock(data=msgpack.dumps(listed))),
            publish=AsyncMock(),
            flush=AsyncMock(),
            close=AsyncMock(),
        )
        connect.return_value = nc

        self.assertEqual(remove_orphaned_win_tasks(), "completed")
        nc.publish.assert_awaited_once()
        subject, payload = nc.publish.await_args.args
        self.assertEqual(subject, self.agent.agent_id)
        self.assertEqual(
            msgpack.loads(payload),
            {"func": "delschedtask", "schedtaskpayload": {"name": "ULRMM_gone"}},
        )

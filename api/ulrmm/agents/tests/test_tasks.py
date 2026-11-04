# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents import tasks
from agents.models import AgentHistory
from logs.models import DebugLog
from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase


class TestAgentTasks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.overdue_agent")

    @patch("alerts.tasks.sleep")
    def test_availability_notifications_go_out_once(self, _):
        alert = baker.make(
            "alerts.Alert", agent=self.agent, alert_type=AlertType.AVAILABILITY
        )
        cases = (
            (tasks.agent_outage_email_task, "send_outage_email", "email_sent"),
            (tasks.agent_outage_sms_task, "send_outage_sms", "sms_sent"),
            (
                tasks.agent_recovery_email_task,
                "send_recovery_email",
                "resolved_email_sent",
            ),
            (tasks.agent_recovery_sms_task, "send_recovery_sms", "resolved_sms_sent"),
        )
        for task, method, stamp in cases:
            with self.subTest(task.name), patch(
                f"agents.models.Agent.{method}"
            ) as send:
                self.assertEqual(task(alert.pk), "ok")
                task(alert.pk)
                send.assert_called_once()
                alert.refresh_from_db()
                self.assertIsNotNone(getattr(alert, stamp))
        self.assertEqual(tasks.agent_outage_email_task(alert.pk + 1), "alert not found")

    @patch("alerts.models.Alert.handle_alert_failure")
    def test_outages_task_raises_only_overdue_agents(self, failure):
        baker.make_recipe("agents.online_agent")
        # silent as long, but nobody watches it: shut down, not overdue
        baker.make_recipe("agents.overdue_agent", overdue_dashboard_alert=False)
        self.assertEqual(tasks.agent_outages_task(), "completed")
        failure.assert_called_once()
        self.assertEqual(failure.call_args.args[0].pk, self.agent.pk)

    @patch("agents.tasks.call_command")
    def test_auto_update_runs_the_command_unless_disabled(self, call_command):
        tasks.auto_self_agent_update_task()
        call_command.assert_called_once_with("update_agents")
        call_command.reset_mock()
        with override_settings(ULRMM_DISABLE_AGENT_AUTO_UPDATE_TASK=True):
            tasks.auto_self_agent_update_task()
        call_command.assert_not_called()

    def test_prune_agent_history_keeps_recent_rows(self):
        old, recent = baker.make("agents.AgentHistory", agent=self.agent, _quantity=2)
        AgentHistory.objects.filter(pk=old.pk).update(
            time=djangotime.now() - timedelta(days=40)
        )
        tasks.prune_agent_history(30)
        self.assertEqual(
            list(AgentHistory.objects.values_list("pk", flat=True)), [recent.pk]
        )

    @patch("core.models.CoreSettings.send_mail", return_value=("ok", True))
    @patch("agents.models.Agent.run_script")
    def test_script_results_mail(self, run_script, send_mail):
        script = baker.make("scripts.Script", name="Disk report")
        run_script.return_value = {
            "retcode": 0,
            "stdout": "fine",
            "stderr": "",
            "execution_time": 1.5,
        }
        tasks.run_script_email_results_task(
            self.agent.pk, script.pk, 30, ["ops@example.com"]
        )
        subject, body = send_mail.call_args.args
        self.assertTrue(subject.endswith(f"{self.agent.hostname} Disk report Results"))
        self.assertIn("Execution time: 1.5000 seconds", body)
        self.assertEqual(
            send_mail.call_args.kwargs, {"override_recipients": ["ops@example.com"]}
        )

        send_mail.reset_mock()
        run_script.return_value = "timeout"
        tasks.run_script_email_results_task(self.agent.pk, script.pk, 30, [])
        send_mail.assert_not_called()
        self.assertTrue(DebugLog.objects.filter(message__contains="timed out").exists())

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone as djangotime
from model_bakery import baker

from checks import tasks
from checks.models import CheckHistory
from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase


class TestCheckTasks(ULRMMTestCase):
    def setUp(self):
        self.agent = baker.make_recipe("agents.agent")
        self.check = baker.make_recipe("checks.ping_check", agent=self.agent)

    @patch("alerts.tasks.sleep")
    def test_check_notifications_go_out_once(self, _):
        alert = baker.make(
            "alerts.Alert",
            agent=self.agent,
            assigned_check=self.check,
            alert_type=AlertType.CHECK,
        )
        self.assertEqual(
            tasks.handle_check_email_alert_task(alert.pk), "check result not found"
        )
        baker.make("checks.CheckResult", agent=self.agent, assigned_check=self.check)

        cases = (
            (tasks.handle_check_email_alert_task, "send_email", "email_sent"),
            (tasks.handle_check_sms_alert_task, "send_sms", "sms_sent"),
            (
                tasks.handle_resolved_check_email_alert_task,
                "send_resolved_email",
                "resolved_email_sent",
            ),
            (
                tasks.handle_resolved_check_sms_alert_task,
                "send_resolved_sms",
                "resolved_sms_sent",
            ),
        )
        for task, method, stamp in cases:
            with self.subTest(task.name), patch(
                f"checks.models.CheckResult.{method}"
            ) as send:
                self.assertEqual(task(alert.pk), "ok")
                task(alert.pk)
                send.assert_called_once()
                alert.refresh_from_db()
                self.assertIsNotNone(getattr(alert, stamp))

    @patch("checks.models.CheckResult.send_email", return_value=("boom", False))
    @patch("alerts.tasks.sleep")
    def test_failed_send_hands_the_claim_back(self, *_):
        baker.make("checks.CheckResult", agent=self.agent, assigned_check=self.check)
        alert = baker.make(
            "alerts.Alert",
            agent=self.agent,
            assigned_check=self.check,
            alert_type=AlertType.CHECK,
        )
        self.assertEqual(tasks.handle_check_email_alert_task(alert.pk), "send failed")
        alert.refresh_from_db()
        self.assertIsNone(alert.email_sent)

    def test_prune_check_history(self):
        old, recent = baker.make(
            "checks.CheckHistory",
            check_id=self.check.pk,
            agent_id=self.agent.agent_id,
            _quantity=2,
        )
        CheckHistory.objects.filter(pk=old.pk).update(
            x=djangotime.now() - timedelta(days=40)
        )
        tasks.prune_check_history(30)
        self.assertEqual(
            list(CheckHistory.objects.values_list("pk", flat=True)), [recent.pk]
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import PropertyMock, patch

from django.utils import timezone as djangotime
from model_bakery import baker

from agents import tasks as agent_tasks
from alerts.models import Alert
from autotasks import tasks as task_tasks
from checks import tasks as check_tasks
from ulrmm.constants import AlertSeverity, AlertType
from ulrmm.test import ULRMMTestCase


class TestSeverityPeak(ULRMMTestCase):
    def test_flapping_severity_keeps_the_peak_and_the_stamps(self):
        sent = djangotime.now()
        alert = baker.make(
            "alerts.Alert",
            alert_type=AlertType.CHECK,
            severity=AlertSeverity.ERROR,
            email_sent=sent,
            sms_sent=sent,
        )
        for severity in (AlertSeverity.WARNING, AlertSeverity.ERROR):
            alert._sync_severity(severity)
            alert.refresh_from_db()
            self.assertEqual(alert.severity, AlertSeverity.ERROR)
            self.assertEqual((alert.email_sent, alert.sms_sent), (sent, sent))

        # an escalation still clears them
        alert.severity = AlertSeverity.WARNING
        alert.save(update_fields=["severity"])
        alert._sync_severity(AlertSeverity.ERROR)
        alert.refresh_from_db()
        self.assertEqual(alert.severity, AlertSeverity.ERROR)
        self.assertIsNone(alert.email_sent)


@patch(
    "core.models.CoreSettings.email_is_configured",
    new=PropertyMock(return_value=True),
)
@patch("checks.tasks.handle_check_email_alert_task.delay")
class TestMaintenanceWindowSilences(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        check = baker.make_recipe(
            "checks.ping_check",
            agent=self.agent,
            email_alert=True,
            alert_severity=AlertSeverity.ERROR,
        )
        self.result = baker.make(
            "checks.CheckResult", agent=self.agent, assigned_check=check
        )

    def test_open_maintenance_run_queues_no_mail(self, email):
        run = baker.make(
            "patches.ScheduleRun",
            agent=self.agent,
            state="installing",
            schedule__kind="maintenance",
        )
        Alert.handle_alert_failure(self.result)
        email.assert_not_called()
        self.assertFalse(Alert.objects.exists())

        run.delete()
        Alert.handle_alert_failure(self.result)
        email.assert_called_once()


@patch("core.models.CoreSettings.send_sms", return_value=("boom", False))
@patch("core.models.CoreSettings.send_mail", return_value=("boom", False))
@patch("alerts.tasks.sleep")
class TestFailedSendKeepsTheStamp(ULRMMTestCase):
    def test_every_sender_hands_the_claim_back(self, *_):
        self.setup_coresettings()
        agent = baker.make_recipe("agents.agent")
        check = baker.make_recipe("checks.ping_check", agent=agent)
        baker.make("checks.CheckResult", agent=agent, assigned_check=check)
        task = baker.make("autotasks.AutomatedTask", agent=agent, name="t")
        baker.make("autotasks.TaskResult", agent=agent, task=task)
        alerts = {
            "agent": baker.make(
                "alerts.Alert", agent=agent, alert_type=AlertType.AVAILABILITY
            ),
            "check": baker.make(
                "alerts.Alert",
                agent=agent,
                assigned_check=check,
                alert_type=AlertType.CHECK,
            ),
            "task": baker.make(
                "alerts.Alert",
                agent=agent,
                assigned_task=task,
                alert_type=AlertType.TASK,
            ),
        }
        cases = (
            ("agent", agent_tasks.agent_outage_email_task, "email_sent"),
            ("agent", agent_tasks.agent_outage_sms_task, "sms_sent"),
            ("agent", agent_tasks.agent_recovery_email_task, "resolved_email_sent"),
            ("agent", agent_tasks.agent_recovery_sms_task, "resolved_sms_sent"),
            ("check", check_tasks.handle_check_email_alert_task, "email_sent"),
            ("check", check_tasks.handle_check_sms_alert_task, "sms_sent"),
            (
                "check",
                check_tasks.handle_resolved_check_email_alert_task,
                "resolved_email_sent",
            ),
            (
                "check",
                check_tasks.handle_resolved_check_sms_alert_task,
                "resolved_sms_sent",
            ),
            ("task", task_tasks.handle_task_email_alert, "email_sent"),
            ("task", task_tasks.handle_task_sms_alert, "sms_sent"),
            (
                "task",
                task_tasks.handle_resolved_task_email_alert,
                "resolved_email_sent",
            ),
            ("task", task_tasks.handle_resolved_task_sms_alert, "resolved_sms_sent"),
        )
        for kind, task_fn, stamp in cases:
            with self.subTest(task_fn.name):
                alert = alerts[kind]
                self.assertEqual(task_fn(alert.pk), "send failed")
                alert.refresh_from_db()
                self.assertIsNone(getattr(alert, stamp))


@patch(
    "core.models.CoreSettings.email_is_configured",
    new=PropertyMock(return_value=True),
)
@patch("agents.tasks.agent_recovery_email_task.delay")
class TestRecoveryNeedsAFailureNotice(ULRMMTestCase):
    def test_recovery_mail_only_after_a_failure_mail(self, recovery):
        self.setup_coresettings()
        agent = baker.make_recipe("agents.agent", overdue_email_alert=True)
        for sent in (None, djangotime.now()):
            alert = baker.make(
                "alerts.Alert",
                agent=agent,
                alert_type=AlertType.AVAILABILITY,
                severity=AlertSeverity.ERROR,
                email_sent=sent,
            )
            Alert.handle_alert_resolve(agent)
            alert.refresh_from_db()
            self.assertTrue(alert.resolved)
        recovery.assert_called_once_with(pk=alert.pk)


class TestStandIn(ULRMMTestCase):
    def test_pings_a_few_online_agents_at_once(self):
        from agents.models import Agent
        from alerts.models import _stand_in_agent

        site = baker.make("clients.Site")
        now = djangotime.now()
        alerting = baker.make_recipe("agents.agent", site=site, last_seen=None)
        baker.make_recipe("agents.agent", site=site, last_seen=None)
        # the newest check-ins first, not the lowest pk
        online = [
            baker.make_recipe(
                "agents.agent", site=site, last_seen=now - dt.timedelta(seconds=40 - i)
            )
            for i in range(4)
        ]
        other_site = baker.make("clients.Site", client=site.client)
        baker.make_recipe("agents.agent", site=other_site, last_seen=now)
        pinged = []

        async def nats_cmd(self, data, timeout=30, wait=True):
            pinged.append(self.pk)
            return "pong" if self.pk == online[2].pk else "timeout"

        with patch.object(Agent, "nats_cmd", nats_cmd):
            self.assertEqual(_stand_in_agent(alerting), online[2])
            self.assertEqual(sorted(pinged), sorted(a.pk for a in online[1:]))
            pinged.clear()
            online[2].delete()
            self.assertIsNone(_stand_in_agent(alerting))
            self.assertEqual(len(pinged), 3)

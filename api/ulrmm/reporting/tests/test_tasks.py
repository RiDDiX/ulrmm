# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.utils import timezone as djangotime
from model_bakery import baker

from core.tasks import core_maintenance_tasks
from logs.models import AuditLog
from reporting.models import ReportHistory
from reporting.tasks import (
    claim,
    email_report,
    prune_report_history_task,
    scheduled_reports_runner,
)
from reporting.tasks import is_due as real_due
from reporting.utils import run_scheduled_report as real_run
from ulrmm.test import ULRMMTestCase

UTC = dt.timezone.utc


class TestPrune(ULRMMTestCase):
    def test_prune(self):
        template = baker.make("reporting.ReportTemplate")
        old = baker.make("reporting.ReportHistory", report_template=template)
        new = baker.make("reporting.ReportHistory", report_template=template)
        now = djangotime.now()
        ReportHistory.objects.filter(pk=old.pk).update(
            date_created=now - dt.timedelta(days=10)
        )
        ReportHistory.objects.filter(pk=new.pk).update(
            date_created=now - dt.timedelta(days=1)
        )
        self.assertEqual(prune_report_history_task(5), "ok")
        self.assertEqual(
            list(ReportHistory.objects.values_list("pk", flat=True)), [new.pk]
        )

    @patch("core.tasks.prune_report_history_task.delay")
    def test_core_maintenance(self, delay):
        self.setup_coresettings()
        self.coresettings.report_history_prune_days = 0
        self.coresettings.save()
        core_maintenance_tasks()
        delay.assert_not_called()

        self.coresettings.report_history_prune_days = 30
        self.coresettings.save()
        core_maintenance_tasks()
        delay.assert_called_once_with(30)


class TestRunner(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.default_time_zone = "UTC"
        self.coresettings.save()
        self.template = baker.make(
            "reporting.ReportTemplate", name="Daily", template_md="hi", type="html"
        )
        # 12:30 UTC is 14:30 in Berlin in summer
        self.now = dt.datetime(2026, 7, 15, 12, 30, tzinfo=UTC)
        self.addCleanup(patch.stopall)
        patch("reporting.tasks.djangotime.now", return_value=self.now).start()
        self.delay = patch("reporting.tasks.email_report.delay").start()

    def make_schedule(self, timezone="Europe/Berlin", **core):
        core.setdefault("schedule_type", "daily")
        core.setdefault("run_time", dt.time(14, 30))
        return baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            schedule=baker.make("core.Schedule", **core),
            timezone=timezone,
            dependencies={},
            email_recipients=["a@example.com"],
        )

    def ran(self, schedule) -> bool:
        schedule.refresh_from_db()
        return schedule.last_run is not None

    def test_daily_in_schedule_zone(self):
        schedule = self.make_schedule()
        scheduled_reports_runner()
        schedule.refresh_from_db()
        self.assertEqual(schedule.locked_at, self.now)
        self.assertIsNotNone(schedule.last_run)
        history = ReportHistory.objects.get()
        self.assertEqual(history.run_by, "system")
        self.delay.assert_called_once()
        self.assertEqual(self.delay.call_args.kwargs["template_name"], "Daily")

    def test_invalid_zone_uses_default(self):
        utc = self.make_schedule(timezone="Not/AZone", run_time=dt.time(12, 30))
        berlin_time = self.make_schedule(timezone="", run_time=dt.time(14, 30))
        scheduled_reports_runner()
        self.assertTrue(self.ran(utc))
        self.assertFalse(self.ran(berlin_time))

    def test_lock(self):
        recent = self.make_schedule()
        recent.locked_at = self.now - dt.timedelta(seconds=30)
        recent.save()
        stale = self.make_schedule()
        stale.locked_at = self.now - dt.timedelta(minutes=2)
        stale.save()
        scheduled_reports_runner()
        self.assertFalse(self.ran(recent))
        self.assertTrue(self.ran(stale))

        # a second claim in the same minute fails
        self.assertFalse(claim(stale, self.now))

    def test_disabled(self):
        schedule = self.make_schedule()
        schedule.enabled = False
        schedule.save()
        scheduled_reports_runner()
        self.assertFalse(self.ran(schedule))

    def test_weekly(self):
        weekday = self.now.astimezone(ZoneInfo("Europe/Berlin")).weekday()
        today = self.make_schedule(schedule_type="weekly", run_time_weekdays=[weekday])
        other = self.make_schedule(
            schedule_type="weekly", run_time_weekdays=[(weekday + 1) % 7]
        )
        scheduled_reports_runner()
        self.assertTrue(self.ran(today))
        self.assertFalse(self.ran(other))

    def test_monthly_days(self):
        patch(
            "reporting.tasks.djangotime.now",
            return_value=dt.datetime(2026, 4, 30, 12, 30, tzinfo=UTC),
        ).start()
        last_day = self.make_schedule(
            schedule_type="monthly",
            monthly_type="days",
            monthly_days_of_month=[32],
            monthly_months_of_year=[4],
        )
        wrong_month = self.make_schedule(
            schedule_type="monthly",
            monthly_type="days",
            monthly_days_of_month=[30],
            monthly_months_of_year=[5],
        )
        scheduled_reports_runner()
        self.assertTrue(self.ran(last_day))
        self.assertFalse(self.ran(wrong_month))

    def test_monthly_weeks(self):
        # 29 July 2026, a Wednesday, in the last week of a 31 day month
        now = dt.datetime(2026, 7, 29, 12, 30, tzinfo=UTC)
        patch("reporting.tasks.djangotime.now", return_value=now).start()
        schedule = self.make_schedule(
            schedule_type="monthly",
            monthly_type="weeks",
            monthly_weeks_of_month=[5],
            monthly_months_of_year=[7],
            run_time_weekdays=[2],
        )
        scheduled_reports_runner()
        self.assertTrue(self.ran(schedule))

    def test_one_failure_does_not_stop_the_rest(self):
        broken = self.make_schedule()
        first = self.make_schedule()
        second = self.make_schedule()

        def due(schedule, now, zone):
            if schedule.pk == broken.schedule_id:
                raise TypeError("bad schedule")
            return real_due(schedule, now, zone)

        def run(schedule, user=None):
            if schedule.pk == first.pk:
                raise RuntimeError("boom")
            return real_run(schedule, user)

        with patch("reporting.tasks.is_due", side_effect=due), patch(
            "reporting.tasks.run_scheduled_report", side_effect=run
        ):
            scheduled_reports_runner()
        self.assertFalse(self.ran(broken))
        self.assertTrue(self.ran(second))

    def test_failed_run_sends_no_email(self):
        self.template.template_md = "{% if %}"
        self.template.save()
        self.make_schedule()
        scheduled_reports_runner()
        self.delay.assert_not_called()
        self.assertTrue(ReportHistory.objects.get().error_data)

    def test_runs_use_the_owner_scope(self):
        client = baker.make("clients.Client")
        baker.make_recipe(
            "agents.agent", site=baker.make("clients.Site", client=client)
        )
        baker.make_recipe("agents.agent")
        owner = self.create_user_with_roles(["can_manage_reports"])
        owner.role.can_view_clients.set([client])
        self.template.template_md = "{{ data_sources.agents }}"
        self.template.template_variables = (
            "data_sources:\n  agents: {model: agent, count: true}"
        )
        self.template.save()
        owned = self.make_schedule()
        owned.owner = owner
        owned.save()
        unowned = self.make_schedule()

        scheduled_reports_runner()
        rows = dict(ReportHistory.objects.values_list("run_by", "report_data"))
        self.assertEqual(rows, {owner.username: "1", "system": "2"})
        self.assertTrue(self.ran(unowned))
        rows = set(ReportHistory.objects.values_list("user", "schedule"))
        self.assertEqual(rows, {(owner.pk, owned.pk), (None, unowned.pk)})

    def test_owner_who_lost_access_is_skipped(self):
        owner = self.create_user_with_roles(["can_view_reports"])
        role = owner.role
        schedule = self.make_schedule()
        schedule.owner = owner
        schedule.save()

        def lose_view():
            role.can_view_reports = False
            role.save()

        def remove_role():
            owner.role = None
            owner.save()

        def block():
            owner.block_dashboard_login = True
            owner.save()

        def disable():
            owner.is_active = False
            owner.save()

        for change, reason in (
            (lose_view, "may no longer view reports"),
            (remove_role, "may no longer view reports"),
            (block, "blocked from dashboard login"),
            (disable, "disabled"),
        ):
            with self.subTest(reason=reason):
                change()
                self.delay.reset_mock()
                ReportHistory.objects.all().delete()
                fresh = type(schedule).objects.get(pk=schedule.pk)
                history, error = real_run(fresh)
                self.assertIn(reason, error)
                self.assertEqual(history.error_data, error)
                self.assertEqual((history.user, history.schedule), (owner, fresh))
                self.delay.assert_not_called()

                owner.refresh_from_db()
                role.can_view_reports = True
                role.save()
                owner.role = role
                owner.block_dashboard_login = False
                owner.is_active = True
                owner.save()

        history, error = real_run(type(schedule).objects.get(pk=schedule.pk))
        self.assertIsNone(error)
        self.delay.assert_called_once()

    def test_runner_writes_no_audit(self):
        self.make_schedule()
        AuditLog.objects.all().delete()
        scheduled_reports_runner()
        self.assertFalse(AuditLog.objects.filter(object_type="reportschedule").exists())


@patch("core.models.CoreSettings.send_mail", return_value=("ok", True))
class TestEmailTask(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_defaults(self, send_mail):
        email_report(template_name="Weekly", attachment="<p>", attachment_type="html")
        kwargs = send_mail.call_args.kwargs
        self.assertEqual(kwargs["subject"], "Scheduled Report: Weekly")
        self.assertEqual(kwargs["body"], "Your report is attached.")
        self.assertEqual(kwargs["attachment_filename"], "Weekly")
        self.assertEqual(kwargs["override_recipients"], [])

    def test_link_block_and_options(self, send_mail):
        email_report(
            template_name="Weekly",
            recipients=["a@example.com"],
            subject="Hello\r\nBcc: x@example.com",
            body="Body",
            attachment="<p>",
            attachment_type="html",
            attachment_name="custom",
            report_link="https://rmm.example.com/reports/history/1/?format=html",
            include_report_link=True,
        )
        kwargs = send_mail.call_args.kwargs
        self.assertEqual(kwargs["subject"], "Hello Bcc: x@example.com")
        self.assertEqual(
            kwargs["body"],
            "Body\n\nView the report online:\n\n"
            "https://rmm.example.com/reports/history/1/?format=html",
        )
        self.assertEqual(kwargs["override_recipients"], ["a@example.com"])
        self.assertEqual(kwargs["attachment_filename"], "custom")

    def test_pdf_is_decoded(self, send_mail):
        email_report(
            template_name="Weekly",
            attachment=base64.b64encode(b"%PDF-1").decode(),
            attachment_type="pdf",
        )
        self.assertEqual(send_mail.call_args.kwargs["attachment"], b"%PDF-1")

    def test_plaintext_extension(self, send_mail):
        email_report(
            template_name="Weekly",
            attachment="a,b",
            attachment_type="plaintext",
            attachment_extension="csv",
        )
        kwargs = send_mail.call_args.kwargs
        self.assertEqual(kwargs["attachment_extension"], "csv")
        self.assertEqual(kwargs["attachment_type"], "plaintext")

    def test_unvalidated_settings_are_not_trusted(self, send_mail):
        for extension in ("../x", "csv\n", "toolongext", 5, ""):
            with self.subTest(extension=extension):
                email_report(
                    template_name="Weekly",
                    attachment="a",
                    attachment_type="plaintext",
                    attachment_extension=extension,
                )
                self.assertIsNone(send_mail.call_args.kwargs["attachment_extension"])
        email_report(
            template_name="Weekly",
            attachment="<p>",
            attachment_type="html",
            report_link="https://rmm.example.com/reports/history/1/?format=html",
            include_report_link="false",
        )
        self.assertEqual(send_mail.call_args.kwargs["body"], "Your report is attached.")

    def test_no_attachment_and_failure_logged(self, send_mail):
        send_mail.return_value = ("SMTP messaging not configured.", False)
        with patch("reporting.tasks.logger.error") as log:
            email_report(template_name="Weekly")
        # empty recipients let the mailer fall back to the alert recipients
        self.assertEqual(send_mail.call_args.kwargs["override_recipients"], [])
        self.assertIsNone(send_mail.call_args.kwargs["attachment"])
        log.assert_called_once()

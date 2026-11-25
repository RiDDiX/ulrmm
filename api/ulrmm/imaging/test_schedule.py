# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.utils import timezone

from logs.models import AuditLog

from . import resolver
from .models import BackupRun, DeviceBackupState, Image, ImageStatus, Profile, Transfer
from .service import backup_rows, queue_capture
from .tasks import imaging_tick
from .test_poll import PollBase


def at(*args):
    return datetime(*args, tzinfo=UTC)


class TestOccurrences(PollBase):
    def vals(self, schedule, zone="Europe/Berlin", **kw):
        return {
            **resolver.DEFAULTS,
            "schedule": schedule,
            "timezone": zone,
            "min_spacing_minutes": 0,
            **kw,
        }

    def next(self, schedule, after, state=None, **kw):
        return resolver.next_occurrence(
            self.vals(schedule, **kw), state, after, self.agent
        )

    def test_daily_dst_spring_and_fall(self):
        daily = {"kind": "daily", "time": "02:30"}
        # 02:30 does not exist on 29 March: the run moves forward to 03:30 CEST
        self.assertEqual(self.next(daily, at(2026, 3, 28, 12)), at(2026, 3, 29, 1, 30))
        # 02:30 exists twice on 25 October: the first one counts
        self.assertEqual(
            self.next(daily, at(2026, 10, 24, 12)), at(2026, 10, 25, 0, 30)
        )

    def test_interval_since_success_and_floor(self):
        state = DeviceBackupState.objects.get(agent=self.agent)
        state.last_success_at = at(2026, 11, 24, 10)
        interval = {"kind": "interval", "hours": 6}
        point = Image.objects.create(
            agent=self.agent,
            destination="images",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
            status=ImageStatus.VERIFIED,
        )
        Image.objects.filter(pk=point.pk).update(created_at=at(2026, 11, 24, 10))
        self.assertEqual(
            self.next(interval, at(2026, 11, 24, 10), state, min_spacing_minutes=60),
            at(2026, 11, 24, 16),
        )
        # without a success (a failed run) the spacing after the newest point counts
        self.assertEqual(
            self.next(interval, at(2026, 11, 24, 10, 5), None, min_spacing_minutes=60),
            at(2026, 11, 24, 11),
        )

    def test_calendar_via_recurrence(self):
        weekly = {
            "kind": "calendar",
            "frequency": "weekly",
            "run_time": "09:00",
            "weekdays": [0],
            "month_day": None,
            "month_week": None,
            "month_weekday": None,
            "dates": [],
            "excluded_dates": ["2026-11-30"],
            "start_date": None,
            "end_date": None,
        }
        # Tuesday 24 November; Monday 30 is excluded
        self.assertEqual(self.next(weekly, at(2026, 11, 24, 12)), at(2026, 12, 7, 8))

    def test_cron_and_semantics(self):
        monday = {"kind": "cron", "expr": "0 3 * * 1"}
        self.assertEqual(
            self.next(monday, at(2026, 11, 24, 12), zone="UTC"), at(2026, 11, 30, 3)
        )
        # day of month and day of week must both match: the next Friday the 13th
        friday13 = {"kind": "cron", "expr": "0 3 13 * 5"}
        self.assertEqual(
            self.next(friday13, at(2026, 11, 24), zone="UTC"), at(2027, 8, 13, 3)
        )

    def test_cron_dst(self):
        cron = {"kind": "cron", "expr": "30 2 * * *"}
        self.assertEqual(self.next(cron, at(2026, 3, 28, 12)), at(2026, 3, 29, 1, 30))

    def test_coalesce_count(self):
        daily = self.vals({"kind": "daily", "time": "05:00"}, zone="UTC")
        old, now = at(2026, 11, 20, 5), at(2026, 11, 23, 6)
        self.assertEqual(resolver.missed(daily, None, old, now, self.agent), 4)
        self.assertEqual(resolver.missed(daily, None, now, now, self.agent), 1)

    def test_windows_defer_and_stop_at(self):
        # Tuesday 24 November 2026, 22:00 to 06:00 belongs to its start day
        night = [{"days": [2], "start": "22:00", "end": "06:00"}]
        vals = self.vals(
            {"kind": "none"}, zone="UTC", windows_allowed=night, stop_at_window_end=True
        )
        self.assertEqual(
            resolver.window(vals, self.agent, at(2026, 11, 24, 21)), (False, None)
        )
        self.assertEqual(
            resolver.window(vals, self.agent, at(2026, 11, 25, 1)),
            (True, at(2026, 11, 25, 6)),
        )
        # Wednesday night is not allowed
        self.assertEqual(
            resolver.window(vals, self.agent, at(2026, 11, 25, 23))[0], False
        )
        blackout = [{"days": [3], "start": "02:00", "end": "02:00"}]
        vals["windows_allowed"], vals["windows_blackout"] = [], blackout
        self.assertEqual(
            resolver.window(vals, self.agent, at(2026, 11, 25, 1)),
            (True, at(2026, 11, 25, 2)),
        )
        self.assertEqual(
            resolver.window(vals, self.agent, at(2026, 11, 26, 1))[0], False
        )


class TestTick(PollBase):
    def due(self, **overrides):
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides=overrides)
        resolver.resolve_device(self.agent, cause="device")
        Profile.objects.filter(pk=profile.pk).update(
            next_run=timezone.now() - timedelta(minutes=1)
        )
        return Profile.objects.get(pk=profile.pk)

    def audits(self, text):
        return AuditLog.objects.filter(message=text).count()

    def test_catch_up_skip_offline(self):
        self.due(schedule={"kind": "daily", "time": "03:00"}, catch_up="skip")
        imaging_tick()
        self.assertFalse(Image.objects.exists())
        self.assertEqual(
            self.audits("Scheduled backup missed while the device was offline."), 1
        )
        self.assertGreater(
            Profile.objects.get(agent=self.agent).next_run, timezone.now()
        )

    def test_not_supported_skip_audited(self):
        self.cap.update(ready=False, reason="VSS is disabled.")
        self.poll()
        self.due(schedule={"kind": "daily", "time": "03:00"})
        imaging_tick()
        self.assertFalse(Image.objects.exists())
        self.assertEqual(self.audits("Scheduled backup skipped: VSS is disabled."), 1)

    def test_coalesce_audit(self):
        now = timezone.now()
        profile = self.due(schedule={"kind": "interval", "hours": 1})
        Profile.objects.filter(pk=profile.pk).update(
            next_run=now - timedelta(minutes=150)
        )
        imaging_tick()
        self.assertEqual(self.audits("3 missed backup runs coalesced into one."), 1)
        self.assertEqual(Image.objects.filter(trigger="schedule").count(), 1)

    def test_waiting_point_replaced(self):
        self.due(schedule={"kind": "daily", "time": "03:00"})
        imaging_tick()
        first = Image.objects.get()
        self.assertEqual(first.trigger, "schedule")
        Profile.objects.filter(agent=self.agent).update(
            next_run=timezone.now() - timedelta(minutes=1)
        )
        Image.objects.filter(pk=first.pk).update(
            created_at=timezone.now() - timedelta(days=1)
        )
        imaging_tick()
        second = Image.objects.get()
        self.assertNotEqual(second.pk, first.pk)
        self.assertEqual(
            self.audits(f"Waiting backup point {first.pk} replaced by {second.pk}."), 1
        )

    def test_claimed_point_not_replaced(self):
        profile = self.due(schedule={"kind": "daily", "time": "03:00"})
        point = queue_capture(profile, "imaging scheduler", trigger="schedule")
        self.assertEqual(self.poll().status_code, 200)
        self.assertIsNone(
            queue_capture(profile, "imaging scheduler", trigger="schedule")
        )
        self.assertTrue(Image.objects.filter(pk=point.pk).exists())
        # the scheduler retries soon, an open point writes no audit row
        self.assertEqual(
            self.audits(
                "Scheduled backup skipped: another backup point is still open."
            ),
            0,
        )

    def test_offline_and_manual_points_not_replaced(self):
        profile = self.due(schedule={"kind": "daily", "time": "03:00"})
        manual = self.queue()
        self.assertIsNone(queue_capture(profile, "imaging scheduler", trigger="event"))
        self.assertTrue(Image.objects.filter(pk=manual.pk).exists())
        Image.objects.filter(pk=manual.pk).update(
            trigger="schedule", native={"method": "linux-offline-disk-v1"}
        )
        self.assertIsNone(
            queue_capture(profile, "imaging scheduler", trigger="schedule")
        )
        self.assertTrue(Image.objects.filter(pk=manual.pk).exists())


class TestClaimDeferrals(PollBase):
    def setUp(self):
        super().setUp()
        self.profile, _ = backup_rows(self.agent)

    def save(self, **overrides):
        Profile.objects.filter(pk=self.profile.pk).update(overrides=overrides)
        resolver.resolve_device(self.agent, cause="device")

    def deferred(self):
        run = BackupRun.objects.get()
        return run.deferred_reason, Image.objects.get(pk=run.image_id).reason

    def test_windows_defer(self):
        now = timezone.now()
        day = now.isoweekday() % 7 + 1
        self.save(
            windows_allowed=[{"days": [day], "start": "10:00", "end": "11:00"}],
            timezone="UTC",
        )
        self.queue()
        self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(self.deferred(), ("window", "Waiting for the backup window."))

    def test_stop_at_in_claim(self):
        from deploy import envelope

        now = timezone.now()
        end = (now + timedelta(hours=2)).replace(second=0, microsecond=0)
        self.save(
            windows_blackout=[
                {"days": [end.isoweekday()], "start": f"{end:%H:%M}", "end": "00:00"}
            ],
            stop_at_window_end=True,
            timezone="UTC",
        )
        self.identity()
        self.queue()
        with patch(
            "imaging.native.envelope.seal_response", wraps=envelope.seal_response
        ) as seal:
            self.assertEqual(self.poll(protocol=2, seal=True).status_code, 200)
        self.assertEqual(seal.call_args.args[2]["stop_at"], int(end.timestamp() * 1000))

    def test_on_battery_deferral(self):
        self.identity()
        self.queue()
        r = self.poll(protocol=2, seal=True, deferred="on_battery")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(self.deferred(), ("on_battery", "Waiting for AC power."))

    def test_legacy_catch_up_uses_first_poll_after_gap(self):
        daily = {"kind": "daily", "time": "03:00"}
        self.save(schedule=daily)
        image = queue_capture(
            Profile.objects.get(pk=self.profile.pk),
            "imaging scheduler",
            trigger="schedule",
        )
        Image.objects.filter(pk=image.pk).update(
            created_at=timezone.now() - timedelta(hours=1)
        )
        DeviceBackupState.objects.filter(agent=self.agent).update(
            last_poll_at=timezone.now() - timedelta(minutes=20)
        )
        self.assertEqual(self.poll().status_code, 204)
        code, reason = self.deferred()
        self.assertEqual(code, "catch_up_delay")
        self.assertTrue(reason.startswith("The device is back online; the missed"))
        # the next poll keeps the start time of the gap
        self.assertEqual(self.poll().status_code, 204)
        self.save(schedule=daily, catch_up_delay_minutes=0)
        self.assertEqual(self.poll().status_code, 200)

    def test_event_point_and_spacing(self):
        self.save(schedule_events=["agent_start"])
        events = {"on_ac": True, "up_since": 1764000000000, "events": ["agent_start"]}
        self.assertEqual(self.poll(protocol=2, conditions=events).status_code, 204)
        point = Image.objects.get()
        self.assertEqual((point.trigger, point.operator), ("event", None))
        point.status = ImageStatus.FAILED
        point.save(update_fields=["status"])
        # within the spacing after the newest point no event point is queued
        self.poll(protocol=2, conditions=events)
        self.assertEqual(Image.objects.count(), 1)
        Image.objects.update(created_at=timezone.now() - timedelta(hours=2))
        self.poll(protocol=2, conditions={**events, "events": ["ac_connected"]})
        self.assertEqual(Image.objects.count(), 1)
        self.poll(protocol=2, conditions=events)
        self.assertEqual(Image.objects.count(), 2)

    def test_quota_refuses_and_deletes_nothing(self):
        state = DeviceBackupState.objects.get(agent=self.agent)
        target = self.profile.target_id
        DeviceBackupState.objects.filter(pk=state.pk).update(usage={str(target): 100})
        self.save(quota_bytes=100)
        old = Image.objects.create(
            agent=self.agent,
            destination="images",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
            status=ImageStatus.VERIFIED,
            target_id=target,
        )
        self.queue()
        self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(
            self.deferred(),
            ("quota_device", "The backup quota of this device is used up."),
        )
        self.assertIn(
            "quota_exceeded", DeviceBackupState.objects.get(pk=state.pk).alerts
        )
        imaging_tick()
        self.assertTrue(Image.objects.filter(pk=old.pk).exists())
        self.assertFalse(Transfer.objects.exists())


class TestScheduleReview(TestTick):
    def test_interval_without_a_point_is_not_due_every_tick(self):
        self.due(schedule={"kind": "interval", "hours": 2}, catch_up="skip")
        imaging_tick()
        imaging_tick()
        self.assertEqual(
            self.audits("Scheduled backup missed while the device was offline."), 1
        )
        due = Profile.objects.get(agent=self.agent).next_run
        self.assertGreater(due, timezone.now() + timedelta(minutes=110))

    def test_replaced_point_keeps_its_blocks_for_the_next_run(self):
        from .models import ImageBlock, ImagePart

        profile = self.due(schedule={"kind": "daily", "time": "03:00"})
        first = queue_capture(profile, "imaging scheduler", trigger="schedule")
        block = ImageBlock.objects.create(
            namespace="n",
            destination="images",
            digest="c" * 64,
            size=1,
            stored_size=1,
            created_at=timezone.now() - timedelta(days=3),
        )
        ImagePart.objects.create(image=first, index=0, block=block)
        second = queue_capture(profile, "imaging scheduler", trigger="schedule")
        self.assertNotEqual(second.pk, first.pk)
        imaging_tick()
        self.assertTrue(ImageBlock.objects.filter(pk=block.pk).exists())

    def test_catch_up_delay_only_for_scheduled_points(self):
        image = self.queue()
        Image.objects.filter(pk=image.pk).update(
            created_at=timezone.now() - timedelta(hours=1)
        )
        DeviceBackupState.objects.filter(agent=self.agent).update(
            last_poll_at=timezone.now() - timedelta(minutes=20)
        )
        self.assertEqual(self.poll().status_code, 200)


class TestOpenPointRetry(TestTick):
    def test_open_point_retries_well_before_a_day(self):
        profile = self.due(schedule={"kind": "interval", "hours": 24})
        point = queue_capture(profile, "imaging scheduler", trigger="schedule")
        self.assertEqual(self.poll().status_code, 200)
        Profile.objects.filter(pk=profile.pk).update(
            next_run=timezone.now() - timedelta(minutes=1)
        )
        imaging_tick()
        due = Profile.objects.get(pk=profile.pk).next_run
        self.assertLess(due, timezone.now() + timedelta(hours=2))
        self.assertFalse(
            AuditLog.objects.filter(
                message__startswith="Scheduled backup skipped"
            ).exists()
        )
        Image.objects.filter(pk=point.pk).update(status=ImageStatus.FAILED)
        Profile.objects.filter(pk=profile.pk).update(next_run=due - timedelta(hours=2))
        imaging_tick()
        self.assertEqual(Image.objects.filter(status="waiting").count(), 1)


class TestQueuedPointFloor(TestTick):
    def test_waiting_point_is_not_replaced_every_tick(self):
        self.due(schedule={"kind": "interval", "hours": 1}, min_spacing_minutes=0)
        imaging_tick()
        first = Image.objects.get()
        due = Profile.objects.get(agent=self.agent).next_run
        self.assertGreaterEqual(due, timezone.now() + timedelta(minutes=14))
        imaging_tick()
        self.assertEqual(Image.objects.get().pk, first.pk)
        self.assertFalse(
            AuditLog.objects.filter(message__startswith="Waiting backup point").exists()
        )


class TestTickIsolation(TestTick):
    def test_one_failing_device_does_not_stop_the_others(self):
        from model_bakery import baker

        from .models import NativeInventory
        from .service import queue_capture as real

        other = baker.make(
            "agents.Agent", plat="windows", goarch="amd64", site=self.agent.site
        )
        NativeInventory.objects.create(agent=other, capability=self.cap)
        broken = self.due(schedule={"kind": "daily", "time": "03:00"})
        backup_rows(other)
        Profile.objects.filter(agent=other).update(
            overrides={"schedule": {"kind": "daily", "time": "03:00"}}
        )
        resolver.resolve_device(other, cause="device")
        Profile.objects.filter(agent=other).update(
            next_run=timezone.now() - timedelta(minutes=1)
        )

        def capture(profile, *args, **kwargs):
            if profile.pk == broken.pk:
                raise KeyError("id")
            return real(profile, *args, **kwargs)

        with patch("imaging.tasks.queue_capture", side_effect=capture):
            imaging_tick()
        self.assertTrue(Image.objects.filter(agent=other).exists())
        self.assertFalse(Image.objects.filter(agent=self.agent).exists())
        due = Profile.objects.get(pk=broken.pk).next_run
        self.assertGreater(due, timezone.now() + timedelta(minutes=14))
        self.assertEqual(self.audits("Scheduled backup failed: internal error."), 1)

    def test_incomplete_stored_report_is_not_ready(self):
        from .models import NativeInventory
        from .service import BAD_REPORT

        bad = {**self.cap, "volumes": [{"mount": "/", "kind": "system"}]}
        r = self.poll(capability=bad)
        self.assertEqual(r.status_code, 400)
        NativeInventory.objects.filter(agent=self.agent).update(capability=bad)
        self.due(schedule={"kind": "daily", "time": "03:00"})
        imaging_tick()
        self.assertFalse(Image.objects.exists())
        self.assertEqual(
            self.audits(f"Scheduled backup skipped: {BAD_REPORT.rstrip('.')}."), 1
        )
        data = self.client.get(self.uri).data
        self.assertEqual((data["ready"], data["not_ready_reason"]), (False, BAD_REPORT))

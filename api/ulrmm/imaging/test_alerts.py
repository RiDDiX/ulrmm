# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from alerts.models import Alert
from notify.dispatch import ALERT_SOURCES
from notify.models import SOURCES

from . import resolver
from .models import BackupPolicy, DeviceBackupState, Profile, StorageTarget
from .service import backup_rows
from .tasks import imaging_tick, imaging_watch
from .test_runs import RunBase


class TestBackupAlerts(RunBase):
    def save(self, **overrides):
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides=overrides)
        resolver.resolve_device(self.agent, cause="device")

    def open_kinds(self):
        return sorted(self.state().alerts)

    def test_each_kind_raises_once_and_resolves(self):
        with patch("notify.dispatch.dispatch") as sent:
            for _ in range(3):
                self.claim()
                self.settle(final={"status": "failed", "reason": "Capture failed: x"})
        self.assertEqual(self.open_kinds(), ["failures_in_row", "run_failed"])
        self.assertEqual(Alert.objects.filter(resolved=False).count(), 2)
        self.assertEqual(sent.call_count, 2)
        self.assertEqual(sent.call_args.args[0]["source"], "backup")
        image = self.claim()
        image.status = "verifying"
        image.save(update_fields=["status"])
        with (
            patch("imaging.tasks.verify_point", return_value=True),
            self.captureOnCommitCallbacks(execute=True),
        ):
            from .tasks import verify_image

            verify_image(str(image.pk))
        self.assertEqual(self.open_kinds(), [])
        self.assertFalse(Alert.objects.filter(resolved=False).exists())
        self.assertEqual(self.state().consecutive_failures, 0)

    def test_stale_beat_rpo_rules(self):
        now = timezone.now()
        vals = {**resolver.DEFAULTS, "timezone": "UTC"}
        rpo = resolver.rpo
        self.assertIsNone(rpo(vals, self.agent, now))
        self.assertEqual(
            rpo({**vals, "rpo_hours": 5}, self.agent, now), timedelta(hours=5)
        )
        interval = {**vals, "schedule": {"kind": "interval", "hours": 6}}
        self.assertEqual(rpo(interval, self.agent, now), timedelta(hours=12))
        daily = {**vals, "schedule": {"kind": "daily", "time": "03:00"}}
        self.assertEqual(rpo(daily, self.agent, now), timedelta(hours=48))
        cron = {**vals, "schedule": {"kind": "cron", "expr": "0 */4 * * *"}}
        self.assertEqual(rpo(cron, self.agent, now), timedelta(hours=8))

        self.save(schedule={"kind": "daily", "time": "03:00"})
        DeviceBackupState.objects.filter(agent=self.agent).update(
            schedule_since=now - timedelta(hours=49)
        )
        imaging_watch()
        imaging_watch()
        self.assertEqual(self.open_kinds(), ["stale"])
        self.assertEqual(Alert.objects.count(), 1)

    def test_quota_high(self):
        target = Profile.objects.get(agent=self.agent).target_id
        self.save(quota_bytes=100)
        DeviceBackupState.objects.filter(agent=self.agent).update(
            usage={str(target): 95}
        )
        imaging_watch()
        self.assertEqual(self.open_kinds(), ["quota_high"])
        DeviceBackupState.objects.filter(agent=self.agent).update(
            usage={str(target): 10}
        )
        imaging_watch()
        self.assertEqual(self.open_kinds(), [])
        StorageTarget.objects.filter(pk=target).update(quota_bytes=100, used_bytes=95)
        with patch("notify.dispatch.dispatch") as sent:
            imaging_watch()
        self.assertEqual(
            sent.call_args.args[0]["dedupe_key"], f"backup:quota90:{target}"
        )

    def fill(self, target):
        from model_bakery import baker

        # another device fills the target, so the usage recompute keeps it full
        other = baker.make("agents.Agent", plat="windows", goarch="amd64")
        backup_rows(other)
        DeviceBackupState.objects.filter(agent=other).update(usage={str(target): 100})
        StorageTarget.objects.filter(pk=target).update(quota_bytes=100, used_bytes=100)

    def test_full_target_alert_stays_until_the_target_has_room(self):
        target = Profile.objects.get(agent=self.agent).target_id
        self.fill(target)
        self.queue()
        with patch("notify.dispatch.dispatch"):
            self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(self.open_kinds(), ["quota_exceeded"])
        with patch("notify.dispatch.notify_alert") as sent:
            imaging_watch()
        self.assertEqual(self.open_kinds(), ["quota_exceeded"])
        sent.assert_not_called()
        StorageTarget.objects.filter(pk=target).update(quota_bytes=1000)
        with patch("notify.dispatch.notify_alert") as sent:
            imaging_watch()
        self.assertEqual(self.open_kinds(), [])
        self.assertTrue(sent.call_args.kwargs["resolved"])

    def test_full_target_of_a_waiting_point_keeps_the_alert(self):
        full = Profile.objects.get(agent=self.agent).target_id
        self.fill(full)
        self.queue()
        roomy = StorageTarget.objects.create(name="roomy")
        self.save(target=roomy.pk)
        self.assertEqual(Profile.objects.get(agent=self.agent).target_id, roomy.pk)
        with patch("notify.dispatch.dispatch"):
            self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(self.open_kinds(), ["quota_exceeded"])
        with patch("notify.dispatch.notify_alert") as sent:
            imaging_watch()
        self.assertEqual(self.open_kinds(), ["quota_exceeded"])
        sent.assert_not_called()
        StorageTarget.objects.filter(pk=full).update(quota_bytes=1000)
        imaging_watch()
        self.assertEqual(self.open_kinds(), [])

    def test_target_unreachable_6h(self):
        with (
            patch("imaging.tasks.directory", side_effect=OSError("gone")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            imaging_tick()
        target = StorageTarget.objects.get(is_default=True)
        self.assertIsNotNone(target.unreachable_since)
        checks = {c["id"]: c for c in self.client.get(self.uri).data["checks"]}
        self.assertEqual(checks["target.reachable"]["state"], "failed")
        with patch("notify.dispatch.dispatch") as sent:
            imaging_watch()
        sent.assert_not_called()
        StorageTarget.objects.update(
            unreachable_since=timezone.now() - timedelta(hours=7)
        )
        with patch("notify.dispatch.dispatch") as sent:
            imaging_watch()
        self.assertEqual(
            sent.call_args.args[0]["dedupe_key"], f"backup:target:{target.pk}"
        )
        imaging_tick()
        self.assertIsNone(StorageTarget.objects.get(pk=target.pk).unreachable_since)

    def test_hook_suspended_notice(self):
        from model_bakery import baker

        script = baker.make("scripts.Script", name="Dump", shell="bash")
        policy = BackupPolicy.objects.create(
            name="Hooks",
            scope="assigned",
            config={
                "hooks": [
                    {
                        "script_id": script.pk,
                        "phase": "pre-backup",
                        "args": [],
                        "env_vars": [],
                        "timeout": 60,
                        "on_fail": "warn",
                    }
                ]
            },
            hooks_pinned={str(script.pk): "0" * 64},
        )
        with patch("notify.dispatch.dispatch") as sent:
            imaging_watch()
        keys = [c.args[0]["dedupe_key"] for c in sent.call_args_list]
        self.assertTrue(
            any(k.startswith(f"backup:hook:{policy.pk}:{script.pk}:") for k in keys)
        )

    def test_smart_warning_from_run(self):
        self.claim()
        warning = {"code": "smart", "detail": "sda: health warning, SMART ok"}
        self.settle(warnings=[warning])
        self.assertEqual(self.open_kinds(), ["smart_warning"])
        self.settle(final={"status": "failed", "reason": "x"})
        self.assertIn("smart_warning", self.open_kinds())
        self.claim()
        self.settle(final={"status": "interrupted", "reason": "x"})
        self.assertNotIn("smart_warning", self.open_kinds())

    def test_backup_source_routes(self):
        self.assertEqual(ALERT_SOURCES["backup"], "backup")
        self.assertIn("backup", SOURCES)


class TestAnswers(RunBase):
    def test_fleet_internal_and_all(self):
        r = self.client.get("/imaging/fleet/?state=legacy")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["internal"])
        self.assertGreaterEqual(r.data["counts"]["all"], 1)
        r = self.client.get("/imaging/fleet/?state=error")
        self.assertEqual(r.data["total"], 0)
        self.assertGreaterEqual(r.data["counts"]["all"], 1)

    def test_target_row_and_device_usage(self):
        row = self.client.get("/imaging/targets/").data[0]
        self.assertIn("storage_encryption", row)
        target = Profile.objects.get(agent=self.agent).target
        DeviceBackupState.objects.filter(agent=self.agent).update(
            usage={str(target.pk): 42}
        )
        usage = self.client.get(self.uri).data["usage"]
        self.assertEqual(
            usage,
            [
                {
                    "target": target.pk,
                    "name": target.name,
                    "stored_bytes": 42,
                    "quota_bytes": 0,
                }
            ],
        )

    def test_default_target_delete_text(self):
        target = StorageTarget.objects.get(is_default=True)
        r = self.client.delete(f"/imaging/targets/{target.pk}/")
        self.assertEqual(
            (r.status_code, r.data["detail"]),
            (409, "The default backup target cannot be deleted."),
        )

    def test_compression_none_keeps_the_stored_level(self):
        body = {"set": {"compression": "none"}}
        r = self.client.put(self.uri, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(
            Profile.objects.get(agent=self.agent).overrides, {"compression": "none"}
        )
        fields = r.data["effective"]["fields"]
        self.assertEqual(fields["compression_level"]["value"], 0)

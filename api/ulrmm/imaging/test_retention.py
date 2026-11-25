# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.conf import settings
from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE

from .models import Image, ImageStatus, Profile, StorageTarget, Transfer
from .retention import plan
from .tasks import _batch, imaging_tick, prune_device
from .test_poll import PollBase

BERLIN = ZoneInfo("Europe/Berlin")
GFS = {"hourly": 0, "daily": 3, "weekly": 3, "monthly": 2, "yearly": 0}


def point(n, *local, protected=False):
    when = datetime(*local, tzinfo=BERLIN)
    return SimpleNamespace(id=n, snapshot_at=when, created_at=when, protected=protected)


EXAMPLE = [
    point(1, 2026, 11, 24, 9, 10),
    point(2, 2026, 11, 23, 21, 5),
    point(3, 2026, 11, 23, 12, 40),
    point(4, 2026, 11, 20, 8, 30),
    point(5, 2026, 11, 19, 8, 30),
    point(6, 2026, 11, 12, 8, 30),
    point(7, 2026, 11, 5, 8, 30),
    point(8, 2026, 10, 30, 8, 30),
    point(9, 2026, 10, 29, 8, 30),
    point(10, 2026, 10, 2, 8, 30),
    point(11, 2026, 9, 28, 8, 30),
]


class TestPlan(SimpleTestCase):
    def test_worked_example_vector(self):
        rules = plan(EXAMPLE, 2, GFS, BERLIN, set())
        self.assertEqual(
            rules,
            {
                1: [
                    "newest",
                    "keep_last",
                    "daily 2026-11-24",
                    "weekly 2026-W48",
                    "monthly 2026-11",
                ],
                2: ["keep_last", "daily 2026-11-23"],
                3: [],
                4: ["daily 2026-11-20", "weekly 2026-W47"],
                5: [],
                6: ["weekly 2026-W46"],
                7: [],
                8: ["monthly 2026-10"],
                9: [],
                10: [],
                11: [],
            },
        )

    def test_protected_and_newest_and_open_grant(self):
        points = [*EXAMPLE[:9], point(10, 2026, 10, 2, 8, 30, protected=True)]
        rules = plan(points, 0, {**GFS, "daily": 1}, BERLIN, {9})
        self.assertEqual(rules[10], ["protected"])
        self.assertEqual(rules[9], ["restore"])
        self.assertEqual(rules[1][0], "newest")

    def test_offline_gap_periods(self):
        # a gap of empty days counts for no tier
        rules = plan(
            EXAMPLE, 0, {**GFS, "daily": 4, "weekly": 0, "monthly": 0}, BERLIN, set()
        )
        kept = [n for n, r in rules.items() if r]
        self.assertEqual(kept, [1, 2, 4, 5])

    def test_dst_day_keys(self):
        # 23:30 UTC on 24 October is already Sunday 25 October in Berlin
        late = SimpleNamespace(
            id="a",
            snapshot_at=datetime(2026, 10, 24, 23, 30, tzinfo=UTC),
            created_at=datetime(2026, 10, 24, 23, 30, tzinfo=UTC),
            protected=False,
        )
        early = SimpleNamespace(
            id="b",
            snapshot_at=datetime(2026, 10, 25, 22, 30, tzinfo=UTC),
            created_at=datetime(2026, 10, 25, 22, 30, tzinfo=UTC),
            protected=False,
        )
        rules = plan([late, early], 0, {"daily": 2}, BERLIN, set())
        # both lie on the local 25th, the day that has 25 hours
        self.assertEqual(rules["b"], ["newest", "daily 2026-10-25"])
        self.assertEqual(rules["a"], [])

    def test_timezone_change(self):
        rules = plan(EXAMPLE[:3], 0, {"daily": 2}, ZoneInfo("Asia/Tokyo"), set())
        # 21:05 in Berlin is already the next day in Tokyo
        self.assertEqual(rules[1], ["newest", "daily 2026-11-24"])
        self.assertEqual(rules[2], [])
        self.assertEqual(rules[3], ["daily 2026-11-23"])

    def test_keep_last_only_and_all_zero(self):
        rules = plan(EXAMPLE, 2, {}, BERLIN, set())
        self.assertEqual([n for n, r in rules.items() if r], [1, 2])
        rules = plan(EXAMPLE, 0, {}, BERLIN, set())
        self.assertTrue(all("all" in r for r in rules.values()))


class TestPrune(PollBase):
    def make(self, status, days, **kw):
        image = Image.objects.create(
            agent=self.agent,
            destination="images",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
            status=status,
            target=Profile.objects.get(agent=self.agent).target,
            snapshot_at=timezone.now() - timedelta(days=days),
            **kw,
        )
        Image.objects.filter(pk=image.pk).update(
            created_at=image.snapshot_at, updated_at=image.snapshot_at
        )
        return image

    def keep(self, **effective):
        profile = Profile.objects.get(agent=self.agent)
        profile.effective = {**profile.effective, **effective}
        profile.save(update_fields=["effective"])

    def test_retention_prunes_by_plan(self):
        self.keep(keep_last=1, gfs={**GFS, "daily": 0, "weekly": 0, "monthly": 0})
        old, mid, new = (self.make(ImageStatus.VERIFIED, d) for d in (3, 2, 1))
        Image.objects.filter(pk=mid.pk).update(protected=True)
        imaging_tick()
        self.assertEqual(
            set(Image.objects.values_list("pk", flat=True)), {mid.pk, new.pk}
        )
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Image {old.pk} removed by retention."
            ).exists()
        )

    def test_failed_points_after_7_days(self):
        lonely = self.make(ImageStatus.FAILED, 10)
        self.assertEqual(prune_device(self.agent.pk, timezone.now()), 0)
        self.make(ImageStatus.VERIFIED, 9)
        young = self.make(ImageStatus.FAILED, 3)
        self.assertEqual(prune_device(self.agent.pk, timezone.now()), 1)
        self.assertFalse(Image.objects.filter(pk=lonely.pk).exists())
        self.assertTrue(Image.objects.filter(pk=young.pk).exists())
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Failed image {lonely.pk} removed after 7 days."
            ).exists()
        )

    def test_preview_answer(self):
        old, new = self.make(ImageStatus.VERIFIED, 2), self.make(
            ImageStatus.VERIFIED, 1
        )
        failed = self.make(ImageStatus.FAILED, 9)
        Transfer.objects.create(
            image=old,
            direction="restore",
            target=self.agent,
            token_digest="x",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        body = {
            "agent_id": self.agent.agent_id,
            "config": {"keep_last": 1, "timezone": "UTC"},
        }
        r = self.client.post("/imaging/retention/preview/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["timezone"], "UTC")
        rows = {row["id"]: row for row in r.data["points"]}
        self.assertEqual(rows[str(new.pk)]["kept_by"], ["newest", "keep_last"])
        self.assertEqual(rows[str(old.pk)]["kept_by"], ["restore"])
        self.assertEqual(
            (rows[str(failed.pk)]["kept_by"], rows[str(failed.pk)]["action"]),
            ([], "delete"),
        )
        body["config"] = {"keep_last": 1, "schedule": {"kind": "none"}}
        r = self.client.post("/imaging/retention/preview/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            self.client.post(
                "/imaging/retention/preview/", {}, format="json"
            ).status_code,
            404,
        )

    def test_protect_endpoint(self):
        image = self.make(ImageStatus.VERIFIED, 1)
        url = f"{self.uri}images/{image.pk}/protect/"
        r = self.client.post(url, {"protected": True}, format="json")
        self.assertEqual((r.status_code, r.data["protected"]), (200, True))
        r = self.client.post(url, {"protected": False}, format="json")
        self.assertEqual(r.status_code, 403)
        with patch("imaging.views.stepup_denied", return_value=None):
            r = self.client.post(url, {"protected": False}, format="json")
        self.assertEqual(r.data["protected"], False)
        self.assertTrue(
            AuditLog.objects.filter(message=f"Image {image.pk} unprotected.").exists()
        )
        self.assertEqual(
            self.client.post(url, {"protected": 1}, format="json").status_code, 400
        )

    def test_usage_exact(self):
        from .models import ImageBlock, ImagePart
        from .service import backup_rows, update_usage

        a, b = self.make(ImageStatus.VERIFIED, 2), self.make(ImageStatus.VERIFIED, 1)
        block = dict(namespace="n", destination="images", size=1)
        shared = ImageBlock.objects.create(digest="a" * 64, stored_size=7, **block)
        own = ImageBlock.objects.create(digest="b" * 64, stored_size=5, **block)
        ImagePart.objects.create(image=a, index=0, block=shared)
        ImagePart.objects.create(image=b, index=0, block=shared)
        ImagePart.objects.create(image=b, index=1, block=own)
        _, state = backup_rows(self.agent)
        update_usage(self.agent, state)
        self.assertEqual(state.usage, {str(a.target_id): 12})


class TestRetentionReview(TestPrune):
    def test_delete_frees_the_quota(self):
        from . import resolver
        from .models import BackupRun, DeviceBackupState, ImageBlock, ImagePart
        from .service import backup_rows, update_usage

        old = self.make(ImageStatus.VERIFIED, 2)
        block = ImageBlock.objects.create(
            namespace="n",
            destination="images",
            digest="d" * 64,
            size=1,
            stored_size=100,
        )
        ImagePart.objects.create(image=old, index=0, block=block)
        # the store holds the block, so the store checks pass
        folder = Path(settings.ULRMM_IMAGING_ROOT, "images")
        folder.mkdir(mode=0o700, exist_ok=True)
        (folder / str(block.pk)).write_bytes(b"x" * 100)
        update_usage(self.agent, backup_rows(self.agent)[1])
        profile = Profile.objects.get(agent=self.agent)
        profile.overrides = {"quota_bytes": 100}
        profile.save(update_fields=["overrides"])
        resolver.resolve_device(self.agent, cause="device")
        self.queue()
        self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(BackupRun.objects.get().deferred_reason, "quota_device")
        with (
            patch("imaging.views.stepup_denied", return_value=None),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.delete(f"{self.uri}images/{old.pk}/")
        self.assertEqual(r.status_code, 204)
        usage = DeviceBackupState.objects.get(agent=self.agent).usage
        self.assertEqual(sum(usage.values()), 0)
        self.assertEqual(self.poll().status_code, 200)

    def test_locked_delete_rechecks_protection(self):
        kept = self.make(ImageStatus.VERIFIED, 2, protected=True)
        self.make(ImageStatus.VERIFIED, 1)
        # a plan made before the point was protected
        with patch(
            "imaging.tasks.plan", side_effect=lambda g, *a: {p.id: [] for p in g}
        ):
            prune_device(self.agent.pk, timezone.now())
        self.assertTrue(Image.objects.filter(pk=kept.pk).exists())

    def test_future_snapshot_is_not_the_newest(self):
        from .retention import when

        future = self.make(ImageStatus.VERIFIED, 3)
        Image.objects.filter(pk=future.pk).update(
            snapshot_at=timezone.now() + timedelta(days=30)
        )
        future.refresh_from_db()
        self.assertEqual(when(future), future.created_at)
        fresh = self.make(ImageStatus.VERIFIED, 1)
        self.keep(keep_last=1)
        prune_device(self.agent.pk, timezone.now())
        self.assertEqual(list(Image.objects.values_list("pk", flat=True)), [fresh.pk])

    def test_just_verified_point_is_kept(self):
        newer = self.make(ImageStatus.VERIFIED, 1)
        older = self.make(ImageStatus.VERIFIED, 2)
        self.keep(keep_last=1)
        prune_device(self.agent.pk, timezone.now(), keep={older.pk})
        self.assertEqual(
            set(Image.objects.values_list("pk", flat=True)), {newer.pk, older.pk}
        )

    def test_preview_returns_the_sort_time(self):
        point = self.make(ImageStatus.VERIFIED, 1)
        Image.objects.filter(pk=point.pk).update(snapshot_at=None)
        point.refresh_from_db()
        body = {"agent_id": self.agent.agent_id}
        row = self.client.post("/imaging/retention/preview/", body, format="json").data[
            "points"
        ][0]
        self.assertIsNone(row["snapshot_at"])
        self.assertEqual(row["at"], point.created_at)

    def test_verified_point_without_run_clears_failure_alerts(self):
        from .models import DeviceBackupState
        from .runs import alert, point_verified
        from .service import backup_rows

        _, state = backup_rows(self.agent)
        alert(self.agent, state, "stale")
        state.consecutive_failures = 4
        state.save()
        point = self.make(ImageStatus.VERIFIED, 0)
        point_verified(point.pk)
        state = DeviceBackupState.objects.get(agent=self.agent)
        self.assertEqual((state.alerts, state.consecutive_failures), ({}, 0))

    def test_failed_removal_does_not_count(self):
        self.keep(keep_last=1)
        old = self.make(ImageStatus.VERIFIED, 3)
        self.make(ImageStatus.VERIFIED, 2)
        self.make(ImageStatus.VERIFIED, 1)
        with patch(
            "imaging.tasks.remove_image_file", side_effect=OSError("busy")
        ) as remove:
            self.assertEqual(prune_device(self.agent.pk, timezone.now()), 0)
        self.assertTrue(Image.objects.filter(pk=old.pk).exists())
        # the device's turn ends at the first refusal
        self.assertEqual(remove.call_count, 1)

    def test_keep_last_counts_per_target(self):
        self.keep(keep_last=1)
        other = StorageTarget.objects.create(name="second")
        old, new, far_old, far_new = (
            self.make(ImageStatus.VERIFIED, d) for d in (4, 3, 2, 1)
        )
        Image.objects.filter(pk__in=(far_old.pk, far_new.pk)).update(target=other)
        prune_device(self.agent.pk, timezone.now())
        self.assertEqual(
            set(Image.objects.values_list("pk", flat=True)), {new.pk, far_new.pk}
        )

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_batch_reaches_every_row_and_wraps(self):
        StorageTarget.objects.create(name="second")
        StorageTarget.objects.create(name="third")
        pks = sorted(StorageTarget.objects.values_list("pk", flat=True))
        self.assertEqual(len(pks), 3)
        from django.core.cache import cache

        key = "imaging:test:cursor"
        cache.delete(key)
        first, second = _batch(key, StorageTarget, 2), _batch(key, StorageTarget, 2)
        self.assertEqual((first, second), (pks[:2], [pks[2], pks[0]]))

    def test_locked_delete_rechecks_an_open_restore(self):
        opened = self.make(ImageStatus.VERIFIED, 2)
        self.make(ImageStatus.VERIFIED, 1)
        Transfer.objects.create(
            image=opened,
            direction="restore",
            target=self.agent,
            token_digest="x",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        # a plan made before the restore grant was opened
        with patch(
            "imaging.tasks.plan", side_effect=lambda g, *a: {p.id: [] for p in g}
        ):
            prune_device(self.agent.pk, timezone.now())
        self.assertTrue(Image.objects.filter(pk=opened.pk).exists())

    def test_preview_of_a_cleared_zone_uses_the_device_zone(self):
        from . import resolver

        profile = Profile.objects.get(agent=self.agent)
        profile.overrides = {"timezone": "Asia/Tokyo"}
        profile.save(update_fields=["overrides"])
        resolver.resolve_device(self.agent, cause="device")
        self.assertEqual(Profile.objects.get(agent=self.agent).timezone, "Asia/Tokyo")
        body = {"agent_id": self.agent.agent_id, "config": {"timezone": ""}}
        r = self.client.post("/imaging/retention/preview/", body, format="json")
        self.assertEqual((r.status_code, r.data["timezone"]), (200, "UTC"))

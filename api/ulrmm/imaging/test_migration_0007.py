# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import time, timedelta
from importlib import import_module
from types import SimpleNamespace

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase
from django.utils import timezone
from model_bakery import baker

backfill = import_module("imaging.migrations.0007_backup_engine_backfill")


class TestBackfill(TestCase):
    """The data steps of 0007 on the historical models. 0007 changes no schema,
    so its models match the test tables and no DDL runs inside the suite."""

    def setUp(self):
        old = self.new = (
            MigrationExecutor(connection)
            .loader.project_state(("imaging", "0007_backup_engine_backfill"))
            .apps
        )
        self.editor = SimpleNamespace(connection=connection)
        # the rows the real 0007 made on the empty test database
        old.get_model("imaging", "StorageTarget").objects.all().delete()
        Profile = old.get_model("imaging", "Profile")
        Policy = old.get_model("imaging", "BackupPolicy")
        Image = old.get_model("imaging", "Image")
        Inventory = old.get_model("imaging", "NativeInventory")
        self.own, self.shared, self.bare = (
            baker.make("agents.Agent", plat="linux", goarch="amd64", time_zone="UTC")
            for _ in range(3)
        )
        self.due = timezone.now() + timedelta(hours=5)
        Profile.objects.create(
            agent_id=self.own.pk,
            destination="fleet",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
            schedule_time=time(2, 30),
            timezone="Europe/Berlin",
            next_run=self.due,
            keep_last=3,
            volumes=["/media/data"],
        )
        self.policy_config = {
            "destination": "office",
            "network_mode": "internet",
            "compression": "gzip",
            "compression_level": 6,
            "schedule_time": "03:00",
            "timezone": "UTC",
        }
        policy = Policy.objects.create(name="Office", config=self.policy_config)
        Profile.objects.create(
            agent_id=self.shared.pk,
            policy_id=policy.pk,
            destination="office",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
            schedule_time=time(3, 0),
            timezone="UTC",
            next_run=self.due,
            keep_last=2,
        )
        Inventory.objects.create(
            agent_id=self.bare.pk, capability={"method": "linux-files-v1"}
        )
        self.verified_at = timezone.now() - timedelta(days=1)
        self.image = Image.objects.create(
            agent_id=self.own.pk,
            status="verified",
            verified_at=self.verified_at,
            destination="fleet",
            network_mode="internet",
            compression="gzip",
            compression_level=6,
        )
        backfill.forward(old, self.editor)

    def test_forward(self):
        Target = self.new.get_model("imaging", "StorageTarget")
        Profile = self.new.get_model("imaging", "Profile")
        Policy = self.new.get_model("imaging", "BackupPolicy")
        State = self.new.get_model("imaging", "DeviceBackupState")
        Image = self.new.get_model("imaging", "Image")
        targets = dict(Target.objects.values_list("name", "pk"))
        self.assertEqual(set(targets), {"images", "fleet", "office"})
        self.assertEqual(
            list(Target.objects.filter(is_default=True).values_list("name", flat=True)),
            ["images"],
        )
        policy = Policy.objects.get()
        self.assertEqual(
            policy.config,
            {
                "target": targets["office"],
                "network_mode": "internet",
                "compression": "gzip",
                "compression_level": 6,
                "schedule": {"kind": "daily", "time": "03:00"},
                "timezone": "UTC",
            },
        )
        self.assertEqual(policy.scope, "assigned")
        own = Profile.objects.get(agent_id=self.own.pk)
        self.assertEqual(
            own.overrides,
            {
                "target": targets["fleet"],
                "network_mode": "internet",
                "compression": "gzip",
                "compression_level": 6,
                "schedule": {"kind": "daily", "time": "02:30"},
                "timezone": "Europe/Berlin",
                "keep_last": 3,
                "volumes": ["/media/data"],
            },
        )
        self.assertEqual(
            own.effective,
            {
                "schedule": {"kind": "daily", "time": "02:30"},
                "timezone": "Europe/Berlin",
                "min_spacing_minutes": 60,
            },
        )
        # only what differs from the policy and the builtin defaults
        self.assertEqual(
            Profile.objects.get(agent_id=self.shared.pk).overrides, {"keep_last": 2}
        )
        bare = Profile.objects.get(agent_id=self.bare.pk)
        self.assertEqual(
            (
                bare.compression_level,
                bare.network_mode,
                bare.schedule_time,
                bare.next_run,
            ),
            (1, "internet", None, None),
        )
        states = {s.agent_id: s for s in State.objects.all()}
        self.assertEqual(set(states), {self.own.pk, self.shared.pk, self.bare.pk})
        self.assertEqual(states[self.own.pk].last_success_at, self.verified_at)
        self.assertIsNotNone(states[self.shared.pk].schedule_since)
        self.assertIsNone(states[self.bare.pk].schedule_since)
        image = Image.objects.get()
        self.assertEqual(image.target_id, targets["fleet"])
        self.assertEqual(image.client_id, self.own.site.client_id)
        self.assertEqual(image.snapshot_at, image.created_at)

        # the first resolve keeps every old column
        from .models import Profile as Current
        from .resolver import resolve_now

        columns = (
            "destination",
            "network_mode",
            "compression",
            "compression_level",
            "schedule_time",
            "timezone",
            "keep_last",
            "volumes",
            "next_run",
        )
        before = {
            p.agent_id: [getattr(p, c) for c in columns] for p in Current.objects.all()
        }
        resolve_now([self.own.pk, self.shared.pk, self.bare.pk], cause="enrol")
        after = {
            p.agent_id: [getattr(p, c) for c in columns] for p in Current.objects.all()
        }
        self.assertEqual(after, before)
        self.assertEqual(
            Current.objects.get(agent_id=self.bare.pk).effective["schedule"],
            {"kind": "none"},
        )

    def test_backward(self):
        Policy = self.new.get_model("imaging", "BackupPolicy")
        Transfer = self.new.get_model("imaging", "Transfer")
        Image = self.new.get_model("imaging", "Image")
        Policy.objects.create(name="Global default", scope="global", config={})
        Transfer.objects.create(
            image_id=Image.objects.get().pk,
            direction="capture",
            user=None,
            authority="policy",
            token_digest="x",
            expires_at=timezone.now(),
        )
        backfill.backward(self.new, self.editor)
        old = self.new
        Policy = old.get_model("imaging", "BackupPolicy")
        Profile = old.get_model("imaging", "Profile")
        self.assertEqual(
            list(Policy.objects.values_list("name", "config")),
            [("Office", self.policy_config)],
        )
        self.assertFalse(old.get_model("imaging", "Transfer").objects.exists())
        self.assertEqual(
            set(Profile.objects.values_list("agent_id", flat=True)),
            {self.own.pk, self.shared.pk},
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from datetime import time, timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from model_bakery import baker

from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import resolver
from .models import (
    BackupPolicy,
    DeviceBackupState,
    Image,
    ImageBlock,
    ImagePart,
    NativeInventory,
    Pairing,
    PolicyChangeHold,
    Profile,
    StorageTarget,
)
from .service import backup_rows

DAILY = {"kind": "daily", "time": "02:00"}


class ResolverBase(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.agent = baker.make(
            "agents.Agent",
            hostname="pc-1",
            plat="linux",
            goarch="amd64",
            time_zone="UTC",
        )
        self.client_obj = self.agent.site.client
        self.default = StorageTarget.objects.get(is_default=True)
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"

    def policy(self, scope="assigned", config=None, **kw):
        return BackupPolicy.objects.create(
            name=kw.pop("name", f"{scope} policy"),
            scope=scope,
            config=config or {},
            **kw,
        )

    def resolve(self, cause="policy", author=None, agent=None):
        return resolver.resolve_device(agent or self.agent, cause=cause, author=author)

    def fields(self, agent=None):
        return resolver.effective(agent or self.agent)["fields"]

    def value(self, key, agent=None):
        return self.fields(agent)[key]["value"]

    def manager(self, *flags):
        user = self.create_user_with_roles(["can_manage_images", *flags])
        return user


class TestResolver(ResolverBase):
    def test_builtin_defaults_field_by_field(self):
        fields = self.fields()
        expected = {"target": self.default.pk, **resolver.DEFAULTS}
        self.assertEqual({k: f["value"] for k, f in fields.items()}, expected)
        self.assertTrue(
            all(f["origin"] == resolver.DEFAULT_ORIGIN for f in fields.values())
        )
        self.assertEqual(
            resolver.DEFAULT_ORIGIN,
            {"level": "default", "id": None, "name": "Global default"},
        )

    def test_six_levels_order(self):
        tag = baker.make("groups.Tag", name="laptops")
        self.agent.tags.add(tag)
        glob = resolver.global_policy()
        glob.config = {"keep_last": 1, "smart": "off"}
        glob.save()
        self.policy("client", {"keep_last": 2}, client=self.client_obj)
        self.policy("site", {"keep_last": 3}, site=self.agent.site)
        self.policy("tag", {"keep_last": 4}, tag=tag)
        assigned = self.policy("assigned", {"keep_last": 5})
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(policy=assigned)
        fields = self.fields()
        self.assertEqual(fields["keep_last"]["origin"]["level"], "assigned")
        self.assertEqual(fields["smart"]["origin"]["level"], "global")
        Profile.objects.filter(pk=profile.pk).update(overrides={"keep_last": 6})
        fields = self.fields()
        self.assertEqual(fields["keep_last"]["origin"], resolver.DEVICE_ORIGIN)
        self.assertEqual(self.value("keep_last"), 6)
        Profile.objects.filter(pk=profile.pk).update(overrides={}, policy=None)
        self.assertEqual(self.value("keep_last"), 4)
        BackupPolicy.objects.filter(scope="tag").delete()
        self.assertEqual(self.value("keep_last"), 3)
        BackupPolicy.objects.filter(scope="site").delete()
        self.assertEqual(self.value("keep_last"), 2)
        BackupPolicy.objects.filter(scope="client").delete()
        self.assertEqual(self.value("keep_last"), 1)

    def test_group_tag_priority_and_age_tiebreak(self):
        tags = [baker.make("groups.Tag", name=f"t{i}") for i in range(3)]
        self.agent.tags.add(*tags)
        now = timezone.now()
        old = self.policy(
            "tag", {"keep_last": 1}, tag=tags[0], created_at=now - timedelta(days=2)
        )
        self.policy("tag", {"keep_last": 2}, tag=tags[1], created_at=now)
        self.assertEqual(self.fields()["keep_last"]["origin"]["id"], old.pk)
        high = self.policy("tag", {"keep_last": 3}, tag=tags[2], priority=5)
        self.assertEqual(self.fields()["keep_last"]["origin"]["id"], high.pk)

    def test_conflict_listed_at_equal_priority(self):
        a, b = (baker.make("groups.Tag", name=n) for n in ("a", "b"))
        self.agent.tags.add(a, b)
        p1 = self.policy("tag", {"keep_last": 1, "smart": "off"}, tag=a)
        p2 = self.policy("tag", {"keep_last": 2}, tag=b)
        self.policy("tag", {"smart": "abort"}, tag=b, priority=3, name="hi")
        conflicts = resolver.effective(self.agent)["conflicts"]
        self.assertEqual(
            conflicts, [{"field": "keep_last", "policies": sorted([p1.pk, p2.pk])}]
        )

    def test_list_and_object_replace_whole(self):
        glob = resolver.global_policy()
        glob.config = {
            "volumes": ["/a", "/b"],
            "gfs": {"hourly": 1, "daily": 2, "weekly": 0, "monthly": 0, "yearly": 0},
        }
        glob.save()
        self.policy("client", {"volumes": ["/c"]}, client=self.client_obj)
        self.assertEqual(self.value("volumes"), ["/c"])
        self.assertEqual(self.value("gfs")["daily"], 2)

    def test_per_method_level_default(self):
        self.assertEqual(self.value("compression_level"), 6)
        NativeInventory.objects.create(
            agent=self.agent, capability={"method": "linux-files-v1"}
        )
        self.assertEqual(self.value("compression_level"), 1)

    def test_enforced_must_be_set(self):
        body = {
            "name": "x",
            "scope": "global",
            "config": {"smart": "off"},
            "enforced": ["target"],
        }
        BackupPolicy.objects.filter(scope="global").delete()
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["enforced"], ["Enforce only settings this policy sets."]
        )
        body["enforced"] = ["smart"]
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("enforced", r.data)

    def test_unknown_config_key_refused(self):
        body = {"name": "x", "scope": "assigned", "config": {"destination": "a"}}
        body["agents"] = [self.agent.agent_id]
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data["config"]["destination"], ["Unknown setting."])

    def test_version_bumps_only_on_hash_change(self):
        _, state = self.resolve()
        self.assertEqual(state.config_version, 1)
        doc = state.config_doc
        _, state = self.resolve()
        self.assertEqual(state.config_version, 1)
        self.assertEqual(state.config_doc, doc)
        self.policy("client", {"smart": "off"}, client=self.client_obj)
        _, state = self.resolve()
        self.assertEqual(state.config_version, 2)
        self.assertIsNotNone(state.pending_since)
        # rules the agent does not get keep the document and its version
        self.policy("site", {"keep_last": 9}, site=self.agent.site)
        _, state = self.resolve()
        self.assertEqual(state.config_version, 2)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_cache_version_key_invalidates(self):
        cache.clear()
        self.assertEqual(self.value("smart"), "warn")
        self.policy("client", {"smart": "off"}, client=self.client_obj)
        # the cached table hides a policy until the version key moves
        self.assertEqual(self.value("smart"), "warn")
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()
        self.assertEqual(self.value("smart"), "off")

    def test_materialised_columns(self):
        nas = StorageTarget.objects.create(name="nas")
        self.policy(
            "client",
            {"target": nas.pk, "schedule": DAILY, "timezone": "Europe/Berlin"},
            client=self.client_obj,
        )
        profile, state = self.resolve()
        self.assertEqual(profile.destination, "nas")
        self.assertEqual(profile.target_id, nas.pk)
        self.assertEqual(profile.schedule_time, time(2, 0))
        self.assertEqual(profile.timezone, "Europe/Berlin")
        self.assertIsNotNone(profile.next_run)
        self.assertIsNotNone(state.schedule_since)
        self.assertEqual(profile.effective["timezone"], "Europe/Berlin")

    def test_first_resolve_keeps_next_run(self):
        due = timezone.now() + timedelta(hours=3)
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(
            schedule_time=time(2, 0),
            timezone="UTC",
            next_run=due,
            overrides={"schedule": DAILY, "timezone": "UTC"},
            effective={"schedule": DAILY, "timezone": "UTC", "min_spacing_minutes": 60},
        )
        profile, _ = self.resolve(cause="enrol")
        self.assertEqual(profile.next_run, due)
        # an empty effective compares against the columns
        Profile.objects.filter(pk=profile.pk).update(effective={})
        DeviceBackupState.objects.filter(agent=self.agent).update(config_version=0)
        profile, _ = self.resolve(cause="enrol")
        self.assertEqual(profile.next_run, due)

    def test_first_resolve_computes_usage(self):
        profile, state = backup_rows(self.agent)
        image = Image.objects.create(
            agent=self.agent,
            destination="images",
            target=self.default,
            network_mode="internet",
            compression="gzip",
            compression_level=6,
        )
        for i, stored in enumerate((100, 250)):
            block = ImageBlock.objects.create(
                namespace="n",
                destination="images",
                digest=f"{i:064x}",
                size=1,
                stored_size=stored,
            )
            ImagePart.objects.create(image=image, index=i, block=block)
        _, state = self.resolve(cause="enrol")
        self.assertEqual(state.usage, {str(self.default.pk): 350})
        self.default.refresh_from_db()
        self.assertEqual(self.default.used_bytes, 350)

    def test_mode_change_deletes_other_mode_pairings(self):
        profile, _ = self.resolve()
        Profile.objects.filter(pk=profile.pk).update(network_mode="internal")
        baker.make(Pairing, agent=self.agent, user=self.john, network_mode="internal")
        self.resolve()
        self.assertFalse(Pairing.objects.filter(agent=self.agent).exists())

    def test_delete_scope_object_with_policy_409(self):
        tag = baker.make("groups.Tag", name="keep")
        group = baker.make("groups.DeviceGroup", name="g", kind="static")
        site = baker.make("clients.Site", client=self.client_obj, name="second")
        self.policy("tag", {}, tag=tag, name="Tag policy")
        self.policy("group", {}, group=group, name="Group policy")
        self.policy("site", {}, site=site, name="Site policy")
        StorageTarget.objects.create(name="cl", scope="client", client=self.client_obj)
        r = self.client.delete(f"/groups/tags/{tag.pk}/")
        self.assertEqual(r.status_code, 409, r.data)
        self.assertEqual(
            r.data["detail"], "Remove the backup policies Tag policy first."
        )
        r = self.client.delete(f"/groups/{group.pk}/")
        self.assertEqual(r.status_code, 409, r.data)
        from imaging.service import scope_blockers

        self.assertEqual(
            scope_blockers(groups=[group.pk]),
            "Remove the backup policies Group policy first.",
        )
        self.assertEqual(
            scope_blockers(clients=[self.client_obj.pk], sites=[site.pk]),
            "Remove the backup policies Site policy and the backup targets cl first.",
        )
        self.assertEqual(scope_blockers(tags=[0]), "")


class TestDeviceSave(ResolverBase):
    def put(self, body):
        return self.client.put(self.uri, body, format="json")

    def setUp(self):
        super().setUp()
        NativeInventory.objects.create(
            agent=self.agent,
            capability={
                "method": "linux-files-v1",
                "ready": True,
                "reason": "",
                "source_id": "s",
                "device_uuid": "74bdac69-aa34-4056-93ea-4c692264d3df",
                "volumes": [],
            },
        )

    def test_device_override_and_reset(self):
        r = self.put({"set": {"keep_last": 4, "smart": "off"}})
        self.assertEqual(r.status_code, 200, r.data)
        fields = r.data["effective"]["fields"]
        self.assertEqual(fields["keep_last"]["origin"]["level"], "device")
        self.assertEqual(r.data["overrides"], {"keep_last": 4, "smart": "off"})
        self.assertEqual(r.data["config"]["keep_last"], 4)
        r = self.put({"reset": ["keep_last"]})
        self.assertEqual(r.data["overrides"], {"smart": "off"})
        self.assertEqual(r.data["config"]["keep_last"], 0)
        self.assertTrue(
            AuditLog.objects.filter(
                message="Backup device settings changed: keep_last."
            ).exists()
        )
        self.assertEqual(self.put({"reset": ["nope"]}).status_code, 400)

    def test_device_save_keeps_policy(self):
        assigned = self.policy("assigned", {"keep_last": 2})
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(policy=assigned)
        self.assertEqual(self.put({"set": {"smart": "off"}}).status_code, 200)
        profile.refresh_from_db()
        self.assertEqual(profile.policy_id, assigned.pk)
        self.assertEqual(profile.keep_last, 2)

    def test_enforced_blocks_lower_levels_and_device_save(self):
        nas = StorageTarget.objects.create(name="nas")
        glob = resolver.global_policy()
        glob.config, glob.enforced = {"target": nas.pk}, ["target"]
        glob.save()
        other = StorageTarget.objects.create(name="other")
        self.policy("client", {"target": other.pk}, client=self.client_obj)
        fields = self.fields()
        self.assertEqual(fields["target"]["value"], nas.pk)
        self.assertTrue(fields["target"]["locked"])
        r = self.put({"set": {"target": other.pk}})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["set"]["target"], ["Enforced by backup policy Global default."]
        )
        r = self.client.get(self.uri)
        self.assertEqual(
            r.data["enforced_by"], {"target": {"id": glob.pk, "name": glob.name}}
        )

    def test_target_scope_check(self):
        other = baker.make("clients.Client", name="Other")
        foreign = StorageTarget.objects.create(name="far", scope="client", client=other)
        r = self.put({"set": {"target": foreign.pk}})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["set"]["target"], ["Backup target far does not cover this device."]
        )
        own = StorageTarget.objects.create(
            name="near", scope="client", client=self.client_obj
        )
        self.assertEqual(self.put({"set": {"target": own.pk}}).status_code, 200)
        self.policy("site", {"target": foreign.pk}, site=self.agent.site)
        Profile.objects.filter(agent=self.agent).update(overrides={})
        checks = {c["id"]: c for c in self.client.get(self.uri).data["checks"]}
        self.assertEqual(checks["target.scope"]["state"], "missing")

    def test_flat_body_refused(self):
        for body in ({"keep_last": 3}, {}, {"set": {}, "keep_last": 3}):
            r = self.put(body)
            self.assertEqual(r.status_code, 400, body)
        self.assertFalse(
            AuditLog.objects.filter(
                message__startswith="Backup device settings"
            ).exists()
        )

    def test_hook_values_and_args_hidden_in_answers(self):
        script = baker.make(
            "scripts.Script", name="Dump", shell="shell", script_body="x"
        )
        hooks = [
            {
                "script_id": script.pk,
                "phase": "pre-backup",
                "args": ["--password", "hunter2"],
                "env_vars": ["PGPASS=secret", "EMPTY="],
                "timeout": 60,
                "on_fail": "abort",
            }
        ]
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides={"hooks": hooks})
        resolver.resolve_device(self.agent, cause="device")
        self.client.force_authenticate(self.manager())
        r = self.client.get(self.uri)
        self.assertNotIn("secret", json.dumps(r.data, default=str))
        self.assertNotIn("hunter2", json.dumps(r.data, default=str))
        shown = r.data["effective"]["fields"]["hooks"]["value"][0]
        self.assertEqual(shown["args_count"], 2)
        self.assertEqual(
            shown["env_vars"],
            [
                {"name": "PGPASS", "value": "", "has_value": True},
                {"name": "EMPTY", "value": "", "has_value": False},
            ],
        )
        self.assertEqual(r.data["overrides"]["hooks"][0]["args_count"], 2)
        self.client.force_authenticate(self.john)
        r = self.client.get(self.uri)
        self.assertEqual(
            r.data["effective"]["fields"]["hooks"]["value"][0]["args"],
            ["--password", "hunter2"],
        )
        self.assertNotIn("secret", json.dumps(r.data, default=str))


class HoldBase(ResolverBase):
    def setUp(self):
        super().setUp()
        self.tag = baker.make("groups.Tag", name="laptops")
        self.policy("tag", {"smart": "off"}, tag=self.tag)
        self.resolve(cause="enrol")

    def tag_change(self, author):
        self.agent.tags.add(self.tag)
        return self.resolve(cause="tag", author=author)


class TestHolds(HoldBase):
    def test_hold_for_author_without_manage(self):
        outsider = self.create_user_with_roles(["can_edit_agent"])
        _, state = self.tag_change(outsider)
        hold = PolicyChangeHold.objects.get(agent=self.agent)
        self.assertEqual(
            (hold.status, hold.cause, hold.author), ("pending", "tag", outsider)
        )
        self.assertEqual(state.memberships["tags"], [])
        self.assertEqual(self.value("smart"), "warn")
        view = resolver.effective(self.agent)["hold"]
        self.assertEqual(
            view["changes"], [{"field": "smart", "held": "warn", "proposed": "off"}]
        )
        self.assertTrue(
            AuditLog.objects.filter(
                message__startswith=f"Backup settings change of {self.agent.hostname} held"
            ).exists()
        )

    def test_no_hold_for_manage_author(self):
        _, state = self.tag_change(self.john)
        self.assertFalse(PolicyChangeHold.objects.exists())
        self.assertEqual(state.memberships["tags"], [self.tag.pk])
        self.assertEqual(self.value("smart"), "off")

    def test_hold_confirm_and_reject(self):
        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        url = f"/imaging/holds/{hold.pk}/confirm/"
        body = {"action": "confirm", "proposed_hash": hold.proposed_hash}
        r = self.client.post(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["fields"]["smart"]["value"], "off")
        hold.refresh_from_db()
        self.assertEqual((hold.status, hold.confirmed_by), ("confirmed", self.john))
        r = self.client.post(url, body, format="json")
        self.assertEqual(r.data, {"detail": "This change was already decided."})
        self.agent.tags.remove(self.tag)
        self.resolve(cause="tag", author=None)
        hold = PolicyChangeHold.objects.get(status="pending")
        r = self.client.post(
            f"/imaging/holds/{hold.pk}/confirm/",
            {"action": "reject", "proposed_hash": hold.proposed_hash},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.value("smart"), "off")

    def test_hold_confirm_stale_hash_409(self):
        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        r = self.client.post(
            f"/imaging/holds/{hold.pk}/confirm/",
            {"action": "confirm", "proposed_hash": "0" * 64},
            format="json",
        )
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.data["detail"], "This change was updated; review it again.")

    def test_rejected_hold_not_repeated(self):
        self.tag_change(None)
        PolicyChangeHold.objects.update(status="rejected", confirmed_by=self.john)
        self.resolve(cause="beat")
        self.assertFalse(PolicyChangeHold.objects.filter(status="pending").exists())

    def test_non_hold_cause_uses_snapshot(self):
        self.agent.tags.add(self.tag)
        for cause in ("policy", "target", "device", "enrol"):
            _, state = self.resolve(cause=cause)
            self.assertEqual(state.memberships["tags"], [])
        self.assertEqual(self.value("smart"), "warn")

    def test_beat_drift_dynamic_group_author(self):
        group = baker.make("groups.DeviceGroup", name="dyn", kind="dynamic")
        self.policy("group", {"keep_last": 3}, group=group)
        weak = self.create_user_with_roles(["can_list_agents"])

        def drift(editor):
            sets = {
                group.pk: {
                    "kind": "dynamic",
                    "modified_by": editor.username,
                    "agents": {self.agent.pk},
                }
            }
            with patch("imaging.resolver.group_sets", return_value=sets):
                return self.resolve(cause="beat")

        drift(weak)
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual((hold.cause, hold.author), ("group_member", weak))
        self.assertEqual(self.value("keep_last"), 0)
        hold.delete()
        _, state = drift(self.john)
        self.assertEqual(state.memberships["groups"], [group.pk])
        self.assertFalse(PolicyChangeHold.objects.exists())

    def test_hold_cause_mapping(self):
        causes = {}
        for cause in ("tag", "group_rule", "site_move"):
            PolicyChangeHold.objects.all().delete()
            DeviceBackupState.objects.filter(agent=self.agent).update(
                memberships={"client": 0, "site": 0, "groups": [], "tags": []}
            )
            self.agent.tags.add(self.tag)
            self.resolve(cause=cause)
            causes[cause] = PolicyChangeHold.objects.get().cause
        PolicyChangeHold.objects.all().delete()
        self.resolve(cause="beat")
        causes["beat"] = PolicyChangeHold.objects.get().cause
        self.assertEqual(
            causes,
            {
                "tag": "tag",
                "group_rule": "group_rule",
                "site_move": "site_move",
                "beat": "unknown",
            },
        )


class TestEquality(ResolverBase):
    def test_dump_and_compare(self):
        import json
        from io import StringIO
        from tempfile import NamedTemporaryFile

        from django.core.management import CommandError, call_command

        resolver.resolve_device(self.agent, cause="enrol")
        with NamedTemporaryFile("r", suffix=".json") as f:
            call_command("imaging_equality", "dump", f.name)
            self.assertTrue(json.load(f)[self.agent.agent_id]["has_profile"])
            call_command("imaging_equality", "compare", f.name, stdout=StringIO())
            Profile.objects.update(overrides={"keep_last": 7})
            with self.assertRaises(CommandError):
                call_command("imaging_equality", "compare", f.name, stdout=StringIO())


BAD_CALENDAR = {
    "kind": "calendar",
    "frequency": "once",
    "run_time": "02:00",
    "weekdays": [],
    "month_day": None,
    "month_week": None,
    "month_weekday": None,
    "dates": ["2026-02-30"],
    "excluded_dates": [],
    "start_date": None,
    "end_date": None,
}


class TestReviewFixes(ResolverBase):
    def other_agent(self, **kw):
        return baker.make("agents.Agent", time_zone="UTC", plat="linux", **kw)

    def test_backup_rows_locks_only_its_row(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        for _ in range(2):
            backup_rows(self.other_agent())
        with CaptureQueriesContext(connection) as ctx:
            backup_rows(self.agent, lock=True)
        table_wide = [
            q["sql"]
            for q in ctx.captured_queries
            if q["sql"].startswith("SELECT")
            and '"imaging_devicebackupstate"' in q["sql"]
            and "WHERE" not in q["sql"]
        ]
        self.assertEqual(table_wide, [])

    def test_poisoned_device_does_not_stop_others(self):
        import contextlib

        from .tasks import imaging_tick

        other = self.other_agent()
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(
            overrides={"schedule": BAD_CALENDAR}
        )
        with self.assertLogs("imaging.resolver", "ERROR"):
            resolver.resolve_now([self.agent.pk, other.pk], cause="enrol")
        self.assertEqual(DeviceBackupState.objects.get(agent=other).config_version, 1)
        with (
            patch("imaging.tasks._ensure_rows", side_effect=RuntimeError),
            patch("imaging.tasks._first_resolve", side_effect=RuntimeError),
            patch("imaging.tasks.directory", contextlib.nullcontext),
            patch("imaging.tasks._expire_uploads") as expire,
            self.assertLogs("imaging.tasks", "ERROR"),
        ):
            imaging_tick()
        expire.assert_called_once()

    def test_calendar_dates_cron_parse_and_zone_names(self):
        from .serializers import ConfigSerializer

        cases = {
            "schedule": [BAD_CALENDAR, {"kind": "cron", "expr": "-- * * * *"}],
            "timezone": ["posixrules"],
        }
        for key, bad_values in cases.items():
            for bad in bad_values:
                serializer = ConfigSerializer(data={key: bad})
                self.assertFalse(serializer.is_valid(), bad)
                self.assertIn(key, serializer.errors)
        self.assertTrue(ConfigSerializer(data={"timezone": "Europe/Berlin"}).is_valid())

    def test_render_falls_back_when_the_target_is_gone(self):
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides={"target": 999999})
        _, state = self.resolve(cause="device")
        doc = json.loads(state.config_doc)
        self.assertEqual(doc["target"]["id"], self.default.pk)

    def test_target_in_use_counts_overrides(self):
        nas = StorageTarget.objects.create(name="nas-override")
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides={"target": nas.pk})
        r = self.client.delete(f"/imaging/targets/{nas.pk}/")
        self.assertEqual(r.status_code, 409)
        self.assertTrue(StorageTarget.objects.filter(pk=nas.pk).exists())

    def test_beat_resolve_writes_nothing_when_unchanged(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        self.resolve(cause="enrol")
        with CaptureQueriesContext(connection) as ctx:
            self.resolve(cause="beat")
        writes = [
            q["sql"]
            for q in ctx.captured_queries
            if q["sql"].startswith("UPDATE")
            and (
                '"imaging_profile"' in q["sql"]
                or '"imaging_devicebackupstate"' in q["sql"]
            )
        ]
        self.assertEqual(writes, [])

    def test_policy_target_must_cover_its_scope(self):
        other = baker.make("clients.Client", name="Far away")
        foreign = StorageTarget.objects.create(name="far", scope="client", client=other)
        own = StorageTarget.objects.create(
            name="own", scope="client", client=self.client_obj
        )
        body = {
            "name": "Clients",
            "scope": "client",
            "client": self.client_obj.pk,
            "config": {"target": foreign.pk},
        }
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["config"]["target"],
            ["Backup target far does not cover the scope of this policy."],
        )
        body["config"]["target"] = own.pk
        self.assertEqual(
            self.client.post("/imaging/policies/", body, format="json").status_code, 201
        )
        NativeInventory.objects.create(
            agent=self.agent,
            capability={
                "method": "linux-files-v1",
                "ready": True,
                "reason": "",
                "source_id": "s",
                "device_uuid": "74bdac69-aa34-4056-93ea-4c692264d3df",
                "volumes": [],
            },
        )
        body = {
            "name": "Some",
            "scope": "assigned",
            "config": {"target": foreign.pk},
            "agents": [self.agent.agent_id],
        }
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["config"]["target"], ["Backup target far does not cover pc-1."]
        )

    def test_queue_capture_fails_a_point_outside_the_target(self):
        from .service import queue_capture

        other = baker.make("clients.Client", name="Far away")
        foreign = StorageTarget.objects.create(name="far", scope="client", client=other)
        self.policy("site", {"target": foreign.pk}, site=self.agent.site)
        profile, _ = self.resolve(cause="policy")
        self.assertEqual(profile.target_id, foreign.pk)
        image = queue_capture(profile, "imaging scheduler", trigger="schedule")
        self.assertEqual(
            (image.status, image.reason),
            ("failed", "Backup target far does not cover this device."),
        )

    def test_target_list_of_a_restricted_role(self):
        other = baker.make("clients.Client", name="Far away")
        StorageTarget.objects.create(name="far", scope="client", client=other)
        StorageTarget.objects.create(
            name="near", scope="client", client=self.client_obj
        )
        user = self.manager()
        user.role.can_view_clients.add(self.client_obj)
        self.client.force_authenticate(user)
        names = {t["name"] for t in self.client.get("/imaging/targets/").data}
        self.assertEqual(names, {"images", "near"})

    def test_default_target_global_and_partial_put(self):
        r = self.client.post(
            "/imaging/targets/",
            {
                "name": "cl",
                "scope": "client",
                "client": self.client_obj.pk,
                "is_default": True,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("is_default", r.data)
        target = StorageTarget.objects.create(
            name="kept",
            scope="client",
            client=self.client_obj,
            quota_bytes=100,
            max_runs=7,
        )
        url = f"/imaging/targets/{target.pk}/"
        r = self.client.put(url, {"max_runs": 9}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        target.refresh_from_db()
        self.assertEqual((target.quota_bytes, target.max_runs), (100, 9))
        self.assertEqual(
            self.client.put(url, {"scope": "global"}, format="json").status_code, 400
        )

    def test_duplicate_target_name_is_a_field_error(self):
        url = "/imaging/targets/"
        r = self.client.post(url, {"name": self.default.name}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.data)
        target = StorageTarget.objects.create(name="spare")
        body = {"name": self.default.name}
        r = self.client.put(f"{url}{target.pk}/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.data)
        r = self.client.put(
            f"{url}{target.pk}/", {"name": "spare", "max_runs": 3}, format="json"
        )
        self.assertEqual(r.status_code, 200, r.data)

    def test_restricted_role_and_client_and_site_policies(self):
        far = baker.make("clients.Client", name="Far away")
        far_site = baker.make("clients.Site", client=far, name="Far site")
        user = self.manager()
        user.role.can_view_clients.add(self.client_obj)
        self.client.force_authenticate(user)
        url = "/imaging/policies/"

        def body(scope, key, name):
            return {"name": name, "scope": scope, scope: key.pk, "config": {}}

        for scope, key in (("client", far), ("site", far_site)):
            r = self.client.post(url, body(scope, key, scope), format="json")
            self.assertEqual(r.status_code, 403)
        own = {}
        for scope, key in (("client", self.client_obj), ("site", self.agent.site)):
            r = self.client.post(url, body(scope, key, scope), format="json")
            self.assertEqual(r.status_code, 201, r.data)
            own[scope] = r.data["id"]
            r = self.client.put(
                f"{url}{own[scope]}/", body(scope, key, f"own {scope}"), format="json"
            )
            self.assertEqual(r.status_code, 200, r.data)
        for scope, key in (("client", far), ("site", far_site)):
            policy = self.policy(scope, name=f"far {scope}", **{scope: key})
            one = f"{url}{policy.pk}/"
            r = self.client.put(one, body(scope, key, "taken"), format="json")
            self.assertEqual(r.status_code, 403)
            self.assertEqual(self.client.delete(one).status_code, 403)
            confirm = {"script_id": 1, "sha256": "0" * 64}
            r = self.client.post(f"{one}hooks/confirm/", confirm, format="json")
            self.assertEqual(r.status_code, 403)
        names = {p["name"] for p in self.client.get(url).data}
        self.assertEqual(names, {"own client", "own site"})


class TestHoldReview(HoldBase):
    def edit_tag_policy(self, config):
        BackupPolicy.objects.filter(tag=self.tag).update(config=config)
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()

    def live_hash(self):
        return resolver.effective(self.agent)["hold"]["proposed_hash"]

    def test_manage_event_does_not_apply_a_pending_change(self):
        outsider = self.create_user_with_roles(["can_edit_agent"])
        self.tag_change(outsider)
        other = baker.make("groups.Tag", name="other")
        self.policy("tag", {"keep_last": 4}, tag=other, name="other policy")
        self.agent.tags.add(other)
        _, state = self.resolve(cause="tag", author=self.john)
        self.assertEqual(state.memberships["tags"], [])
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual(
            sorted(hold.proposed_memberships["tags"]), sorted([self.tag.pk, other.pk])
        )
        self.assertEqual((self.value("smart"), self.value("keep_last")), ("warn", 0))

    def test_reverted_change_withdraws_the_hold(self):
        self.tag_change(None)
        self.agent.tags.remove(self.tag)
        _, state = self.resolve(cause="tag")
        hold = PolicyChangeHold.objects.get()
        self.assertEqual(hold.status, "rejected")
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Held backup settings change {hold.pk} withdrawn."
            ).exists()
        )
        # a redo is held again, a withdrawn hold suppresses nothing
        self.tag_change(None)
        self.assertTrue(PolicyChangeHold.objects.filter(status="pending").exists())

    def test_confirm_locks_profile_before_hold(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        with CaptureQueriesContext(connection) as ctx:
            self.client.post(
                f"/imaging/holds/{hold.pk}/confirm/",
                {"action": "confirm", "proposed_hash": hold.proposed_hash},
                format="json",
            )
        locks = [
            q["sql"].split(" FROM ")[1].split()[0]
            for q in ctx.captured_queries
            if "FOR UPDATE" in q["sql"]
            and (
                '"imaging_profile"' in q["sql"]
                or '"imaging_policychangehold"' in q["sql"]
            )
        ]
        self.assertEqual(locks[0], '"imaging_profile"')

    def test_confirm_binds_to_the_live_proposal(self):
        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        url = f"/imaging/holds/{hold.pk}/confirm/"
        before = resolver.effective(self.agent)["hold"]["proposed_hash"]
        self.assertEqual(before, hold.proposed_hash)
        # the policy edit reaches the hold before any resolve
        BackupPolicy.objects.filter(tag=self.tag).update(config={"smart": "abort"})
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()
        body = {"action": "confirm", "proposed_hash": before}
        r = self.client.post(url, body, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.data["detail"], "This change was updated; review it again.")
        fresh = resolver.effective(self.agent)["hold"]["proposed_hash"]
        self.assertNotEqual(fresh, before)
        rows = self.client.get("/imaging/fleet/").data["rows"]
        row = next(r for r in rows if r["agent_id"] == self.agent.agent_id)
        self.assertEqual(row["hold"], {"id": hold.pk, "proposed_hash": fresh})
        body["proposed_hash"] = fresh
        r = self.client.post(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["fields"]["smart"]["value"], "abort")

    def test_beat_keeps_cause_and_author_of_a_pending_hold(self):
        outsider = self.create_user_with_roles(["can_edit_agent"])
        self.tag_change(outsider)
        self.resolve(cause="beat")
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual((hold.cause, hold.author), ("tag", outsider))
        # a policy edit changes the proposal, not the membership event
        self.edit_tag_policy({"smart": "abort"})
        self.resolve(cause="beat")
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual(hold.proposed_hash, self.live_hash())
        self.assertEqual((hold.cause, hold.author), ("tag", outsider))

    def test_rejected_live_proposal_is_not_held_again(self):
        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        self.edit_tag_policy({"smart": "abort"})
        body = {"action": "reject", "proposed_hash": self.live_hash()}
        r = self.client.post(f"/imaging/holds/{hold.pk}/confirm/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.resolve(cause="beat")
        self.assertFalse(PolicyChangeHold.objects.filter(status="pending").exists())

    def test_hold_without_a_change_is_withdrawn(self):
        self.tag_change(None)
        hold = PolicyChangeHold.objects.get()
        BackupPolicy.objects.filter(tag=self.tag).delete()
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()
        _, state = self.resolve(cause="beat")
        hold.refresh_from_db()
        self.assertEqual(hold.status, "rejected")
        self.assertEqual(state.memberships["tags"], [self.tag.pk])
        self.assertEqual(
            DeviceBackupState.objects.get(agent=self.agent).memberships,
            resolver.memberships(self.agent, resolver.group_sets()),
        )

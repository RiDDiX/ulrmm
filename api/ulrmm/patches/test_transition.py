# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker

from core.tasks import core_maintenance_tasks
from core.utils import get_core_settings
from logs.models import DebugLog
from ulrmm.test import ULRMMTestCase
from winupdate.posix import PACKAGE_MANAGERS, parse_packages_output
from winupdate.tasks import _import_updates

from .mirror import POSIX_FAMILIES, mirror_agent_updates, sync_agent_updates
from .models import (
    ACTOR_MIGRATED,
    ACTOR_MIRRORED,
    MIGRATED_REJECTION_REASON,
    Patch,
    PatchDevice,
    PatchEvent,
    PatchPolicy,
)
from .tasks import prune_patch_events

PCRE = "U\tapt\tlibpcre2-8-0\tamd64\t10.42-1\t10.42-1+deb12u1\tImportant\t\nR\t0\n"
PCRE_NEXT = PCRE.replace("10.42-1+deb12u1", "10.42-1+deb12u2")


def win_update(agent, guid, **kwargs):
    kwargs.setdefault("title", f"update {guid}")
    kwargs.setdefault("severity", "Critical")
    kwargs.setdefault("revision_number", 1)
    return baker.make("winupdate.WinUpdate", agent=agent, guid=guid, **kwargs)


class TestBackfillMapping(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")

    def sync(self):
        return sync_agent_updates(self.agent, ACTOR_MIGRATED)

    def test_action_maps_onto_state_and_approval(self):
        expected = {
            "approve": ("approved", "approved"),
            "ignore": ("rejected", "rejected"),
            "nothing": ("discovered", "undecided"),
            "inherit": ("discovered", "undecided"),
        }
        for action in expected:
            win_update(self.agent, f"{{{action}}}", action=action)

        self.sync()

        for action, (state, approval) in expected.items():
            record = PatchDevice.objects.get(patch__external_id=f"{{{action}}}")
            self.assertEqual(record.state, state)
            self.assertEqual(record.approval, approval)

        rejected = PatchDevice.objects.get(patch__external_id="{ignore}")
        self.assertEqual(rejected.approval_reason, MIGRATED_REJECTION_REASON)
        self.assertIsNone(rejected.approved_by)
        self.assertIsNone(rejected.approved_by_policy)

    def test_installed_and_failed_rows(self):
        installed_at = djangotime.now()
        win_update(
            self.agent,
            "{installed}",
            action="approve",
            installed=True,
            result="success",
            date_installed=installed_at,
        )
        win_update(self.agent, "{failed}", action="approve", result="failed")

        self.sync()

        installed = PatchDevice.objects.get(patch__external_id="{installed}")
        self.assertEqual(installed.state, "installed")
        self.assertEqual(installed.approval, "approved")
        self.assertEqual(installed.installed_at, installed_at)

        failed = PatchDevice.objects.get(patch__external_id="{failed}")
        self.assertEqual(failed.state, "failed")
        self.assertEqual(failed.approval, "approved")
        self.assertEqual(failed.attempts, 1)
        self.assertEqual(failed.last_error_kind, "unknown")
        self.assertIsNone(failed.installed_at)

    def test_windows_identity_is_the_guid(self):
        win_update(
            self.agent,
            "{abc}",
            title="t" * 300,
            severity="",
            revision_number=7,
            kb_article_ids=["5000001"],
        )

        self.sync()

        record = Patch.objects.get()
        self.assertEqual(record.provider, "wua")
        self.assertEqual(record.os_family, "windows")
        self.assertEqual(record.external_id, "{abc}")
        self.assertEqual(record.candidate_version, "7")
        self.assertEqual(record.package, "t" * 255)
        self.assertEqual(record.severity, "none")
        self.assertFalse(record.security)
        self.assertEqual(record.advisories, ["5000001"])

    def test_posix_identity_is_the_candidate_key(self):
        win_update(
            self.agent,
            "apt:libpcre2-8-0:amd64:10.42-1+deb12u1",
            title="libpcre2-8-0",
            severity="Important",
        )

        self.sync()

        record = Patch.objects.get()
        self.assertEqual(record.provider, "apt")
        self.assertEqual(record.os_family, "debian")
        self.assertEqual(record.package, "libpcre2-8-0")
        self.assertEqual(record.arch, "amd64")
        self.assertEqual(record.candidate_version, "10.42-1+deb12u1")
        self.assertEqual(record.external_id, "")
        self.assertEqual(record.severity, "important")
        self.assertTrue(record.security)

    def test_every_package_manager_has_a_family(self):
        self.assertEqual(set(POSIX_FAMILIES), set(PACKAGE_MANAGERS))

    def test_duplicate_rows_collapse_to_the_newest(self):
        win_update(self.agent, "{dupe}", action="nothing")
        win_update(self.agent, "{dupe}", action="approve")

        counts = self.sync()

        self.assertEqual(counts["duplicates"], 1)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(PatchDevice.objects.get().approval, "approved")

    def test_the_same_patch_on_two_agents_is_one_catalogue_row(self):
        other = baker.make_recipe("agents.agent")
        win_update(self.agent, "{shared}")
        win_update(other, "{shared}")

        self.sync()
        sync_agent_updates(other, ACTOR_MIGRATED)

        self.assertEqual(Patch.objects.count(), 1)
        self.assertEqual(PatchDevice.objects.count(), 2)

    def test_one_event_per_created_record_with_the_reserved_actor(self):
        win_update(self.agent, "{approved}", action="approve")

        self.sync()

        event = PatchEvent.objects.get()
        self.assertEqual(event.actor, ACTOR_MIGRATED)
        self.assertEqual(event.event_type, "approved")
        self.assertEqual(event.to_state, "approved")
        self.assertEqual(event.candidate_version, "1")
        self.assertEqual(event.payload, {"action": "approve"})


class TestBackfillCommand(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")

    def backfill(self) -> str:
        out = StringIO()
        call_command("backfill_patches", stdout=out)
        return out.getvalue()

    def test_a_second_run_creates_nothing(self):
        win_update(self.agent, "{one}", action="approve")
        win_update(self.agent, "{two}", action="ignore")
        win_update(self.agent, "{two}", action="ignore")
        baker.make("winupdate.WinUpdatePolicy", agent=self.agent, critical="approve")

        first = self.backfill()
        self.assertIn("2 created", first)
        self.assertIn("1 duplicate rows collapsed", first)
        self.assertIn("1 policies mapped", first)
        counts = (
            Patch.objects.count(),
            PatchDevice.objects.count(),
            PatchEvent.objects.count(),
            PatchPolicy.objects.count(),
        )

        second = self.backfill()
        self.assertIn("0 created", second)
        self.assertIn("0 updated", second)
        self.assertIn("2 unchanged", second)
        self.assertEqual(
            counts,
            (
                Patch.objects.count(),
                PatchDevice.objects.count(),
                PatchEvent.objects.count(),
                PatchPolicy.objects.count(),
            ),
        )

    def test_an_all_inherit_agent_policy_is_skipped(self):
        baker.make("winupdate.WinUpdatePolicy", agent=self.agent)

        out = self.backfill()

        self.assertIn("0 policies mapped", out)
        self.assertIn("1 policies skipped", out)
        self.assertFalse(PatchPolicy.objects.exists())

    def test_a_policy_attached_to_both_is_skipped(self):
        baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            policy=baker.make("automation.Policy"),
            critical="approve",
        )

        out = self.backfill()

        self.assertIn("0 policies mapped", out)
        self.assertIn("1 policies skipped", out)
        self.assertFalse(PatchPolicy.objects.exists())

    def test_an_agent_policy_with_a_decision_is_mapped(self):
        baker.make("winupdate.WinUpdatePolicy", agent=self.agent, critical="approve")

        self.backfill()

        policy = PatchPolicy.objects.get(agent=self.agent)
        self.assertEqual(
            policy.auto_approve, [{"severity": "critical", "action": "approve"}]
        )
        self.assertIsNone(policy.windows)
        self.assertIsNone(policy.reboot)
        self.assertIsNone(policy.retry)
        self.assertEqual(policy.os_family_scope, [])

    def test_a_policy_row_maps_every_field(self):
        policy = baker.make("automation.Policy")
        baker.make(
            "winupdate.WinUpdatePolicy",
            policy=policy,
            critical="approve",
            low="manual",
            other="ignore",
            run_time_frequency="daily",
            run_time_days=[0, 3],
            run_time_hour=2,
            reboot_after_install="required",
            reprocess_failed_inherit=False,
            reprocess_failed=True,
            reprocess_failed_times=3,
            email_if_fail=True,
        )

        self.backfill()

        mapped = PatchPolicy.objects.get(policy=policy)
        self.assertEqual(
            mapped.auto_approve,
            [
                {"severity": "critical", "action": "approve"},
                {"severity": "low", "action": "require_manual"},
                {"severity": "none", "action": "reject"},
            ],
        )
        self.assertEqual(
            mapped.windows,
            [
                {
                    "days": [0, 3],
                    "start_hour": 2,
                    "duration_minutes": 120,
                    "timezone": "agent",
                }
            ],
        )
        self.assertEqual(mapped.reboot, {"mode": "when_required"})
        self.assertEqual(mapped.retry, {"max_attempts": 3, "email_if_fail": True})

    def test_a_monthly_policy_maps_the_day_of_month(self):
        policy = baker.make("automation.Policy")
        baker.make(
            "winupdate.WinUpdatePolicy",
            policy=policy,
            run_time_frequency="monthly",
            run_time_day=17,
        )

        self.backfill()

        self.assertEqual(
            PatchPolicy.objects.get(policy=policy).windows[0]["day_of_month"], 17
        )


class TestIngestMirror(ULRMMTestCase):
    def setUp(self):
        self.url = "/api/v3/winupdates/"
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.authenticate_agent(self.agent)

    def wua_update(self, guid):
        return {
            "guid": guid,
            "kb_article_ids": ["5000001"],
            "title": f"update {guid}",
            "installed": False,
            "downloaded": False,
            "description": "",
            "severity": "Critical",
            "categories": [],
            "category_ids": [],
            "more_info_urls": [],
            "support_url": "",
            "revision_number": 1,
        }

    def test_a_windows_scan_mirrors_into_the_patch_records(self):
        r = self.client.post(
            self.url, {"wua_updates": [self.wua_update("{offered}")]}, format="json"
        )

        self.assertEqual(r.status_code, 200)
        record = PatchDevice.objects.get()
        self.assertEqual(record.agent, self.agent)
        self.assertEqual(record.patch.external_id, "{offered}")
        self.assertEqual(record.state, "discovered")

        event = PatchEvent.objects.get()
        self.assertEqual(event.actor, ACTOR_MIRRORED)
        self.assertEqual(event.payload["approval_semantics"], "script_path")

    def test_a_posix_import_mirrors_into_the_patch_records(self):
        _import_updates(self.agent, parse_packages_output(PCRE))

        record = PatchDevice.objects.get()
        self.assertEqual(record.patch.provider, "apt")
        self.assertEqual(record.patch.candidate_version, "10.42-1+deb12u1")
        self.assertEqual(PatchEvent.objects.get().actor, ACTOR_MIRRORED)

    def test_the_mirror_leaves_the_update_rows_alone(self):
        win_update(self.agent, "{one}", action="approve")
        win_update(self.agent, "{two}", action="ignore", installed=True)
        before = list(self.agent.winupdates.order_by("id").values())

        mirror_agent_updates(self.agent)

        self.assertEqual(list(self.agent.winupdates.order_by("id").values()), before)

    def test_a_mirror_failure_leaves_the_ingest_alone(self):
        with patch("patches.mirror.sync_agent_updates", side_effect=Exception("boom")):
            r = self.client.post(
                self.url, {"wua_updates": [self.wua_update("{offered}")]}, format="json"
            )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.agent.winupdates.count(), 1)
        self.assertFalse(PatchDevice.objects.exists())
        self.assertTrue(
            DebugLog.objects.filter(
                agent=self.agent, message__contains="patch records failed"
            ).exists()
        )

    def test_a_later_decision_reaches_the_records_on_the_next_scan(self):
        update = win_update(self.agent, "{offered}", action="nothing")
        mirror_agent_updates(self.agent)

        update.action = "approve"
        update.save(update_fields=["action"])
        mirror_agent_updates(self.agent)

        record = PatchDevice.objects.get()
        self.assertEqual(record.approval, "approved")
        self.assertEqual(record.state, "approved")

        events = list(PatchEvent.objects.order_by("id"))
        self.assertEqual([i.event_type for i in events], ["discovered", "approved"])
        self.assertEqual(events[1].actor, ACTOR_MIRRORED)
        self.assertEqual(events[1].prev_hash, events[0].hash)
        self.assertEqual(events[1].from_state, "discovered")
        self.assertEqual(events[1].to_state, "approved")

    def test_the_first_event_of_a_created_record_starts_the_chain(self):
        win_update(self.agent, "{offered}", action="approve")

        mirror_agent_updates(self.agent)

        event = PatchEvent.objects.get()
        self.assertEqual(event.prev_hash, "")
        self.assertEqual(event.from_state, "")
        # written without the lookup save() does, same chain semantics
        self.assertEqual(event.hash, event.compute_hash())

    def test_a_result_that_moves_the_state_gets_its_own_event(self):
        update = win_update(self.agent, "{offered}", action="approve")
        mirror_agent_updates(self.agent)

        update.installed = True
        update.result = "success"
        update.save(update_fields=["installed", "result"])
        mirror_agent_updates(self.agent)

        self.assertEqual(PatchDevice.objects.get().state, "installed")
        event = PatchEvent.objects.order_by("id").last()
        self.assertEqual(event.event_type, "transaction_finished")
        self.assertEqual(event.actor, ACTOR_MIRRORED)
        self.assertEqual(event.from_state, "approved")
        self.assertEqual(event.to_state, "installed")
        self.assertEqual(event.payload["result"], "success")
        self.assertEqual(event.payload["approval_semantics"], "script_path")

    def test_a_new_candidate_supersedes_the_record_it_replaces(self):
        _import_updates(self.agent, parse_packages_output(PCRE))

        _import_updates(self.agent, parse_packages_output(PCRE_NEXT))

        closed = PatchDevice.objects.get(patch__candidate_version="10.42-1+deb12u1")
        self.assertEqual(closed.state, "superseded")
        event = closed.events.order_by("id").last()
        self.assertEqual(event.event_type, "superseded")
        self.assertEqual(event.actor, ACTOR_MIRRORED)
        self.assertEqual(event.from_state, "discovered")
        self.assertEqual(event.candidate_version, "10.42-1+deb12u1")
        self.assertEqual(
            PatchDevice.objects.get(patch__candidate_version="10.42-1+deb12u2").state,
            "discovered",
        )

    def test_a_record_the_scan_no_longer_offers_goes_obsolete(self):
        gone = win_update(self.agent, "{gone}")
        win_update(self.agent, "{kept}")
        mirror_agent_updates(self.agent)

        gone.delete()
        mirror_agent_updates(self.agent)

        record = PatchDevice.objects.get(patch__external_id="{gone}")
        self.assertEqual(record.state, "obsolete")
        event = record.events.order_by("id").last()
        self.assertEqual(event.event_type, "obsolete")
        self.assertEqual(event.from_state, "discovered")
        self.assertEqual(event.to_state, "obsolete")
        self.assertEqual(
            PatchDevice.objects.get(patch__external_id="{kept}").state, "discovered"
        )

    def test_a_closed_record_is_not_reopened_by_an_unchanged_scan(self):
        _import_updates(self.agent, parse_packages_output(PCRE))
        _import_updates(self.agent, parse_packages_output(PCRE_NEXT))
        events = PatchEvent.objects.count()

        _import_updates(self.agent, parse_packages_output(PCRE_NEXT))

        self.assertEqual(
            PatchDevice.objects.get(patch__candidate_version="10.42-1+deb12u1").state,
            "superseded",
        )
        self.assertEqual(PatchEvent.objects.count(), events)

    def test_a_rescan_refreshes_the_catalogue_metadata(self):
        update = win_update(self.agent, "{offered}", severity="", kb_article_ids=[])
        mirror_agent_updates(self.agent)
        self.assertEqual(Patch.objects.get().severity, "none")

        update.severity = "Critical"
        update.kb_article_ids = ["5000002"]
        update.title = "update {offered} v2"
        update.save(update_fields=["severity", "kb_article_ids", "title"])
        mirror_agent_updates(self.agent)

        patch = Patch.objects.get()
        self.assertEqual(patch.severity, "critical")
        self.assertTrue(patch.security)
        self.assertEqual(patch.advisories, ["5000002"])
        self.assertEqual(patch.package, "update {offered} v2")

    def test_the_mirror_costs_a_handful_of_queries(self):
        for i in range(5):
            win_update(self.agent, f"{{guid-{i}}}")
        mirror_agent_updates(self.agent)

        with CaptureQueriesContext(connection) as queries:
            mirror_agent_updates(self.agent)

        # read the rows, read and refresh the catalogue, read the records,
        # plus the savepoint pair the atomic block takes inside the test
        self.assertEqual(len(queries), 6)


class TestPatchEventPrune(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.record = self.patch_device()

    def patch_device(self):
        return PatchDevice.objects.create(
            patch=baker.make("patches.Patch"), agent=baker.make_recipe("agents.agent")
        )

    def event(self, days_ago, record=None):
        event = PatchEvent.objects.create(
            patch_device=record or self.record,
            event_type="discovered",
            actor=ACTOR_MIGRATED,
        )
        PatchEvent.objects.filter(pk=event.pk).update(
            at=djangotime.now() - djangotime.timedelta(days=days_ago)
        )
        return event

    @patch("core.tasks.prune_patch_events.delay")
    def test_a_default_maintenance_run_keeps_every_event(self, prune):
        self.event(400)

        core_maintenance_tasks()

        prune.assert_not_called()
        self.assertEqual(PatchEvent.objects.count(), 1)

    @patch("core.tasks.prune_patch_events.delay")
    def test_the_maintenance_run_dispatches_when_the_setting_is_set(self, prune):
        core = get_core_settings()
        core.patch_event_prune_days = 30
        core.save(update_fields=["patch_event_prune_days"])

        core_maintenance_tasks()

        prune.assert_called_once_with(30)

    def test_only_an_oldest_first_prefix_goes(self):
        self.event(40)
        self.event(39)
        kept = self.event(1)
        # older than the cut-off but behind a kept event: the chain stays whole
        after = self.event(38)

        prune_patch_events(30)

        self.assertCountEqual(
            PatchEvent.objects.values_list("id", flat=True), [kept.id, after.id]
        )

    def test_a_record_whose_events_are_all_old_is_emptied(self):
        other = self.patch_device()
        self.event(40)
        kept = self.event(1, record=other)

        prune_patch_events(30)

        self.assertCountEqual(
            PatchEvent.objects.values_list("id", flat=True), [kept.id]
        )

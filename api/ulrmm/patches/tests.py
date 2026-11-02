# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.db.utils import IntegrityError
from model_bakery import baker

from core.models import CoreSettings
from ulrmm.test import ULRMMTestCase

from .models import (
    HostFacts,
    Patch,
    PatchDevice,
    PatchEvent,
    PatchEventType,
    PatchHostState,
    PatchPolicy,
    RecoveryState,
    SystemUpgradeState,
)


class TestPatchIdentity(ULRMMTestCase):
    def test_external_id_is_the_identity_when_it_exists(self):
        baker.make("patches.Patch", provider="wua", external_id="{guid-1}")

        with self.assertRaises(IntegrityError), transaction.atomic():
            # a different title and revision, same UpdateID, is the same patch
            Patch.objects.create(
                os_family="windows",
                provider="wua",
                package="another title",
                candidate_version="204",
                external_id="{guid-1}",
            )

    def test_same_external_id_on_another_provider_is_a_different_patch(self):
        baker.make("patches.Patch", provider="wua", external_id="{guid-1}")
        baker.make("patches.Patch", provider="apt", external_id="{guid-1}")

        self.assertEqual(Patch.objects.count(), 2)

    def test_candidate_is_the_identity_without_an_external_id(self):
        fields = {
            "os_family": "debian",
            "provider": "apt",
            "package": "libpcre2-8-0",
            "arch": "amd64",
            "candidate_version": "10.42-1+deb12u1",
            "origin": "bookworm-security",
        }
        Patch.objects.create(**fields)

        with self.assertRaises(IntegrityError), transaction.atomic():
            Patch.objects.create(**fields)

    def test_a_new_candidate_without_an_external_id_is_a_new_patch(self):
        fields = {
            "os_family": "debian",
            "provider": "apt",
            "package": "libpcre2-8-0",
            "arch": "amd64",
            "origin": "bookworm-security",
        }
        Patch.objects.create(candidate_version="10.42-1", **fields)
        Patch.objects.create(candidate_version="10.42-1+deb12u1", **fields)

        self.assertEqual(Patch.objects.count(), 2)

    def test_empty_external_id_does_not_collide(self):
        # the partial index must not fold every "" row onto one row
        baker.make("patches.Patch", provider="apt", package="one", external_id="")
        baker.make("patches.Patch", provider="apt", package="two", external_id="")

        self.assertEqual(Patch.objects.count(), 2)


class TestPatchDevice(ULRMMTestCase):
    def test_one_record_per_patch_and_agent(self):
        agent = baker.make_recipe("agents.agent")
        patch = baker.make("patches.Patch")
        PatchDevice.objects.create(patch=patch, agent=agent)

        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchDevice.objects.create(patch=patch, agent=agent)

    def test_same_patch_on_another_agent(self):
        patch = baker.make("patches.Patch")
        for _ in range(2):
            PatchDevice.objects.create(
                patch=patch, agent=baker.make_recipe("agents.agent")
            )

        self.assertEqual(patch.devices.count(), 2)

    def test_defaults_of_a_discovered_record(self):
        record = PatchDevice.objects.create(
            patch=baker.make("patches.Patch"), agent=baker.make_recipe("agents.agent")
        )

        self.assertEqual(record.state, "discovered")
        self.assertEqual(record.approval, "undecided")
        self.assertEqual(record.recovery_state, RecoveryState.NONE)
        self.assertEqual(record.attempts, 0)
        self.assertTrue(record.installable)
        self.assertIsNone(record.approved_by)
        self.assertIsNone(record.approved_by_policy)
        self.assertIsNone(record.carried_from)


class TestPatchEventChain(ULRMMTestCase):
    def setUp(self):
        self.record = PatchDevice.objects.create(
            patch=baker.make("patches.Patch"), agent=baker.make_recipe("agents.agent")
        )

    def event(self, event_type, actor="system:migrated"):
        return PatchEvent.objects.create(
            patch_device=self.record, event_type=event_type, actor=actor
        )

    def test_first_event_has_no_predecessor(self):
        first = self.event(PatchEventType.DISCOVERED)

        self.assertEqual(first.prev_hash, "")
        self.assertEqual(first.hash, first.compute_hash())

    def test_each_event_chains_onto_the_previous_one(self):
        first = self.event(PatchEventType.DISCOVERED)
        second = self.event(PatchEventType.EVALUATED)

        self.assertEqual(second.prev_hash, first.hash)
        self.assertEqual(second.hash, second.compute_hash())
        self.assertNotEqual(first.hash, second.hash)

    def test_the_chain_is_per_record(self):
        other = PatchDevice.objects.create(
            patch=baker.make("patches.Patch"), agent=baker.make_recipe("agents.agent")
        )
        self.event(PatchEventType.DISCOVERED)
        elsewhere = PatchEvent.objects.create(
            patch_device=other, event_type=PatchEventType.DISCOVERED, actor="system"
        )

        self.assertEqual(elsewhere.prev_hash, "")

    def test_two_events_cannot_share_a_predecessor(self):
        first = self.event(PatchEventType.DISCOVERED)
        self.event(PatchEventType.EVALUATED)

        # the losing half of a race: both writers read the same newest event
        forked = PatchEvent(
            patch_device=self.record,
            event_type=PatchEventType.APPROVED,
            actor="system:mirrored",
            prev_hash=first.hash,
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchEvent.objects.bulk_create([forked])

    def test_a_changed_event_no_longer_matches_its_hash(self):
        event = self.event(PatchEventType.APPROVED)
        event.actor = "someone else"

        self.assertNotEqual(event.hash, event.compute_hash())


class TestPatchPolicyAttachment(ULRMMTestCase):
    def test_both_attachment_points_are_refused(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchPolicy.objects.create(
                agent=baker.make_recipe("agents.agent"),
                policy=baker.make("automation.Policy"),
            )

    def test_a_policy_attached_to_nothing_is_refused(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchPolicy.objects.create()

    def test_one_row_per_agent(self):
        agent = baker.make_recipe("agents.agent")
        PatchPolicy.objects.create(agent=agent)

        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchPolicy.objects.create(agent=agent)

    def test_one_row_per_automation_policy(self):
        policy = baker.make("automation.Policy")
        PatchPolicy.objects.create(policy=policy)

        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchPolicy.objects.create(policy=policy)


class TestPatchHostState(ULRMMTestCase):
    def test_defaults(self):
        state = PatchHostState.objects.create(agent=baker.make_recipe("agents.agent"))

        self.assertEqual(state.system_upgrade_state, SystemUpgradeState.CURRENT)
        self.assertEqual(state.holds, [])
        self.assertFalse(state.unpatchable)
        self.assertIsNone(state.unpatchable_since)
        self.assertEqual(state.unpatchable_blockers, [])

    def test_one_row_per_agent(self):
        agent = baker.make_recipe("agents.agent")
        PatchHostState.objects.create(agent=agent)

        with self.assertRaises(IntegrityError), transaction.atomic():
            PatchHostState.objects.create(agent=agent)


class TestHostFacts(ULRMMTestCase):
    def test_one_row_per_agent(self):
        agent = baker.make_recipe("agents.agent")
        HostFacts.objects.create(agent=agent)

        with self.assertRaises(IntegrityError), transaction.atomic():
            HostFacts.objects.create(agent=agent)

    def test_created_empty(self):
        facts = HostFacts.objects.create(agent=baker.make_recipe("agents.agent"))

        self.assertEqual(facts.distro, "")
        self.assertEqual(facts.providers, [])
        self.assertEqual(facts.origins, [])
        self.assertEqual(facts.maintenance, {})
        self.assertEqual(facts.reboot_required, {})
        self.assertIsNone(facts.reported_at)


class TestPatchEventPruneDays(ULRMMTestCase):
    def test_defaults_to_keep_forever(self):
        self.assertEqual(CoreSettings.objects.create().patch_event_prune_days, 0)

    def test_cannot_be_negative(self):
        core = CoreSettings.objects.create()
        core.patch_event_prune_days = -1

        with self.assertRaises(IntegrityError), transaction.atomic():
            core.save()

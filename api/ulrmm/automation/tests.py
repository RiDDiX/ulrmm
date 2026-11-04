# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker

from agents.models import Agent
from checks.models import CheckResult
from ulrmm.test import ULRMMTestCase

from .models import Policy

FLAGS = [
    "can_list_automation_policies",
    "can_manage_automation_policies",
    "can_list_agents",
    "can_edit_agent",
    "can_list_sites",
    "can_manage_sites",
]


class TestPolicyAssignmentScope(ULRMMTestCase):
    """A policy that reaches no agent belongs to whatever it is assigned to.
    site1 is the role's; site3 (company2) is foreign and has no agents."""

    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.setup_base_instance()
        self.user = self.create_user_with_roles(FLAGS)
        self.user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=self.user)

    def test_foreign_empty_site_hides_the_policy(self):
        foreign = baker.make("automation.Policy", name="foreign")
        self.site3.workstation_policy = foreign
        self.site3.save()

        self.assertEqual(
            self.client.get(f"/automation/policies/{foreign.pk}/").status_code, 403
        )
        r = self.client.put(
            f"/automation/policies/{foreign.pk}/", {"name": "taken"}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            self.client.delete(f"/automation/policies/{foreign.pk}/").status_code, 403
        )
        names = {p["name"] for p in self.client.get("/automation/policies/").data}
        self.assertNotIn("foreign", names)
        foreign.refresh_from_db()
        self.assertEqual(foreign.name, "foreign")

    def test_default_slot_is_nobodys(self):
        default = baker.make("automation.Policy", name="default")
        self.coresettings.server_policy = default
        self.coresettings.save()
        self.assertEqual(
            self.client.get(f"/automation/policies/{default.pk}/").status_code, 403
        )

    def test_unassigned_and_own_empty_site_stay_open(self):
        unassigned = baker.make("automation.Policy", name="new")
        own = baker.make("automation.Policy", name="own")
        self.site1.server_policy = own
        self.site1.save()

        for policy in (unassigned, own):
            self.assertEqual(
                self.client.get(f"/automation/policies/{policy.pk}/").status_code, 200
            )
            r = self.client.put(
                f"/automation/policies/{policy.pk}/", {"desc": "x"}, format="json"
            )
            self.assertEqual(r.status_code, 200)
        names = {p["name"] for p in self.client.get("/automation/policies/").data}
        self.assertTrue({"new", "own"} <= names)

    def test_own_policy_also_assigned_abroad_is_read_only(self):
        policy = baker.make("automation.Policy")
        baker.make_recipe("agents.agent", site=self.site1, policy=policy)
        self.site3.server_policy = policy
        self.site3.save()

        self.assertEqual(
            self.client.get(f"/automation/policies/{policy.pk}/").status_code, 200
        )
        r = self.client.put(
            f"/automation/policies/{policy.pk}/", {"desc": "x"}, format="json"
        )
        self.assertEqual(r.status_code, 403)

    def test_site_cannot_take_a_foreign_policy(self):
        foreign = baker.make("automation.Policy")
        self.site3.workstation_policy = foreign
        self.site3.save()

        r = self.client.put(
            f"/clients/sites/{self.site1.pk}/",
            {"site": {"server_policy": foreign.pk}},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "You cannot assign this policy.")

    @patch("core.views.sync_mesh_perms_task.delay")
    def test_default_slot_cannot_take_a_foreign_policy(self, _sync):
        self.user.role.can_edit_core_settings = True
        self.user.role.save()
        foreign = baker.make("automation.Policy")
        baker.make_recipe("agents.agent", site=self.site3, policy=foreign)

        r = self.client.put(
            "/core/settings/", {"server_policy": foreign.pk}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.coresettings.refresh_from_db()
        self.assertIsNone(self.coresettings.server_policy_id)

    @patch("agents.views.sync_mesh_perms_task.delay")
    def test_agent_cannot_take_a_foreign_policy(self, _sync):
        agent = baker.make_recipe("agents.agent", site=self.site1)
        foreign = baker.make("automation.Policy")
        baker.make_recipe("agents.agent", site=self.site3, policy=foreign)
        unassigned = baker.make("automation.Policy")

        r = self.client.put(
            f"/agents/{agent.agent_id}/", {"policy": foreign.pk}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "You cannot assign this policy.")
        agent.refresh_from_db()
        self.assertIsNone(agent.policy_id)

        r = self.client.put(
            f"/agents/{agent.agent_id}/", {"policy": unassigned.pk}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        agent.refresh_from_db()
        self.assertEqual(agent.policy_id, unassigned.pk)
        # the form sends the current policy along on every later save
        agent.policy = foreign
        agent.save()
        r = self.client.put(
            f"/agents/{agent.agent_id}/", {"policy": foreign.pk}, format="json"
        )
        self.assertEqual(r.status_code, 200)


class TestPolicyStatusNotRun(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.setup_base_instance()
        self.policy = baker.make("automation.Policy", active=True)
        self.site1.workstation_policy = self.policy
        self.site1.save()
        self.ran, self.waiting = (
            baker.make_recipe(
                "agents.agent",
                site=self.site1,
                monitoring_type="workstation",
                hostname=name,
            )
            for name in ("ran", "waiting")
        )
        # an agent outside the policy gets no row
        baker.make_recipe(
            "agents.agent", site=self.site3, monitoring_type="workstation"
        )
        # the agents' policy check lists live in the shared redis
        Policy.forget_cached_policies()

    def test_check_lists_agents_before_their_first_run(self):
        check = baker.make_recipe("checks.ping_check", policy=self.policy)
        baker.make(CheckResult, agent=self.ran, assigned_check=check, status="passing")

        r = self.client.get(f"/automation/checks/{check.pk}/status/")
        self.assertEqual(r.status_code, 200)
        by_host = {row["hostname"]: row for row in r.data}
        self.assertEqual(set(by_host), {self.ran.hostname, self.waiting.hostname})
        self.assertEqual(by_host[self.ran.hostname]["status"], "passing")
        waiting = by_host[self.waiting.hostname]
        self.assertEqual(waiting["status"], "pending")
        self.assertIsNone(waiting["last_run"])
        self.assertEqual(waiting["check_type"], "ping")
        self.assertEqual(waiting["id"], f"agent-{self.waiting.pk}")

    def test_task_lists_agents_before_their_first_sync(self):
        task = baker.make_recipe("autotasks.task", policy=self.policy)

        r = self.client.get(f"/automation/tasks/{task.pk}/status/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            sorted(row["hostname"] for row in r.data),
            sorted([self.ran.hostname, self.waiting.hostname]),
        )
        self.assertTrue(all(row["status"] == "pending" for row in r.data))

    def test_scoped_role_sees_its_own_agents_only(self):
        check = baker.make_recipe("checks.ping_check", policy=self.policy)
        self.site3.workstation_policy = self.policy
        self.site3.save()
        # a result of an agent outside the role's scope stays hidden too
        baker.make(CheckResult, agent=self.ran, assigned_check=check)
        user = self.create_user_with_roles(["can_list_automation_policies"])
        user.role.can_view_sites.set([self.site3])
        self.client.force_authenticate(user=user)

        r = self.client.get(f"/automation/checks/{check.pk}/status/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 1)
        self.assertEqual(r.data[0]["status"], "pending")


# the merged policy checks live in the cache, so the tests need a real one
@override_settings(
    CACHES={
        "default": {
            "BACKEND": "ulrmm.golden.base.GoldenCache",
            "LOCATION": "policy-merge",
        }
    }
)
class TestPolicyMergeCache(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_base_instance()
        self.policy = baker.make("automation.Policy", active=True)
        self.site1.workstation_policy = self.policy
        self.site1.save()
        self.check = baker.make_recipe("checks.ping_check", policy=self.policy)
        self.excluded, self.member = baker.make_recipe(
            "agents.workstation_agent", site=self.site1, _quantity=2
        )
        self.policy.excluded_agents.add(self.excluded)
        cache.clear()

    def policy_checks(self, agent: Agent) -> list[int]:
        fresh = Agent.objects.get(pk=agent.pk)
        return [check.pk for check in fresh.get_checks_from_policies()]

    def test_excluded_agent_does_not_decide_for_its_site(self):
        for first in (self.excluded, self.member):
            cache.clear()
            self.policy_checks(first)
            self.assertEqual(self.policy_checks(self.member), [self.check.pk])
            self.assertEqual(self.policy_checks(self.excluded), [])

    def test_moved_agent_gets_the_new_sites_checks(self):
        agent = baker.make_recipe("agents.workstation_agent", site=self.site2)
        baker.make_recipe("checks.ping_check", agent=agent, ip="192.0.2.1")
        self.assertEqual(self.policy_checks(agent), [])

        agent.site = self.site1
        with self.captureOnCommitCallbacks(execute=True):
            agent.save()
        self.assertEqual(self.policy_checks(agent), [self.check.pk])

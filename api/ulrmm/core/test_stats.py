# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from collections import Counter

from model_bakery import baker

from agents.models import Agent
from core.stats import _overdue_q, fleet_stats
from ulrmm.test import ULRMMTestCase


class TestFleetStats(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.url = "/core/stats/"

    def test_requires_auth(self):
        self.check_not_authenticated("get", self.url)

    def test_counts_are_aggregated(self):
        site = baker.make("clients.Site")
        baker.make_recipe("agents.online_agent", site=site, _quantity=3)
        baker.make_recipe("agents.overdue_agent", site=site, _quantity=2)

        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)

        agents = r.data["agents"]
        self.assertEqual(agents["total"], 5)
        # overdue agents are past both windows, so they are not counted online
        self.assertEqual(agents["online"], 3)
        self.assertEqual(agents["overdue"], 2)
        self.assertEqual(len(r.data["by_plat"]), 1)
        self.assertIn("checks", r.data)

        # the buckets cover the whole fleet, online agents included
        buckets = r.data["last_seen_buckets"]
        self.assertEqual(buckets["under_1d"], 5)
        self.assertEqual(sum(buckets.values()), agents["total"])

    def test_failed_patches_counted_apart_from_pending(self):
        site = baker.make("clients.Site")
        failing = baker.make_recipe("agents.online_agent", site=site)
        waiting = baker.make_recipe("agents.online_agent", site=site)
        switched = baker.make_recipe("agents.online_agent", site=site)
        done = baker.make_recipe("agents.online_agent", site=site)

        # two failures on one agent still count the agent once
        baker.make_recipe(
            "winupdate.approved_winupdate", agent=failing, result="failed", _quantity=2
        )
        baker.make_recipe("winupdate.approved_winupdate", agent=waiting)
        baker.make_recipe(
            "winupdate.winupdate", agent=switched, action="ignore", result="failed"
        )
        baker.make_recipe(
            "winupdate.approved_winupdate", agent=done, installed=True, result="failed"
        )

        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        # failed is a subset of pending, not a separate bucket
        self.assertEqual(r.data["patches_pending_agents"], 2)
        self.assertEqual(r.data["patches_failed_agents"], 1)

    def test_scoped_user_sees_only_their_failed_patches(self):
        mine = baker.make("clients.Site")
        other = baker.make("clients.Site")
        for site in (mine, other):
            agent = baker.make_recipe("agents.online_agent", site=site)
            baker.make_recipe(
                "winupdate.approved_winupdate", agent=agent, result="failed"
            )

        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_sites.set([mine])
        self.client.force_authenticate(user=user)

        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["patches_failed_agents"], 1)

    def test_scoped_user_sees_only_their_agents(self):
        mine = baker.make("clients.Site")
        other = baker.make("clients.Site")
        baker.make_recipe("agents.online_agent", site=mine, _quantity=2)
        baker.make_recipe("agents.online_agent", site=other, _quantity=4)

        self.check_authorized_superuser("get", self.url)

        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_sites.set([mine])
        self.client.force_authenticate(user=user)

        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["agents"]["total"], 2)


class TestOverdueNeedsMonitoring(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_status_and_counts_agree(self):
        def silent(**kw):
            return baker.make_recipe(
                "agents.overdue_agent", overdue_dashboard_alert=False, **kw
            )

        def template(**kw):
            return baker.make("alerts.AlertTemplate", **kw)

        script = baker.make("scripts.Script")
        expected = {
            silent(overdue_email_alert=True): "overdue",
            silent(overdue_text_alert=True): "overdue",
            silent(alert_template=template(agent_always_alert=True)): "overdue",
            silent(alert_template=template(agent_always_email=True)): "overdue",
            silent(alert_template=template(action=script)): "overdue",
            silent(
                alert_template=template(action=script, agent_script_actions=False)
            ): "offline",
            silent(alert_template=template()): "offline",
            silent(): "offline",
            baker.make_recipe("agents.overdue_agent"): "overdue",
            baker.make_recipe("agents.offline_agent", overdue_email_alert=True): (
                "offline"
            ),
            baker.make_recipe("agents.online_agent", overdue_email_alert=True): (
                "online"
            ),
            baker.make_recipe("agents.agent", last_seen=None): "offline",
        }

        agents = Agent.objects.all()
        self.assertEqual({a: a.status for a in agents}, expected)
        self.assertEqual(
            set(agents.filter(_overdue_q())),
            {a for a, s in expected.items() if s == "overdue"},
        )
        counts = fleet_stats(agents)["agents"]
        want = Counter(expected.values())
        for status in ("online", "offline", "overdue"):
            self.assertEqual(counts[status], want[status], status)

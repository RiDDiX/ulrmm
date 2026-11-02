# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.test import ULRMMTestCase


class TestAlertListAgentFilter(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent, self.other = baker.make_recipe("agents.agent", _quantity=2)
        self.mine = baker.make("alerts.Alert", agent=self.agent, _quantity=2)
        self.theirs = baker.make("alerts.Alert", agent=self.other)

    def ids(self, body):
        r = self.client.patch("/alerts/", body, format="json")
        self.assertEqual(r.status_code, 200)
        return {a["id"] for a in r.data}

    def test_agent_filter(self):
        mine = {a.pk for a in self.mine}
        self.assertEqual(self.ids({"agentFilter": self.agent.agent_id}), mine)
        self.assertEqual(
            self.ids({"timeFilter": 30, "agentFilter": self.agent.agent_id}), mine
        )
        self.assertEqual(self.ids({"agentFilter": "nope"}), set())
        # callers without it still get every agent's alerts
        self.assertEqual(self.ids({"timeFilter": 30}), mine | {self.theirs.pk})

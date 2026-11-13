# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.test import ULRMMTestCase


class TestHistoryNewest(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        rows = baker.make("agents.AgentHistory", agent=self.agent, _quantity=8)
        self.pks = sorted(row.pk for row in rows)
        self.url = f"/agents/{self.agent.agent_id}/history/"

    def ids(self, query=""):
        r = self.client.get(self.url + query)
        self.assertEqual(r.status_code, 200)
        return [row["id"] for row in r.data]

    def test_newest_returns_the_latest_rows_oldest_first(self):
        self.assertEqual(self.ids("?newest=3"), self.pks[-3:])
        self.assertEqual(self.ids("?newest=500"), self.pks)

    def test_other_values_are_ignored(self):
        for value in ("0", "501", "-2", "x", ""):
            self.assertEqual(self.ids(f"?newest={value}"), self.pks)
        self.assertEqual(self.ids(), self.pks)

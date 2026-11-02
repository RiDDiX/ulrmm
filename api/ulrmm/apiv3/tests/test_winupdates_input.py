# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from logs.models import DebugLog
from ulrmm.test import ULRMMTestCase

URL = "/api/v3/winupdates/"


def wua(guid, **changes):
    item = {
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
    item.update(changes)
    return item


class TestWinUpdatesInput(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        baker.make("winupdate.WinUpdatePolicy", agent=self.agent)
        self.authenticate_agent(self.agent)

    def post(self, body):
        return self.client.post(URL, body, format="json")

    def guids(self):
        return set(self.agent.winupdates.values_list("guid", flat=True))

    def test_item_without_title_is_skipped(self):
        untitled = wua("untitled")
        del untitled["title"]
        r = self.post({"wua_updates": [wua("good"), untitled, wua("null", title=None)]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.guids(), {"good", "null"})
        self.assertEqual(self.agent.winupdates.get(guid="null").title, "")

    def test_long_kb_id_is_skipped_not_cut(self):
        long_kb = wua("long", kb_article_ids=["9" * 99])
        r = self.post({"wua_updates": [wua("good"), long_kb]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.guids(), {"good"})

        # 98 digits still fit the 100 chars of kb
        r = self.post({"wua_updates": [wua("fits", kb_article_ids=["9" * 98])]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.agent.winupdates.get(guid="fits").kb, "KB" + "9" * 98)

    def test_only_long_kb_item_is_an_empty_scan(self):
        r = self.post({"wua_updates": [wua("long", kb_article_ids=["9" * 120])]})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Empty payload")
        self.assertFalse(self.agent.winupdates.exists())

    def test_missing_list_is_required(self):
        r = self.post({"agent_id": self.agent.agent_id})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "wua_updates is required")
        self.assertFalse(DebugLog.objects.filter(agent=self.agent).exists())

    def test_null_and_empty_list_stay_empty_payload(self):
        for value in (None, []):
            r = self.post({"wua_updates": value})
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "Empty payload")
        self.assertEqual(
            DebugLog.objects.filter(
                agent=self.agent, message__contains="returned no updates"
            ).count(),
            2,
        )

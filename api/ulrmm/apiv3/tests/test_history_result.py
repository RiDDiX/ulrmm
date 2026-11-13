# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.shortcuts import get_object_or_404
from model_bakery import baker

from agents.models import AgentHistory, Note
from ulrmm.constants import AgentHistoryType
from ulrmm.test import ULRMMTestCase

RESULT = {
    "script_results": {
        "stdout": "out",
        "stderr": "",
        "retcode": 0,
        "execution_time": 1,
    }
}


class TestHistoryResultOnce(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.authenticate_agent(self.agent)
        self.hist = baker.make(
            "agents.AgentHistory",
            agent=self.agent,
            type=AgentHistoryType.SCRIPT_RUN,
            save_to_agent_note=True,
        )
        self.url = f"/api/v3/{self.hist.pk}/{self.agent.agent_id}/histresult/"

    def test_a_retry_racing_the_first_write_stores_nothing(self):
        # both requests read the row before either wrote it
        stale = AgentHistory.objects.get(pk=self.hist.pk)
        first = self.client.patch(self.url, RESULT, format="json")
        self.assertEqual(first.status_code, 200)

        def lookup(rows, *args, **kwargs):
            if rows.model is AgentHistory:
                return stale
            return get_object_or_404(rows, *args, **kwargs)

        with patch("apiv3.views.get_object_or_404", side_effect=lookup):
            second = self.client.patch(self.url, RESULT, format="json")
        self.assertEqual(second.status_code, 400)
        self.assertEqual(Note.objects.filter(agent=self.agent).count(), 1)

    def test_a_late_retry_is_refused(self):
        self.client.patch(self.url, RESULT, format="json")
        r = self.client.patch(self.url, RESULT, format="json")
        self.assertEqual(r.status_code, 400)
        self.hist.refresh_from_db()
        self.assertEqual(self.hist.script_results["stdout"], "out")
        self.assertEqual(Note.objects.filter(agent=self.agent).count(), 1)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

base_url = "/agents"


class TestKeepAwake(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent", site=baker.make("clients.Site"))
        self.url = f"{base_url}/{self.agent.agent_id}/keepawake/"

    @patch("agents.models.Agent.nats_cmd")
    def test_hold_and_release(self, nats_cmd):
        nats_cmd.return_value = "ok"
        before = djangotime.now()
        r = self.client.post(self.url, {"minutes": 120}, format="json")
        self.assertEqual(r.status_code, 200)
        data = nats_cmd.call_args.args[0]
        self.assertEqual(data["func"], "keepawake")
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.keep_awake_until)
        span = self.agent.keep_awake_until - before
        self.assertTrue(119 * 60 <= span.total_seconds() <= 121 * 60)
        self.assertEqual(data["until"], int(self.agent.keep_awake_until.timestamp()))
        self.assertTrue(
            AuditLog.objects.filter(
                agent_id=self.agent.agent_id, message__contains="keep awake on"
            ).exists()
        )

        r = self.client.post(self.url, {"minutes": 0}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(nats_cmd.call_args.args[0], {"func": "keepawake", "until": 0})
        self.agent.refresh_from_db()
        self.assertIsNone(self.agent.keep_awake_until)
        self.assertTrue(
            AuditLog.objects.filter(message__contains="keep awake off on").exists()
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_bad_input_and_agent_errors(self, nats_cmd):
        nats_cmd.return_value = "ok"
        for bad in ({"minutes": 361}, {"minutes": -1}, {"minutes": "soon"}):
            r = self.client.post(self.url, bad, format="json")
            self.assertEqual(r.status_code, 400, bad)
        nats_cmd.assert_not_called()

        nats_cmd.return_value = "timeout"
        r = self.client.post(self.url, {"minutes": 60}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("contact", r.json())
        nats_cmd.return_value = "until is more than 6h0m0s ahead"
        r = self.client.post(self.url, {"minutes": 60}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("refused", r.json())
        self.agent.refresh_from_db()
        self.assertIsNone(self.agent.keep_awake_until)

        self.check_not_authenticated("post", self.url)

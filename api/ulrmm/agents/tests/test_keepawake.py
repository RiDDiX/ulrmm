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


class TestKeepAwakeAC(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent",
            site=baker.make("clients.Site"),
            plat="darwin",
            version="2.03.11.2026",
        )
        self.url = f"{base_url}/{self.agent.agent_id}/keepawake/"

    @patch("agents.models.Agent.nats_cmd")
    def test_on_and_off(self, nats_cmd):
        nats_cmd.return_value = "ok"
        r = self.client.post(self.url, {"ac": True}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"keep_awake_ac": True})
        self.assertEqual(
            nats_cmd.call_args.args[0], {"func": "keepawakeac", "ac": True}
        )
        self.agent.refresh_from_db()
        self.assertTrue(self.agent.keep_awake_ac)
        self.assertIsNone(self.agent.keep_awake_until)
        self.assertTrue(
            AuditLog.objects.filter(
                agent_id=self.agent.agent_id,
                message__contains="stay awake on power on",
            ).exists()
        )

        r = self.client.post(self.url, {"ac": False}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            nats_cmd.call_args.args[0], {"func": "keepawakeac", "ac": False}
        )
        self.agent.refresh_from_db()
        self.assertFalse(self.agent.keep_awake_ac)
        self.assertTrue(
            AuditLog.objects.filter(
                message__contains="stay awake on power off on"
            ).exists()
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_refused_before_the_agent(self, nats_cmd):
        nats_cmd.return_value = "ok"
        for bad in ("true", 1, None, [True]):
            r = self.client.post(self.url, {"ac": bad}, format="json")
            self.assertEqual(r.status_code, 400, bad)

        self.agent.version = "1.03.11.2026"
        self.agent.save(update_fields=["version"])
        r = self.client.post(self.url, {"ac": True}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("2.03.11.2026", r.json())

        self.agent.version = "2.03.11.2026"
        for plat in ("windows", "linux", "freebsd"):
            self.agent.plat = plat
            self.agent.save(update_fields=["plat", "version"])
            r = self.client.post(self.url, {"ac": True}, format="json")
            self.assertEqual(r.status_code, 400, plat)
            self.assertIn("macOS", r.json())
        nats_cmd.assert_not_called()
        self.agent.refresh_from_db()
        self.assertFalse(self.agent.keep_awake_ac)

    @patch("agents.models.Agent.nats_cmd")
    def test_agent_refuses(self, nats_cmd):
        nats_cmd.return_value = "stay awake on power is only available on macOS"
        r = self.client.post(self.url, {"ac": True}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("refused", r.json())
        nats_cmd.return_value = "timeout"
        r = self.client.post(self.url, {"ac": True}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("contact", r.json())
        self.agent.refresh_from_db()
        self.assertFalse(self.agent.keep_awake_ac)

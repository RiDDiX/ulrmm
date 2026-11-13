# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from model_bakery import baker

from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

OK = {"success": True, "errormsg": ""}


@patch("agents.models.Agent.nats_cmd")
class TestServiceActionAudit(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        self.url = f"/services/{self.agent.agent_id}/spooler/"

    def audit_rows(self):
        return AuditLog.objects.filter(agent_id=self.agent.agent_id).count()

    def test_restart_with_a_failed_start_is_audited(self, nats_cmd):
        nats_cmd.side_effect = [OK, {"success": False, "errormsg": "access denied"}]
        r = self.client.post(self.url, {"sv_action": "restart"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "access denied")
        self.assertEqual(self.audit_rows(), 1)

    def test_a_timed_out_stop_is_audited(self, nats_cmd):
        nats_cmd.return_value = "timeout"
        r = self.client.post(self.url, {"sv_action": "stop"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.audit_rows(), 1)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from model_bakery import baker

from apiv3.views import TRUNCATED
from ulrmm.constants import ULRMM_MAX_REQUEST_SIZE, AgentHistoryType
from ulrmm.test import ULRMMTestCase


class TestAgentBodyLimit(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.authenticate_agent(self.agent)

    def test_oversized_upload_refused_before_the_view(self):
        big = str(ULRMM_MAX_REQUEST_SIZE + 1)
        body = {"id": 1, "agent_id": self.agent.agent_id}
        with patch("apiv3.views.apply_result") as apply:
            r = self.client.patch(
                "/api/v3/checkrunner/", body, format="json", CONTENT_LENGTH=big
            )
        self.assertEqual((r.status_code, r.data), (400, "Request too large"))
        apply.assert_not_called()

        # reads stay open
        r = self.client.get(
            f"/api/v3/{self.agent.agent_id}/checkrunner/", CONTENT_LENGTH=big
        )
        self.assertEqual(r.status_code, 200)

    def test_oversized_task_result_stored_truncated(self):
        task = baker.make("autotasks.AutomatedTask", agent=self.agent)
        body = {"stdout": "x", "stderr": "", "retcode": 0, "execution_time": "1"}
        with patch("apiv3.views.Alert.handle_alert_failure"):
            r = self.client.patch(
                f"/api/v3/{task.pk}/{self.agent.agent_id}/taskrunner/",
                body,
                format="json",
                CONTENT_LENGTH=str(ULRMM_MAX_REQUEST_SIZE + 1),
            )
        self.assertEqual(r.status_code, 200)
        result = task.taskresults.get(agent=self.agent)
        self.assertEqual((result.stderr, result.retcode), (TRUNCATED, 1))

    def test_oversized_history_result_stored_truncated(self):
        cmd = baker.make(
            "agents.AgentHistory", agent=self.agent, type=AgentHistoryType.CMD_RUN
        )
        script = baker.make(
            "agents.AgentHistory", agent=self.agent, type=AgentHistoryType.SCRIPT_RUN
        )
        for hist in (cmd, script):
            r = self.client.patch(
                f"/api/v3/{hist.pk}/{self.agent.agent_id}/histresult/",
                {"results": "x"},
                format="json",
                CONTENT_LENGTH=str(ULRMM_MAX_REQUEST_SIZE + 1),
            )
            self.assertEqual(r.status_code, 200)
            hist.refresh_from_db()
        self.assertEqual(cmd.results, TRUNCATED)
        self.assertEqual(script.script_results["stderr"], TRUNCATED)

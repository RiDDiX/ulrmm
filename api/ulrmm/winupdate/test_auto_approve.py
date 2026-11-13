# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from model_bakery import baker

from logs.models import DebugLog
from ulrmm.test import ULRMMTestCase

from .tasks import auto_approve_updates_task


class TestAutoApproveKeepsGoing(ULRMMTestCase):
    @patch("winupdate.tasks.time.sleep")
    @patch("winupdate.tasks.posix_refresh_all_task.delay")
    @patch("agents.models.Agent.nats_cmd")
    @patch("agents.models.Agent.approve_updates")
    @patch("agents.models.Agent.delete_superseded_updates")
    def test_one_failing_agent_does_not_stop_the_rest(self, superseded, approve, *_):
        self.setup_coresettings()
        baker.make_recipe("agents.agent", _quantity=2)
        superseded.side_effect = [RuntimeError("broken"), None]

        auto_approve_updates_task()

        self.assertEqual(superseded.call_count, 2)
        approve.assert_called_once()
        logged = DebugLog.objects.filter(message__contains="broken")
        self.assertEqual(logged.count(), 1)

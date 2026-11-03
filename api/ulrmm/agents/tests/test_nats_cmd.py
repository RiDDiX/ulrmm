# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import AsyncMock, patch

from asgiref.sync import async_to_sync
from model_bakery import baker
from nats.errors import NoRespondersError
from nats.errors import TimeoutError as NatsTimeout

from ulrmm.test import ULRMMTestCase


class TestNatsCmd(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent")

    @patch("agents.models.nats.connect")
    def test_no_responders_is_timeout(self, connect):
        # agent not connected: callers show "Unable to contact the agent"
        # instead of answering 500
        nc = AsyncMock()
        nc.request.side_effect = NoRespondersError
        connect.return_value = nc
        ret = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, timeout=1)
        self.assertEqual(ret, "timeout")
        nc.close.assert_awaited_once()

    @patch("agents.models.nats.connect")
    def test_connection_closed_when_the_request_raises(self, connect):
        nc = AsyncMock()
        nc.request.side_effect = RuntimeError
        connect.return_value = nc
        with self.assertRaises(RuntimeError):
            async_to_sync(self.agent.nats_cmd)({"func": "ping"}, timeout=1)
        nc.close.assert_awaited_once()

    @patch("agents.models.nats.connect")
    def test_timeout(self, connect):
        nc = AsyncMock()
        nc.request.side_effect = NatsTimeout
        connect.return_value = nc
        ret = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, timeout=1)
        self.assertEqual(ret, "timeout")
        nc.close.assert_awaited_once()

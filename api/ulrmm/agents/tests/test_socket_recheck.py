# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from asgiref.sync import async_to_sync
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from agents.consumers import (
    RECHECK_SECONDS,
    CommandStreamConsumer,
    TerminalStreamConsumer,
    active_streams,
)
from agents.models import AgentPlat
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase


def _consumer(cls, user, agent_id):
    consumer = cls()
    consumer.user = user
    consumer.scope = {"client": ("192.0.2.9", 0)}
    consumer.agent_id = agent_id
    consumer.channel_name = f"chan-{cls.__name__}"
    consumer.channel_layer = AsyncMock()
    consumer.close = AsyncMock()
    consumer.send_json = AsyncMock()
    return consumer


@override_settings(CACHES=LOCMEM_CACHE)
class SocketCase(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        self.role = baker.make(
            "accounts.Role", can_send_cmd=True, can_use_terminal=True
        )
        self.user = baker.make(
            "accounts.User", role=self.role, is_active=True, totp_key="JBSWY3DPEHPK3PXP"
        )
        self.token, _ = AuthToken.objects.create(self.user)
        self.user.auth_digest = self.token.digest


@patch("agents.models.Agent.nats_stream_cmd", new_callable=AsyncMock)
class TestCommandSocketRecheck(SocketCase):
    def send(self):
        consumer = _consumer(CommandStreamConsumer, self.user, self.agent.agent_id)
        consumer.authorized = True

        async def run():
            await consumer.receive_json({"cmd": "whoami"})
            streams = active_streams.pop(consumer.channel_name, {})
            await asyncio.gather(*(task for _, task in streams.values()))

        async_to_sync(run)()
        return consumer

    def assert_refused(self, stream):
        consumer = self.send()
        consumer.close.assert_awaited_once_with(code=4403)
        self.assertFalse(consumer.authorized)
        stream.assert_not_called()

    def test_a_live_session_runs_the_command(self, stream):
        consumer = self.send()
        consumer.close.assert_not_called()
        stream.assert_called_once()

    def test_ended_session(self, stream):
        self.token.delete()
        self.assert_refused(stream)

    def test_disabled_user(self, stream):
        self.user.__class__.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assert_refused(stream)

    def test_2fa_reset_after_connect(self, stream):
        self.user.__class__.objects.filter(pk=self.user.pk).update(totp_key=None)
        self.assert_refused(stream)

    def test_role_flag_removed(self, stream):
        self.role.can_send_cmd = False
        self.role.save()
        self.assert_refused(stream)


@patch.object(TerminalStreamConsumer, "_nats_publish", new_callable=AsyncMock)
class TestTerminalSocketRecheck(SocketCase):
    def setUp(self):
        super().setUp()
        self.term = _consumer(TerminalStreamConsumer, self.user, self.agent.agent_id)
        self.term.session_id = "s1"

    def receive(self, content):
        async_to_sync(self.term.receive_json)(content)

    def test_input_is_rechecked_at_most_every_ten_seconds(self, publish):
        self.term.started = True
        with patch("agents.consumers.time.monotonic", return_value=1000.0):
            self.receive({"action": "input", "data": "a"})
        self.token.delete()
        with patch("agents.consumers.time.monotonic", return_value=1005.0):
            self.receive({"action": "input", "data": "b"})
        self.assertEqual(publish.await_count, 2)
        self.term.close.assert_not_called()

        later = 1000.0 + RECHECK_SECONDS
        with patch("agents.consumers.time.monotonic", return_value=later):
            self.receive({"action": "input", "data": "c"})
        self.assertEqual(publish.await_count, 2)
        self.term.close.assert_awaited_once_with(code=4403)

    def test_start_is_refused_after_the_session_ended(self, publish):
        self.token.delete()
        self.receive({"action": "start"})
        self.term.close.assert_awaited_once_with(code=4403)
        publish.assert_not_called()
        self.assertFalse(self.term.started)

    @patch("agents.consumers.envelope.amode", new_callable=AsyncMock)
    def test_a_new_start_clears_an_earlier_kill(self, amode, publish):
        amode.return_value = "legacy"
        self.term.killed = True
        self.term.nc = SimpleNamespace(subscribe=AsyncMock(), is_closed=False)
        target = AsyncMock(return_value=(AgentPlat.WINDOWS, "host", "cmd"))
        with (
            patch.object(TerminalStreamConsumer, "_terminal_target", new=target),
            patch.object(TerminalStreamConsumer, "_audit_start", new=AsyncMock()),
        ):
            self.receive({"action": "start"})
        self.assertTrue(self.term.started)
        self.assertFalse(self.term.killed)
        publish.assert_awaited_once()

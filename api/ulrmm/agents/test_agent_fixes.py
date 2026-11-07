# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from unittest.mock import AsyncMock, patch

from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext
from model_bakery import baker

from agents.consumers import CommandStreamConsumer, active_streams
from agents.models import _MAX_CHECK_INTERVAL, _MIN_RUN_INTERVAL, Agent
from checks.models import Check
from ulrmm.test import ULRMMTestCase


class TestDisconnectStopsEveryStream(SimpleTestCase):
    def test_all_streams_of_the_socket_stop(self):
        finished = []

        async def stream(cmd_id, stop):
            await stop.wait()
            finished.append(cmd_id)

        async def run():
            consumer = CommandStreamConsumer()
            consumer.channel_name = "chan-disconnect"
            consumer.channel_layer = AsyncMock()
            consumer.cmd_id = "second"
            streams = {}
            for cmd_id in ("first", "second"):
                stop = asyncio.Event()
                streams[cmd_id] = (stop, asyncio.ensure_future(stream(cmd_id, stop)))
            active_streams[consumer.channel_name] = streams

            await consumer.disconnect(1000)
            return streams

        streams = asyncio.run(run())
        self.assertTrue(all(stop.is_set() for stop, _ in streams.values()))
        self.assertTrue(all(task.done() for _, task in streams.values()))
        self.assertEqual(sorted(finished), ["first", "second"])
        self.assertNotIn("chan-disconnect", active_streams)

    def test_a_cancelled_disconnect_stays_cancelled(self):
        async def run():
            consumer = CommandStreamConsumer()
            consumer.channel_name = "chan-cancel"
            consumer.channel_layer = AsyncMock()
            # a stream that does not react to its stop event
            hung = asyncio.ensure_future(asyncio.sleep(60))
            active_streams[consumer.channel_name] = {"x": (asyncio.Event(), hung)}
            closing = asyncio.ensure_future(consumer.disconnect(1000))
            await asyncio.sleep(0)
            closing.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await closing
            consumer.channel_layer.group_discard.assert_not_called()

        asyncio.run(run())


class TestPolicyOverrides(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent", check_interval=600)
        policy = baker.make("automation.Policy", active=True, enforced=True)
        self.agent.policy = policy
        self.agent.save()
        baker.make_recipe(
            "checks.ping_check", policy=policy, ip="192.0.2.1", run_interval=600
        )
        self.own = baker.make_recipe(
            "checks.ping_check", agent=self.agent, ip="192.0.2.1", run_interval=60
        )

    def test_flags_are_reset_and_set_in_one_transaction(self):
        Check.objects.filter(pk=self.own.pk).update(overridden_by_policy=True)
        with CaptureQueriesContext(connection) as ctx:
            Agent.objects.get(pk=self.agent.pk).get_checks_from_policies()
        sql = [q["sql"] for q in ctx.captured_queries]
        updates = [i for i, q in enumerate(sql) if q.startswith("UPDATE")]
        self.assertEqual(len(updates), 2)
        opened = [i for i, q in enumerate(sql) if q.startswith("SAVEPOINT")]
        released = [i for i, q in enumerate(sql) if q.startswith("RELEASE SAVEPOINT")]
        self.assertTrue(opened and released)
        self.assertLess(opened[0], updates[0])
        self.assertLess(updates[-1], released[-1])
        self.own.refresh_from_db()
        self.assertTrue(self.own.overridden_by_policy)

    def test_overridden_check_does_not_speed_up_the_runner(self):
        with self.settings(CHECK_INTERVAL_JITTER=(0, 0)):
            interval = Agent.objects.get(pk=self.agent.pk).check_run_interval()
        self.assertEqual(interval, 600)


@patch("agents.views.sync_mesh_perms_task.delay")
class TestCheckIntervalBound(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        self.url = f"/agents/{self.agent.agent_id}/"

    def test_zero_is_refused_and_the_minimum_accepted(self, _):
        for refused in (0, _MAX_CHECK_INTERVAL + 1):
            r = self.client.put(self.url, {"check_interval": refused}, format="json")
            self.assertEqual(r.status_code, 400)
        r = self.client.put(
            self.url, {"check_interval": _MIN_RUN_INTERVAL}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.check_interval, _MIN_RUN_INTERVAL)

    def test_a_stored_zero_does_not_drop_the_poll_to_jitter(self, _):
        Agent.objects.filter(pk=self.agent.pk).update(check_interval=0)
        with self.settings(CHECK_INTERVAL_JITTER=(0, 0)):
            interval = Agent.objects.get(pk=self.agent.pk).check_run_interval()
        self.assertEqual(interval, _MIN_RUN_INTERVAL)

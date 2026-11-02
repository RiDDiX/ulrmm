# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker

from agents import tasks
from agents.models import Agent
from agents.serializers import AgentSerializer, AgentTableSerializer
from core.stats import _overdue_q, fleet_stats, power_event_q
from notify import tamper
from patches import maintenance
from patches.models import RunState
from ulrmm.test import ULRMMTestCase

MIN = dt.timedelta(minutes=1)


def announced(recipe="agents.overdue_agent", kind="shutdown", at=MIN, **kw):
    """An agent with a power event `at` after its last check-in."""
    agent = baker.make_recipe(recipe, **kw)
    when = None if at is None else agent.last_seen + at
    Agent.objects.filter(pk=agent.pk).update(power_event=kind, power_event_at=when)
    return Agent.objects.get(pk=agent.pk)


class TestPowerEventStatus(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_status_and_counts_agree(self):
        expected = {
            baker.make_recipe("agents.overdue_agent"): "overdue",
            announced(kind="shutdown"): "offline",
            announced(kind="restart", at=-MIN): "offline",
            announced(kind="shutdown_or_restart", at=dt.timedelta(0)): "offline",
            announced(kind="sleep", at=-2 * MIN): "offline",
            # announced before an earlier silence, the agent checked in since
            announced(kind="shutdown", at=-3 * MIN): "overdue",
            announced(kind="", at=MIN): "overdue",
            announced(kind="shutdown", at=None): "overdue",
            announced("agents.online_agent", overdue_email_alert=True): "online",
            announced("agents.offline_agent", overdue_email_alert=True): "offline",
        }
        agents = Agent.objects.all()
        self.assertEqual({a: a.status for a in agents}, expected)
        self.assertEqual(
            set(agents.filter(_overdue_q())),
            {a for a, s in expected.items() if s == "overdue"},
        )
        counts = fleet_stats(agents)["agents"]
        want = Counter(expected.values())
        for status in ("online", "offline", "overdue"):
            self.assertEqual(counts[status], want[status], status)

        # the four quiet announcements plus the offline one
        self.assertEqual(sum(a.planned_offline for a in agents), 5)
        online = Agent.objects.get(pk=list(expected)[8].pk)
        with self.assertNumQueries(0):
            self.assertFalse(online.planned_offline)
            self.assertTrue(online.power_event_applies)

        # never seen since the announcement was recorded
        never = baker.make_recipe("agents.agent", last_seen=None)
        never.record_power_event("shutdown", "rmm: john")
        agents = Agent.objects.all()
        self.assertEqual(
            set(agents.filter(power_event_q())),
            {a for a in agents if a.power_event_applies},
        )
        never.refresh_from_db()
        self.assertTrue(never.planned_offline)
        self.assertEqual(never.status, "offline")

    @patch("alerts.models.Alert.handle_alert_failure")
    def test_cancel(self, failure):
        agent = announced()
        # natsapi stores a cancel as an empty kind with the time it came in
        Agent.objects.filter(pk=agent.pk).update(
            power_event="", power_event_at=agent.last_seen + 2 * MIN
        )
        agent.refresh_from_db()
        self.assertFalse(agent.planned_offline)
        self.assertEqual(agent.status, "overdue")
        self.assertIn(agent, Agent.objects.filter(_overdue_q()))
        tasks.agent_outages_task()
        failure.assert_called_once()

    @patch("alerts.models.Alert.handle_alert_failure")
    def test_outages_task(self, failure):
        agent = announced()
        self.assertEqual(tasks.agent_outages_task(), "completed")
        failure.assert_not_called()

        # back after the shutdown, then silent without a word: alert
        Agent.objects.filter(pk=agent.pk).update(
            power_event_at=agent.last_seen - 5 * MIN
        )
        tasks.agent_outages_task()
        failure.assert_called_once()
        self.assertEqual(failure.call_args.args[0].pk, agent.pk)

    def test_serializers(self):
        agent = announced(kind="restart")
        Agent.objects.filter(pk=agent.pk).update(power_event_by="bob")
        agent.refresh_from_db()
        for serializer in (AgentSerializer, AgentTableSerializer):
            data = serializer(agent).data
            self.assertEqual(data["power_event"], "restart", serializer)
            self.assertEqual(data["power_event_by"], "bob")
            self.assertIsNotNone(data["power_event_at"])
            self.assertTrue(data["planned_offline"])


@patch("notify.tamper.dispatch")
class TestPowerEventTamper(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.tamper_watch = True
        self.coresettings.save()
        self.now = djangotime.now()

    def test_agent_announcement_is_expected(self, dispatch):
        agent = announced("agents.agent", last_seen=self.now - 30 * MIN)
        self.assertTrue(tamper.expected_offline(agent))
        self.assertEqual(tamper.watch(self.now), "0 raised")

        Agent.objects.filter(pk=agent.pk).update(
            power_event_at=agent.last_seen - 3 * MIN
        )
        self.assertEqual(tamper.watch(self.now), "1 raised")
        dispatch.assert_called_once()


class TestAgentListQueries(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def queries(self):
        with CaptureQueriesContext(connection) as ctx:
            r = self.client.get("/agents/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(all("planned_offline" in row for row in r.data))
        return len(ctx)

    def test_no_query_per_agent(self):
        announced()
        one = self.queries()
        announced(kind="sleep")
        announced(kind="restart", at=-5 * MIN)
        self.assertEqual(self.queries(), one)


class TestServerRecordsPower(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def agent(self):
        return baker.make_recipe(
            "agents.agent", last_seen=djangotime.now(), wmi_detail={"nics": []}
        )

    def event(self, agent):
        agent.refresh_from_db()
        return agent.power_event, agent.power_event_by, agent.power_event_at

    def test_power_buttons(self):
        for path, kind in (
            ("reboot", "restart"),
            ("shutdown", "shutdown"),
            ("suspend", "sleep"),
        ):
            agent = self.agent()
            with patch("agents.views._ask", return_value="timeout"):
                r = self.client.post(f"/agents/{agent.agent_id}/{path}/")
            self.assertEqual(r.status_code, 400)
            self.assertEqual(self.event(agent), ("", "", None))

            with patch("agents.views._ask", return_value="ok"):
                r = self.client.post(f"/agents/{agent.agent_id}/{path}/")
            self.assertEqual(r.status_code, 200)
            event, by, at = self.event(agent)
            self.assertEqual((event, by), (kind, "rmm: john"))
            self.assertLess(djangotime.now() - at, MIN)
            self.assertTrue(agent.power_event_applies)

    @patch("agents.views.abulk_nats_command", new_callable=AsyncMock)
    def test_bulk_sleep(self, abulk):
        agent = self.agent()
        data = {"mode": "suspend", "target": "agents", "agents": [agent.agent_id]}
        data.update(monType="all", osType="all")
        r = self.client.post("/agents/actions/bulk/", data, format="json")
        self.assertEqual(r.status_code, 200)
        abulk.assert_called_once()
        self.assertEqual(self.event(agent)[:2], ("sleep", "rmm: john"))

    @patch("agents.models.Agent.nats_cmd", new_callable=AsyncMock)
    def test_patch_reboot(self, nats_cmd):
        agent = self.agent()
        policy = SimpleNamespace(reboot_after_install="always")
        with patch("agents.models.Agent.get_patch_policy", return_value=policy):
            self.assertTrue(agent.handle_patch_reboot(True))
        self.assertEqual(nats_cmd.call_args.args[0], {"func": "rebootnow"})
        self.assertEqual(self.event(agent)[:2], ("restart", "rmm: patch reboot"))

    @patch("agents.models.Agent.nats_cmd", new_callable=AsyncMock)
    def test_schedule_sleep(self, nats_cmd):
        agent = self.agent()
        schedule = baker.make("patches.MaintenanceSchedule", kind="sleep", name="night")
        run = baker.make(
            "patches.ScheduleRun",
            agent=agent,
            schedule=schedule,
            state=RunState.IDLE_WAIT,
        )
        nats_cmd.side_effect = lambda data, **kw: {"idle": -1, "suspend": "ok"}[
            data["func"]
        ]
        maintenance._idle(run, djangotime.now())
        run.refresh_from_db()
        self.assertEqual(run.state, RunState.SLEPT)
        self.assertEqual(
            self.event(agent)[:2], ("sleep", "rmm: sleep schedule (night)")
        )

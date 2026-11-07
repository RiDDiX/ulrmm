# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import patch

from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.constants import AgentMonType
from ulrmm.test import ULRMMTestCase

from .maintenance import run_pass
from .models import MaintenanceSchedule, RunState, ScheduleRun


class TestIdleWaitPing(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.base = djangotime.now().replace(second=0, microsecond=0)
        self.pc = baker.make_recipe(
            "agents.agent",
            hostname="pc",
            time_zone="UTC",
            last_seen=self.base,
            monitoring_type=AgentMonType.WORKSTATION,
        )
        s = baker.make(
            "patches.MaintenanceSchedule",
            name="night",
            kind="sleep",
            frequency="daily",
            run_time=(self.base - dt.timedelta(minutes=1)).time(),
            duration=120,
            agents=[self.pc.agent_id],
        )
        MaintenanceSchedule.objects.filter(pk=s.pk).update(modified_by="john")
        self.answers = {"ping": "pong", "idle": 60}
        self.calls = []

        def nats(agent, data, timeout=30, wait=True):
            self.calls.append(data["func"])
            return self.answers.get(data["func"])

        p = patch("agents.models.Agent.nats_cmd", autospec=True, side_effect=nats)
        p.start()
        self.addCleanup(p.stop)

    def test_unreachable_idle_wait_skips_the_idle_call(self):
        run_pass(self.base)
        self.assertEqual(ScheduleRun.objects.get().state, RunState.IDLE_WAIT)
        self.assertEqual(self.calls.count("idle"), 1)

        # nats itself down: wait for the next pass
        self.answers["ping"] = "natsdown"
        run_pass(self.base + dt.timedelta(minutes=1))
        self.assertEqual(ScheduleRun.objects.get().state, RunState.IDLE_WAIT)

        self.answers["ping"] = "timeout"
        run_pass(self.base + dt.timedelta(minutes=2))
        run = ScheduleRun.objects.get()
        self.assertEqual(run.state, RunState.LEFT_AWAKE)
        self.assertIn("not reachable", run.detail)
        self.assertEqual(self.calls.count("idle"), 1)

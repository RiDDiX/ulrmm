# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.utils import DISPLAY_PROBE, calculate_agent_checks, get_agent_display
from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "agent-display",
        }
    }
)
class TestAgentDisplay(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, last_seen=djangotime.now()
        )
        self.key = f"agent_display_{self.agent.agent_id}"

    @patch("agents.models.Agent.nats_cmd")
    def test_probe_answers(self, nats_cmd):
        for reply in ("present", "absent"):
            cache.clear()
            nats_cmd.return_value = f"{reply}\n"
            self.assertEqual(get_agent_display(self.agent), reply)
            self.assertEqual(cache.get(self.key), reply)

        nats_cmd.assert_called_with(
            {
                "func": "rawcmd",
                "timeout": 5,
                "payload": {"command": DISPLAY_PROBE, "shell": "/bin/bash"},
            },
            timeout=8,
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_unknown_is_not_cached(self, nats_cmd):
        for reply in ("timeout", "natsdown", "", "present absent", "x11", {}, None):
            nats_cmd.return_value = reply
            self.assertEqual(get_agent_display(self.agent), "unknown")

        nats_cmd.side_effect = Exception("nats")
        self.assertEqual(get_agent_display(self.agent), "unknown")
        self.assertIsNone(cache.get(self.key))

    @patch("agents.models.Agent.nats_cmd")
    def test_second_call_uses_cache(self, nats_cmd):
        nats_cmd.return_value = "absent\n"
        self.assertEqual(get_agent_display(self.agent), "absent")
        self.assertEqual(get_agent_display(self.agent), "absent")
        nats_cmd.assert_called_once()

    @patch("agents.models.Agent.nats_cmd")
    def test_windows_and_mac_are_not_probed(self, nats_cmd):
        for plat in (AgentPlat.WINDOWS, AgentPlat.DARWIN):
            agent = baker.make_recipe(
                "agents.online_agent", plat=plat, last_seen=djangotime.now()
            )
            self.assertEqual(get_agent_display(agent), "present")
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_offline_agent_is_not_probed(self, nats_cmd):
        agent = baker.make_recipe("agents.offline_agent", plat=AgentPlat.LINUX)
        self.assertEqual(get_agent_display(agent), "unknown")

        cache.set(f"agent_display_{agent.agent_id}", "absent", 60)
        self.assertEqual(get_agent_display(agent), "absent")
        nats_cmd.assert_not_called()


class TestCheckSummary(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")

    def test_never_run_checks_are_pending(self):
        baker.make("checks.Check", agent=self.agent, check_type="ping", _quantity=2)
        summary = calculate_agent_checks(self.agent)
        self.assertEqual(
            (summary["total"], summary["passing"], summary["pending"]), (2, 0, 2)
        )
        self.assertFalse(summary["has_failing_checks"])

    def test_counts_by_result(self):
        ran, waiting, never = baker.make(
            "checks.Check", agent=self.agent, check_type="ping", _quantity=3
        )
        baker.make(
            "checks.CheckResult", agent=self.agent, assigned_check=ran, status="passing"
        )
        baker.make(
            "checks.CheckResult",
            agent=self.agent,
            assigned_check=waiting,
            status="pending",
        )
        summary = calculate_agent_checks(self.agent)
        self.assertEqual(
            {k: summary[k] for k in ("total", "passing", "pending", "failing")},
            {"total": 3, "passing": 1, "pending": 2, "failing": 0},
        )

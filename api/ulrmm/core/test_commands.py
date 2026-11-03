# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from model_bakery import baker

from ulrmm.test import ULRMMTestCase


def run(*args) -> str:
    out = StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


class TestCoreCommands(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_get_config_prints_one_value(self):
        self.assertEqual(run("get_config", "api"), settings.ALLOWED_HOSTS[0] + "\n")
        self.assertEqual(
            run("get_config", "dbname"), settings.DATABASES["default"]["NAME"] + "\n"
        )
        self.assertEqual(run("get_config", "meshsite"), settings.MESH_SITE + "\n")
        self.assertEqual(run("get_config", "nonsense"), "")

    @patch("core.management.commands.bulk_restart_agents.sleep")
    @patch(
        "core.management.commands.bulk_restart_agents.get_mesh_ws_url",
        return_value="wss://mesh",
    )
    @patch(
        "core.management.commands.bulk_restart_agents.get_agent_url",
        return_value="https://dl/agent",
    )
    @patch("agents.models.Agent.recover")
    def test_bulk_restart_recovers_both_services(self, recover, *_):
        agent = baker.make_recipe("agents.online_agent")
        out = run("bulk_restart_agents")
        self.assertIn(agent.hostname, out)
        recover.assert_any_call(
            "agent", "wss://mesh", wait=False, agent_url="https://dl/agent"
        )
        recover.assert_any_call("mesh", "", wait=False)
        self.assertEqual(recover.call_count, 2)

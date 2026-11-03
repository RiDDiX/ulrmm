# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import Agent
from ulrmm.test import ULRMMTestCase


def run(*args) -> str:
    out = StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


class TestAgentCommands(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    @patch("agents.management.commands.bulk_delete_agents.reload_nats")
    @patch("agents.models.Agent.nats_cmd")
    def test_bulk_delete_lists_first_and_deletes_with_flag(self, nats_cmd, reload):
        stale = baker.make_recipe(
            "agents.agent",
            hostname="STALE-01",
            last_seen=djangotime.now() - djangotime.timedelta(days=60),
        )
        baker.make_recipe("agents.online_agent", hostname="FRESH-01")

        self.assertIn("Must have at least one parameter", run("bulk_delete_agents"))
        listing = run("bulk_delete_agents", "--days", "30")
        self.assertIn("STALE-01", listing)
        self.assertNotIn("FRESH-01", listing)
        self.assertEqual(Agent.objects.count(), 2)

        self.assertIn(
            "Deleted 1 agents", run("bulk_delete_agents", "--days", "30", "--delete")
        )
        self.assertFalse(Agent.objects.filter(pk=stale.pk).exists())
        nats_cmd.assert_called_once_with({"func": "uninstall"}, wait=False)
        reload.assert_called_once()

    @patch("agents.tasks.send_agent_update_task.delay")
    def test_update_agents_queues_outdated_agents(self, delay):
        old = baker.make_recipe("agents.agent", version="1.3.0")
        baker.make_recipe("agents.agent", version=settings.LATEST_AGENT_VER)
        run("update_agents")
        delay.assert_called_once_with(agent_ids=[old.agent_id], force=False)

        delay.reset_mock()
        self.coresettings.agent_auto_update = False
        self.coresettings.save()
        run("update_agents")
        delay.assert_not_called()

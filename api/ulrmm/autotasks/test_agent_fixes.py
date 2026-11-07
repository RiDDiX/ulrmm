# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from agents.models import AgentCustomField
from autotasks.models import TaskResult
from clients.models import SiteCustomField
from ulrmm.test import ULRMMTestCase


class TestCollectorOwner(ULRMMTestCase):
    def setUp(self):
        self.setup_base_instance()
        self.agent = baker.make_recipe("agents.agent", site=self.site1)

    def test_site_field_is_written_to_the_agents_site(self):
        task = baker.make(
            "autotasks.AutomatedTask",
            agent=self.agent,
            custom_field=self.site_customfield,
        )
        result = TaskResult.objects.create(
            agent=self.agent, task=task, stdout="noise\nsite value\n"
        )
        result.save_collector_results()

        row = SiteCustomField.objects.get(site=self.site1, field=self.site_customfield)
        self.assertEqual(row.value, "site value")
        self.assertFalse(AgentCustomField.objects.exists())

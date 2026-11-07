# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker

from agents.models import Agent
from ulrmm.test import ULRMMTestCase


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "ulrmm.golden.base.GoldenCache",
            "LOCATION": "site-move",
        }
    }
)
class TestSiteDeleteMovesAgents(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.setup_base_instance()
        cache.clear()

    @patch("alerts.tasks.cache_agents_alert_template.delay")
    @patch("clients.views.verify_fresh_totp", return_value=True)
    def test_moved_agents_lose_the_old_sites_policy_checks(self, *_):
        policy = baker.make("automation.Policy", active=True)
        self.site1.workstation_policy = policy
        self.site1.save()
        check = baker.make_recipe("checks.ping_check", policy=policy)
        agent = baker.make_recipe("agents.workstation_agent", site=self.site1)
        self.assertEqual([c.pk for c in agent.get_checks_from_policies()], [check.pk])

        with self.captureOnCommitCallbacks(execute=True):
            r = self.client.delete(
                f"/clients/sites/{self.site1.pk}/?move_to_site={self.site3.pk}",
                {"totp_code": "000000"},
                format="json",
            )
        self.assertEqual(r.status_code, 200)
        fresh = Agent.objects.get(pk=agent.pk)
        self.assertEqual(fresh.site_id, self.site3.pk)
        self.assertEqual(fresh.get_checks_from_policies(), [])

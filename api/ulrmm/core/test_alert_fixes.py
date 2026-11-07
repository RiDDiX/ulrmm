# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from model_bakery import baker

from alerts.models import Alert
from core.tasks import resolve_alerts_task
from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase


class TestResolveAlertsTask(ULRMMTestCase):
    def test_resolves_only_online_agents(self):
        self.setup_coresettings()
        back = baker.make_recipe(
            "agents.online_agent", version=settings.LATEST_AGENT_VER
        )
        down = baker.make_recipe(
            "agents.overdue_agent", version=settings.LATEST_AGENT_VER
        )
        back_alert, down_alert = (
            baker.make("alerts.Alert", agent=agent, alert_type=AlertType.AVAILABILITY)
            for agent in (back, down)
        )
        self.assertEqual(resolve_alerts_task(), "completed")
        back_alert.refresh_from_db()
        down_alert.refresh_from_db()
        self.assertTrue(back_alert.resolved)
        self.assertFalse(down_alert.resolved)
        self.assertEqual(Alert.objects.filter(resolved=False).count(), 1)

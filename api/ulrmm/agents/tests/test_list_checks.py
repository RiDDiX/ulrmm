# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import MagicMock, patch

from model_bakery import baker

from ulrmm.constants import AGENT_CHECKS_CACHE_PREFIX
from ulrmm.test import ULRMMTestCase


class TestAgentListChecks(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agents = baker.make_recipe("agents.agent", _quantity=5)

    def test_check_summaries_come_from_one_cache_call(self):
        first = self.agents[0].pk
        views_cache, serializer_cache = MagicMock(), MagicMock()
        views_cache.get_many.return_value = {
            f"{AGENT_CHECKS_CACHE_PREFIX}{first}": {"total": 3}
        }
        with (
            patch("agents.views.cache", views_cache),
            patch("agents.serializers.cache", serializer_cache),
        ):
            r = self.client.get("/agents/", format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 5)
        views_cache.get_many.assert_called_once()
        self.assertEqual(len(views_cache.get_many.call_args.args[0]), 5)
        serializer_cache.get.assert_not_called()
        checks = {row["agent_id"]: row["checks"] for row in r.data}
        self.assertEqual(checks[self.agents[0].agent_id], {"total": 3})

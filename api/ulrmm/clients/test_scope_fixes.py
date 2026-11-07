# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker

from agents.models import Agent
from clients.models import Client, Site
from ulrmm.constants import ROLE_CACHE_PREFIX
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase


@override_settings(CACHES=LOCMEM_CACHE)
@patch("alerts.tasks.cache_agents_alert_template.delay")
@patch("clients.views.verify_fresh_totp", return_value=True)
class TestDeleteKeepsRoleScope(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.setup_base_instance()
        self.agent = baker.make_recipe("agents.agent", site=self.site1)
        self.role = baker.make("accounts.Role", name="company1 only")

    def delete(self, url):
        return self.client.delete(url, {"totp_code": "000000"}, format="json")

    def delete_company1(self):
        return self.delete(f"/clients/{self.company1.pk}/?move_to_site={self.site3.pk}")

    def test_client_delete_refused_when_a_role_would_see_everything(self, *_):
        self.role.can_view_clients.set([self.company1])
        r = self.delete_company1()
        self.assertEqual(r.status_code, 400)
        self.assertIn("company1 only", r.data)
        self.assertTrue(Client.objects.filter(pk=self.company1.pk).exists())
        self.assertEqual(list(self.role.can_view_clients.all()), [self.company1])
        self.assertEqual(Agent.objects.get(pk=self.agent.pk).site_id, self.site1.pk)

    def test_a_site_of_the_client_counts_as_going_away(self, *_):
        self.role.can_view_sites.set([self.site2])
        self.assertEqual(self.delete_company1().status_code, 400)

    def test_a_scope_edit_after_the_first_check_is_caught(self, *_):
        self.role.can_view_clients.set([self.company1, self.company2])

        def narrowed_meanwhile(*_):
            self.role.can_view_clients.remove(self.company2)
            return True

        with patch("clients.views.verify_fresh_totp", side_effect=narrowed_meanwhile):
            r = self.delete_company1()
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Client.objects.filter(pk=self.company1.pk).exists())
        self.assertEqual(Agent.objects.get(pk=self.agent.pk).site_id, self.site1.pk)

    def test_client_delete_drops_the_role_cache(self, *_):
        self.role.can_view_clients.set([self.company1, self.company2])
        key = f"{ROLE_CACHE_PREFIX}{self.role.pk}"
        cache.set(key, "stale")
        r = self.delete_company1()
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(list(self.role.can_view_clients.all()), [self.company2])
        self.assertIsNone(cache.get(key))

    def test_site_delete(self, *_):
        self.role.can_view_sites.set([self.site1])
        url = f"/clients/sites/{self.site1.pk}/?move_to_site={self.site2.pk}"
        self.assertEqual(self.delete(url).status_code, 400)
        self.assertTrue(Site.objects.filter(pk=self.site1.pk).exists())

        self.role.can_view_sites.add(self.site3)
        key = f"{ROLE_CACHE_PREFIX}{self.role.pk}"
        cache.set(key, "stale")
        self.assertEqual(self.delete(url).status_code, 200)
        self.assertEqual(list(self.role.can_view_sites.all()), [self.site3])
        self.assertIsNone(cache.get(key))

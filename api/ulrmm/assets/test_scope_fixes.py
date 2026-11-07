# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.test import ULRMMTestCase


class TestLicenseCountsVisibleAgents(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.site1, self.site2 = baker.make("clients.Site", _quantity=2)
        self.a1 = baker.make_recipe("agents.agent", site=self.site1)
        self.a2 = baker.make_recipe("agents.agent", site=self.site2)
        self.lic = baker.make(
            "assets.License", name="Office", seats=1, agents=[self.a1, self.a2]
        )
        user = self.create_user_with_roles(
            ["can_list_agents", "can_manage_credentials"]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)

    def test_assigned_and_over_seats(self):
        r = self.client.get(f"/lifecycle/licenses/{self.lic.pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["assigned"], 1)
        self.assertFalse(r.data["over_seats"])

        r = self.client.get("/lifecycle/summary/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["licenses_over_seats"], [])

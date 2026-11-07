# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.test import ULRMMTestCase

from .models import GlobalKVStore, URLAction


class TestRunURLActionGlobalKeys(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        GlobalKVStore.objects.create(name="token", value="s3cret")
        self.site = baker.make("clients.Site")
        self.action = URLAction.objects.create(
            name="hook", pattern="https://example.com/?t={{ global.token }}"
        )

    def run_as(self, flags):
        self.client.force_authenticate(user=self.create_user_with_roles(flags))
        return self.client.patch(
            "/core/urlaction/run/",
            {"site": self.site.pk, "action": self.action.pk},
            format="json",
        )

    def test_global_keys_need_the_keystore_right(self):
        self.assertEqual(self.run_as(["can_run_urlactions"]).status_code, 403)

        r = self.run_as(["can_run_urlactions", "can_view_global_keystore"])
        self.assertEqual(r.status_code, 200)
        self.assertIn("s3cret", r.data)

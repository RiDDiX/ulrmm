# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import User
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

NEW_PASSWORD = "superSekret123456"


@override_settings(CACHES=LOCMEM_CACHE)
@patch("accounts.views.verify_fresh_totp", return_value=True)
class TestResetOtherUserNeedsGrant(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.setup_base_instance()
        self.actor = self.create_user_with_roles(["can_manage_accounts"])
        self.actor.role.can_view_clients.set([self.company1])
        # a role without clients and sites reaches all of them
        self.target = User.objects.create_user(username="bob", password="hunter2x")
        self.target.role = baker.make("accounts.Role")
        self.target.totp_key = "AB5RI6YPFTZAS52G"
        self.target.save()

    def reset(self):
        pw = self.client.post(
            "/accounts/users/reset/",
            {"id": self.target.pk, "password": NEW_PASSWORD, "totp_code": "0"},
            format="json",
        )
        totp = self.client.put(
            "/accounts/users/reset_totp/",
            {"id": self.target.pk, "totp_code": "0"},
            format="json",
        )
        return pw.status_code, totp.status_code

    def test_scoped_actor_cannot_take_over_a_wider_account(self, _):
        self.client.force_authenticate(user=self.actor)
        self.assertEqual(self.reset(), (403, 403))
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password("hunter2x"))
        self.assertEqual(self.target.totp_key, "AB5RI6YPFTZAS52G")

    def test_superuser_still_resets(self, _):
        self.assertEqual(self.reset(), (200, 200))
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password(NEW_PASSWORD))

    def other_account_calls(self):
        user = f"/accounts/{self.target.pk}/users/"
        digest = AuthToken.objects.get(user=self.target).digest
        return [
            ("put", user, {"first_name": "Bobby"}),
            ("delete", f"/accounts/sessions/{digest}/", {}),
            ("delete", f"/accounts/users/{self.target.pk}/sessions/", {}),
            ("delete", user, {}),
        ]

    def test_scoped_actor_cannot_edit_delete_or_log_out_a_wider_account(self, _):
        AuthToken.objects.create(user=self.target)
        self.client.force_authenticate(user=self.actor)
        for method, url, data in self.other_account_calls():
            r = getattr(self.client, method)(url, data, format="json")
            self.assertEqual(r.status_code, 403, (method, url))
        self.target.refresh_from_db()
        self.assertEqual(self.target.first_name, "")
        self.assertTrue(AuthToken.objects.filter(user=self.target).exists())

    def test_superuser_still_edits_deletes_and_logs_out(self, _):
        AuthToken.objects.create(user=self.target)
        for method, url, data in self.other_account_calls():
            r = getattr(self.client, method)(url, data, format="json")
            self.assertEqual(r.status_code, 200, (method, url))
        self.assertFalse(User.objects.filter(pk=self.target.pk).exists())

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import time
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey, Role, User
from accounts.serializers import RoleSerializer
from accounts.utils import (
    CHANGE_NEEDS_TOTP,
    TOTP_FAIL_LIMIT,
    console_stepup_remaining,
    verify_fresh_totp,
)
from accounts.views import CHANGE_NEEDS_DASHBOARD
from clients.models import Deployment, InstallerToken
from logs.models import AuditLog
from ulrmm.constants import AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase


@override_settings(CACHES=LOCMEM_CACHE)
class TestLoginTOTP(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.setup_client()
        self.user = User.objects.create_user(username="totp", password="hunter2x")
        self.user.totp_key = pyotp.random_base32()
        self.user.save()
        self.totp = pyotp.TOTP(self.user.totp_key)

    def login(self, code):
        return self.client.post(
            "/v2/login/",
            {"username": "totp", "password": "hunter2x", "twofactor": code},
            format="json",
        )

    def test_a_code_logs_in_once(self):
        code = self.totp.now()
        self.assertEqual(self.login(code).status_code, 200)
        self.assertEqual(self.login(code).status_code, 400)

    def test_old_codes_refused(self):
        valid = {self.totp.at(time.time() + step) for step in (-30, 0, 30)}
        old = next(
            c
            for c in (self.totp.at(time.time() - 30 * n) for n in range(2, 11))
            if c not in valid
        )
        self.assertEqual(self.login(old).status_code, 400)

    def test_locked_after_failures(self):
        for _ in range(TOTP_FAIL_LIMIT):
            self.assertEqual(self.login(wrong_code(self.totp)).status_code, 400)
        self.assertEqual(self.login(self.totp.now()).status_code, 400)

    @override_settings(DEBUG=True)
    def test_no_debug_code(self):
        self.assertEqual(self.login("sekret").status_code, 400)


@override_settings(CACHES=LOCMEM_CACHE)
class TestUserReset(ULRMMTestCase):
    new_pw = "superSekret123456"

    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.setup_client()
        self.user = User.objects.create_user(username="me", password="hunter2x")
        self.user.totp_key = pyotp.random_base32()
        self.user.save()
        self.totp = pyotp.TOTP(self.user.totp_key)
        self.current, token = AuthToken.objects.create(user=self.user)
        AuthToken.objects.create(user=self.user)
        APIKey.objects.create(name="mine", key="minekey", user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

    def assert_only_this_session_left(self):
        self.assertEqual(list(AuthToken.objects.filter(user=self.user)), [self.current])
        self.assertFalse(APIKey.objects.filter(user=self.user).exists())

    def assert_nothing_changed(self):
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("hunter2x"))
        self.assertTrue(self.user.totp_key)
        self.assertEqual(AuthToken.objects.filter(user=self.user).count(), 2)

    def put(self, url, **data):
        return self.client.put(url, data, format="json")

    def test_reset_pw(self):
        url = "/accounts/resetpw/"
        for code in (None, wrong_code(self.totp)):
            self.assertEqual(
                self.put(url, password=self.new_pw, code=code).status_code, 400
            )
        self.assert_nothing_changed()

        code = self.totp.now()
        self.assertEqual(
            self.put(url, password=self.new_pw, code=code).status_code, 200
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_pw))
        self.assert_only_this_session_left()
        self.assertEqual(self.client.get("/core/version/").status_code, 200)

        # same code, second put
        self.assertEqual(
            self.put(url, password="other-Passw0rd", code=code).status_code, 400
        )

        self.client.credentials()
        self.check_not_authenticated("put", url)

    def test_reset_pw_refuses_weak_password(self):
        r = self.put("/accounts/resetpw/", password="password", code=self.totp.now())
        self.assertEqual(r.status_code, 400)
        self.assert_nothing_changed()

    def test_reset_2fa(self):
        url = "/accounts/reset2fa/"
        r = self.put(url)
        self.assertEqual(r.status_code, 400)
        self.assert_nothing_changed()

        r = self.put(url, code=self.totp.now())
        self.assertEqual(r.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.totp_key)
        self.assert_only_this_session_left()

        self.client.credentials()
        self.check_not_authenticated("put", url)

    def test_self_reset_through_user_actions(self):
        url = "/accounts/users/reset/"
        data = {"id": self.user.pk, "password": self.new_pw}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.put("/accounts/users/reset_totp/", id=self.user.pk)
        self.assertEqual(r.status_code, 400)
        self.assert_nothing_changed()

        data["code"] = self.totp.now()
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_pw))
        self.assert_only_this_session_left()

    def test_api_key_cannot_reset(self):
        self.client.credentials(HTTP_X_API_KEY="minekey")
        code = self.totp.now()
        for method, url, data in (
            ("put", "/accounts/resetpw/", {"password": self.new_pw}),
            ("put", "/accounts/reset2fa/", {}),
            ("post", "/accounts/users/reset/", {"password": self.new_pw}),
            ("put", "/accounts/users/reset_totp/", {}),
        ):
            data = {**data, "id": self.user.pk, "code": code}
            r = getattr(self.client, method)(url, data, format="json")
            self.assertEqual(r.status_code, 403, url)
        self.assert_nothing_changed()

    def test_new_totp_ends_other_sessions(self):
        from accounts.utils import commit_pending_totp_key, set_pending_totp_key

        key = pyotp.random_base32()
        set_pending_totp_key(self.user, key)
        self.assertTrue(commit_pending_totp_key(self.user, key))
        self.assertFalse(AuthToken.objects.filter(user=self.user).exists())
        self.assertFalse(APIKey.objects.filter(user=self.user).exists())


class TestInstallerTokenScope(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.installer = User.objects.create_user(
            username="installer", is_installer_user=True, block_dashboard_login=True
        )
        obj, self.token = AuthToken.objects.create(
            user=self.installer, expiry=dt.timedelta(hours=24)
        )
        self.deployment = baker.make(
            "clients.Deployment", auth_token=obj, token_key=self.token
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")

    def test_installer_token_rejected_outside_install_views(self):
        for method, url in (
            ("post", "/logoutall/"),
            ("post", "/logout/"),
            ("put", "/accounts/resetpw/"),
            ("put", "/accounts/reset2fa/"),
            ("post", "/core/ai/generate/"),
            ("get", "/core/version/"),
        ):
            r = getattr(self.client, method)(url, format="json")
            self.assertEqual(r.status_code, 401, url)

        self.assertEqual(Deployment.objects.count(), 1)
        self.assertEqual(self.installer.auth_token_set.count(), 1)

    def test_installer_token_accepted_on_install_views(self):
        r = self.client.get("/api/v3/installer/")
        self.assertEqual(r.status_code, 200)

        r = self.client.post(
            "/api/v3/installer/", {"version": settings.LATEST_AGENT_VER}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        # authenticated and reached the arch check
        r = self.client.post(
            "/api/v3/meshexe/", {"goarch": "bogus", "plat": "bogus"}, format="json"
        )
        self.assertEqual(r.status_code, 400)

    @patch("apiv3.views.cache_agents_alert_template.delay")
    @patch("apiv3.views.reload_nats")
    def test_installer_token_can_create_agent(self, reload_nats, cache_template):
        data = {
            "agent_id": "a" * 40,
            "hostname": "host",
            "site": self.deployment.site.pk,
            "monitoring_type": "server",
            "description": "",
            "mesh_node_id": "",
            "goarch": "amd64",
            "plat": "linux",
        }
        r = self.client.post("/api/v3/newagent/", data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("token", r.data)

    def test_installer_token_is_not_extended(self):
        token = AuthToken.objects.create(
            user=self.installer, expiry=dt.timedelta(hours=1)
        )
        InstallerToken.objects.create(auth_token=token[0], site=self.deployment.site)
        expiry = token[0].expiry
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token[1]}")

        self.assertEqual(self.client.get("/api/v3/installer/").status_code, 200)
        self.assertEqual(self.client.get("/core/version/").status_code, 401)
        token[0].refresh_from_db()
        self.assertEqual(token[0].expiry, expiry)

    def test_password_only_token_refused_on_install_views(self):
        # token from the credential check, no totp yet
        user = User.objects.create_user(username="nototp", is_superuser=True)
        obj, token = AuthToken.objects.create(user=user, expiry=dt.timedelta(minutes=3))
        expiry = obj.expiry
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        self.assertEqual(self.client.get("/api/v3/installer/").status_code, 401)
        self.assertEqual(self.client.get("/core/version/").status_code, 401)
        obj.refresh_from_db()
        self.assertEqual(obj.expiry, expiry)

        user.totp_key = "AB5RI6YPFTZAS52G"
        user.save()
        self.assertEqual(self.client.get("/api/v3/installer/").status_code, 200)

    def test_dashboard_token_logout_still_works(self):
        user = User.objects.create_user(username="bob2")
        _, token = AuthToken.objects.create(user=user)
        AuthToken.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        r = self.client.post("/logoutall/")
        self.assertEqual(r.status_code, 204)
        self.assertFalse(user.auth_token_set.exists())
        self.assertEqual(Deployment.objects.count(), 1)


class TestPatchPermissionGrant(ULRMMTestCase):
    def test_the_flags_are_serialized_for_the_role_form(self):
        role = baker.make("accounts.Role")

        fields = RoleSerializer(role).data

        for flag in (
            "can_view_patches",
            "can_approve_patches",
            "can_install_patches_now",
            "can_manage_patch_policies",
            "can_enable_unofficial_sources",
        ):
            self.assertIn(flag, fields)


def wrong_code(totp: pyotp.TOTP) -> str:
    # outside the ±30s window pyotp accepts
    valid = {totp.at(time.time() + step) for step in (-30, 0, 30)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


@override_settings(CACHES=LOCMEM_CACHE)
class TestFreshTOTP(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username="fresh", password="hunter2x")
        self.user.totp_key = pyotp.random_base32()
        self.user.save()
        self.totp = pyotp.TOTP(self.user.totp_key)

    def test_a_code_works_once(self):
        code = self.totp.now()
        self.assertTrue(verify_fresh_totp(self.user, code))
        self.assertFalse(verify_fresh_totp(self.user, code))

    def test_bad_codes(self):
        for code in (None, "", "12345", "abcdef", "1234567", wrong_code(self.totp)):
            self.assertFalse(verify_fresh_totp(self.user, code))

    def test_locked_after_failures(self):
        for _ in range(TOTP_FAIL_LIMIT):
            self.assertFalse(verify_fresh_totp(self.user, wrong_code(self.totp)))
        self.assertFalse(verify_fresh_totp(self.user, self.totp.now()))

    def test_counted_before_the_check(self):
        # incr runs first, so overlapping guesses each get their own count
        fails = f"totp_fail_{self.user.pk}"
        seen = []
        with patch(
            "accounts.utils.pyotp.TOTP.verify",
            side_effect=lambda *a, **kw: seen.append(cache.get(fails)),
        ):
            for _ in range(TOTP_FAIL_LIMIT + 2):
                self.assertFalse(verify_fresh_totp(self.user, "123456"))
        self.assertEqual(seen, list(range(1, TOTP_FAIL_LIMIT + 1)))

    def test_a_good_code_does_not_count(self):
        for _ in range(TOTP_FAIL_LIMIT - 1):
            self.assertFalse(verify_fresh_totp(self.user, wrong_code(self.totp)))
        self.assertTrue(verify_fresh_totp(self.user, self.totp.now()))
        self.assertEqual(cache.get(f"totp_fail_{self.user.pk}"), TOTP_FAIL_LIMIT - 1)

    def test_user_without_totp(self):
        code = self.totp.now()
        self.user.totp_key = ""
        self.assertFalse(verify_fresh_totp(self.user, code))


@override_settings(CACHES=LOCMEM_CACHE)
class TestConsoleStepUp(ULRMMTestCase):
    url = "/accounts/users/console_stepup/"

    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.setup_client()
        self.user = User.objects.create_user(username="stepup", password="hunter2x")
        self.user.totp_key = pyotp.random_base32()
        self.user.save()
        self.totp = pyotp.TOTP(self.user.totp_key)
        _, self.token = AuthToken.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")

    def test_step_up(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["remaining"], 0)

        r = self.client.post(self.url, {"code": wrong_code(self.totp)}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(console_stepup_remaining(self.user), 0)
        self.assertTrue(
            AuditLog.objects.filter(
                username="stepup", action=AuditActionType.FAILED_LOGIN
            ).exists()
        )

        code = self.totp.now()
        r = self.client.post(self.url, {"code": code}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.data["remaining"], 3590)
        self.assertTrue(
            AuditLog.objects.filter(
                username="stepup", action=AuditActionType.LOGIN
            ).exists()
        )

        # same code, second post
        r = self.client.post(self.url, {"code": code}, format="json")
        self.assertEqual(r.status_code, 400)

        # 60 min from the post, not sliding
        with patch("accounts.utils.time.time", return_value=time.time() + 3601):
            r = self.client.get(self.url)
        self.assertEqual(r.data["remaining"], 0)

    def test_only_codes_are_throttled(self):
        rate = settings.ULRMM_LOGIN_MIN_THROTTLE
        for _ in range(rate + 1):
            self.assertEqual(self.client.get(self.url).status_code, 200)

        for _ in range(rate):
            r = self.client.post(self.url, {"code": "12345"}, format="json")
            self.assertEqual(r.status_code, 400)
        r = self.client.post(self.url, {"code": "12345"}, format="json")
        self.assertEqual(r.status_code, 429)

    def test_step_up_belongs_to_one_login(self):
        from ulrmm.utils import get_user

        _, other = AuthToken.objects.create(user=self.user)
        r = self.client.post(self.url, {"code": self.totp.now()}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(self.client.get(self.url).data["remaining"], 3590)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {other}")
        self.assertEqual(self.client.get(self.url).data["remaining"], 0)
        # websocket auth uses the same knox token
        ws_user = get_user.func(f"access_token={other}".encode())
        self.assertEqual(console_stepup_remaining(ws_user), 0)
        ws_user = get_user.func(f"access_token={self.token}".encode())
        self.assertGreater(console_stepup_remaining(ws_user), 3590)

    def test_api_key_cannot_step_up(self):
        APIKey.objects.create(name="stepup", key="stepupkey", user=self.user)
        self.client.credentials(HTTP_X_API_KEY="stepupkey")

        r = self.client.post(self.url, {"code": self.totp.now()}, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(console_stepup_remaining(self.user), 0)

        self.client.credentials()
        self.check_not_authenticated("post", self.url)


class TestReviewFixes(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_add_user_input_errors_answer_400(self):
        base = {"username": "jane", "password": "ASd1234asd", "email": "j@example.com"}
        for change in (
            {"email": None},
            {"username": "u" * 151},
            {"first_name": "n" * 151},
            {"email": "a" * 300 + "@example.com"},
        ):
            data = {k: v for k, v in {**base, **change}.items() if v is not None}
            r = self.client.post("/accounts/users/", data, format="json")
            self.assertEqual(r.status_code, 400, change)
        self.assertFalse(User.objects.filter(username="jane").exists())

    def test_add_user_keeps_access_flags(self):
        base = {"password": "ASd1234asd", "email": "j@example.com"}
        for name, flags, want in (
            ("apionly", {"is_active": False, "block_dashboard_login": True}, (0, 1)),
            ("plain", {}, (1, 0)),
            ("strings", {"is_active": "no", "block_dashboard_login": 1}, (1, 0)),
        ):
            data = {**base, "username": name, **flags}
            r = self.client.post("/accounts/users/", data, format="json")
            self.assertEqual(r.status_code, 200, name)
            user = User.objects.get(username=name)
            got = (user.is_active, user.block_dashboard_login)
            self.assertEqual(got, tuple(map(bool, want)), name)

    def test_unicode_digit_pk_answers_400(self):
        r = self.client.post("/accounts/users/reset/", {"id": "²"}, format="json")
        self.assertEqual(r.status_code, 400)


class TestInstallerUserCommand(ULRMMTestCase):
    def test_creates_once(self):
        from io import StringIO

        from django.core.management import call_command

        for expected in (
            "Installer user has been created",
            "Installer user already exists",
        ):
            out = StringIO()
            call_command("create_installer_user", stdout=out)
            self.assertEqual(
                out.getvalue().splitlines(),
                ["Checking if installer user has been created...", expected],
            )
        user = User.objects.get(is_installer_user=True)
        self.assertTrue(user.block_dashboard_login)
        self.assertEqual(len(user.username), 32)
        self.assertTrue(user.has_usable_password())


NEW_PASSWORD = "superSekret123456"


class TestCodeForOtherAccounts(ULRMMTestCase):
    """Changing logins, API keys and roles of other accounts needs the
    actor's fresh code, superusers included."""

    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.john.totp_key = pyotp.random_base32()
        self.john.save(update_fields=["totp_key"])
        self.totp = pyotp.TOTP(self.john.totp_key)
        self.bob = User.objects.create_user(username="bob", password="hunter2x")
        self.bob.totp_key = "AB5RI6YPFTZAS52G"
        self.bob.save(update_fields=["totp_key"])
        self.bob_key = APIKey.objects.create(name="bob", key="bobkey", user=self.bob)
        self.john_key = APIKey.objects.create(
            name="john", key="johnkey", user=self.john
        )
        self.role = baker.make("accounts.Role", name="ops")
        self.spare = baker.make("accounts.Role", name="spare")

    def guarded(self):
        bob, role = self.bob.pk, self.role.pk
        return [
            ("post", "/accounts/apikeys/", {"name": "new", "user": bob}),
            ("put", f"/accounts/apikeys/{self.bob_key.pk}/", {"name": "renamed"}),
            ("put", f"/accounts/apikeys/{self.john_key.pk}/", {"user": bob}),
            ("delete", f"/accounts/apikeys/{self.bob_key.pk}/", {}),
            ("post", "/accounts/roles/", {"name": "new"}),
            ("put", f"/accounts/roles/{role}/", {"name": "renamed"}),
            ("put", f"/accounts/{bob}/users/", {"role": role}),
            ("put", f"/accounts/{bob}/users/", {"is_active": False}),
            ("put", f"/accounts/{bob}/users/", {"block_dashboard_login": True}),
            (
                "post",
                "/accounts/users/",
                {
                    "username": "carol",
                    "password": "ASd1234asd!",
                    "email": "c@example.com",
                    "role": role,
                },
            ),
            ("post", "/accounts/users/reset/", {"id": bob, "password": NEW_PASSWORD}),
            ("put", "/accounts/users/reset/", {"id": bob}),
            ("delete", f"/accounts/roles/{self.spare.pk}/", {}),
        ]

    def send(self, method, url, data):
        return getattr(self.client, method)(url, data, format="json")

    def test_refused_without_a_fresh_code(self):
        for method, url, data in self.guarded():
            for code in (None, wrong_code(self.totp)):
                body = data if code is None else {**data, "totp_code": code}
                r = self.send(method, url, body)
                self.assertEqual(r.status_code, 400, (method, url, data))
                self.assertEqual(r.data, CHANGE_NEEDS_TOTP)

        self.bob.refresh_from_db()
        self.assertTrue(self.bob.check_password("hunter2x"))
        self.assertEqual(self.bob.totp_key, "AB5RI6YPFTZAS52G")
        self.assertEqual(
            (self.bob.role, self.bob.is_active, self.bob.block_dashboard_login),
            (None, True, False),
        )
        self.assertEqual(
            set(APIKey.objects.values_list("name", "user")),
            {("bob", self.bob.pk), ("john", self.john.pk)},
        )
        self.assertEqual(
            set(Role.objects.values_list("name", flat=True)), {"ops", "spare"}
        )
        self.assertFalse(User.objects.filter(username="carol").exists())

    def test_accepted_with_a_code(self):
        for method, url, data in self.guarded():
            r = self.send(method, url, {**data, "totp_code": self.totp.now()})
            self.assertEqual(r.status_code, 200, (method, url, data))

        self.bob.refresh_from_db()
        self.assertTrue(self.bob.check_password(NEW_PASSWORD))
        self.assertEqual(self.bob.totp_key, "")
        self.assertFalse(self.bob.is_active)
        # the resets ended every API key of bob
        self.assertFalse(APIKey.objects.filter(user=self.bob).exists())
        self.assertEqual(
            set(Role.objects.values_list("name", flat=True)), {"new", "renamed"}
        )
        self.assertTrue(User.objects.filter(username="carol").exists())

    def test_a_role_in_use_is_not_deleted(self):
        self.bob.role = self.role
        self.bob.save(update_fields=["role"])
        url = f"/accounts/roles/{self.role.pk}/"
        r = self.client.delete(url, {"totp_code": self.totp.now()}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data, "This role is still assigned to users. Unassign it first."
        )
        self.bob.refresh_from_db()
        self.assertEqual(self.bob.role, self.role)

        self.bob.role = None
        self.bob.save(update_fields=["role"])
        r = self.client.delete(url, {"totp_code": self.totp.now()}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Role.objects.filter(pk=self.role.pk).exists())

    def test_own_account_and_plain_fields_need_no_code(self):
        bob = f"/accounts/{self.bob.pk}/users/"
        for method, url, data in (
            ("post", "/accounts/apikeys/", {"name": "mine", "user": self.john.pk}),
            ("put", f"/accounts/apikeys/{self.john_key.pk}/", {"name": "johns"}),
            ("put", f"/accounts/{self.john.pk}/users/", {"email": "j@example.com"}),
            ("put", bob, {"email": "b@example.com"}),
            # the edit form sends these back unchanged
            ("put", bob, {"role": None, "is_active": True}),
            (
                "post",
                "/accounts/users/",
                {"username": "dan", "password": "ASd1234asd!", "email": "d@x.com"},
            ),
            ("delete", f"/accounts/apikeys/{self.john_key.pk}/", {}),
        ):
            r = self.send(method, url, data)
            self.assertEqual(r.status_code, 200, (method, url, data))

    def test_api_key_callers_are_refused(self):
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_X_API_KEY="johnkey")
        code = self.totp.now()
        for method, url, data in self.guarded():
            r = self.send(method, url, {**data, "totp_code": code})
            self.assertEqual(r.status_code, 403, (method, url, data))
            self.assertEqual(r.data["detail"], CHANGE_NEEDS_DASHBOARD)

        self.bob.refresh_from_db()
        self.assertTrue(self.bob.check_password("hunter2x"))
        self.assertTrue(Role.objects.filter(name="ops").exists())
        self.assertEqual(APIKey.objects.count(), 2)


class TestGrantOnlyWhatYouHold(ULRMMTestCase):
    """A role or account manager without superuser rights hands out only
    flags and clients/sites its own role holds."""

    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.setup_base_instance()
        self.manager = self.create_user_with_roles(
            [
                "can_list_accounts",
                "can_manage_accounts",
                "can_list_roles",
                "can_manage_roles",
                "can_list_agents",
            ]
        )
        self.manager.role.can_view_clients.set([self.company1])
        self.manager.totp_key = pyotp.random_base32()
        self.manager.save(update_fields=["totp_key"])
        self.client.force_authenticate(user=self.manager)
        self.target = baker.make("accounts.User")

    def code(self):
        return pyotp.TOTP(self.manager.totp_key).now()

    def add_role(self, **data):
        data = {"name": "r", "can_view_clients": [self.company1.pk], **data}
        r = self.client.post(
            "/accounts/roles/", {**data, "totp_code": self.code()}, format="json"
        )
        return r

    def test_flags(self):
        r = self.add_role(can_run_scripts=True, can_edit_agent=True)
        self.assertEqual(r.status_code, 403)
        # the first missing flag in model order
        self.assertIn("can_edit_agent", r.data["detail"])
        self.assertFalse(Role.objects.filter(name="r").exists())

        r = self.add_role(can_list_agents=True, can_list_roles=True)
        self.assertEqual(r.status_code, 200)

        role = Role.objects.get(name="r")
        url = f"/accounts/roles/{role.pk}/"
        r = self.client.put(
            url,
            {"name": "r", "can_send_cmd": True, "totp_code": self.code()},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("can_send_cmd", r.data["detail"])
        role.refresh_from_db()
        self.assertFalse(role.can_send_cmd)

        # a role holding more than the manager stays out of reach, rename included
        role.can_use_terminal = True
        role.save()
        r = self.client.put(
            url, {"name": "renamed", "totp_code": self.code()}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("can_use_terminal", r.data["detail"])
        r = self.client.put(
            url,
            {"name": "renamed", "can_use_terminal": False, "totp_code": self.code()},
            format="json",
        )
        self.assertEqual(r.status_code, 200)

    def test_scope(self):
        sites = "can_view_sites"
        for data in (
            {"can_view_clients": [self.company2.pk]},
            {"can_view_clients": [self.company1.pk, self.company2.pk]},
            {"can_view_clients": [], sites: [self.site3.pk]},
            # no clients and no sites means all of them
            {"can_view_clients": [], sites: []},
        ):
            r = self.add_role(**data)
            self.assertEqual(r.status_code, 403, data)
            self.assertEqual(
                r.data["detail"],
                "You can only grant clients and sites inside your own scope.",
            )
        self.assertFalse(Role.objects.filter(name="r").exists())

        r = self.add_role(can_view_clients=[], can_view_sites=[self.site1.pk])
        self.assertEqual(r.status_code, 200)

        # a site-scoped manager does not hold the whole client
        self.manager.role.can_view_clients.clear()
        self.manager.role.can_view_sites.set([self.site1])
        r = self.add_role(name="r2")
        self.assertEqual(r.status_code, 403)
        r = self.add_role(
            name="r2", can_view_clients=[], can_view_sites=[self.site1.pk]
        )
        self.assertEqual(r.status_code, 200)

    def test_assigning_a_role(self):
        wide = baker.make("accounts.Role", can_edit_agent=True)
        wide.can_view_clients.set([self.company1])
        unscoped = baker.make("accounts.Role", can_list_agents=True)
        narrow = baker.make("accounts.Role", can_list_agents=True)
        narrow.can_view_sites.set([self.site2])
        url = f"/accounts/{self.target.pk}/users/"

        for role, detail in (
            (wide, "Your role does not have can_edit_agent, so you cannot grant it."),
            (unscoped, "You can only grant clients and sites inside your own scope."),
        ):
            r = self.client.put(
                url, {"role": role.pk, "totp_code": self.code()}, format="json"
            )
            self.assertEqual((r.status_code, r.data["detail"]), (403, detail))
            r = self.client.post(
                "/accounts/users/",
                {
                    "username": "eve",
                    "password": "ASd1234asd!",
                    "email": "e@example.com",
                    "role": role.pk,
                    "totp_code": self.code(),
                },
                format="json",
            )
            self.assertEqual((r.status_code, r.data["detail"]), (403, detail))
        self.target.refresh_from_db()
        self.assertIsNone(self.target.role)
        self.assertFalse(User.objects.filter(username="eve").exists())

        r = self.client.put(
            url, {"role": narrow.pk, "totp_code": self.code()}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.target.refresh_from_db()
        self.assertEqual(self.target.role, narrow)

        # a user that already has a wider role can still be edited otherwise
        self.target.role = wide
        self.target.save()
        r = self.client.put(
            url, {"role": wide.pk, "email": "t@example.com"}, format="json"
        )
        self.assertEqual(r.status_code, 200)

    def test_superusers_are_not_limited(self):
        john = baker.make(
            "accounts.User", is_superuser=True, totp_key=pyotp.random_base32()
        )
        self.client.force_authenticate(user=john)
        r = self.client.post(
            "/accounts/roles/",
            {
                "name": "all",
                "can_use_terminal": True,
                "totp_code": pyotp.TOTP(john.totp_key).now(),
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)


class TestUserFields(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_is_superuser_is_read_only(self):
        bob = User.objects.create_user(username="bob", password="hunter2x")
        r = self.client.get("/accounts/users/")
        flags = {row["username"]: row["is_superuser"] for row in r.data}
        self.assertEqual((flags["john"], flags["bob"]), (True, False))

        r = self.client.put(
            f"/accounts/{bob.pk}/users/", {"is_superuser": True}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        bob.refresh_from_db()
        self.assertFalse(bob.is_superuser)

    def test_dashboard_colors(self):
        url = "/accounts/users/ui/"
        for color in ("info", "red", "light-blue", "blue-grey-14"):
            r = self.client.patch(url, {"dash_info_color": color}, format="json")
            self.assertEqual(r.status_code, 200, color)
        for color in ("redd", "red-15", "", "#ff0000"):
            r = self.client.patch(url, {"dash_info_color": color}, format="json")
            self.assertEqual(r.status_code, 400, color)
        self.john.refresh_from_db()
        self.assertEqual(self.john.dash_info_color, "blue-grey-14")

        # an unchanged value stored before the check does not block a save
        User.objects.filter(pk=self.john.pk).update(dash_info_color="#ff0000")
        # the client is authenticated with this object, a request reads it
        self.john.refresh_from_db()
        r = self.client.patch(
            url, {"dash_info_color": "#ff0000", "dark_mode": False}, format="json"
        )
        self.assertEqual(r.status_code, 200)

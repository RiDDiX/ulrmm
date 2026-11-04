# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import importlib
import json
import socket
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pyotp
import requests
from allauth.socialaccount.models import SocialAccount, SocialApp
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.urls import clear_url_caches
from knox.models import AuthToken
from model_bakery import baker
from rest_framework.test import APIClient

from accounts.models import APIKey, User
from accounts.utils import CHANGE_NEEDS_TOTP
from accounts.views import CHANGE_NEEDS_DASHBOARD
from core.models import CoreSettings
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.util_settings import get_backend_url

from . import utils as sso_utils
from .adapter import IdPSession
from .utils import IdPURLError, check_idp_url, derive_provider_id, provider_icon

PROVIDERS_URL = "/accounts/ssoproviders/"
SETTINGS_URL = "/accounts/ssoproviders/settings/"
ACCOUNT_URL = "/accounts/ssoproviders/account/"
TOKEN_URL = "/accounts/ssoproviders/token/"
CONFIG_URL = "/_allauth/browser/v1/config/"
REDIRECT_URL = "/_allauth/browser/v1/auth/provider/redirect/"
SESSION_KEY = "account_authentication_methods"

PUBLIC_ADDRESS = [(2, 1, 6, "", ("93.184.216.34", 443))]


def resolves_to(address):
    return patch(
        "sso.utils.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (address, 443))],
    )


def make_app(name="corp idp", provider_id="corp-idp", role=None, **kwargs):
    return SocialApp.objects.create(
        provider="openid_connect",
        provider_id=provider_id,
        name=name,
        client_id=kwargs.pop("client_id", "cid"),
        secret=kwargs.pop("secret", "very-secret"),
        settings={
            "server_url": kwargs.pop("server_url", "https://idp.example.com"),
            "role": role,
        },
        **kwargs,
    )


def with_code(user, body=None):
    # provider changes need the actor's fresh code
    if not user.totp_key:
        user.totp_key = pyotp.random_base32()
        user.save(update_fields=["totp_key"])
    return {**(body or {}), "totp_code": pyotp.TOTP(user.totp_key).now()}


def callback_url(provider_id):
    backend = get_backend_url(
        settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
    )
    return f"{backend}/accounts/oidc/{provider_id}/login/callback/"


def set_sso(enabled=True, block=False):
    core = CoreSettings.objects.first()
    core.sso_enabled = enabled
    core.block_local_user_logon = block
    core.save()


class SSOTestCase(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        # hermetic: hostnames in issuer URLs resolve to a public address
        resolver = patch("sso.utils.socket.getaddrinfo", return_value=PUBLIC_ADDRESS)
        resolver.start()
        self.addCleanup(resolver.stop)

    def account_manager(self):
        return self.create_user_with_roles(["can_list_accounts", "can_manage_accounts"])


class TestSSOSettingsModule(SSOTestCase):
    def test_email_matching_is_off(self):
        self.assertFalse(settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION)
        self.assertFalse(settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT)
        self.assertEqual(
            settings.SOCIALACCOUNT_ADAPTER, "sso.adapter.SSOAccountAdapter"
        )
        self.assertTrue(
            settings.SOCIALACCOUNT_PROVIDERS["openid_connect"]["OAUTH_PKCE_ENABLED"]
        )
        self.assertNotIn("ee.sso", settings.INSTALLED_APPS)
        self.assertIn("sso", settings.INSTALLED_APPS)

    def test_provider_id_rule(self):
        self.assertEqual(derive_provider_id("My IdP!"), "my-idp")
        self.assertEqual(derive_provider_id("corp idp"), "corp-idp")
        self.assertEqual(derive_provider_id("a_b-C"), "a_b-c")
        self.assertEqual(derive_provider_id("!!!"), "")

    def test_icons(self):
        self.assertEqual(
            provider_icon("https://login.microsoftonline.com/x"), "mdi-microsoft"
        )
        self.assertEqual(provider_icon("https://idp.example.com"), "mdi-key")
        self.assertEqual(provider_icon(None), "mdi-key")
        # first match in table order wins
        self.assertEqual(
            provider_icon("https://github.com/?via=accounts.google.com"), "mdi-google"
        )

    def test_idp_url_check(self):
        check_idp_url("https://idp.example.com/realms/x")
        for url in (
            "http://idp.example.com",
            "ftp://idp.example.com",
            "https://",
            "https://user:pw@idp.example.com",
            "https://127.0.0.1",
            "https://localhost:8443",
            "https://10.1.2.3",
            "https://169.254.169.254/latest",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            # NAT64 and IPv4-compatible forms of metadata and loopback
            "https://[64:ff9b::a9fe:a9fe]/",
            "https://[::a9fe:a9fe]/",
            "https://[64:ff9b::7f00:1]/",
            "https://100.100.100.200",
            "https://idp.example.com:99999",
        ):
            with self.assertRaises(IdPURLError, msg=url):
                check_idp_url(url)

        with resolves_to("192.168.1.10"), self.assertRaises(IdPURLError):
            check_idp_url("https://idp.internal.example")

        with override_settings(SSO_ALLOW_PRIVATE_ISSUER=True):
            check_idp_url("https://10.1.2.3")
            with self.assertRaises(IdPURLError):
                check_idp_url("http://10.1.2.3")

    def test_idp_session_refuses_internal_targets(self):
        # checked before anything is sent, so no network is needed
        for url in ("https://127.0.0.1/token", "http://idp.example.com/userinfo"):
            with self.assertRaises(requests.exceptions.InvalidURL):
                IdPSession().get(url)

    def test_idp_session_connects_to_the_checked_address(self):
        connected = []

        def connect(sock, address):
            connected.append(address[:2])

        answers = [PUBLIC_ADDRESS, [(2, 1, 6, "", ("127.0.0.1", 443))]]

        def rebinding(*args, **kwargs):
            # public for the first lookup, loopback from then on
            return answers.pop(0) if len(answers) > 1 else answers[0]

        url = "https://idp.example.org/.well-known/openid-configuration"
        with patch.object(socket.socket, "connect", connect):
            with patch("sso.utils.socket.getaddrinfo", side_effect=rebinding):
                with self.assertRaises(requests.exceptions.ConnectionError):
                    IdPSession().get(url)
            self.assertEqual(connected, [])

            # a public answer is connected to as resolved, and TLS still
            # verifies the host name
            with patch(
                "urllib3.connection._ssl_wrap_socket_and_match_hostname",
                side_effect=OSError("stop"),
            ) as wrap:
                with self.assertRaises(requests.exceptions.ConnectionError):
                    IdPSession().get(url)
            self.assertEqual(connected, [("93.184.216.34", 443)])
            self.assertEqual(
                wrap.call_args.kwargs["server_hostname"], "idp.example.org"
            )


class TestSSOProviders(SSOTestCase):
    body = {
        "name": "My IdP!",
        "client_id": "cid",
        "secret": "s3cret",
        "server_url": "https://idp.example.com",
    }

    def test_create_derives_fields(self):
        for role in (0, "", None):
            SocialApp.objects.all().delete()
            r = self.client.post(
                PROVIDERS_URL,
                with_code(self.john, {**self.body, "role": role}),
                format="json",
            )
            self.assertEqual(r.status_code, 200, r.data)
            self.assertEqual(r.data, "ok")
            app = SocialApp.objects.get()
            self.assertEqual(app.provider_id, "my-idp")
            self.assertEqual(app.provider, "openid_connect")
            self.assertEqual(app.secret, "s3cret")
            self.assertEqual(
                app.settings, {"server_url": "https://idp.example.com", "role": None}
            )

        role = baker.make("accounts.Role")
        SocialApp.objects.all().delete()
        r = self.client.post(
            PROVIDERS_URL,
            with_code(self.john, {**self.body, "role": role.pk}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(SocialApp.objects.get().settings["role"], role.pk)

    def test_unknown_roles_are_kept(self):
        for role in (99999, "abc", 1.5):
            SocialApp.objects.all().delete()
            r = self.client.post(
                PROVIDERS_URL,
                with_code(self.john, {**self.body, "role": role}),
                format="json",
            )
            self.assertEqual(r.status_code, 200, role)
            self.assertEqual(SocialApp.objects.get().settings["role"], role)

        # a provider whose role was deleted stays editable
        role = baker.make("accounts.Role")
        app = SocialApp.objects.get()
        app.settings = {**app.settings, "role": role.pk}
        app.save()
        role.delete()
        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            with_code(self.john, {"client_id": "c2", "secret": "", "role": role.pk}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual((app.client_id, app.settings["role"]), ("c2", role.pk))

    def test_create_rejects_bad_ids(self):
        make_app(name="My IdP", provider_id="my-idp")
        r = self.client.post(PROVIDERS_URL, self.body, format="json")
        self.assertEqual(r.status_code, 400)
        # case-insensitive against older ids
        SocialApp.objects.all().delete()
        make_app(name="My IdP", provider_id="My-IdP")
        r = self.client.post(PROVIDERS_URL, self.body, format="json")
        self.assertEqual(r.status_code, 400)

        for name in ("!!!", "---", "openid_connect"):
            r = self.client.post(
                PROVIDERS_URL, {**self.body, "name": name}, format="json"
            )
            self.assertEqual(r.status_code, 400, name)
        self.assertEqual(SocialApp.objects.count(), 1)

    def test_bad_input_is_400(self):
        for body in (
            {k: v for k, v in self.body.items() if k != "name"},
            {k: v for k, v in self.body.items() if k != "server_url"},
            {**self.body, "server_url": "http://idp.example.com"},
            {**self.body, "server_url": "https://169.254.169.254"},
            {**self.body, "name": "x" * 41},
        ):
            r = self.client.post(PROVIDERS_URL, body, format="json")
            self.assertEqual(r.status_code, 400, body)
        self.assertFalse(SocialApp.objects.exists())

        # form-encoded bodies are validated the same way
        r = self.client.post(PROVIDERS_URL, {"name": "x"})
        self.assertEqual(r.status_code, 400)

    def test_list_fields(self):
        app = make_app()
        r = self.client.get(PROVIDERS_URL)
        self.assertEqual(r.status_code, 200)
        item = r.data[0]
        self.assertEqual(item["id"], app.pk)
        self.assertEqual(item["provider_id"], "corp-idp")
        self.assertEqual(item["server_url"], "https://idp.example.com")
        self.assertIsNone(item["role"])
        self.assertTrue(item["secret_set"])
        self.assertEqual(item["callback_url"], callback_url("corp-idp"))
        self.assertEqual(
            item["javascript_origin_url"], settings.CORS_ORIGIN_WHITELIST[0]
        )
        self.assertNotIn("secret", item)
        self.assertNotIn("very-secret", json.dumps(r.data))
        self.assertIsNone(item["blocked_reason"])

    @patch.object(sso_utils, "_reported_blocks", set())
    def test_blocked_issuers_are_flagged(self):
        # saved before the URL rule existed
        make_app(name="Plain", provider_id="plain", server_url="http://idp.lan")
        make_app(name="Internal", provider_id="internal", server_url="https://10.0.0.5")
        make_app()

        with self.assertLogs("ulrmm", "WARNING") as logs:
            r = self.client.get(PROVIDERS_URL)
        reasons = {p["provider_id"]: p["blocked_reason"] for p in r.data}
        self.assertEqual(reasons["plain"], "The URL must be an https:// address.")
        self.assertIn("private", reasons["internal"])
        self.assertIsNone(reasons["corp-idp"])
        hints = {
            name: "SSO_ALLOW_PRIVATE_ISSUER" in line
            for line in logs.output
            for name in ("plain", "internal")
            if f"provider {name} " in line
        }
        self.assertEqual(hints, {"plain": False, "internal": True})
        self.assertEqual(len(logs.output), 2)

        # logged once per process
        with self.assertNoLogs("ulrmm", "WARNING"):
            self.client.get(PROVIDERS_URL)

        with override_settings(SSO_ALLOW_PRIVATE_ISSUER=True):
            r = self.client.get(PROVIDERS_URL)
        reasons = {p["provider_id"]: p["blocked_reason"] for p in r.data}
        self.assertIsNone(reasons["internal"])
        self.assertTrue(reasons["plain"])

    def test_non_object_body_is_400(self):
        app = make_app()
        for body in ([], ["client_id"], "x", 5):
            r = self.client.put(f"{PROVIDERS_URL}{app.pk}/", body, format="json")
            self.assertEqual(r.status_code, 400, body)

    def test_permissions(self):
        app = make_app()
        lister = self.create_user_with_roles(["can_list_accounts"])
        nobody = self.create_user_with_roles([])

        self.client.force_authenticate(user=nobody)
        self.assertEqual(self.client.get(PROVIDERS_URL).status_code, 403)
        self.assertEqual(self.client.get(SETTINGS_URL).status_code, 403)

        self.client.force_authenticate(user=lister)
        self.assertEqual(self.client.get(PROVIDERS_URL).status_code, 200)
        for method, url, body in (
            ("post", PROVIDERS_URL, self.body),
            ("put", f"{PROVIDERS_URL}{app.pk}/", self.body),
            ("delete", f"{PROVIDERS_URL}{app.pk}/", {}),
            (
                "post",
                SETTINGS_URL,
                {"sso_enabled": True, "block_local_user_logon": False},
            ),
            ("delete", ACCOUNT_URL, {"provider": "corp-idp", "account": "x"}),
        ):
            r = getattr(self.client, method)(url, body, format="json")
            self.assertEqual(r.status_code, 403, f"{method} {url}")

        self.client.logout()
        self.assertEqual(self.client.get(PROVIDERS_URL).status_code, 401)

    def test_missing_pk_is_404(self):
        url = f"{PROVIDERS_URL}99999/"
        self.assertEqual(
            self.client.put(url, self.body, format="json").status_code, 404
        )
        self.assertEqual(self.client.delete(url).status_code, 404)

    def test_edit(self):
        app = make_app()
        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            with_code(
                self.john,
                {
                    "name": "renamed",
                    "provider_id": "other",
                    "provider": "github",
                    "client_id": "cid2",
                    "secret": "",
                    "server_url": "https://login.example.org",
                },
            ),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual(app.name, "corp idp")
        self.assertEqual(app.provider_id, "corp-idp")
        self.assertEqual(app.provider, "openid_connect")
        self.assertEqual(app.client_id, "cid2")
        self.assertEqual(app.secret, "very-secret")
        self.assertEqual(app.settings["server_url"], "https://login.example.org")

        # keys that are not sent keep their stored value
        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            with_code(self.john, {"secret": "new"}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual(app.secret, "new")
        self.assertEqual(
            app.settings, {"server_url": "https://login.example.org", "role": None}
        )

        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            with_code(self.john, {"secret": "ignored", "secret_clear": True}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual(app.secret, "")

        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            {"server_url": "https://127.0.0.1"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_delete_keeps_links(self):
        app = make_app()
        user = baker.make("accounts.User")
        SocialAccount.objects.create(user=user, provider="corp-idp", uid="s1")
        r = self.client.delete(
            f"{PROVIDERS_URL}{app.pk}/", with_code(self.john), format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(SocialApp.objects.exists())
        self.assertTrue(SocialAccount.objects.filter(uid="s1").exists())
        self.assertTrue(User.objects.get(pk=user.pk).is_sso_user)

    def test_changes_are_audited_without_the_secret(self):
        self.client.post(PROVIDERS_URL, with_code(self.john, self.body), format="json")
        app = SocialApp.objects.get()
        url = f"{PROVIDERS_URL}{app.pk}/"
        self.client.put(url, with_code(self.john, {"secret": "n3w"}), format="json")
        self.client.delete(url, with_code(self.john), format="json")

        logs = AuditLog.objects.filter(object_type=AuditObjType.CORE).order_by("id")
        self.assertEqual(
            [log.action for log in logs],
            [AuditActionType.ADD, AuditActionType.MODIFY, AuditActionType.DELETE],
        )
        dumped = json.dumps([[log.before_value, log.after_value] for log in logs])
        self.assertNotIn("s3cret", dumped)
        self.assertNotIn("n3w", dumped)
        self.assertIn("My IdP!", logs[0].message)

    def test_superuser_rules(self):
        admin = self.account_manager()
        super_role = baker.make("accounts.Role", is_superuser=True)
        plain_role = baker.make("accounts.Role")
        self.client.force_authenticate(user=admin)

        r = self.client.post(
            PROVIDERS_URL, {**self.body, "role": super_role.pk}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertFalse(SocialApp.objects.exists())

        r = self.client.post(
            PROVIDERS_URL,
            with_code(admin, {**self.body, "role": plain_role.pk}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app = SocialApp.objects.get()

        # a role-only superuser counts as a superuser for linked accounts
        role_super = self.create_user_with_roles(["is_superuser"])
        SocialAccount.objects.create(user=role_super, provider="my-idp", uid="s1")
        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            {"server_url": "https://evil.example.com"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            self.client.delete(f"{PROVIDERS_URL}{app.pk}/").status_code, 403
        )
        app.refresh_from_db()
        self.assertEqual(app.settings["server_url"], "https://idp.example.com")

        # superuser role holders manage it
        self.client.force_authenticate(user=role_super)
        r = self.client.put(
            f"{PROVIDERS_URL}{app.pk}/",
            with_code(role_super, {"role": super_role.pk}),
            format="json",
        )
        self.assertEqual(r.status_code, 200)

    def test_changes_need_a_fresh_code(self):
        app = make_app()
        with_code(self.john)
        url = f"{PROVIDERS_URL}{app.pk}/"
        for method, path, body in (
            ("post", PROVIDERS_URL, self.body),
            ("put", url, {"client_id": "c2"}),
            ("delete", url, {}),
        ):
            r = getattr(self.client, method)(path, body, format="json")
            self.assertEqual(r.status_code, 400, method)
            self.assertEqual(r.data, CHANGE_NEEDS_TOTP)
        app.refresh_from_db()
        self.assertEqual(app.client_id, "cid")
        self.assertEqual(SocialApp.objects.count(), 1)

    def test_api_key_callers_are_refused(self):
        app = make_app()
        APIKey.objects.create(name="john", key="johnkey", user=self.john)
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_X_API_KEY="johnkey")
        url = f"{PROVIDERS_URL}{app.pk}/"
        for method, path, body in (
            ("post", PROVIDERS_URL, self.body),
            ("put", url, {"client_id": "c2"}),
            ("delete", url, {}),
        ):
            r = getattr(self.client, method)(
                path, with_code(self.john, body), format="json"
            )
            self.assertEqual(r.status_code, 403, method)
            self.assertEqual(r.data["detail"], CHANGE_NEEDS_DASHBOARD)
        app.refresh_from_db()
        self.assertEqual(app.client_id, "cid")
        self.assertEqual(SocialApp.objects.count(), 1)

    def test_role_flags_must_be_held(self):
        admin = self.account_manager()
        strong = baker.make("accounts.Role", can_run_scripts=True)
        weak = baker.make("accounts.Role", can_list_accounts=True)
        self.client.force_authenticate(user=admin)

        r = self.client.post(
            PROVIDERS_URL,
            with_code(admin, {**self.body, "role": strong.pk}),
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("can_run_scripts", r.data["detail"])
        self.assertFalse(SocialApp.objects.exists())

        app = make_app(role=weak.pk)
        url = f"{PROVIDERS_URL}{app.pk}/"
        r = self.client.put(url, with_code(admin, {"role": strong.pk}), format="json")
        self.assertEqual(r.status_code, 403)
        # nor redirect a provider that already holds such a role
        held = make_app(name="held", provider_id="held", role=strong.pk)
        r = self.client.put(
            f"{PROVIDERS_URL}{held.pk}/",
            with_code(admin, {"server_url": "https://evil.example.com"}),
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        app.refresh_from_db()
        held.refresh_from_db()
        self.assertEqual(app.settings["role"], weak.pk)
        self.assertEqual(held.settings["server_url"], "https://idp.example.com")

        r = self.client.put(url, with_code(admin, {"client_id": "c2"}), format="json")
        self.assertEqual(r.status_code, 200)


class TestSSOSettings(SSOTestCase):
    def test_get(self):
        r = self.client.get(SETTINGS_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data, {"block_local_user_logon": False, "sso_enabled": False}
        )

    def test_bad_input_is_400(self):
        r = self.client.post(
            SETTINGS_URL, {"block_local_user_logon": True}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(SETTINGS_URL, {"sso_enabled": True}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_fail_safe(self):
        r = self.client.post(
            SETTINGS_URL,
            {"sso_enabled": True, "block_local_user_logon": True},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        core = CoreSettings.objects.first()
        self.assertTrue(core.sso_enabled and core.block_local_user_logon)

        r = self.client.post(
            SETTINGS_URL,
            {"sso_enabled": False, "block_local_user_logon": True},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        core = CoreSettings.objects.first()
        self.assertFalse(core.sso_enabled or core.block_local_user_logon)

    def test_change_is_audited(self):
        AuditLog.objects.all().delete()
        self.client.post(
            SETTINGS_URL,
            {"sso_enabled": True, "block_local_user_logon": False},
            format="json",
        )
        log = AuditLog.objects.get(object_type="coresettings")
        self.assertEqual(log.action, AuditActionType.MODIFY)
        self.assertFalse(log.before_value["sso_enabled"])
        self.assertTrue(log.after_value["sso_enabled"])

    @patch("core.views.sync_mesh_perms_task")
    def test_core_settings_put_cannot_change_the_flags(self, _sync):
        editor = self.create_user_with_roles(
            ["can_view_core_settings", "can_edit_core_settings"]
        )
        for user in (editor, self.john):
            self.client.force_authenticate(user=user)
            r = self.client.put(
                "/core/settings/",
                {"sso_enabled": True, "block_local_user_logon": True},
                format="json",
            )
            self.assertEqual(r.status_code, 200)
            core = CoreSettings.objects.first()
            self.assertFalse(core.sso_enabled or core.block_local_user_logon)

        r = self.client.get("/core/settings/")
        self.assertIn("sso_enabled", r.data)
        self.assertIn("block_local_user_logon", r.data)


class TestPasswordLoginRules(SSOTestCase):
    def check_creds(self, username, password="hunter2x"):
        client = APIClient()
        return client.post(
            "/v2/checkcreds/",
            {"username": username, "password": password},
            format="json",
        )

    def login(self, user, code=""):
        client = APIClient()
        return client.post(
            "/v2/login/",
            {"username": user.username, "password": "hunter2x", "twofactor": code},
            format="json",
        )

    def make_user(self, username, **kwargs):
        user = User.objects.create_user(
            username=username, password="hunter2x", **kwargs
        )
        user.totp_key = pyotp.random_base32()
        user.save()
        return user

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_block_local_logon(self):
        cache.clear()
        set_sso(enabled=True, block=True)
        plain = self.make_user("plain")
        role_super = self.make_user(
            "rolesuper", role=baker.make("accounts.Role", is_superuser=True)
        )
        root = self.make_user("root", is_superuser=True)

        r = self.check_creds(plain.username)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Bad credentials")
        code = pyotp.TOTP(plain.totp_key).now()
        self.assertEqual(self.login(plain, code).status_code, 400)

        # role superusers keep the password login too
        for user in (root, role_super):
            r = self.check_creds(user.username)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.data, {"totp": True})
            r = self.login(user, pyotp.TOTP(user.totp_key).now())
            self.assertEqual(r.status_code, 200)
            self.assertIn("token", r.data)

    def test_admin_resets_disabled_while_blocked(self):
        set_sso(enabled=True, block=True)
        target = self.make_user("target")
        for method in ("post", "put"):
            for url in ("/accounts/users/reset/", "/accounts/users/reset_totp/"):
                r = getattr(self.client, method)(
                    url, {"id": target.pk, "password": "N3w-passw0rd!"}, format="json"
                )
                self.assertEqual(r.status_code, 403, f"{method} {url}")

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_sso_users_cannot_use_a_password(self):
        cache.clear()
        user = self.make_user("ssouser")
        SocialAccount.objects.create(user=user, provider="corp-idp", uid="s1")
        self.assertEqual(self.check_creds("ssouser").status_code, 400)
        code = pyotp.TOTP(user.totp_key).now()
        self.assertEqual(self.login(user, code).status_code, 400)

    def test_sso_users_cannot_self_reset(self):
        user = self.make_user("ssouser")
        SocialAccount.objects.create(user=user, provider="corp-idp", uid="s1")
        self.client.force_authenticate(user=user)
        r = self.client.put(
            "/accounts/resetpw/", {"password": "N3w-passw0rd!"}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.put("/accounts/reset2fa/").status_code, 403)

    def test_sso_users_skip_mfa_enrolment(self):
        sso_user = User.objects.create_user(username="ssouser", password="hunter2x")
        SocialAccount.objects.create(user=sso_user, provider="corp-idp", uid="s1")
        local = User.objects.create_user(username="local", password="hunter2x")

        for user, status in ((sso_user, 200), (local, 401)):
            _, token = AuthToken.objects.create(user=user)
            client = APIClient()
            client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
            self.assertEqual(client.get("/core/version/").status_code, status)


class TestTokenExchange(SSOTestCase):
    def setUp(self):
        super().setUp()
        set_sso(enabled=True)
        self.app = make_app()
        self.user = User.objects.create_user(
            username="carol", first_name="Alice", last_name="Smith", email="a@x.com"
        )
        SocialAccount.objects.create(user=self.user, provider="corp-idp", uid="s1")

    def session_client(self, user=None, records=None, **kwargs):
        client = APIClient(**kwargs)
        client.force_login(user or self.user)
        session = client.session
        session[SESSION_KEY] = (
            records
            if records is not None
            else [
                {
                    "method": "socialaccount",
                    "at": time.time(),
                    "provider": "corp-idp",
                    "uid": "s1",
                }
            ]
        )
        session.save()
        return client

    def exchange(self, client, **extra):
        return client.post(
            TOKEN_URL, {}, format="json", REMOTE_ADDR="203.0.113.9", **extra
        )

    def assert_refused(self, client):
        before = AuthToken.objects.count()
        r = self.exchange(client)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, "No pending login session found")
        self.assertEqual(AuthToken.objects.count(), before)
        self.assertFalse(AuditLog.objects.filter(action=AuditActionType.LOGIN).exists())
        # the session is gone
        self.assertEqual(self.exchange(client).status_code, 403)

    def test_success(self):
        client = self.session_client()
        r = self.exchange(client)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["username"], "carol")
        self.assertEqual(r.data["provider"], "corp-idp")
        self.assertEqual(r.data["name"], "Alice Smith")
        self.assertIn("expiry", r.data)

        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login_ip, "203.0.113.9")
        self.assertIsNotNone(self.user.last_login)

        log = AuditLog.objects.get(action=AuditActionType.LOGIN)
        self.assertEqual(log.username, "carol")
        self.assertEqual(log.object_type, AuditObjType.USER)
        self.assertIn("corp-idp", log.message)
        self.assertEqual(log.debug_info["uid"], "s1")
        self.assertEqual(log.debug_info["ip"], "203.0.113.9")

        # single use
        self.assertEqual(self.exchange(client).status_code, 403)

        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Token {r.data['token']}")
        self.assertEqual(api.get("/core/version/").status_code, 200)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_throttled(self):
        cache.clear()
        rate = settings.ULRMM_LOGIN_MIN_THROTTLE
        before = AuthToken.objects.count()
        for _ in range(rate):
            self.assertEqual(self.exchange(self.session_client()).status_code, 200)
        r = self.exchange(self.session_client())
        self.assertEqual(r.status_code, 429)
        self.assertEqual(AuthToken.objects.count(), before + rate)

    def test_name_fallback(self):
        for first, last, email, expected in (
            ("Alice", "", "a@x.com", "Alice"),
            ("", "Smith", "a@x.com", "a@x.com"),
            ("", "", "", None),
        ):
            User.objects.filter(pk=self.user.pk).update(
                first_name=first, last_name=last, email=email
            )
            r = self.exchange(self.session_client())
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.data["name"], expected)

    def test_refused_while_sso_disabled(self):
        set_sso(enabled=False)
        self.assert_refused(self.session_client())
        log = AuditLog.objects.get(action=AuditActionType.FAILED_LOGIN)
        self.assertEqual(log.username, "carol")

    def test_refused_without_a_record(self):
        self.assert_refused(self.session_client(records=[]))
        self.assert_refused(
            self.session_client(
                records=[{"method": "password", "at": time.time(), "username": "carol"}]
            )
        )

    def test_refused_for_stale_records(self):
        stale = {
            "method": "socialaccount",
            "at": time.time() - 600,
            "provider": "corp-idp",
            "uid": "s1",
        }
        self.assert_refused(self.session_client(records=[stale]))

        # the latest record counts
        fresh = {**stale, "at": time.time()}
        r = self.exchange(self.session_client(records=[fresh, stale]))
        self.assertEqual(r.status_code, 403)
        r = self.exchange(self.session_client(records=[stale, fresh]))
        self.assertEqual(r.status_code, 200)

    def test_refused_for_unlinked_identities(self):
        record = {"method": "socialaccount", "at": time.time(), "provider": "corp-idp"}
        self.assert_refused(self.session_client(records=[{**record, "uid": "other"}]))

        self.app.delete()
        self.assert_refused(self.session_client())

    def test_refused_for_blocked_users(self):
        User.objects.filter(pk=self.user.pk).update(block_dashboard_login=True)
        self.assert_refused(self.session_client())
        User.objects.filter(pk=self.user.pk).update(
            block_dashboard_login=False, is_installer_user=True
        )
        self.assert_refused(self.session_client())

    def test_refused_for_non_sso_users(self):
        local = User.objects.create_user(username="local", password="hunter2x")
        client = self.session_client(user=local)
        r = self.exchange(client)
        self.assertEqual(r.status_code, 403)
        self.assertFalse(AuthToken.objects.filter(user=local).exists())

    def test_needs_session_and_csrf(self):
        _, token = AuthToken.objects.create(user=self.user)
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        self.assertIn(self.exchange(api).status_code, (401, 403))

        client = self.session_client(enforce_csrf_checks=True)
        r = self.exchange(client)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(AuthToken.objects.filter(user=self.user).count(), 1)

        client.get(CONFIG_URL)
        csrf = client.cookies["csrftoken"].value
        r = self.exchange(client, HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(r.status_code, 200)

    def test_ip_source(self):
        forwarded = {"HTTP_X_FORWARDED_FOR": "198.51.100.4"}
        self.exchange(self.session_client(), **forwarded)
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login_ip, "203.0.113.9")

        with override_settings(ULRMM_TRUST_X_FORWARDED_FOR=True):
            self.exchange(self.session_client(), **forwarded)
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login_ip, "198.51.100.4")


class TestLoginConfig(SSOTestCase):
    def providers(self):
        r = APIClient().get(CONFIG_URL)
        self.assertEqual(r.status_code, 200)
        self.assertIn("csrftoken", r.cookies)
        self.assertIn("no-store", r["Cache-Control"])
        self.assertIn("Expires", r)
        data = r.json()
        self.assertEqual(data["status"], 200)
        self.assertNotIn("account", data["data"])
        return data["data"]["socialaccount"]["providers"]

    def test_empty_while_disabled(self):
        make_app()
        self.assertEqual(self.providers(), [])

    def test_entries(self):
        set_sso(enabled=True)
        make_app(
            name="Microsoft",
            provider_id="microsoft",
            server_url="https://login.microsoftonline.com/tenant/v2.0",
        )
        make_app()
        self.assertEqual(
            sorted(self.providers(), key=lambda p: p["id"]),
            [
                {"id": "corp-idp", "name": "corp idp", "icon": "mdi-key"},
                {"id": "microsoft", "name": "Microsoft", "icon": "mdi-microsoft"},
            ],
        )

    def test_blocked_issuers_are_left_out(self):
        set_sso(enabled=True)
        make_app(name="Plain", provider_id="plain", server_url="http://idp.lan")
        make_app(name="Internal", provider_id="internal", server_url="https://10.0.0.5")
        make_app()
        self.assertEqual(
            [p["id"] for p in self.providers()],
            ["corp-idp"],
        )

    def test_no_dns_lookup(self):
        # the login page and the provider list must not wait on the resolver
        set_sso(enabled=True)
        make_app(server_url="https://idp.internal.example")
        with patch("sso.utils.socket.getaddrinfo") as lookup:
            self.assertEqual([p["id"] for p in self.providers()], ["corp-idp"])
            r = self.client.get(PROVIDERS_URL)
            self.assertIsNone(r.data[0]["blocked_reason"])
        lookup.assert_not_called()

        # the save check still resolves the name
        with resolves_to("10.0.0.5"), self.assertRaises(IdPURLError):
            check_idp_url("https://idp.internal.example")

    def test_code_point_order(self):
        # allauth sorted by name in Python: uppercase and punctuation first
        set_sso(enabled=True)
        for name, provider_id in (
            ("corp idp", "a"),
            ("Corp-B", "b"),
            ("Corp A", "c"),
            ("Corp_A", "d"),
            ("Corp A", "e"),
        ):
            make_app(name=name, provider_id=provider_id)
        self.assertEqual([p["id"] for p in self.providers()], ["c", "e", "b", "d", "a"])

    def test_head_and_options(self):
        browser = APIClient()
        r = browser.head(CONFIG_URL)
        self.assertEqual(r.status_code, 200)
        r = browser.options(CONFIG_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Allow"], "GET, HEAD, OPTIONS")
        r = browser.options(REDIRECT_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Allow"], "POST, OPTIONS")
        self.assertEqual(browser.put(CONFIG_URL).status_code, 405)

    def test_ambiguous_ids_are_dropped(self):
        set_sso(enabled=True)
        make_app()
        make_app(name="corp idp 2")
        make_app(name="Other", provider_id="other")
        self.assertEqual(
            self.providers(), [{"id": "other", "name": "Other", "icon": "mdi-key"}]
        )


class FakeResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code
        self.text = json.dumps(data)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(str(self.status_code))


class FakeIdP:
    discovery = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "userinfo_endpoint": "https://idp.example.com/userinfo",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }

    def __init__(self, claims):
        self.claims = claims
        self.token_requests = []

    # allauth opens the session with "with", like requests.Session
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResponse(self.discovery)
        if url == self.discovery["userinfo_endpoint"]:
            return FakeResponse(self.claims)
        return FakeResponse({}, 404)

    def request(self, method, url, **kwargs):
        self.token_requests.append(kwargs.get("data") or {})
        return FakeResponse(
            {"access_token": "at", "token_type": "Bearer", "expires_in": 300}
        )


class TestLoginFlow(SSOTestCase):
    claims = {
        "sub": "s1",
        "preferred_username": "carol",
        "given_name": "Alice",
        "family_name": "Smith",
        "email": "alice@example.com",
    }

    def setUp(self):
        super().setUp()
        set_sso(enabled=True)
        self.role = baker.make("accounts.Role", can_list_agents=True)
        self.app = make_app(role=self.role.pk)
        self.host = settings.ALLOWED_HOSTS[0]
        self.callback = settings.HEADLESS_FRONTEND_URLS["socialaccount_login_error"]
        self.browser = APIClient()

    def idp(self, claims=None):
        self.fake_idp = FakeIdP(claims or self.claims)
        return patch(
            "sso.adapter.SSOAccountAdapter.get_requests_session",
            return_value=self.fake_idp,
        )

    def start(self, **fields):
        body = {
            "provider": "corp-idp",
            "process": "login",
            "callback_url": self.callback,
        }
        return self.browser.post(REDIRECT_URL, {**body, **fields}, HTTP_HOST=self.host)

    def finish(self, state, **params):
        query = {"code": "abc", "state": state, **params}
        return self.browser.get(
            "/accounts/oidc/corp-idp/login/callback/", query, HTTP_HOST=self.host
        )

    def sign_in(self, claims=None):
        with self.idp(claims):
            r = self.start()
            self.assertEqual(r.status_code, 302)
            state = parse_qs(urlsplit(r["Location"]).query)["state"][0]
            with patch("core.tasks.sync_mesh_perms_task") as sync:
                with self.captureOnCommitCallbacks(execute=True):
                    r = self.finish(state)
        return r, sync

    def error_of(self, response):
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(
            f"{location.scheme}://{location.netloc}{location.path}", self.callback
        )
        return parse_qs(location.query).get("error", [""])[0]

    def session_user(self):
        return self.browser.session.get("_auth_user_id")

    def test_start_redirects_to_the_idp(self):
        with self.idp():
            r = self.start()
        self.assertEqual(r.status_code, 302)
        location = urlsplit(r["Location"])
        self.assertEqual(location.netloc, "idp.example.com")
        self.assertEqual(location.path, "/authorize")
        params = parse_qs(location.query)
        self.assertTrue(params["state"][0])
        self.assertTrue(params["code_challenge"][0])
        self.assertEqual(params["code_challenge_method"][0], "S256")
        self.assertEqual(params["client_id"][0], "cid")
        self.assertEqual(params["redirect_uri"][0], callback_url("corp-idp"))

    def test_start_refusals(self):
        with self.idp():
            for fields in (
                {"callback_url": "https://evil.example.com/account/provider/callback"},
                {"callback_url": f"{self.callback}/../x"},
                {"process": "connect"},
                {"provider": "unknown"},
                {"provider": ""},
            ):
                r = self.start(**fields)
                self.assertEqual(self.error_of(r), "unknown", fields)
        self.assertNotIn("socialaccount_states", self.browser.session.keys())

        csrf_browser = APIClient(enforce_csrf_checks=True)
        r = csrf_browser.post(
            REDIRECT_URL,
            {"provider": "corp-idp", "process": "login", "callback_url": self.callback},
            HTTP_HOST=self.host,
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.browser.get(REDIRECT_URL).status_code, 405)

    def test_unreachable_idp_is_a_clean_error(self):
        with patch.object(FakeIdP, "get", side_effect=requests.ConnectionError("down")):
            with self.idp():
                r = self.start()
        self.assertEqual(self.error_of(r), "unknown")
        self.assertTrue(
            AuditLog.objects.filter(action=AuditActionType.FAILED_LOGIN).exists()
        )

    def test_sign_up_then_exchange(self):
        r, sync = self.sign_in()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], self.callback)

        user = User.objects.get(username="carol")
        self.assertEqual(user.role, self.role)
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.totp_key)
        self.assertEqual((user.first_name, user.last_name), ("Alice", "Smith"))
        self.assertTrue(
            SocialAccount.objects.filter(
                user=user, provider="corp-idp", uid="s1"
            ).exists()
        )
        sync.delay.assert_called()
        # PKCE verifier and client secret go to the token endpoint
        token_request = self.fake_idp.token_requests[0]
        self.assertTrue(token_request["code_verifier"])
        self.assertEqual(token_request["client_secret"], "very-secret")

        session = self.browser.session
        self.assertEqual(session.get("_auth_user_id"), str(user.pk))
        self.assertEqual(session[SESSION_KEY][-1]["method"], "socialaccount")
        self.assertLessEqual(session.get_expiry_age(), 300)

        r = self.browser.post(TOKEN_URL, {}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["username"], "carol")
        self.assertEqual(r.data["provider"], "corp-idp")

    def test_existing_link_logs_in_the_same_user(self):
        self.sign_in()
        user = User.objects.get(username="carol")
        other_role = baker.make("accounts.Role")
        User.objects.filter(pk=user.pk).update(role=other_role)

        self.browser = APIClient()
        r, _ = self.sign_in()
        self.assertEqual(r["Location"], self.callback)
        self.assertEqual(User.objects.filter(username__startswith="carol").count(), 1)
        self.assertEqual(User.objects.get(pk=user.pk).role, other_role)
        self.assertEqual(self.session_user(), str(user.pk))

    def test_no_email_takeover(self):
        bob = User.objects.create_user(
            username="bob", email="x@y.com", password="hunter2x"
        )
        users = User.objects.count()
        r, _ = self.sign_in({**self.claims, "sub": "s2", "email": "x@y.com"})
        self.assertTrue(self.error_of(r))
        self.assertIsNone(self.session_user())
        self.assertFalse(SocialAccount.objects.filter(user=bob).exists())
        self.assertEqual(User.objects.count(), users)

        # stored addresses keep the case of their local part
        User.objects.create_user(username="dave", email="Dave@Example.com")
        users = User.objects.count()
        self.browser = APIClient()
        r, _ = self.sign_in({**self.claims, "sub": "s3", "email": "dave@example.com"})
        self.assertTrue(self.error_of(r))
        self.assertIsNone(self.session_user())
        self.assertEqual(User.objects.count(), users)

    def test_state_is_bound_to_the_provider(self):
        make_app(name="Other", provider_id="other")
        with self.idp():
            r = self.start()
            state = parse_qs(urlsplit(r["Location"]).query)["state"][0]
            r = self.browser.get(
                "/accounts/oidc/other/login/callback/",
                {"code": "abc", "state": state},
                HTTP_HOST=self.host,
            )
            self.assertEqual(self.error_of(r), "unknown")
            self.assertEqual(self.fake_idp.token_requests, [])
            # the state is spent
            self.assertTrue(self.error_of(self.finish(state)))
        self.assertIsNone(self.session_user())
        self.assertFalse(SocialAccount.objects.exists())
        log = AuditLog.objects.get(action=AuditActionType.FAILED_LOGIN)
        self.assertIn("not started at provider other", log.message)

    def test_blocked_linked_user_cannot_sign_in(self):
        self.sign_in()
        User.objects.filter(username="carol").update(block_dashboard_login=True)
        self.browser = APIClient()
        r, _ = self.sign_in()
        self.assertTrue(self.error_of(r))
        self.assertIsNone(self.session_user())

    def test_disabled_sso_blocks_the_flow(self):
        set_sso(enabled=False)
        with self.idp():
            r = self.start()
        self.assertEqual(self.error_of(r), "unknown")

        # started while enabled, finished after it was turned off
        set_sso(enabled=True)
        with self.idp():
            r = self.start()
            state = parse_qs(urlsplit(r["Location"]).query)["state"][0]
            set_sso(enabled=False)
            r = self.finish(state)
        self.assertEqual(self.error_of(r), "unknown")
        self.assertFalse(User.objects.filter(username="carol").exists())
        self.assertIsNone(self.session_user())
        self.assertTrue(
            AuditLog.objects.filter(action=AuditActionType.FAILED_LOGIN).exists()
        )

    def test_idp_error_is_audited(self):
        with self.idp():
            r = self.start()
            state = parse_qs(urlsplit(r["Location"]).query)["state"][0]
            r = self.finish(state, error="access_denied")
        self.assertTrue(self.error_of(r))
        log = AuditLog.objects.get(action=AuditActionType.FAILED_LOGIN)
        self.assertIn("corp-idp", log.message)

        # a callback nobody started is not audited
        AuditLog.objects.all().delete()
        r = APIClient().get(
            "/accounts/oidc/corp-idp/login/callback/?code=x&state=y",
            HTTP_HOST=self.host,
        )
        self.assertTrue(self.error_of(r))
        self.assertFalse(AuditLog.objects.exists())


class TestDisconnect(SSOTestCase):
    def setUp(self):
        super().setUp()
        self.user = baker.make("accounts.User", username="linked")
        SocialAccount.objects.create(user=self.user, provider="corp-idp", uid="s1")

    def test_disconnect(self):
        r = self.client.delete(
            ACCOUNT_URL, {"provider": "corp-idp", "account": "s1"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(SocialAccount.objects.exists())
        self.assertFalse(User.objects.get(pk=self.user.pk).is_sso_user)
        log = AuditLog.objects.get(object_type=AuditObjType.USER)
        self.assertEqual(log.action, AuditActionType.DELETE)
        self.assertIn("linked", log.message)

    def test_unknown_and_bad_input(self):
        r = self.client.delete(
            ACCOUNT_URL, {"provider": "corp-idp", "account": "nope"}, format="json"
        )
        self.assertEqual(r.status_code, 404)
        r = self.client.delete(ACCOUNT_URL, {"provider": "corp-idp"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_superuser_link_needs_a_superuser(self):
        SocialAccount.objects.create(user=self.alice, provider="corp-idp", uid="s9")
        self.client.force_authenticate(user=self.account_manager())
        r = self.client.delete(
            ACCOUNT_URL, {"provider": "corp-idp", "account": "s9"}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertTrue(SocialAccount.objects.filter(uid="s9").exists())

        r = self.client.delete(
            ACCOUNT_URL, {"provider": "corp-idp", "account": "s1"}, format="json"
        )
        self.assertEqual(r.status_code, 200)


class TestUserListSocialAccounts(SSOTestCase):
    def accounts_of(self, username):
        r = self.client.get("/accounts/users/")
        self.assertEqual(r.status_code, 200)
        return next(u for u in r.data if u["username"] == username)["social_accounts"]

    def test_entries(self):
        make_app()
        linked = baker.make("accounts.User", username="linked")
        SocialAccount.objects.create(
            user=linked,
            provider="corp-idp",
            uid="s1",
            extra_data={"email": "linked@example.com", "groups": ["secret"]},
        )
        orphan = baker.make("accounts.User", username="orphan")
        SocialAccount.objects.create(user=orphan, provider="gone", uid="s2")
        make_app(name="dup 1", provider_id="dup")
        make_app(name="dup 2", provider_id="dup")
        dup = baker.make("accounts.User", username="dup")
        SocialAccount.objects.create(user=dup, provider="dup", uid="s3")

        entries = self.accounts_of("linked")
        self.assertEqual(entries[0]["display"], "linked@example.com")
        self.assertEqual(
            set(entries[0]),
            {"uid", "provider", "display", "last_login", "date_joined"},
        )
        self.assertEqual(self.accounts_of("orphan")[0]["display"], "Orphaned Provider")
        self.assertEqual(self.accounts_of("dup")[0]["display"], "Unknown")
        self.assertEqual(self.accounts_of("john"), [])

        # the label does not depend on SSO being switched on
        set_sso(enabled=False)
        SocialAccount.objects.filter(uid="s1").update(extra_data={})
        self.assertEqual(self.accounts_of("linked")[0]["display"], "corp idp")


class TestURLToggle(SSOTestCase):
    def test_disable_sso_unmounts_the_routes(self):
        import ulrmm.urls

        make_app()
        try:
            with override_settings(ULRMM_DISABLE_SSO=True):
                importlib.reload(ulrmm.urls)
                clear_url_caches()
                for url in (
                    PROVIDERS_URL,
                    CONFIG_URL,
                    "/accounts/oidc/corp-idp/login/callback/",
                ):
                    self.assertEqual(self.client.get(url).status_code, 404, url)
                self.assertEqual(self.client.get("/accounts/users/").status_code, 200)
        finally:
            importlib.reload(ulrmm.urls)
            clear_url_caches()

        self.assertEqual(self.client.get(PROVIDERS_URL).status_code, 200)

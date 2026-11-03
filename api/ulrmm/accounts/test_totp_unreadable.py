# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import importlib
from types import SimpleNamespace

import pyotp
from django.apps import apps
from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from knox.models import AuthToken

from accounts.models import TOTP_KEY_INFO, TOTP_UNREADABLE, User
from accounts.utils import (
    TOTP_UNREADABLE_MSG,
    TOTPUnreadable,
    get_pending_totp_key,
    verify_fresh_totp,
)
from core.models import KEYSTORE_VALUE_INFO, GlobalKVStore
from logs.models import AuditLog
from remote.utils import encrypt_secret
from ulrmm.auth import needs_mfa_enrolment
from ulrmm.constants import AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

LOST = base64.b64encode(b"l" * 32).decode()
KEY = "AB5RI6YPFTZAS52G"


def store_raw(model, field, pk, value):
    table = model._meta.db_table
    column = model._meta.get_field(field).column
    with connection.cursor() as cursor:
        cursor.execute(
            f'UPDATE "{table}" SET "{column}" = %s WHERE id = %s', [value, pk]
        )


def raw(model, field, pk):
    table = model._meta.db_table
    column = model._meta.get_field(field).column
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT "{column}" FROM "{table}" WHERE id = %s', [pk])
        return cursor.fetchone()[0]


def lost_token(value, info):
    # written with a key the server no longer has
    with override_settings(FIELD_ENCRYPTION_KEYS=[LOST]):
        return encrypt_secret(value, info)


@override_settings(CACHES=LOCMEM_CACHE)
class TestUnreadableTOTPKey(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.setup_client()
        self.user = User.objects.create_user(username="lost", password="hunter2x")
        self.token = lost_token(KEY, TOTP_KEY_INFO)
        store_raw(User, "totp_key", self.user.pk, self.token)
        self.user = User.objects.get(pk=self.user.pk)

    def session(self, user=None):
        _, token = AuthToken.objects.create(user=user or self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

    def creds(self, **extra):
        return {"username": "lost", "password": "hunter2x", **extra}

    def assert_refused(self, r):
        self.assertEqual(r.status_code, 400)
        message = r.data if isinstance(r.data, str) else r.data["detail"]
        self.assertEqual(message, TOTP_UNREADABLE_MSG)

    def assert_key_kept(self):
        self.assertEqual(raw(User, "totp_key", self.user.pk), self.token)

    def test_reads_as_sentinel_other_fields_as_empty(self):
        self.assertEqual(self.user.totp_key, TOTP_UNREADABLE)
        kv = GlobalKVStore.objects.create(name="k", value="v")
        store_raw(GlobalKVStore, "value", kv.pk, lost_token("v", KEYSTORE_VALUE_INFO))
        self.assertEqual(GlobalKVStore.objects.get(pk=kv.pk).value, "")

    def test_no_enrolment_offered(self):
        self.assertFalse(needs_mfa_enrolment(self.user))
        self.session()
        self.assertEqual(self.client.get("/core/version/").status_code, 200)
        self.assert_refused(self.client.post("/accounts/users/setup_totp/"))
        self.assertFalse(get_pending_totp_key(self.user))
        self.assert_key_kept()

    def test_check_creds_refused(self):
        r = self.client.post("/v2/checkcreds/", self.creds(), format="json")
        self.assert_refused(r)
        self.assertNotIn("token", r.data)
        self.assertFalse(AuthToken.objects.filter(user=self.user).exists())

    def test_login_refused(self):
        for code in ("", "123456", pyotp.TOTP(KEY).now()):
            r = self.client.post(
                "/v2/login/", self.creds(twofactor=code), format="json"
            )
            self.assert_refused(r)
        self.assertFalse(AuthToken.objects.filter(user=self.user).exists())
        self.assertTrue(
            AuditLog.objects.filter(
                username="lost", action=AuditActionType.FAILED_LOGIN
            ).exists()
        )
        self.assert_key_kept()

    def test_stepup_and_own_resets_refused(self):
        self.session()
        code = {"code": pyotp.TOTP(KEY).now()}
        self.assert_refused(
            self.client.post("/accounts/users/console_stepup/", code, format="json")
        )
        self.assert_refused(self.client.put("/accounts/reset2fa/", code, format="json"))
        self.assert_refused(
            self.client.put(
                "/accounts/users/reset/", {"id": self.user.pk, **code}, format="json"
            )
        )
        self.assert_key_kept()

    def test_changes_to_others_refused(self):
        self.user.is_superuser = True
        self.user.save(update_fields=["is_superuser"])
        other = User.objects.create_user(username="other", password="hunter2x")
        self.session()
        r = self.client.put(
            "/accounts/users/reset/",
            {"id": other.pk, "totp_code": "123456"},
            format="json",
        )
        self.assert_refused(r)

    def test_shared_check_raises(self):
        with self.assertRaises(TOTPUnreadable):
            verify_fresh_totp(self.user, "123456")

    def test_admin_reset_clears_it(self):
        admin = User.objects.create_user(
            username="admin", password="hunter2x", is_superuser=True
        )
        admin.totp_key = pyotp.random_base32()
        admin.save(update_fields=["totp_key"])
        self.session(admin)
        r = self.client.put(
            "/accounts/users/reset/",
            {"id": self.user.pk, "totp_code": pyotp.TOTP(admin.totp_key).now()},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        user = User.objects.get(pk=self.user.pk)
        self.assertEqual(user.totp_key, "")
        self.assertTrue(needs_mfa_enrolment(user))

    def test_reverse_migration_keeps_column_short(self):
        readable = User.objects.create_user(username="ok", password="hunter2x")
        readable.totp_key = KEY
        readable.save(update_fields=["totp_key"])
        migration = importlib.import_module("accounts.migrations.0003_encrypt_totp_key")
        migration.decrypt(apps, SimpleNamespace(connection=connection))
        self.assertEqual(raw(User, "totp_key", self.user.pk), TOTP_UNREADABLE)
        self.assertLessEqual(len(TOTP_UNREADABLE), 50)
        self.assertEqual(raw(User, "totp_key", readable.pk), KEY)
        # read back after the forward migration ran again: still fail-closed
        migration.encrypt(apps, SimpleNamespace(connection=connection))
        self.assertEqual(User.objects.get(pk=self.user.pk).totp_key, TOTP_UNREADABLE)

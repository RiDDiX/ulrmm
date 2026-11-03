# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
from io import StringIO
from unittest.mock import patch

from cryptography.fernet import InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import override_settings
from model_bakery import baker

from accounts.models import TOTP_KEY_INFO, User
from agents.models import UNINSTALL_CODE_INFO, Agent
from core.models import (
    KEYSTORE_VALUE_INFO,
    URLACTION_HEADERS_INFO,
    GlobalKVStore,
    URLAction,
    recrypt_column,
)
from remote.utils import _derive, decrypt_secret, encrypt_secret
from ulrmm.test import ULRMMTestCase

OLD = base64.b64encode(b"o" * 32).decode()
NEW = base64.b64encode(b"n" * 32).decode()


def raw(model, field, pk):
    table = model._meta.db_table
    column = model._meta.get_field(field).column
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT "{column}" FROM "{table}" WHERE id = %s', [pk])
        return cursor.fetchone()[0]


def opens(token, secret, info) -> bool:
    try:
        _derive(secret, info).decrypt(token.encode())
        return True
    except InvalidToken:
        return False


class TestFieldKeys(ULRMMTestCase):
    def test_without_keys_secret_key_as_before(self):
        from django.conf import settings

        token = encrypt_secret("v", b"info")
        self.assertTrue(opens(token, settings.SECRET_KEY.encode(), b"info"))

    def test_first_key_encrypts_all_decrypt(self):
        from django.conf import settings

        legacy = encrypt_secret("legacy", b"info")
        with override_settings(FIELD_ENCRYPTION_KEYS=[OLD]):
            old = encrypt_secret("old", b"info")
        with override_settings(FIELD_ENCRYPTION_KEYS=[NEW, OLD]):
            new = encrypt_secret("new", b"info")
            self.assertTrue(opens(new, b"n" * 32, b"info"))
            self.assertFalse(opens(new, settings.SECRET_KEY.encode(), b"info"))
            self.assertEqual(decrypt_secret(old, b"info"), "old")
            self.assertEqual(decrypt_secret(legacy, b"info"), "legacy")
            with self.assertRaises(InvalidToken):
                decrypt_secret(new, b"other column")
        with override_settings(FIELD_ENCRYPTION_KEYS=[NEW]):
            with self.assertRaises(InvalidToken):
                decrypt_secret(old, b"info")

    def test_bad_keys(self):
        for keys in (["not base64!"], [base64.b64encode(b"x" * 16).decode()]):
            with override_settings(FIELD_ENCRYPTION_KEYS=keys):
                with self.assertRaises(ImproperlyConfigured):
                    encrypt_secret("v", b"info")


class TestEncryptedColumns(ULRMMTestCase):
    def test_stored_encrypted_read_plain(self):
        kv = GlobalKVStore.objects.create(name="token", value="s3cret")
        action = baker.make(
            "core.URLAction", rest_headers='{"Authorization": "x"}', rest_body="b"
        )
        user = User.objects.create_user(username="u", password="p" * 20)
        user.totp_key = "AB5RI6YPFTZAS52G"
        user.save(update_fields=["totp_key"])
        stored = raw(GlobalKVStore, "value", kv.pk)
        self.assertNotIn("s3cret", stored)
        self.assertEqual(decrypt_secret(stored, KEYSTORE_VALUE_INFO), "s3cret")
        self.assertEqual(
            decrypt_secret(
                raw(URLAction, "rest_headers", action.pk), URLACTION_HEADERS_INFO
            ),
            '{"Authorization": "x"}',
        )
        self.assertEqual(
            decrypt_secret(raw(User, "totp_key", user.pk), TOTP_KEY_INFO),
            "AB5RI6YPFTZAS52G",
        )
        self.assertEqual(GlobalKVStore.objects.get(name="token").value, "s3cret")
        self.assertEqual(User.objects.get(pk=user.pk).totp_key, "AB5RI6YPFTZAS52G")
        # script arguments resolve {{global.token}} through this
        from ulrmm.utils import get_db_value

        self.assertEqual(get_db_value(string="global.token"), "s3cret")

    def test_migration_encrypts_plaintext(self):
        kv = GlobalKVStore.objects.create(name="k", value="x")
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{GlobalKVStore._meta.db_table}" SET value = %s WHERE id = %s',
                ["plain value", kv.pk],
            )
        self.assertEqual(GlobalKVStore.objects.get(pk=kv.pk).value, "plain value")
        self.assertEqual(
            recrypt_column(
                connection, GlobalKVStore, "value", KEYSTORE_VALUE_INFO, plain=True
            ),
            (1, 0, 0),
        )
        stored = raw(GlobalKVStore, "value", kv.pk)
        self.assertEqual(decrypt_secret(stored, KEYSTORE_VALUE_INFO), "plain value")


class TestRotateCommand(ULRMMTestCase):
    def test_rotate(self):
        kv = GlobalKVStore.objects.create(name="k", value="kv secret")
        agent = baker.make_recipe(
            "agents.agent", uninstall_code=encrypt_secret("code", UNINSTALL_CODE_INFO)
        )
        # a value no key opens is reported and left alone
        with override_settings(FIELD_ENCRYPTION_KEYS=[OLD]):
            lost = encrypt_secret("lost", b"core.GlobalKVStore.value")
        other = GlobalKVStore.objects.create(name="other", value="y")
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{GlobalKVStore._meta.db_table}" SET value = %s WHERE id = %s',
                [lost, other.pk],
            )
        out = StringIO()
        with override_settings(FIELD_ENCRYPTION_KEYS=[NEW]):
            with self.assertRaisesMessage(CommandError, "core.GlobalKVStore.value (1)"):
                call_command("rotate_field_keys", stdout=out)
            self.assertEqual(GlobalKVStore.objects.get(pk=kv.pk).value, "kv secret")
            code = Agent.objects.get(pk=agent.pk).uninstall_code
            self.assertEqual(decrypt_secret(code, UNINSTALL_CODE_INFO), "code")
        self.assertTrue(
            opens(raw(GlobalKVStore, "value", kv.pk), b"n" * 32, KEYSTORE_VALUE_INFO)
        )
        self.assertTrue(opens(code, b"n" * 32, UNINSTALL_CODE_INFO))
        self.assertEqual(raw(GlobalKVStore, "value", other.pk), lost)
        self.assertIn(
            "core.GlobalKVStore.value: 1 re-encrypted, 1 unreadable", out.getvalue()
        )
        self.assertIn("agents.Agent.uninstall_code: 1 re-encrypted", out.getvalue())
        self.assertIn("accounts.User.totp_key", out.getvalue())
        self.assertIn("vault.Credential.secret", out.getvalue())

    def test_rotate_all_readable(self):
        GlobalKVStore.objects.create(name="k", value="kv secret")
        out = StringIO()
        with override_settings(FIELD_ENCRYPTION_KEYS=[NEW]):
            call_command("rotate_field_keys", stdout=out)
        self.assertIn("core.GlobalKVStore.value: 1 re-encrypted\n", out.getvalue())

    def test_row_changed_meanwhile_keeps_newer_value(self):
        kv = GlobalKVStore.objects.create(name="k", value="old value")
        newer = encrypt_secret("newer value", KEYSTORE_VALUE_INFO)
        from remote import utils

        rotate = utils.rotate_secret

        def write_meanwhile(value, info):
            # a save between the command's read and its write
            with connection.cursor() as cursor:
                cursor.execute(
                    f'UPDATE "{GlobalKVStore._meta.db_table}" SET value = %s '
                    "WHERE id = %s",
                    [newer, kv.pk],
                )
            return rotate(value, info)

        with patch.object(utils, "rotate_secret", side_effect=write_meanwhile):
            result = recrypt_column(
                connection, GlobalKVStore, "value", KEYSTORE_VALUE_INFO, plain=True
            )
        self.assertEqual(result, (0, 0, 1))
        self.assertEqual(raw(GlobalKVStore, "value", kv.pk), newer)
        self.assertEqual(GlobalKVStore.objects.get(pk=kv.pk).value, "newer value")

    def test_help_states_procedure(self):
        from core.management.commands.rotate_field_keys import Command

        for step in ("first in FIELD_ENCRYPTION_KEYS", "restart", "remove"):
            self.assertIn(step, Command.help)

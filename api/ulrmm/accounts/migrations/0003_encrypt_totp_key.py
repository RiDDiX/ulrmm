# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import core.models
from django.db import migrations

import accounts.models


def encrypt(apps, schema_editor):
    core.models.recrypt_column(
        schema_editor.connection,
        apps.get_model("accounts", "User"),
        "totp_key",
        accounts.models.TOTP_KEY_INFO,
        plain=True,
    )


def decrypt(apps, schema_editor):
    # a token no key opens would not fit the varchar(50) column again
    core.models.decrypt_column(
        schema_editor.connection,
        apps.get_model("accounts", "User"),
        "totp_key",
        accounts.models.TOTP_KEY_INFO,
        unreadable=accounts.models.TOTP_UNREADABLE,
    )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_squashed"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="totp_key",
            field=core.models.EncryptedTextField(
                blank=True,
                hkdf_info=accounts.models.TOTP_KEY_INFO,
                null=True,
                unreadable=accounts.models.TOTP_UNREADABLE,
            ),
        ),
        migrations.RunPython(encrypt, decrypt),
    ]

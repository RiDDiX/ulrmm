# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import core.models
from django.db import migrations

COLUMNS = (
    ("GlobalKVStore", "value", core.models.KEYSTORE_VALUE_INFO),
    ("URLAction", "rest_body", core.models.URLACTION_BODY_INFO),
    ("URLAction", "rest_headers", core.models.URLACTION_HEADERS_INFO),
)


def encrypt(apps, schema_editor):
    for model, field, info in COLUMNS:
        core.models.recrypt_column(
            schema_editor.connection,
            apps.get_model("core", model),
            field,
            info,
            plain=True,
        )


def decrypt(apps, schema_editor):
    for model, field, info in COLUMNS:
        core.models.decrypt_column(
            schema_editor.connection, apps.get_model("core", model), field, info
        )


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_coresettings_default_shell_freebsd"),
    ]

    operations = [
        migrations.AlterField(
            model_name="globalkvstore",
            name="value",
            field=core.models.EncryptedTextField(
                hkdf_info=core.models.KEYSTORE_VALUE_INFO
            ),
        ),
        migrations.AlterField(
            model_name="urlaction",
            name="rest_body",
            field=core.models.EncryptedTextField(
                blank=True,
                default="",
                hkdf_info=core.models.URLACTION_BODY_INFO,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="urlaction",
            name="rest_headers",
            field=core.models.EncryptedTextField(
                blank=True,
                default="",
                hkdf_info=core.models.URLACTION_HEADERS_INFO,
                null=True,
            ),
        ),
        migrations.RunPython(encrypt, decrypt),
    ]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import core.models
import importers.models
from django.db import migrations

COLUMNS = (
    ("ImportSource", "snapshot", importers.models.SNAPSHOT_INFO),
    ("ImportedDevice", "data", importers.models.DEVICE_DATA_INFO),
)


def encrypt(apps, schema_editor):
    for model, field, info in COLUMNS:
        core.models.recrypt_column(
            schema_editor.connection,
            apps.get_model("importers", model),
            field,
            info,
            plain=True,
        )


def decrypt(apps, schema_editor):
    # the column turns back into JSON: what no key opens becomes empty
    for model, field, info in COLUMNS:
        core.models.decrypt_column(
            schema_editor.connection,
            apps.get_model("importers", model),
            field,
            info,
            unreadable="{}",
        )


class Migration(migrations.Migration):

    dependencies = [
        ("importers", "0003_old_agent_removal"),
    ]

    operations = [
        migrations.AlterField(
            model_name="importsource",
            name="snapshot",
            field=importers.models.EncryptedJSONField(
                blank=True,
                default=dict,
                hkdf_info=importers.models.SNAPSHOT_INFO,
                unreadable="{}",
            ),
        ),
        migrations.AlterField(
            model_name="importeddevice",
            name="data",
            field=importers.models.EncryptedJSONField(
                blank=True,
                default=dict,
                hkdf_info=importers.models.DEVICE_DATA_INFO,
                unreadable="{}",
            ),
        ),
        migrations.RunPython(encrypt, decrypt),
    ]

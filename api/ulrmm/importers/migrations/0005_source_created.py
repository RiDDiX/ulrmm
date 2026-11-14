# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("importers", "0004_encrypt_snapshot"),
    ]

    operations = [
        migrations.AddField(
            model_name="importsource",
            name="created",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="recovery_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

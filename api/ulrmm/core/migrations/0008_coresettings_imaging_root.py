# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0007_rename_ai_settings"),
    ]

    operations = [
        migrations.AddField(
            model_name="coresettings",
            name="imaging_root",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
        migrations.AddField(
            model_name="coresettings",
            name="imaging_store_id",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="coresettings",
            name="imaging_store_fs",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]

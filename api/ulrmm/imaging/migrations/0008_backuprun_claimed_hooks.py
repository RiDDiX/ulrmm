# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("imaging", "0007_backup_engine_backfill"),
    ]

    operations = [
        migrations.AddField(
            model_name="backuprun",
            name="claimed_hooks",
            field=models.JSONField(blank=True, default=list),
        ),
    ]

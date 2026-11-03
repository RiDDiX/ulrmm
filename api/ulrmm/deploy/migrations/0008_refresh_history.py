# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0007_legacy_credentials"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentcredential",
            name="refresh_history",
            field=models.JSONField(blank=True, default=list),
        ),
    ]

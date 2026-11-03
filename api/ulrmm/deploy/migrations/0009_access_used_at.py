# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0008_refresh_history"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentcredential",
            name="access_used_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

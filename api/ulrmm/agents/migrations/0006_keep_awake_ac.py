# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agents", "0005_power_event"),
    ]

    operations = [
        migrations.AddField(
            model_name="agent",
            name="keep_awake_ac",
            field=models.BooleanField(default=False),
        ),
    ]

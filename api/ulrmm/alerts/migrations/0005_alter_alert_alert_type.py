# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("alerts", "0004_alert_unique_open_check_alert_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="alert",
            name="alert_type",
            field=models.CharField(
                choices=[
                    ("availability", "Availability"),
                    ("check", "Check"),
                    ("task", "Task"),
                    ("custom", "Custom"),
                    ("network", "Network"),
                    ("agent", "Agent"),
                    ("backup", "Backup"),
                ],
                default="availability",
                max_length=20,
            ),
        ),
    ]

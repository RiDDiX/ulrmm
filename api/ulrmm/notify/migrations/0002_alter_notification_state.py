# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("notify", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="notification",
            name="state",
            field=models.CharField(
                choices=[
                    ("queued", "Queued"),
                    ("sending", "Sending"),
                    ("held", "Held for quiet hours"),
                    ("sent", "Sent"),
                    ("failed", "Failed"),
                    ("dropped", "Over the rate limit"),
                ],
                default="queued",
                max_length=10,
            ),
        ),
    ]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("laps", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="lapsstate",
            name="pending_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="lapsstate",
            name="pending_secret",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="lapsstate",
            name="pending_account",
            field=models.CharField(blank=True, default="", max_length=20),
        ),
    ]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agents", "0004_freebsd_platform"),
    ]

    operations = [
        migrations.AddField(
            model_name="agent",
            name="power_event",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="agent",
            name="power_event_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agent",
            name="power_event_by",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]

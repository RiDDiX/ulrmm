# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0012_base_iso"),
    ]

    operations = [
        migrations.AddField(
            model_name="baseiso",
            name="built_by",
            field=models.CharField(blank=True, max_length=150),
        ),
        migrations.AddField(
            model_name="baseiso",
            name="kind",
            field=models.CharField(
                choices=[("base", "Base"), ("built", "Built")],
                default="base",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="baseiso",
            name="target",
            field=models.CharField(blank=True, max_length=32),
        ),
    ]

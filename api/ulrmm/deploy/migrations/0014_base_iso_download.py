# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0013_base_iso_kind"),
    ]

    operations = [
        migrations.AddField(
            model_name="baseiso",
            name="expected_sha256",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AlterField(
            model_name="baseiso",
            name="status",
            field=models.CharField(
                choices=[
                    ("downloading", "Downloading"),
                    ("verifying", "Verifying"),
                    ("inspecting", "Inspecting"),
                    ("ready", "Ready"),
                    ("error", "Error"),
                ],
                default="inspecting",
                max_length=16,
            ),
        ),
    ]

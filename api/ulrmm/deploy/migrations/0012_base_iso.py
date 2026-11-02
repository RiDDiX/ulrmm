# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0011_integrity_events"),
    ]

    operations = [
        migrations.CreateModel(
            name="BaseIso",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=200)),
                ("filename", models.CharField(max_length=255, unique=True)),
                ("size", models.BigIntegerField(default=0)),
                ("sha256", models.CharField(blank=True, max_length=64)),
                ("label", models.CharField(blank=True, max_length=32)),
                ("os", models.CharField(blank=True, max_length=16)),
                ("bios", models.BooleanField(default=False)),
                ("efi", models.BooleanField(default=False)),
                ("udf", models.BooleanField(default=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("downloading", "Downloading"),
                            ("inspecting", "Inspecting"),
                            ("ready", "Ready"),
                            ("error", "Error"),
                        ],
                        default="inspecting",
                        max_length=16,
                    ),
                ),
                ("error", models.CharField(blank=True, max_length=500)),
                ("source_url", models.URLField(blank=True)),
                ("added", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]

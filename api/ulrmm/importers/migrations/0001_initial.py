# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import core.models
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("agents", "0005_power_event"),
        ("clients", "0004_deployment_max_enrollments"),
    ]

    operations = [
        migrations.CreateModel(
            name="ImportSource",
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
                ("created_by", models.CharField(blank=True, max_length=255, null=True)),
                ("created_time", models.DateTimeField(auto_now_add=True, null=True)),
                (
                    "modified_by",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("modified_time", models.DateTimeField(auto_now=True, null=True)),
                (
                    "kind",
                    models.CharField(
                        choices=[
                            ("upstream", "Upstream RMM server"),
                            ("ninjaone", "NinjaOne"),
                        ],
                        max_length=20,
                    ),
                ),
                ("name", models.CharField(max_length=100)),
                ("url", models.CharField(max_length=255)),
                ("verify_tls", models.BooleanField(default=True)),
                ("options", models.JSONField(blank=True, default=dict)),
                (
                    "secret",
                    core.models.EncryptedTextField(
                        blank=True,
                        default="",
                        hkdf_info=b"importers.ImportSource.secret",
                    ),
                ),
                ("snapshot", models.JSONField(blank=True, default=dict)),
                ("last_fetch", models.DateTimeField(blank=True, null=True)),
                ("last_import", models.DateTimeField(blank=True, null=True)),
                (
                    "last_error",
                    models.CharField(blank=True, default="", max_length=500),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="ImportedDevice",
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
                ("ref", models.CharField(max_length=255)),
                ("hostname", models.CharField(max_length=255)),
                ("serial", models.CharField(blank=True, default="", max_length=255)),
                ("plat", models.CharField(blank=True, default="", max_length=20)),
                ("goarch", models.CharField(blank=True, default="", max_length=20)),
                (
                    "monitoring_type",
                    models.CharField(blank=True, default="", max_length=20),
                ),
                ("os_name", models.CharField(blank=True, default="", max_length=255)),
                ("data", models.JSONField(blank=True, default=dict)),
                (
                    "migrate_state",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("", "Not sent"),
                            ("sent", "Installer sent"),
                            ("failed", "Sending failed"),
                            ("linked", "Linked to an agent"),
                        ],
                        default="",
                        max_length=20,
                    ),
                ),
                (
                    "migrate_error",
                    models.CharField(blank=True, default="", max_length=500),
                ),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
                (
                    "agent",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="agents.agent",
                    ),
                ),
                (
                    "site",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="clients.site",
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="devices",
                        to="importers.importsource",
                    ),
                ),
            ],
            options={
                "unique_together": {("source", "ref")},
            },
        ),
    ]

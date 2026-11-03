# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("agents", "0004_freebsd_platform"),
        ("deploy", "0005_sec2_identity_keys"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentCredential",
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
                (
                    "kind",
                    models.CharField(
                        choices=[
                            ("legacy", "Legacy token"),
                            ("family", "Token family"),
                        ],
                        max_length=10,
                    ),
                ),
                ("access_digest", models.CharField(max_length=64, unique=True)),
                ("access_expires", models.DateTimeField(blank=True, null=True)),
                (
                    "refresh_digest",
                    models.CharField(blank=True, max_length=64, null=True, unique=True),
                ),
                ("refresh_expires", models.DateTimeField(blank=True, null=True)),
                ("family", models.UUIDField(blank=True, null=True)),
                ("generation", models.PositiveIntegerField(default=0)),
                (
                    "prev_refresh_digest",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("prev_rotated_at", models.DateTimeField(blank=True, null=True)),
                ("rotated_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("legacy_nats", models.TextField(blank=True, default="")),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "agent",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="credential",
                        to="agents.agent",
                    ),
                ),
            ],
        ),
    ]

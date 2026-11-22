# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("agents", "0006_keep_awake_ac"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Image",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("waiting", "Waiting"),
                            ("uploading", "Uploading"),
                            ("verifying", "Verifying"),
                            ("verified", "Verified"),
                            ("failed", "Failed"),
                        ],
                        default="waiting",
                        max_length=9,
                    ),
                ),
                (
                    "reason",
                    models.CharField(
                        blank=True,
                        default="Boot the device into offline recovery and issue capture access.",
                        max_length=255,
                    ),
                ),
                ("destination", models.CharField(max_length=64)),
                ("network_mode", models.CharField(max_length=8)),
                ("compression", models.CharField(max_length=4)),
                ("compression_level", models.PositiveSmallIntegerField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("verified_at", models.DateTimeField(null=True)),
                ("offset", models.PositiveBigIntegerField(default=0)),
                ("size", models.PositiveBigIntegerField(null=True)),
                ("raw_size", models.PositiveBigIntegerField(null=True)),
                ("sector_size", models.PositiveIntegerField(null=True)),
                ("device_uuid", models.UUIDField(null=True)),
                ("disk_id", models.CharField(blank=True, max_length=255)),
                ("architecture", models.CharField(blank=True, max_length=20)),
                ("boot_mode", models.CharField(blank=True, max_length=4)),
                ("sha256", models.CharField(blank=True, max_length=64)),
                ("raw_sha256", models.CharField(blank=True, max_length=64)),
                (
                    "agent",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="agents.agent",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Pairing",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("network_mode", models.CharField(max_length=8)),
                ("device_uuid", models.UUIDField()),
                ("disk_id", models.CharField(max_length=255)),
                ("token_digest", models.CharField(max_length=64)),
                ("expires_at", models.DateTimeField()),
                (
                    "agent",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE, to="agents.agent"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Transfer",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "direction",
                    models.CharField(
                        choices=[("capture", "Capture"), ("restore", "Restore")],
                        max_length=7,
                    ),
                ),
                ("device_uuid", models.UUIDField(null=True)),
                ("disk_id", models.CharField(blank=True, max_length=255)),
                ("token_digest", models.CharField(max_length=64)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("completed_at", models.DateTimeField(null=True)),
                (
                    "image",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="imaging.image"
                    ),
                ),
                (
                    "pairing",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="imaging.pairing",
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="agents.agent",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Profile",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("destination", models.CharField(default="images", max_length=64)),
                ("network_mode", models.CharField(default="internal", max_length=8)),
                ("compression", models.CharField(default="gzip", max_length=4)),
                ("compression_level", models.PositiveSmallIntegerField(default=6)),
                ("schedule_time", models.TimeField(blank=True, null=True)),
                ("timezone", models.CharField(default="UTC", max_length=64)),
                ("next_run", models.DateTimeField(db_index=True, null=True)),
                (
                    "agent",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE, to="agents.agent"
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="image",
            constraint=models.UniqueConstraint(
                condition=models.Q(
                    ("status__in", ("waiting", "uploading", "verifying"))
                ),
                fields=("agent",),
                name="imaging_one_active_capture",
            ),
        ),
    ]

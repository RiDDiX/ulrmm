# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import core.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0005_encrypt_keystore_urlactions"),
    ]

    operations = [
        migrations.CreateModel(
            name="ReleaseRepo",
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
                ("name", models.CharField(max_length=32, unique=True)),
                ("repo_url", models.CharField(max_length=255)),
                (
                    "token",
                    core.models.EncryptedTextField(
                        blank=True, default="", hkdf_info=b"core.ReleaseRepo.token"
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("position", models.PositiveSmallIntegerField(default=0)),
            ],
            options={
                "ordering": ("position", "id"),
            },
        ),
    ]

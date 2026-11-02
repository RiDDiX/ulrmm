# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import django.core.validators
from django.db import migrations, models


def create_row(apps, schema_editor):
    Branding = apps.get_model("branding", "Branding")
    if not Branding.objects.exists():
        Branding.objects.create(pk=1)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Branding",
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
                (
                    "product_name",
                    models.CharField(default="UniversalLocal RMM", max_length=255),
                ),
                (
                    "company_name",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                (
                    "support_url",
                    models.CharField(
                        blank=True,
                        max_length=500,
                        null=True,
                        validators=[
                            django.core.validators.URLValidator(("http", "https"))
                        ],
                    ),
                ),
                ("logo", models.TextField(blank=True, null=True)),
                ("favicon", models.TextField(blank=True, null=True)),
                ("hide_upstream_links", models.BooleanField(default=False)),
            ],
            options={"verbose_name_plural": "branding"},
        ),
        migrations.RunPython(create_row, noop),
    ]

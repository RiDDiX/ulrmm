# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agents", "0003_squashed"),
        ("software", "0002_installedsoftware_unique_installed_software_agent"),
    ]

    operations = [
        migrations.CreateModel(
            name="InstalledDrivers",
            fields=[
                (
                    "agent",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="driver_inventory",
                        serialize=False,
                        to="agents.agent",
                    ),
                ),
                ("received", models.DateTimeField()),
                ("data", models.JSONField(default=dict)),
            ],
        ),
    ]

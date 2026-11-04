# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("clients", "0004_deployment_max_enrollments"),
        ("deploy", "0015_update_reverted"),
    ]

    operations = [
        migrations.AddField(
            model_name="baseiso",
            name="deployment",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="clients.deployment",
            ),
        ),
    ]

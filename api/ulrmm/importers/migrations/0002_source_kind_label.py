# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("importers", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="importsource",
            name="kind",
            field=models.CharField(
                choices=[
                    ("upstream", "Compatible RMM server"),
                    ("ninjaone", "NinjaOne"),
                ],
                max_length=20,
            ),
        ),
    ]

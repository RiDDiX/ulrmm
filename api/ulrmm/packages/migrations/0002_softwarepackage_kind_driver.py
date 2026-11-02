# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("packages", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="softwarepackage",
            name="kind",
            field=models.CharField(
                choices=[
                    ("exe", "EXE"),
                    ("msi", "MSI"),
                    ("msix", "MSIX"),
                    ("appx", "AppX"),
                    ("pkg", "macOS pkg"),
                    ("deb", "deb"),
                    ("rpm", "rpm"),
                    ("driver", "Driver package"),
                ],
                max_length=8,
            ),
        ),
    ]

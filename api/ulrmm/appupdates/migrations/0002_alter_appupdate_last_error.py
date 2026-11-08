# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("appupdates", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="appupdate",
            name="last_error",
            field=models.CharField(blank=True, default="", max_length=1500),
        ),
    ]

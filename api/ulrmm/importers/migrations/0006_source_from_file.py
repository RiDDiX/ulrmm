# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("importers", "0005_source_created"),
    ]

    operations = [
        migrations.AddField(
            model_name="importsource",
            name="from_file",
            field=models.BooleanField(default=False),
        ),
    ]

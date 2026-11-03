# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models

DRIVERS_CATEGORY = "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0"


def flag_drivers(apps, schema_editor):
    WinUpdate = apps.get_model("winupdate", "WinUpdate")
    WinUpdate.objects.filter(category_ids__contains=[DRIVERS_CATEGORY]).update(
        is_driver=True
    )


class Migration(migrations.Migration):

    dependencies = [
        ("winupdate", "0001_squashed"),
    ]

    operations = [
        migrations.AddField(
            model_name="winupdate",
            name="is_driver",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="winupdatepolicy",
            name="drivers",
            field=models.CharField(
                choices=[
                    ("include", "Include"),
                    ("exclude", "Exclude"),
                    ("inherit", "Inherit"),
                ],
                default="inherit",
                max_length=16,
            ),
        ),
        migrations.RunPython(flag_drivers, migrations.RunPython.noop),
    ]

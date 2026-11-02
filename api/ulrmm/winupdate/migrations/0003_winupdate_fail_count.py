# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


def count_failed(apps, schema_editor):
    WinUpdate = apps.get_model("winupdate", "WinUpdate")
    WinUpdate.objects.filter(result="failed", installed=False).update(fail_count=1)


class Migration(migrations.Migration):

    dependencies = [
        ("winupdate", "0002_winupdate_is_driver_policy_drivers"),
    ]

    operations = [
        migrations.AddField(
            model_name="winupdate",
            name="fail_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.RunPython(count_failed, migrations.RunPython.noop),
    ]

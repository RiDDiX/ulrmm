# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("importers", "0002_source_kind_label"),
    ]

    operations = [
        migrations.AddField(
            model_name="importeddevice",
            name="remove_requested_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="remove_state",
            field=models.CharField(
                blank=True,
                choices=[
                    ("", "Not requested"),
                    ("waiting_here", "Waiting for the device here"),
                    ("waiting_there", "Waiting for the device over there"),
                    ("sending", "Removal being sent"),
                    ("removed", "Old agent removed"),
                    ("not_removed", "Old agent not removed"),
                ],
                default="",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="remove_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="remove_reason",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="remove_tried_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="importeddevice",
            name="recovery",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
    ]

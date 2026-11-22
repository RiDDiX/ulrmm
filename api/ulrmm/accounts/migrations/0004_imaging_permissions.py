# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_encrypt_totp_key"),
    ]

    operations = [
        migrations.AddField(
            model_name="role",
            name="can_manage_images",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="role",
            name="can_restore_images",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="role",
            name="can_view_images",
            field=models.BooleanField(default=False),
        ),
    ]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_releaserepo"),
    ]

    operations = [
        migrations.RenameField(
            model_name="coresettings",
            old_name="open_ai_token",
            new_name="ai_api_key",
        ),
        migrations.RenameField(
            model_name="coresettings",
            old_name="open_ai_model",
            new_name="ai_model",
        ),
    ]

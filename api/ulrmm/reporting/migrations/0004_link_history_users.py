# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations
from django.db.models import OuterRef, Subquery


def link_history_users(apps, schema_editor):
    ReportHistory = apps.get_model("reporting", "ReportHistory")
    User = apps.get_model("accounts", "User")
    # rows from before 0003 only carry the username as text
    ReportHistory.objects.filter(user__isnull=True).exclude(run_by="system").update(
        user=Subquery(
            User.objects.filter(username=OuterRef("run_by")).values("pk")[:1]
        )
    )


class Migration(migrations.Migration):
    dependencies = [
        ("reporting", "0003_reporthistory_user_schedule"),
    ]

    operations = [
        migrations.RunPython(
            link_history_users, reverse_code=migrations.RunPython.noop
        ),
    ]

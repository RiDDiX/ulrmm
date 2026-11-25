# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("agents", "0006_keep_awake_ac"),
        ("clients", "0004_deployment_max_enrollments"),
        ("groups", "0001_initial"),
        ("imaging", "0005_profile_volumes"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="BackupRun",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, primary_key=True, serialize=False
                    ),
                ),
                (
                    "trigger",
                    models.CharField(
                        choices=[
                            ("schedule", "Schedule"),
                            ("manual", "Manual"),
                            ("event", "Event"),
                        ],
                        max_length=8,
                    ),
                ),
                ("policy_version", models.PositiveIntegerField(null=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("deferred", "Deferred"),
                            ("running", "Running"),
                            ("paused", "Paused"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                            ("interrupted", "Interrupted"),
                        ],
                        default="deferred",
                        max_length=11,
                    ),
                ),
                (
                    "step",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("", "None"),
                            ("snapshot", "Snapshot"),
                            ("scan", "Scan"),
                            ("transfer", "Transfer"),
                            ("verify", "Verify"),
                            ("cleanup", "Cleanup"),
                        ],
                        default="",
                        max_length=8,
                    ),
                ),
                ("deferred_reason", models.CharField(blank=True, max_length=32)),
                ("reason", models.CharField(blank=True, max_length=255)),
                (
                    "pause_reason",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("", "None"),
                            ("network", "Network"),
                            ("battery", "Battery"),
                        ],
                        default="",
                        max_length=8,
                    ),
                ),
                ("pause_max_minutes", models.PositiveSmallIntegerField(default=30)),
                ("agent_protocol", models.PositiveSmallIntegerField(default=0)),
                ("counters", models.JSONField(default=dict)),
                ("log", models.JSONField(default=list)),
                ("log_start", models.PositiveIntegerField(default=0)),
                ("warnings", models.JSONField(default=list)),
                ("hooks", models.JSONField(default=list)),
                ("cancel_requested", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("started_at", models.DateTimeField(null=True)),
                ("ended_at", models.DateTimeField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name="DeviceBackupState",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("protocol", models.PositiveSmallIntegerField(default=0)),
                ("config_version", models.PositiveIntegerField(default=0)),
                ("config_hash", models.CharField(blank=True, max_length=64)),
                ("config_doc", models.TextField(blank=True)),
                ("effective_hash", models.CharField(blank=True, max_length=64)),
                ("memberships", models.JSONField(default=dict)),
                ("pending_since", models.DateTimeField(null=True)),
                ("acked_version", models.PositiveIntegerField(default=0)),
                ("acked_hash", models.CharField(blank=True, max_length=64)),
                ("acked_at", models.DateTimeField(null=True)),
                (
                    "ack_status",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("", "None"),
                            ("applied", "Applied"),
                            ("error", "Error"),
                        ],
                        default="",
                        max_length=7,
                    ),
                ),
                ("ack_errors", models.JSONField(default=list)),
                ("checks", models.JSONField(default=list)),
                ("checks_at", models.DateTimeField(null=True)),
                ("capabilities", models.JSONField(default=list)),
                ("conditions", models.JSONField(default=dict)),
                ("sealed", models.BooleanField(default=False)),
                ("ready", models.BooleanField(default=False)),
                ("not_ready_reason", models.CharField(blank=True, max_length=255)),
                ("last_poll_at", models.DateTimeField(null=True)),
                ("last_success_at", models.DateTimeField(null=True)),
                ("schedule_since", models.DateTimeField(null=True)),
                ("consecutive_failures", models.PositiveIntegerField(default=0)),
                ("consecutive_interruptions", models.PositiveIntegerField(default=0)),
                ("usage", models.JSONField(default=dict)),
                ("alerts", models.JSONField(default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="PolicyChangeHold",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "cause",
                    models.CharField(
                        choices=[
                            ("group_rule", "Group Rule"),
                            ("group_member", "Group Member"),
                            ("tag", "Tag"),
                            ("site_move", "Site Move"),
                            ("unknown", "Unknown"),
                        ],
                        max_length=12,
                    ),
                ),
                ("held_hash", models.CharField(max_length=64)),
                ("proposed_hash", models.CharField(max_length=64)),
                ("proposed_memberships", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("confirmed_at", models.DateTimeField(null=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("confirmed", "Confirmed"),
                            ("rejected", "Rejected"),
                        ],
                        default="pending",
                        max_length=9,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="StorageTarget",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=64, unique=True)),
                (
                    "kind",
                    models.CharField(
                        choices=[("server", "Server")], default="server", max_length=8
                    ),
                ),
                (
                    "scope",
                    models.CharField(
                        choices=[
                            ("global", "Global"),
                            ("client", "Client"),
                            ("site", "Site"),
                        ],
                        default="global",
                        max_length=6,
                    ),
                ),
                ("params", models.JSONField(blank=True, default=dict)),
                ("quota_bytes", models.PositiveBigIntegerField(default=0)),
                ("max_runs", models.PositiveSmallIntegerField(default=5)),
                ("is_default", models.BooleanField(default=False)),
                ("used_bytes", models.PositiveBigIntegerField(default=0)),
                ("unreachable_since", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="client",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="clients.client",
            ),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="created_at",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="enforced",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="group",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="groups.devicegroup",
            ),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="hooks_approved_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="hooks_approved_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="hooks_pinned",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="priority",
            field=models.SmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="scope",
            field=models.CharField(
                choices=[
                    ("global", "Global"),
                    ("client", "Client"),
                    ("site", "Site"),
                    ("group", "Group"),
                    ("tag", "Tag"),
                    ("assigned", "Assigned"),
                ],
                default="assigned",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="site",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="clients.site",
            ),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="tag",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="groups.tag",
            ),
        ),
        migrations.AddField(
            model_name="image",
            name="client",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to="clients.client",
            ),
        ),
        migrations.AddField(
            model_name="image",
            name="protected",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="image",
            name="snapshot_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name="image",
            name="trigger",
            field=models.CharField(
                choices=[
                    ("schedule", "Schedule"),
                    ("manual", "Manual"),
                    ("event", "Event"),
                ],
                default="manual",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="profile",
            name="effective",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="profile",
            name="hooks_approved_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name="profile",
            name="hooks_approved_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="profile",
            name="hooks_pinned",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="profile",
            name="overrides",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="transfer",
            name="authority",
            field=models.CharField(
                choices=[("user", "User"), ("policy", "Policy")],
                default="user",
                max_length=7,
            ),
        ),
        migrations.AddField(
            model_name="transfer",
            name="config_version",
            field=models.PositiveIntegerField(null=True),
        ),
        migrations.AddField(
            model_name="transfer",
            name="policy",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="imaging.backuppolicy",
            ),
        ),
        migrations.AlterField(
            model_name="transfer",
            name="user",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddConstraint(
            model_name="backuppolicy",
            constraint=models.UniqueConstraint(
                condition=models.Q(("scope", "global")),
                fields=("scope",),
                name="imaging_one_global_policy",
            ),
        ),
        migrations.AddConstraint(
            model_name="backuppolicy",
            constraint=models.UniqueConstraint(
                condition=models.Q(("scope", "client")),
                fields=("client",),
                name="imaging_one_client_policy",
            ),
        ),
        migrations.AddConstraint(
            model_name="backuppolicy",
            constraint=models.UniqueConstraint(
                condition=models.Q(("scope", "site")),
                fields=("site",),
                name="imaging_one_site_policy",
            ),
        ),
        migrations.AddConstraint(
            model_name="backuppolicy",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("client", None),
                        ("group", None),
                        ("scope__in", ("global", "assigned")),
                        ("site", None),
                        ("tag", None),
                    ),
                    models.Q(
                        ("client__isnull", False),
                        ("group", None),
                        ("scope", "client"),
                        ("site", None),
                        ("tag", None),
                    ),
                    models.Q(
                        ("client", None),
                        ("group", None),
                        ("scope", "site"),
                        ("site__isnull", False),
                        ("tag", None),
                    ),
                    models.Q(
                        ("client", None),
                        ("group__isnull", False),
                        ("scope", "group"),
                        ("site", None),
                        ("tag", None),
                    ),
                    models.Q(
                        ("client", None),
                        ("group", None),
                        ("scope", "tag"),
                        ("site", None),
                        ("tag__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="imaging_policy_scope_keys",
            ),
        ),
        migrations.AddField(
            model_name="backuprun",
            name="cancelled_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="backuprun",
            name="image",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="runs",
                to="imaging.image",
            ),
        ),
        migrations.AddField(
            model_name="backuprun",
            name="policy",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="imaging.backuppolicy",
            ),
        ),
        migrations.AddField(
            model_name="transfer",
            name="run",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="imaging.backuprun",
            ),
        ),
        migrations.AddField(
            model_name="devicebackupstate",
            name="agent",
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="backup_state",
                to="agents.agent",
            ),
        ),
        migrations.AddField(
            model_name="policychangehold",
            name="agent",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="agents.agent"
            ),
        ),
        migrations.AddField(
            model_name="policychangehold",
            name="author",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="policychangehold",
            name="confirmed_by",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="storagetarget",
            name="client",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="clients.client",
            ),
        ),
        migrations.AddField(
            model_name="storagetarget",
            name="site",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="clients.site",
            ),
        ),
        migrations.AddField(
            model_name="image",
            name="target",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="imaging.storagetarget",
            ),
        ),
        migrations.AddField(
            model_name="profile",
            name="target",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="imaging.storagetarget",
            ),
        ),
        migrations.AddIndex(
            model_name="backuprun",
            index=models.Index(
                fields=["status", "updated_at"], name="imaging_run_status"
            ),
        ),
        migrations.AddConstraint(
            model_name="policychangehold",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status", "pending")),
                fields=("agent",),
                name="imaging_one_pending_hold",
            ),
        ),
        migrations.AddConstraint(
            model_name="storagetarget",
            constraint=models.UniqueConstraint(
                condition=models.Q(("is_default", True)),
                fields=("is_default",),
                name="imaging_one_default_target",
            ),
        ),
        migrations.AddConstraint(
            model_name="storagetarget",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("client", None), ("scope", "global"), ("site", None)),
                    models.Q(
                        ("client__isnull", False), ("scope", "client"), ("site", None)
                    ),
                    models.Q(
                        ("client", None), ("scope", "site"), ("site__isnull", False)
                    ),
                    _connector="OR",
                ),
                name="imaging_target_scope_keys",
            ),
        ),
    ]

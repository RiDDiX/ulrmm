# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("deploy", "0016_baseiso_deployment"),
    ]

    operations = [
        migrations.AlterField(
            model_name="securityevent",
            name="kind",
            field=models.CharField(
                choices=[
                    ("cert_refused", "Client certificate refused"),
                    ("nats_refused", "NATS connection refused"),
                    ("pin_mismatch", "Server certificate pin mismatch"),
                    ("pin_rescue", "Pin set fetched after a mismatch"),
                    ("insecure_dropped", "Insecure agent setting removed"),
                    ("update_refused", "Agent update refused"),
                    ("tls_failure", "TLS connection failed"),
                    ("backup_unencrypted", "Backup written unencrypted"),
                    ("token_expired_max", "Session past its maximum lifetime"),
                    ("enroll_limit", "Deployment enrollment limit reached"),
                    ("identity_registered", "Agent identity registered"),
                    ("identity_rotated", "Agent identity rotated"),
                    ("identity_conflict", "Agent identity conflict"),
                    ("identity_unreadable", "Agent identity unreadable"),
                    ("unsigned_command", "Unsigned command refused"),
                    ("envelope_refused", "Command envelope refused"),
                    ("clock_skew", "Agent clock skew"),
                    ("e2e_refused", "Encrypted session refused"),
                    ("token_reuse", "Refresh token reused"),
                    ("quarantined", "Agent quarantined"),
                    ("released", "Agent released"),
                    ("rotation_forced", "Rotation requested"),
                    ("grace_recovery", "Offline recovery"),
                    ("command_key_rotated", "Command key rotated"),
                    ("integrity_mismatch", "Agent binary does not match the build"),
                    ("config_tampered", "Agent config changed outside the agent"),
                    ("update_reverted", "Agent update reverted"),
                    ("backup_failed", "Scheduled backup failed"),
                ],
                max_length=32,
            ),
        ),
    ]

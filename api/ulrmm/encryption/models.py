# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models
from django.utils import timezone as djangotime


class KeyKind(models.TextChoices):
    BITLOCKER = "bitlocker", "BitLocker"
    FILEVAULT = "filevault", "FileVault"


class KeyStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    # no longer reported by the endpoint, kept for old backups and images
    STALE = "stale", "Stale"


class RecoveryKey(models.Model):
    agent = models.ForeignKey(
        "agents.Agent", on_delete=models.CASCADE, related_name="recovery_keys"
    )
    kind = models.CharField(max_length=16, choices=KeyKind.choices)
    # drive letter or volume path; "/" for FileVault
    volume = models.CharField(max_length=64)
    # BitLocker key protector id; empty for FileVault
    protector_id = models.CharField(max_length=64, blank=True, default="")
    # Fernet token from encryption.utils.seal
    key = models.TextField()
    collected_at = models.DateTimeField(default=djangotime.now)
    status = models.CharField(
        max_length=16, choices=KeyStatus.choices, default=KeyStatus.ACTIVE
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent", "kind", "volume", "protector_id"],
                name="unique_recovery_key",
            )
        ]


class EncryptionState(models.Model):
    """Volumes from the last complete collection. Recovery keys are separate."""

    agent = models.OneToOneField(
        "agents.Agent", on_delete=models.CASCADE, related_name="encryption_state"
    )
    # [{"volume", "kind", "protection" on|off|unknown, "percent"}]
    volumes = models.JSONField(default=list)
    collected_at = models.DateTimeField(null=True, blank=True)
    # last failed collection; volumes keep the last complete one
    error = models.TextField(blank=True, default="")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone as django_timezone


class ImageStatus(models.TextChoices):
    WAITING = "waiting"
    UPLOADING = "uploading"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"


ACTIVE_STATUSES = (ImageStatus.WAITING, ImageStatus.UPLOADING, ImageStatus.VERIFYING)
RECEIVING_REASON = "Receiving disk image."
NATIVE_RECEIVING_REASON = "Receiving native backup blocks."
MODE_CHANGED = (
    "The network mode changed after this capture was queued. Request a new capture."
)
WAITING_REASON = "Boot the device into offline recovery and issue capture access."


class Profile(models.Model):
    policy = models.ForeignKey("BackupPolicy", null=True, on_delete=models.PROTECT)
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    agent = models.OneToOneField("agents.Agent", on_delete=models.CASCADE)
    destination = models.CharField(max_length=64, default="images")
    network_mode = models.CharField(max_length=8, default="internal")
    compression = models.CharField(max_length=4, default="gzip")
    compression_level = models.PositiveSmallIntegerField(default=6)
    schedule_time = models.TimeField(null=True, blank=True)
    timezone = models.CharField(max_length=64, default="UTC")
    next_run = models.DateTimeField(null=True, db_index=True)
    keep_last = models.PositiveSmallIntegerField(default=0)


class Image(models.Model):
    native = models.JSONField(null=True)
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    new_bytes = models.PositiveBigIntegerField(default=0)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey("agents.Agent", null=True, on_delete=models.SET_NULL)
    status = models.CharField(
        max_length=9, choices=ImageStatus.choices, default=ImageStatus.WAITING
    )
    reason = models.CharField(max_length=255, default=WAITING_REASON, blank=True)
    destination = models.CharField(max_length=64)
    network_mode = models.CharField(max_length=8)
    compression = models.CharField(max_length=4)
    compression_level = models.PositiveSmallIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(null=True)
    offset = models.PositiveBigIntegerField(default=0)
    size = models.PositiveBigIntegerField(null=True)
    raw_size = models.PositiveBigIntegerField(null=True)
    sector_size = models.PositiveIntegerField(null=True)
    device_uuid = models.UUIDField(null=True)
    disk_id = models.CharField(max_length=255, blank=True)
    architecture = models.CharField(max_length=20, blank=True)
    boot_mode = models.CharField(max_length=4, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    raw_sha256 = models.CharField(max_length=64, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent"],
                condition=Q(status__in=ACTIVE_STATUSES),
                name="imaging_one_active_capture",
            )
        ]


class Pairing(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.OneToOneField("agents.Agent", on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    network_mode = models.CharField(max_length=8)
    device_uuid = models.UUIDField()
    disk_id = models.CharField(max_length=255)
    token_digest = models.CharField(max_length=64)
    expires_at = models.DateTimeField()


class Transfer(models.Model):
    class Direction(models.TextChoices):
        CAPTURE = "capture"
        RESTORE = "restore"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    image = models.ForeignKey(Image, on_delete=models.CASCADE)
    pairing = models.ForeignKey(Pairing, on_delete=models.CASCADE, null=True)
    direction = models.CharField(max_length=7, choices=Direction.choices)
    target = models.ForeignKey("agents.Agent", null=True, on_delete=models.CASCADE)
    device_uuid = models.UUIDField(null=True)
    disk_id = models.CharField(max_length=255, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token_digest = models.CharField(max_length=64)
    expires_at = models.DateTimeField(db_index=True)
    renew_until = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)


class NativeInventory(models.Model):
    agent = models.OneToOneField("agents.Agent", on_delete=models.CASCADE)
    capability = models.JSONField()
    observed_at = models.DateTimeField(auto_now=True)


class BackupPolicy(models.Model):
    name = models.CharField(max_length=100)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    config = models.JSONField()


class ImageBlock(models.Model):
    created_at = models.DateTimeField(default=django_timezone.now)
    network_mode = models.CharField(max_length=8, default="internal")
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    namespace = models.CharField(max_length=64)
    destination = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    size = models.PositiveIntegerField()
    stored_size = models.PositiveIntegerField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["namespace", "digest"], name="imaging_block_digest"
            )
        ]


class ImagePart(models.Model):
    id = models.BigAutoField(primary_key=True)
    image = models.ForeignKey(Image, related_name="parts", on_delete=models.CASCADE)
    index = models.PositiveIntegerField()
    block = models.ForeignKey(ImageBlock, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["image", "index"], name="imaging_part_index"
            )
        ]

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
WINDOWS_METHOD = "windows-wbadmin-tar-v1"
LINUX_OFFLINE_METHOD = "linux-offline-disk-v1"
LINUX_FILES_METHOD = "linux-files-v1"
MACOS_METHOD = "macos-timemachine-disk-v1"
METHODS = {
    "windows": {WINDOWS_METHOD},
    "linux": {LINUX_OFFLINE_METHOD, LINUX_FILES_METHOD},
    "darwin": {MACOS_METHOD},
}
# wbadmin and the files method: stream length is not the disk size
STREAM_METHODS = {WINDOWS_METHOD, LINUX_FILES_METHOD}
VOLUME_KINDS = ("system", "extra", "network", "unsupported", "unmounted")
SELECTABLE_KINDS = ("extra", "unmounted")


class TargetKind(models.TextChoices):
    SERVER = "server"


class TargetScope(models.TextChoices):
    GLOBAL = "global"
    CLIENT = "client"
    SITE = "site"


class PolicyScope(models.TextChoices):
    GLOBAL = "global"
    CLIENT = "client"
    SITE = "site"
    GROUP = "group"
    TAG = "tag"
    ASSIGNED = "assigned"


class Trigger(models.TextChoices):
    SCHEDULE = "schedule"
    MANUAL = "manual"
    EVENT = "event"


class Authority(models.TextChoices):
    USER = "user"
    POLICY = "policy"


class AckStatus(models.TextChoices):
    NONE = ""
    APPLIED = "applied"
    ERROR = "error"


class HoldCause(models.TextChoices):
    GROUP_RULE = "group_rule"
    GROUP_MEMBER = "group_member"
    TAG = "tag"
    SITE_MOVE = "site_move"
    UNKNOWN = "unknown"


class HoldStatus(models.TextChoices):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class RunStatus(models.TextChoices):
    DEFERRED = "deferred"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class RunStep(models.TextChoices):
    NONE = ""
    SNAPSHOT = "snapshot"
    SCAN = "scan"
    TRANSFER = "transfer"
    VERIFY = "verify"
    CLEANUP = "cleanup"


class PauseReason(models.TextChoices):
    NONE = ""
    NETWORK = "network"
    BATTERY = "battery"


OPEN_RUNS = (RunStatus.RUNNING, RunStatus.PAUSED)


class StorageTarget(models.Model):
    name = models.CharField(max_length=64, unique=True)
    kind = models.CharField(
        max_length=8, choices=TargetKind.choices, default=TargetKind.SERVER
    )
    scope = models.CharField(
        max_length=6, choices=TargetScope.choices, default=TargetScope.GLOBAL
    )
    client = models.ForeignKey(
        "clients.Client", null=True, blank=True, on_delete=models.PROTECT
    )
    site = models.ForeignKey(
        "clients.Site", null=True, blank=True, on_delete=models.PROTECT
    )
    params = models.JSONField(default=dict, blank=True)
    quota_bytes = models.PositiveBigIntegerField(default=0)
    max_runs = models.PositiveSmallIntegerField(default=5)
    is_default = models.BooleanField(default=False)
    used_bytes = models.PositiveBigIntegerField(default=0)
    unreachable_since = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=django_timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["is_default"],
                condition=Q(is_default=True),
                name="imaging_one_default_target",
            ),
            models.CheckConstraint(
                condition=Q(scope="global", client=None, site=None)
                | Q(scope="client", client__isnull=False, site=None)
                | Q(scope="site", site__isnull=False, client=None),
                name="imaging_target_scope_keys",
            ),
        ]


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
    volumes = models.JSONField(default=list, blank=True)
    overrides = models.JSONField(default=dict, blank=True)
    effective = models.JSONField(default=dict, blank=True)
    target = models.ForeignKey(StorageTarget, null=True, on_delete=models.PROTECT)
    hooks_approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    hooks_approved_at = models.DateTimeField(null=True)
    hooks_pinned = models.JSONField(default=dict, blank=True)


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
    target = models.ForeignKey(StorageTarget, null=True, on_delete=models.PROTECT)
    client = models.ForeignKey(
        "clients.Client", null=True, on_delete=models.SET_NULL, related_name="+"
    )
    trigger = models.CharField(
        max_length=8, choices=Trigger.choices, default=Trigger.MANUAL
    )
    snapshot_at = models.DateTimeField(null=True)
    protected = models.BooleanField(default=False)

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
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE
    )
    token_digest = models.CharField(max_length=64)
    expires_at = models.DateTimeField(db_index=True)
    renew_until = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)
    authority = models.CharField(
        max_length=7, choices=Authority.choices, default=Authority.USER
    )
    policy = models.ForeignKey("BackupPolicy", null=True, on_delete=models.SET_NULL)
    config_version = models.PositiveIntegerField(null=True)
    run = models.ForeignKey("BackupRun", null=True, on_delete=models.SET_NULL)


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
    scope = models.CharField(
        max_length=8, choices=PolicyScope.choices, default=PolicyScope.ASSIGNED
    )
    client = models.ForeignKey(
        "clients.Client", null=True, blank=True, on_delete=models.PROTECT
    )
    site = models.ForeignKey(
        "clients.Site", null=True, blank=True, on_delete=models.PROTECT
    )
    group = models.ForeignKey(
        "groups.DeviceGroup", null=True, blank=True, on_delete=models.PROTECT
    )
    tag = models.ForeignKey(
        "groups.Tag", null=True, blank=True, on_delete=models.PROTECT
    )
    priority = models.SmallIntegerField(default=0)
    enforced = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(default=django_timezone.now)
    hooks_approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    hooks_approved_at = models.DateTimeField(null=True)
    hooks_pinned = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["scope"],
                condition=Q(scope="global"),
                name="imaging_one_global_policy",
            ),
            models.UniqueConstraint(
                fields=["client"],
                condition=Q(scope="client"),
                name="imaging_one_client_policy",
            ),
            models.UniqueConstraint(
                fields=["site"],
                condition=Q(scope="site"),
                name="imaging_one_site_policy",
            ),
            models.CheckConstraint(
                condition=Q(
                    scope__in=("global", "assigned"),
                    client=None,
                    site=None,
                    group=None,
                    tag=None,
                )
                | Q(
                    scope="client",
                    client__isnull=False,
                    site=None,
                    group=None,
                    tag=None,
                )
                | Q(scope="site", site__isnull=False, client=None, group=None, tag=None)
                | Q(
                    scope="group", group__isnull=False, client=None, site=None, tag=None
                )
                | Q(scope="tag", tag__isnull=False, client=None, site=None, group=None),
                name="imaging_policy_scope_keys",
            ),
        ]


class DeviceBackupState(models.Model):
    agent = models.OneToOneField(
        "agents.Agent", on_delete=models.CASCADE, related_name="backup_state"
    )
    protocol = models.PositiveSmallIntegerField(default=0)
    config_version = models.PositiveIntegerField(default=0)
    config_hash = models.CharField(max_length=64, blank=True)
    config_doc = models.TextField(blank=True)
    effective_hash = models.CharField(max_length=64, blank=True)
    memberships = models.JSONField(default=dict)
    pending_since = models.DateTimeField(null=True)
    acked_version = models.PositiveIntegerField(default=0)
    acked_hash = models.CharField(max_length=64, blank=True)
    acked_at = models.DateTimeField(null=True)
    ack_status = models.CharField(
        max_length=7, choices=AckStatus.choices, blank=True, default=AckStatus.NONE
    )
    ack_errors = models.JSONField(default=list)
    checks = models.JSONField(default=list)
    checks_at = models.DateTimeField(null=True)
    capabilities = models.JSONField(default=list)
    conditions = models.JSONField(default=dict)
    sealed = models.BooleanField(default=False)
    ready = models.BooleanField(default=False)
    not_ready_reason = models.CharField(max_length=255, blank=True)
    last_poll_at = models.DateTimeField(null=True)
    last_success_at = models.DateTimeField(null=True)
    schedule_since = models.DateTimeField(null=True)
    consecutive_failures = models.PositiveIntegerField(default=0)
    consecutive_interruptions = models.PositiveIntegerField(default=0)
    usage = models.JSONField(default=dict)
    alerts = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)


class PolicyChangeHold(models.Model):
    agent = models.ForeignKey("agents.Agent", on_delete=models.CASCADE)
    cause = models.CharField(max_length=12, choices=HoldCause.choices)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    held_hash = models.CharField(max_length=64)
    proposed_hash = models.CharField(max_length=64)
    proposed_memberships = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=django_timezone.now)
    confirmed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    confirmed_at = models.DateTimeField(null=True)
    status = models.CharField(
        max_length=9, choices=HoldStatus.choices, default=HoldStatus.PENDING
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent"],
                condition=Q(status="pending"),
                name="imaging_one_pending_hold",
            )
        ]


class BackupRun(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    image = models.ForeignKey(Image, related_name="runs", on_delete=models.CASCADE)
    trigger = models.CharField(max_length=8, choices=Trigger.choices)
    policy = models.ForeignKey(BackupPolicy, null=True, on_delete=models.SET_NULL)
    policy_version = models.PositiveIntegerField(null=True)
    status = models.CharField(
        max_length=11, choices=RunStatus.choices, default=RunStatus.DEFERRED
    )
    step = models.CharField(
        max_length=8, choices=RunStep.choices, blank=True, default=RunStep.NONE
    )
    deferred_reason = models.CharField(max_length=32, blank=True)
    reason = models.CharField(max_length=255, blank=True)
    pause_reason = models.CharField(
        max_length=8, choices=PauseReason.choices, blank=True, default=PauseReason.NONE
    )
    pause_max_minutes = models.PositiveSmallIntegerField(default=30)
    agent_protocol = models.PositiveSmallIntegerField(default=0)
    counters = models.JSONField(default=dict)
    log = models.JSONField(default=list)
    log_start = models.PositiveIntegerField(default=0)
    warnings = models.JSONField(default=list)
    hooks = models.JSONField(default=list)
    claimed_hooks = models.JSONField(default=list, blank=True)
    cancel_requested = models.BooleanField(default=False)
    cancelled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    created_at = models.DateTimeField(default=django_timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True)
    ended_at = models.DateTimeField(null=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "updated_at"], name="imaging_run_status")
        ]


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

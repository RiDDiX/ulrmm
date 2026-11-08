# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt

from django.conf import settings
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.utils import timezone as djangotime
from rest_framework.exceptions import PermissionDenied

MODE_CACHE_KEY = "deploy_mtls_mode"
POLICY_VER_KEY = "deploy_policy_ver"
# rotation policy fields and their bounds; a null override inherits
POLICY_LIMITS = {
    "rekey_minutes": (5, 1440),
    "rekey_mb": (1, 4096),
    "cert_ttl_hours": (1, 2160),
    "renew_pct": (10, 90),
    "offline_grace_days": (0, 90),
}
POLICY_FIELDS = tuple(POLICY_LIMITS) + ("auto_quarantine",)
ENROLL_LIMIT = "this deployment link has reached its enrollment limit"


class EnrollmentLimit(PermissionDenied):
    default_detail = ENROLL_LIMIT

    def __init__(self, deployment_id):
        super().__init__()
        self.deployment_id = deployment_id

    def record(self, request, hostname="") -> None:
        """The security event; call it after the transaction rolled back."""
        from .events import record

        record(
            SecurityEventKind.ENROLL_LIMIT,
            SecurityEventSeverity.WARNING,
            ip=getattr(request, "_client_ip", None),
            detail=f"deployment {self.deployment_id} host {hostname}",
        )


class Enrollment(models.Model):
    """The deployment an agent enrolled through."""

    agent = models.OneToOneField(
        "agents.Agent", related_name="enrollment", on_delete=models.CASCADE
    )
    deployment = models.ForeignKey(
        "clients.Deployment",
        related_name="enrollments",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.agent} - {self.deployment_id}"

    def save(self, *args, **kwargs):
        if not (
            self._state.adding
            and self.deployment_id
            and self.deployment.max_enrollments is not None
        ):
            return super().save(*args, **kwargs)
        from clients.models import Deployment

        with transaction.atomic():
            # parallel enrollments of one deployment wait for each other here
            cap = (
                Deployment.objects.select_for_update()
                .filter(pk=self.deployment_id)
                .values_list("max_enrollments", flat=True)
                .first()
            )
            used = Enrollment.objects.filter(deployment_id=self.deployment_id).count()
            if cap is not None and used >= cap:
                raise EnrollmentLimit(self.deployment_id)
            super().save(*args, **kwargs)


class MtlsMode(models.TextChoices):
    OFF = "off", "Off"
    OPTIONAL = "optional", "Optional"
    REQUIRED = "required", "Required"


def _bounds(name):
    low, high = POLICY_LIMITS[name]
    return [MinValueValidator(low), MaxValueValidator(high)]


def _rekey_minutes():
    return int(getattr(settings, "E2E_REKEY_SECONDS", 3600)) // 60


def _rekey_mb():
    return int(getattr(settings, "E2E_REKEY_BYTES", 64 << 20)) >> 20


def _grace_days():
    return getattr(settings, "OFFLINE_GRACE", dt.timedelta(days=30)).days


class AgentSecuritySettings(models.Model):
    """Agent client certificates and the global rotation policy. Singleton,
    pk 1, created on the first save."""

    mtls_mode = models.CharField(
        max_length=10, choices=MtlsMode.choices, default=MtlsMode.OPTIONAL
    )
    cert_days = models.PositiveIntegerField(
        default=180, validators=[MinValueValidator(30), MaxValueValidator(825)]
    )
    # SPKI pins (b64 sha256) agents accept besides the running chain
    backup_pins = models.JSONField(default=list, blank=True)
    sec2_mode = models.CharField(
        max_length=10, choices=MtlsMode.choices, default=MtlsMode.OPTIONAL
    )
    rekey_minutes = models.PositiveIntegerField(
        default=_rekey_minutes, validators=_bounds("rekey_minutes")
    )
    rekey_mb = models.PositiveIntegerField(
        default=_rekey_mb, validators=_bounds("rekey_mb")
    )
    # null: cert_days
    cert_ttl_hours = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("cert_ttl_hours")
    )
    renew_pct = models.PositiveIntegerField(default=75, validators=_bounds("renew_pct"))
    offline_grace_days = models.PositiveIntegerField(
        default=_grace_days, validators=_bounds("offline_grace_days")
    )
    auto_quarantine = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)
        cache.delete_many([MODE_CACHE_KEY, POLICY_VER_KEY])


class RotationPolicy(models.Model):
    """Rotation overrides of one client or one site; null fields inherit."""

    client = models.ForeignKey(
        "clients.Client",
        related_name="rotation_policies",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    site = models.ForeignKey(
        "clients.Site",
        related_name="rotation_policies",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    rekey_minutes = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("rekey_minutes")
    )
    rekey_mb = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("rekey_mb")
    )
    cert_ttl_hours = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("cert_ttl_hours")
    )
    renew_pct = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("renew_pct")
    )
    offline_grace_days = models.PositiveIntegerField(
        null=True, blank=True, validators=_bounds("offline_grace_days")
    )
    auto_quarantine = models.BooleanField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["client"], name="deploy_rotation_policy_client"
            ),
            models.UniqueConstraint(
                fields=["site"], name="deploy_rotation_policy_site"
            ),
            models.CheckConstraint(
                check=models.Q(client__isnull=False, site__isnull=True)
                | models.Q(client__isnull=True, site__isnull=False),
                name="deploy_rotation_policy_one_scope",
            ),
        ]

    def __str__(self):
        return f"rotation policy client={self.client_id} site={self.site_id}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        cache.delete(POLICY_VER_KEY)

    def delete(self, *args, **kwargs):
        out = super().delete(*args, **kwargs)
        cache.delete(POLICY_VER_KEY)
        return out


class AgentCertificate(models.Model):
    """A client certificate issued to an agent; matched by its SHA-1
    fingerprint, which is what nginx passes on."""

    agent = models.ForeignKey(
        "agents.Agent", related_name="certificates", on_delete=models.CASCADE
    )
    serial = models.CharField(max_length=40)
    fingerprint_sha1 = models.CharField(max_length=40, unique=True)
    fingerprint_sha256 = models.CharField(max_length=64)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    issued_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.agent_id} {self.serial}"

    def is_active(self, now=None) -> bool:
        now = now or djangotime.now()
        # a renewal revokes the previous certificate a few minutes ahead
        revoked = self.revoked_at is not None and self.revoked_at <= now
        return not revoked and self.not_before <= now < self.not_after


class PinSet(models.Model):
    """A pin set as published in the pin document; seq grows by one per change."""

    seq = models.PositiveIntegerField(unique=True)
    primary = models.JSONField(default=list)
    backup = models.JSONField(default=list)
    # command keys and sec2 mode, as published to agents
    cmd = models.JSONField(default=list, blank=True)
    sec2 = models.CharField(max_length=10, blank=True, default="")
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"pins {self.seq}"


class SecurityEventKind(models.TextChoices):
    CERT_REFUSED = "cert_refused", "Client certificate refused"
    NATS_REFUSED = "nats_refused", "NATS connection refused"
    PIN_MISMATCH = "pin_mismatch", "Server certificate pin mismatch"
    PIN_RESCUE = "pin_rescue", "Pin set fetched after a mismatch"
    INSECURE_DROPPED = "insecure_dropped", "Insecure agent setting removed"
    UPDATE_REFUSED = "update_refused", "Agent update refused"
    TLS_FAILURE = "tls_failure", "TLS connection failed"
    BACKUP_UNENCRYPTED = "backup_unencrypted", "Backup written unencrypted"
    TOKEN_EXPIRED_MAX = "token_expired_max", "Session past its maximum lifetime"
    ENROLL_LIMIT = "enroll_limit", "Deployment enrollment limit reached"
    IDENTITY_REGISTERED = "identity_registered", "Agent identity registered"
    IDENTITY_ROTATED = "identity_rotated", "Agent identity rotated"
    IDENTITY_CONFLICT = "identity_conflict", "Agent identity conflict"
    IDENTITY_UNREADABLE = "identity_unreadable", "Agent identity unreadable"
    UNSIGNED_COMMAND = "unsigned_command", "Unsigned command refused"
    ENVELOPE_REFUSED = "envelope_refused", "Command envelope refused"
    CLOCK_SKEW = "clock_skew", "Agent clock skew"
    E2E_REFUSED = "e2e_refused", "Encrypted session refused"
    TOKEN_REUSE = "token_reuse", "Refresh token reused"
    QUARANTINED = "quarantined", "Agent quarantined"
    RELEASED = "released", "Agent released"
    ROTATION_FORCED = "rotation_forced", "Rotation requested"
    GRACE_RECOVERY = "grace_recovery", "Offline recovery"
    COMMAND_KEY_ROTATED = "command_key_rotated", "Command key rotated"
    INTEGRITY_MISMATCH = "integrity_mismatch", "Agent binary does not match the build"
    CONFIG_TAMPERED = "config_tampered", "Agent config changed outside the agent"
    UPDATE_REVERTED = "update_reverted", "Agent update reverted"
    BACKUP_FAILED = "backup_failed", "Scheduled backup failed"


class SecurityEventSeverity(models.TextChoices):
    INFO = "info", "Info"
    WARNING = "warning", "Warning"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class SecurityEvent(models.Model):
    kind = models.CharField(max_length=32, choices=SecurityEventKind.choices)
    severity = models.CharField(max_length=10, choices=SecurityEventSeverity.choices)
    agent = models.ForeignKey(
        "agents.Agent",
        related_name="security_events",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    # the agent's agent_id, kept when the agent is deleted
    agent_uid = models.CharField(max_length=255, blank=True, default="")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    detail = models.CharField(max_length=500, blank=True, default="")
    count = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [models.Index(fields=["kind", "agent_uid", "last_seen"])]

    def __str__(self):
        return f"{self.kind} {self.agent_uid}"


class IdentityState(models.TextChoices):
    ACTIVE = "active", "Active"
    QUARANTINED = "quarantined", "Quarantined"
    BLOCKED = "blocked", "Blocked"


class AgentIdentity(models.Model):
    """The agent's public keys: Ed25519 identity, static X25519 and the NATS
    nkey. A row without keys (nkey null) is a block of an agent that never
    registered one."""

    agent = models.OneToOneField(
        "agents.Agent", related_name="identity", on_delete=models.CASCADE
    )
    ed25519 = models.CharField(max_length=44, blank=True, default="")
    x25519 = models.CharField(max_length=44, blank=True, default="")
    nkey = models.CharField(max_length=56, unique=True, null=True, blank=True)
    kid = models.CharField(max_length=16, blank=True, default="")
    caps = models.JSONField(default=list, blank=True)
    state = models.CharField(
        max_length=12, choices=IdentityState.choices, default=IdentityState.ACTIVE
    )
    pin_seq = models.PositiveIntegerField(default=0)
    registered_at = models.DateTimeField(default=djangotime.now)
    rotated_at = models.DateTimeField(null=True, blank=True)
    prev_ed25519 = models.CharField(max_length=44, blank=True, default="")
    prev_until = models.DateTimeField(null=True, blank=True)
    quarantined_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=200, blank=True, default="")
    release_until = models.DateTimeField(null=True, blank=True)
    rotate_pending = models.JSONField(default=list, blank=True)
    last_hs = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["state"])]

    def __str__(self):
        return f"{self.agent_id} {self.kid} {self.state}"


class CredentialKind(models.TextChoices):
    LEGACY = "legacy", "Legacy token"
    FAMILY = "family", "Token family"


class AgentCredential(models.Model):
    """HMAC digests of the agent's REST tokens; the plaintext is kept (field
    encrypted) only while the agent still logs in to NATS with a password."""

    agent = models.OneToOneField(
        "agents.Agent", related_name="credential", on_delete=models.CASCADE
    )
    kind = models.CharField(max_length=10, choices=CredentialKind.choices)
    access_digest = models.CharField(max_length=64, unique=True)
    access_expires = models.DateTimeField(null=True, blank=True)
    # first request with the current access token; a retried refresh after
    # that is a second holder
    access_used_at = models.DateTimeField(null=True, blank=True)
    refresh_digest = models.CharField(max_length=64, unique=True, null=True, blank=True)
    refresh_expires = models.DateTimeField(null=True, blank=True)
    family = models.UUIDField(null=True, blank=True)
    generation = models.PositiveIntegerField(default=0)
    prev_refresh_digest = models.CharField(max_length=64, blank=True, default="")
    prev_rotated_at = models.DateTimeField(null=True, blank=True)
    # refresh digests before prev_refresh_digest, oldest first
    refresh_history = models.JSONField(default=list, blank=True)
    rotated_ip = models.GenericIPAddressField(null=True, blank=True)
    legacy_nats = models.TextField(blank=True, default="")
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.agent_id} {self.kind} {self.generation}"


class CommandKeyState(models.TextChoices):
    NEXT = "next", "Next"
    CURRENT = "current", "Current"
    RETIRED = "retired", "Retired"


class CommandKey(models.Model):
    """Ed25519 key the server signs agent commands with; the seed is field
    encrypted. Exactly one is current."""

    kid = models.CharField(max_length=16, unique=True)
    seed = models.TextField()
    state = models.CharField(max_length=10, choices=CommandKeyState.choices)
    created = models.DateTimeField(auto_now_add=True)
    switched_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["state"],
                condition=models.Q(state="current"),
                name="deploy_one_current_command_key",
            )
        ]

    def __str__(self):
        return f"{self.kid} {self.state}"


class BaseIso(models.Model):
    """A base installer image kept in ISO_DIR that the ISO builder copies."""

    class Status(models.TextChoices):
        DOWNLOADING = "downloading", "Downloading"
        VERIFYING = "verifying", "Verifying"
        INSPECTING = "inspecting", "Inspecting"
        READY = "ready", "Ready"
        ERROR = "error", "Error"

    class Kind(models.TextChoices):
        BASE = "base", "Base"
        BUILT = "built", "Built"

    name = models.CharField(max_length=200)
    # basename inside ISO_DIR
    filename = models.CharField(max_length=255, unique=True)
    size = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    label = models.CharField(max_length=32, blank=True)
    os = models.CharField(max_length=16, blank=True)
    bios = models.BooleanField(default=False)
    efi = models.BooleanField(default=False)
    udf = models.BooleanField(default=False)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.INSPECTING
    )
    error = models.CharField(max_length=500, blank=True)
    source_url = models.URLField(blank=True)
    expected_sha256 = models.CharField(max_length=64, blank=True)
    added = models.DateTimeField(auto_now_add=True)
    # built: an image the ISO builder made, never offered as a base
    kind = models.CharField(max_length=8, choices=Kind.choices, default=Kind.BASE)
    built_by = models.CharField(max_length=150, blank=True)
    target = models.CharField(max_length=32, blank=True)
    deployment = models.ForeignKey(
        "clients.Deployment", null=True, blank=True, on_delete=models.SET_NULL
    )

    def __str__(self) -> str:
        return self.filename

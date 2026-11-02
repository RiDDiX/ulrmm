# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import json

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.utils import timezone as djangotime

from logs.models import BaseAuditModel

# Reserved actors and the reserved rejection reason. Rows the transition plan
# creates have no person and no policy behind them, so the event chain carries
# one of these instead (design 3.4 and section 7 invariant 2).
ACTOR_MIGRATED = "system:migrated"
ACTOR_MIRRORED = "system:mirrored"
MIGRATED_REJECTION_REASON = "migrated from action=ignore"


class OSFamily(models.TextChoices):
    WINDOWS = "windows", "Windows"
    DEBIAN = "debian", "Debian"
    RHEL = "rhel", "RHEL"
    SUSE = "suse", "SUSE"
    ARCH = "arch", "Arch"
    ALPINE = "alpine", "Alpine"
    DARWIN = "darwin", "Darwin"
    FREEBSD = "freebsd", "FreeBSD"
    PORTABLE = "portable", "Portable"


class PatchSeverity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    IMPORTANT = "important", "Important"
    MODERATE = "moderate", "Moderate"
    LOW = "low", "Low"
    # the manager has a severity vocabulary and this update has no severity
    NONE = "none", "None"
    # the manager cannot tell
    UNKNOWN = "unknown", "Unknown"


class PatchState(models.TextChoices):
    DISCOVERED = "discovered", "Discovered"
    EVALUATED = "evaluated", "Evaluated"
    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    SCHEDULED = "scheduled", "Scheduled"
    INSTALLING = "installing", "Installing"
    INSTALLED = "installed", "Installed"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"
    SUPERSEDED = "superseded", "Superseded"
    OBSOLETE = "obsolete", "Obsolete"


class PatchApproval(models.TextChoices):
    UNDECIDED = "undecided", "Undecided"
    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"


class PatchErrorKind(models.TextChoices):
    LOCK = "lock", "Lock"
    NETWORK = "network", "Network"
    DEPENDENCY = "dependency", "Dependency"
    DISK = "disk", "Disk"
    GPG = "gpg", "GPG"
    INTERRUPTED = "interrupted", "Interrupted"
    TIMEOUT = "timeout", "Timeout"
    REFUSED = "refused", "Refused"
    UNKNOWN = "unknown", "Unknown"


class RecoveryState(models.TextChoices):
    NONE = "none", "None"
    ATTEMPTED = "attempted", "Attempted"
    REFUSED = "refused", "Refused"


class SystemUpgradeState(models.TextChoices):
    CURRENT = "current", "Current"
    PENDING = "pending", "Pending"
    # an all-or-nothing provider left half a transaction behind
    PARTIAL = "partial", "Partial"
    FAILED = "failed", "Failed"


class MissedWindow(models.TextChoices):
    SKIP = "skip", "Skip"
    NEXT_WINDOW = "next_window", "Next Window"
    INSTALL_ASAP = "install_asap", "Install ASAP"


class PatchEventType(models.TextChoices):
    DISCOVERED = "discovered", "Discovered"
    EVALUATED = "evaluated", "Evaluated"
    APPROVAL_REQUESTED = "approval_requested", "Approval Requested"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    REOPENED = "reopened", "Reopened"
    APPROVAL_VOIDED = "approval_voided", "Approval Voided"
    CARRIED_FORWARD = "carried_forward", "Carried Forward"
    SCHEDULED = "scheduled", "Scheduled"
    WINDOW_MISSED = "window_missed", "Window Missed"
    PLAN_CREATED = "plan_created", "Plan Created"
    PLAN_DIVERGED = "plan_diverged", "Plan Diverged"
    TRANSACTION_STARTED = "transaction_started", "Transaction Started"
    TRANSACTION_FINISHED = "transaction_finished", "Transaction Finished"
    TRANSACTION_TIMED_OUT = "transaction_timed_out", "Transaction Timed Out"
    VERIFICATION_PASSED = "verification_passed", "Verification Passed"
    VERIFICATION_FAILED = "verification_failed", "Verification Failed"
    RECOVERY_ATTEMPTED = "recovery_attempted", "Recovery Attempted"
    RECOVERY_REFUSED = "recovery_refused", "Recovery Refused"
    RETRY_SCHEDULED = "retry_scheduled", "Retry Scheduled"
    RETRY_EXHAUSTED = "retry_exhausted", "Retry Exhausted"
    SUPERSEDED = "superseded", "Superseded"
    OBSOLETE = "obsolete", "Obsolete"
    UNPATCHABLE = "unpatchable", "Unpatchable"
    REBOOT_REQUESTED = "reboot_requested", "Reboot Requested"
    REBOOT_PERFORMED = "reboot_performed", "Reboot Performed"
    EMERGENCY_INSTALL = "emergency_install", "Emergency Install"
    RING_ADVANCED = "ring_advanced", "Ring Advanced"
    RING_STALLED = "ring_stalled", "Ring Stalled"
    ROLLOUT_HALTED = "rollout_halted", "Rollout Halted"
    POLICY_CHANGED = "policy_changed", "Policy Changed"
    UNOFFICIAL_SOURCE_ENABLED = "unofficial_source_enabled", "Unofficial Source Enabled"
    UNOFFICIAL_RECIPE_APPROVED = (
        "unofficial_recipe_approved",
        "Unofficial Recipe Approved",
    )


class Patch(models.Model):
    """Fleet-level identity of one update. Global, not per tenant: the scope
    lives on PatchDevice and the fleet endpoints filter by it.
    """

    class Meta:
        constraints = [
            # a stable external id is the whole identity where one exists
            models.UniqueConstraint(
                fields=["provider", "external_id"],
                condition=~models.Q(external_id=""),
                name="patch_unique_external_id",
            ),
            # and only where it does not, the candidate makes the identity
            models.UniqueConstraint(
                fields=["provider", "package", "arch", "candidate_version", "origin"],
                condition=models.Q(external_id=""),
                name="patch_unique_candidate",
            ),
        ]
        verbose_name_plural = "patches"

    os_family = models.CharField(max_length=255, choices=OSFamily.choices)
    provider = models.CharField(max_length=255)
    # display data, never identity: WUA returns the title in the device language
    package = models.CharField(max_length=255)
    arch = models.CharField(max_length=255, blank=True, default="")
    candidate_version = models.CharField(max_length=255, blank=True, default="")
    external_id = models.CharField(max_length=255, blank=True, default="")
    origin = models.CharField(max_length=255, blank=True, default="")
    official = models.BooleanField(default=True)
    # null where the manager cannot tell
    security = models.BooleanField(null=True, blank=True, default=None)
    severity = models.CharField(
        max_length=255, choices=PatchSeverity.choices, default=PatchSeverity.UNKNOWN
    )
    advisories = ArrayField(models.CharField(max_length=255), blank=True, default=list)
    release_metadata = models.JSONField(blank=True, default=dict)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.provider} {self.package} {self.candidate_version}"


class PatchPolicy(models.Model):
    """Successor to WinUpdatePolicy, same attachment points.

    The jsonb fields have no per-key inherit semantics: a value replaces the
    whole blob, null means inherit (design 3.1).
    """

    class Meta:
        constraints = [
            # a policy hangs off an agent or off an automation policy, and the
            # resolution chain reads at most one row per attachment point
            models.CheckConstraint(
                check=models.Q(agent__isnull=True, policy__isnull=False)
                | models.Q(agent__isnull=False, policy__isnull=True),
                name="patchpolicy_agent_or_policy",
            ),
            models.UniqueConstraint(
                fields=["agent"],
                condition=models.Q(agent__isnull=False),
                name="patchpolicy_unique_agent",
            ),
            models.UniqueConstraint(
                fields=["policy"],
                condition=models.Q(policy__isnull=False),
                name="patchpolicy_unique_policy",
            ),
        ]
        verbose_name_plural = "patch policies"

    agent = models.ForeignKey(
        "agents.Agent",
        related_name="patchpolicy",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="patchpolicy",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    # empty means all families; a policy whose scope excludes the agent's
    # family falls through to the next one in the chain
    os_family_scope = ArrayField(
        models.CharField(max_length=255, choices=OSFamily.choices),
        blank=True,
        default=list,
    )
    auto_approve = models.JSONField(null=True, blank=True, default=None)
    windows = models.JSONField(null=True, blank=True, default=None)
    blackouts = models.JSONField(null=True, blank=True, default=None)
    rings = models.JSONField(null=True, blank=True, default=None)
    missed_window = models.CharField(
        max_length=255, choices=MissedWindow.choices, default=MissedWindow.NEXT_WINDOW
    )
    retry = models.JSONField(null=True, blank=True, default=None)
    reboot = models.JSONField(null=True, blank=True, default=None)
    unofficial_sources = models.JSONField(null=True, blank=True, default=None)
    noninteractive_config = models.JSONField(null=True, blank=True, default=None)
    auto_recover = models.BooleanField(default=True)

    def __str__(self):
        if self.agent:
            return self.agent.hostname

        return self.policy.name


class PatchDevice(models.Model):
    """One row per (Patch, Agent). The lifecycle lives here."""

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["patch", "agent"], name="patchdevice_unique_patch_agent"
            ),
        ]

    patch = models.ForeignKey(Patch, related_name="devices", on_delete=models.CASCADE)
    agent = models.ForeignKey(
        "agents.Agent", related_name="patch_devices", on_delete=models.CASCADE
    )
    # null where the provider has no installed-version concept
    installed_version = models.CharField(max_length=255, null=True, blank=True)
    state = models.CharField(
        max_length=255, choices=PatchState.choices, default=PatchState.DISCOVERED
    )
    approval = models.CharField(
        max_length=255, choices=PatchApproval.choices, default=PatchApproval.UNDECIDED
    )
    approved_by = models.ForeignKey(
        "accounts.User",
        related_name="patch_approvals",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    approved_by_policy = models.ForeignKey(
        PatchPolicy,
        related_name="patch_approvals",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    approval_reason = models.TextField(blank=True, default="")
    # the predecessor a carried-forward rejection came from (row succession)
    carried_from = models.ForeignKey(
        "self",
        related_name="carried_to",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    scheduled_for = models.DateTimeField(null=True, blank=True)
    ring = models.IntegerField(default=0)
    attempts = models.PositiveIntegerField(default=0)
    last_error_kind = models.CharField(
        max_length=255, choices=PatchErrorKind.choices, blank=True, default=""
    )
    last_error_detail = models.TextField(blank=True, default="")
    dependency_changes = models.JSONField(blank=True, default=dict)
    reboot_required = models.BooleanField(default=False)
    # false for an unofficial package that is not on the policy allowlist
    installable = models.BooleanField(default=True)
    transaction_id = models.UUIDField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    recovery_state = models.CharField(
        max_length=255, choices=RecoveryState.choices, default=RecoveryState.NONE
    )
    installed_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    skipped_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.agent.hostname} {self.patch}"


class PatchEvent(models.Model):
    """Append-only, one row per transition or decision, hash chained per
    patch_device so a pruned prefix stays verifiable and a middle deletion
    does not."""

    class Meta:
        constraints = [
            # the chain forks when two writers append to the same predecessor,
            # so the second one loses here instead of at read time
            models.UniqueConstraint(
                fields=["patch_device", "prev_hash"],
                name="patchevent_unique_prev_hash",
            ),
        ]

    patch_device = models.ForeignKey(
        PatchDevice, related_name="events", on_delete=models.CASCADE
    )
    event_type = models.CharField(max_length=255, choices=PatchEventType.choices)
    # a username, a policy, an agent, or one of the reserved system actors
    actor = models.CharField(max_length=255)
    at = models.DateTimeField(default=djangotime.now)
    from_state = models.CharField(
        max_length=255, choices=PatchState.choices, blank=True, default=""
    )
    to_state = models.CharField(
        max_length=255, choices=PatchState.choices, blank=True, default=""
    )
    candidate_version = models.CharField(max_length=255, blank=True, default="")
    payload = models.JSONField(blank=True, default=dict)
    prev_hash = models.CharField(max_length=64, blank=True, default="")
    hash = models.CharField(max_length=64, blank=True, default="")

    def __str__(self):
        return f"{self.patch_device_id} {self.event_type}"

    def compute_hash(self) -> str:
        parts = (
            self.prev_hash,
            str(self.patch_device_id),
            self.event_type,
            self.actor,
            self.at.isoformat(),
            self.from_state,
            self.to_state,
            self.candidate_version,
            json.dumps(self.payload or {}, sort_keys=True, default=str),
        )
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.pk:
            last = (
                PatchEvent.objects.filter(patch_device_id=self.patch_device_id)
                .order_by("id")
                .last()
            )
            self.prev_hash = last.hash if last else ""
            self.hash = self.compute_hash()

        super().save(*args, **kwargs)


class HostFacts(models.Model):
    """The typed form of the facts the agent reports. Kept off Agent, which is
    already the widest and hottest row in the schema, and written by a
    different path at a different cadence."""

    class Meta:
        verbose_name_plural = "host facts"

    agent = models.OneToOneField(
        "agents.Agent", related_name="host_facts", on_delete=models.CASCADE
    )
    os = models.CharField(max_length=255, blank=True, default="")
    family = models.CharField(max_length=255, blank=True, default="")
    distro = models.CharField(max_length=255, blank=True, default="")
    version_id = models.CharField(max_length=255, blank=True, default="")
    codename = models.CharField(max_length=255, blank=True, default="")
    arch = models.CharField(max_length=255, blank=True, default="")
    kernel = models.CharField(max_length=255, blank=True, default="")
    providers = models.JSONField(blank=True, default=list)
    origins = models.JSONField(blank=True, default=list)
    maintenance = models.JSONField(blank=True, default=dict)
    reboot_required = models.JSONField(blank=True, default=dict)
    reported_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.agent.hostname


class PatchHostState(models.Model):
    """Server-owned device-level state, unlike HostFacts, which the agent
    writes and would clobber on its next report."""

    agent = models.OneToOneField(
        "agents.Agent", related_name="patch_host_state", on_delete=models.CASCADE
    )
    # provider, package, reason, actor, set_at per entry
    holds = models.JSONField(blank=True, default=list)
    unpatchable = models.BooleanField(default=False)
    unpatchable_since = models.DateTimeField(null=True, blank=True)
    unpatchable_blockers = models.JSONField(blank=True, default=list)
    system_upgrade_state = models.CharField(
        max_length=255,
        choices=SystemUpgradeState.choices,
        default=SystemUpgradeState.CURRENT,
    )

    def __str__(self):
        return self.agent.hostname


class ScheduleKind(models.TextChoices):
    MAINTENANCE = "maintenance", "Maintenance window"
    SLEEP = "sleep", "Sleep"
    WAKE = "wake", "Wake"


class ScheduleFrequency(models.TextChoices):
    ONCE = "once", "Once"
    DAILY = "daily", "Daily"
    WEEKLY = "weekly", "Weekly"
    MONTHLY = "monthly", "Monthly"


class MaintenanceSchedule(BaseAuditModel):
    """maint window or sleep/wake schedule.

    acts for last saver: only their current targets + while they have the perms.
    """

    name = models.CharField(max_length=255)
    kind = models.CharField(max_length=20, choices=ScheduleKind.choices)
    enabled = models.BooleanField(default=True)
    frequency = models.CharField(max_length=20, choices=ScheduleFrequency.choices)
    # wall time per device tz
    run_time = models.TimeField()
    # once
    dates = ArrayField(models.DateField(), blank=True, default=list)
    # weekly, 0=Mon
    weekdays = ArrayField(models.PositiveSmallIntegerField(), blank=True, default=list)
    # monthly: dom or nth (1-4/-1) weekday
    month_day = models.PositiveSmallIntegerField(null=True, blank=True)
    month_week = models.SmallIntegerField(null=True, blank=True)
    month_weekday = models.PositiveSmallIntegerField(null=True, blank=True)
    # window len, or idle wait for sleep
    duration = models.PositiveIntegerField(default=120)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    excluded_dates = ArrayField(models.DateField(), blank=True, default=list)
    # resolved each run
    agents = ArrayField(models.CharField(max_length=200), blank=True, default=list)
    sites = ArrayField(models.PositiveIntegerField(), blank=True, default=list)
    clients = ArrayField(models.PositiveIntegerField(), blank=True, default=list)

    def __str__(self):
        return self.name

    @staticmethod
    def serialize(schedule):
        from . import serializers

        return serializers.MaintenanceScheduleSerializer(schedule).data


class RunState(models.TextChoices):
    NEW = "new", "New"
    WAKING = "waking", "Waking"
    SCANNING = "scanning", "Scanning"
    SCANNED = "scanned", "Scanned"
    INSTALLING = "installing", "Installing"
    INSTALLED = "installed", "Installed"
    REBOOTING = "rebooting", "Rebooting"
    IDLE_WAIT = "idle_wait", "Waiting for idle"
    # terminal
    DONE = "done", "Done"
    SLEPT = "slept", "Put to sleep"
    LEFT_AWAKE = "left_awake", "Left awake"
    TIMEOUT = "timeout", "Window ended"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"
    REFUSED = "refused", "Refused"


class ScheduleRun(models.Model):
    """one run of schedule on one device at one occurrence."""

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["schedule", "agent", "occurrence"],
                name="schedulerun_unique_occurrence",
            ),
        ]

    schedule = models.ForeignKey(
        MaintenanceSchedule, related_name="runs", on_delete=models.CASCADE
    )
    agent = models.ForeignKey(
        "agents.Agent", related_name="schedule_runs", on_delete=models.CASCADE
    )
    occurrence = models.DateTimeField()
    ends = models.DateTimeField()
    state = models.CharField(
        max_length=20, choices=RunState.choices, default=RunState.NEW
    )
    # only if we woke it may the run sleep it
    woke = models.BooleanField(default=False)
    wakes = models.PositiveSmallIntegerField(default=0)
    # state entry time
    changed = models.DateTimeField()
    detail = models.CharField(max_length=255, blank=True, default="")

    def __str__(self):
        return f"{self.schedule} {self.agent} {self.occurrence}"

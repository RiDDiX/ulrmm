# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib.postgres.fields import ArrayField
from django.db import models

from logs.models import BaseAuditModel

# the choice values are part of the migrations, keep values and order
PATCH_ACTION_CHOICES = [
    ("inherit", "Inherit"),
    ("approve", "Approve"),
    ("ignore", "Ignore"),
    ("nothing", "Do Nothing"),
]

AUTO_APPROVAL_CHOICES = [
    ("manual", "Manual"),
    ("approve", "Approve"),
    ("ignore", "Ignore"),
    ("inherit", "Inherit"),
]

# built from plain arithmetic, strftime would depend on the locale
RUN_TIME_HOUR_CHOICES = [
    (hour, f"{(hour % 12) or 12:02d} {'AM' if hour < 12 else 'PM'}")
    for hour in range(24)
]

RUN_TIME_DAY_CHOICES = [(day, day) for day in range(1, 32)]

REBOOT_AFTER_INSTALL_CHOICES = [
    ("never", "Never"),
    ("required", "When Required"),
    ("always", "Always"),
    ("inherit", "Inherit"),
]

DRIVER_CHOICES = [
    ("include", "Include"),
    ("exclude", "Exclude"),
    ("inherit", "Inherit"),
]

# WUA category "Drivers"
DRIVERS_CATEGORY = "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0"

SCHEDULE_FREQUENCY_CHOICES = [
    ("daily", "Daily/Weekly"),
    ("monthly", "Monthly"),
    ("inherit", "Inherit"),
]


def _text_list():
    return ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )


class WinUpdate(models.Model):
    """One offered or installed update of an agent. Windows rows carry the WUA
    UpdateID as guid, Linux/macOS rows manager:name:arch:version."""

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(
        "agents.Agent", related_name="winupdates", on_delete=models.CASCADE
    )
    guid = models.CharField(max_length=255, null=True, blank=True)
    kb = models.CharField(max_length=100, null=True, blank=True)
    title = models.TextField(null=True, blank=True)
    installed = models.BooleanField(default=False)
    downloaded = models.BooleanField(default=False)
    description = models.TextField(null=True, blank=True)
    severity = models.CharField(max_length=255, null=True, blank=True)
    categories = _text_list()
    category_ids = _text_list()
    kb_article_ids = _text_list()
    more_info_urls = ArrayField(
        models.TextField(null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    support_url = models.TextField(null=True, blank=True)
    revision_number = models.IntegerField(null=True, blank=True)
    action = models.CharField(
        max_length=100, choices=PATCH_ACTION_CHOICES, default="nothing"
    )
    result = models.CharField(max_length=255, default="n/a")
    # failed installs since the last success, the policy's reprocess limit
    fail_count = models.PositiveIntegerField(default=0)
    date_installed = models.DateTimeField(null=True, blank=True)
    is_driver = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.agent.hostname} {self.kb or self.title}"


class WinUpdatePolicy(BaseAuditModel):
    """Patch approval and schedule settings of one agent or one policy."""

    agent = models.ForeignKey(
        "agents.Agent",
        related_name="winupdatepolicy",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="winupdatepolicy",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    critical = models.CharField(
        max_length=100, choices=AUTO_APPROVAL_CHOICES, default="inherit"
    )
    important = models.CharField(
        max_length=100, choices=AUTO_APPROVAL_CHOICES, default="inherit"
    )
    moderate = models.CharField(
        max_length=100, choices=AUTO_APPROVAL_CHOICES, default="inherit"
    )
    low = models.CharField(
        max_length=100, choices=AUTO_APPROVAL_CHOICES, default="inherit"
    )
    other = models.CharField(
        max_length=100, choices=AUTO_APPROVAL_CHOICES, default="inherit"
    )
    # driver updates have no severity; include lets them follow "other",
    # inherit on a policy means exclude
    drivers = models.CharField(max_length=16, choices=DRIVER_CHOICES, default="inherit")

    run_time_hour = models.IntegerField(choices=RUN_TIME_HOUR_CHOICES, default=3)
    run_time_frequency = models.CharField(
        max_length=100, choices=SCHEDULE_FREQUENCY_CHOICES, default="inherit"
    )
    # weekdays, 0 = Monday
    run_time_days = ArrayField(
        models.IntegerField(blank=True), null=True, blank=True, default=list
    )
    run_time_day = models.IntegerField(choices=RUN_TIME_DAY_CHOICES, default=1)

    reboot_after_install = models.CharField(
        max_length=50, choices=REBOOT_AFTER_INSTALL_CHOICES, default="inherit"
    )

    reprocess_failed_inherit = models.BooleanField(default=True)
    reprocess_failed = models.BooleanField(default=False)
    reprocess_failed_times = models.PositiveIntegerField(default=5)
    email_if_fail = models.BooleanField(default=False)

    def __str__(self) -> str:
        if self.agent_id:
            return self.agent.hostname
        if self.policy_id:
            return self.policy.name
        return f"Patch policy {self.pk}"

    @staticmethod
    def serialize(policy):
        from . import serializers

        return serializers.WinUpdatePolicySerializer(policy).data

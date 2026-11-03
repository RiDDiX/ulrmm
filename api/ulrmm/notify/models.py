# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from logs.models import BaseAuditModel
from ulrmm.constants import AlertSeverity

# never change: stored secrets could no longer be decrypted
HKDF_INFO = b"notify.Channel.secret"

SOURCES = (
    "check",
    "agent",
    "task",
    "netmon",
    "vuln",
    "appupdate",
    "tamper",
    "license",
    "laps",
)


class ChannelKind(models.TextChoices):
    MATRIX = "matrix", "Matrix"
    TELEGRAM = "telegram", "Telegram"
    NTFY = "ntfy", "ntfy"
    SLACK = "slack", "Slack"
    TEAMS = "teams", "Microsoft Teams"
    WEBHOOK = "webhook", "Webhook"
    EMAIL = "email", "Email"


class State(models.TextChoices):
    QUEUED = "queued", "Queued"
    HELD = "held", "Held for quiet hours"
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"
    DROPPED = "dropped", "Over the rate limit"


class Channel(BaseAuditModel):
    name = models.CharField(max_length=80)
    kind = models.CharField(max_length=20, choices=ChannelKind.choices)
    # settings that are not secret, see serializers.CONFIG
    config = models.JSONField(default=dict, blank=True)
    # Fernet token with HKDF_INFO. matrix, telegram or ntfy token, the
    # slack or teams webhook url, the signing key of a webhook
    secret = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    # wall time in the default time zone of the global settings
    quiet_start = models.TimeField(null=True, blank=True)
    quiet_end = models.TimeField(null=True, blank=True)
    min_severity = models.CharField(
        max_length=20, choices=AlertSeverity.choices, default=AlertSeverity.INFO
    )
    last_sent = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True, default="")

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(channel):
        from . import serializers

        return serializers.ChannelAuditSerializer(channel).data


class Route(BaseAuditModel):
    name = models.CharField(max_length=80)
    # empty list matches every severity or source
    severities = models.JSONField(default=list, blank=True)
    sources = models.JSONField(default=list, blank=True)
    channels = models.ManyToManyField(Channel, related_name="routes", blank=True)
    # 0 = no escalation
    escalate_after_minutes = models.PositiveIntegerField(default=0)
    escalate_to = models.ManyToManyField(
        Channel, related_name="escalations", blank=True
    )
    mute_in_maintenance = models.BooleanField(default=True)

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(route):
        from . import serializers

        return serializers.RouteSerializer(route).data


class Notification(models.Model):
    route = models.ForeignKey(
        Route, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    channel = models.ForeignKey(
        Channel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="notifications",
    )
    alert = models.ForeignKey(
        "alerts.Alert",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="notifications",
    )
    source = models.CharField(max_length=20)
    severity = models.CharField(max_length=20, default=AlertSeverity.INFO)
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True, default="")
    # an event with a key that already has rows is not sent again
    dedupe_key = models.CharField(max_length=200, blank=True, default="", db_index=True)
    escalation_level = models.PositiveSmallIntegerField(default=0)
    state = models.CharField(max_length=10, choices=State.choices, default=State.QUEUED)
    created = models.DateTimeField(auto_now_add=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=500, blank=True, default="")

    def __str__(self) -> str:
        return self.title

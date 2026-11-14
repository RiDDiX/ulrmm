# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json

from django.db import models

from core.models import EncryptedTextField
from logs.models import BaseAuditModel, hmac_marker

# never change: stored secrets could no longer be decrypted
SECRET_INFO = b"importers.ImportSource.secret"
SNAPSHOT_INFO = b"importers.ImportSource.snapshot"
DEVICE_DATA_INFO = b"importers.ImportedDevice.data"


class EncryptedJSONField(EncryptedTextField):
    """A dict stored encrypted like the key store values. What the other
    server hands out holds its secrets in plain text (key store values, web
    hook headers, script arguments), so the column never does."""

    def from_db_value(self, value, expression, connection):
        value = super().from_db_value(value, expression, connection)
        return json.loads(value) if value else {}

    def get_prep_value(self, value):
        return super().get_prep_value(json.dumps(value))


class SourceKind(models.TextChoices):
    UPSTREAM = "upstream", "Compatible RMM server"
    NINJAONE = "ninjaone", "NinjaOne"


class MigrateState(models.TextChoices):
    NONE = "", "Not sent"
    SENT = "sent", "Installer sent"
    FAILED = "failed", "Sending failed"
    LINKED = "linked", "Linked to an agent"


class RemoveState(models.TextChoices):
    NONE = "", "Not requested"
    WAITING_HERE = "waiting_here", "Waiting for the device here"
    WAITING_THERE = "waiting_there", "Waiting for the device over there"
    SENDING = "sending", "Removal being sent"
    REMOVED = "removed", "Old agent removed"
    NOT_REMOVED = "not_removed", "Old agent not removed"


class ImportSource(BaseAuditModel):
    kind = models.CharField(max_length=20, choices=SourceKind.choices)
    name = models.CharField(max_length=100)
    url = models.CharField(max_length=255)
    verify_tls = models.BooleanField(default=True)
    # non-secret settings of the source, e.g. a NinjaOne client id
    options = models.JSONField(default=dict, blank=True)
    # JSON object of the source's secrets (API key, client secret, password)
    secret = EncryptedTextField(hkdf_info=SECRET_INFO, blank=True, default="")
    # normalized data of the last fetch, see sources.base.validate
    snapshot = EncryptedJSONField(
        hkdf_info=SNAPSHOT_INFO, unreadable="{}", blank=True, default=dict
    )
    last_fetch = models.DateTimeField(null=True, blank=True)
    last_import = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True, default="")

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(source):
        return {
            "id": source.pk,
            "kind": source.kind,
            "name": source.name,
            "url": source.url,
            "verify_tls": source.verify_tls,
            "options": source.options,
            # the log shows that a secret changed, never the secret
            "secret": hmac_marker(source.secret),
        }


class ImportedDevice(models.Model):
    """A device of the source. It becomes an agent once the ulrmm agent
    enrolls on it, see link.on_enroll."""

    source = models.ForeignKey(
        ImportSource, related_name="devices", on_delete=models.CASCADE
    )
    # the device's id in the source
    ref = models.CharField(max_length=255)
    site = models.ForeignKey(
        "clients.Site", null=True, blank=True, on_delete=models.SET_NULL
    )
    hostname = models.CharField(max_length=255)
    serial = models.CharField(max_length=255, blank=True, default="")
    plat = models.CharField(max_length=20, blank=True, default="")
    goarch = models.CharField(max_length=20, blank=True, default="")
    monitoring_type = models.CharField(max_length=20, blank=True, default="")
    os_name = models.CharField(max_length=255, blank=True, default="")
    # description, notes and custom field values, applied when it links
    data = EncryptedJSONField(
        hkdf_info=DEVICE_DATA_INFO, unreadable="{}", blank=True, default=dict
    )
    agent = models.ForeignKey(
        "agents.Agent",
        null=True,
        blank=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )
    migrate_state = models.CharField(
        max_length=20, choices=MigrateState.choices, blank=True, default=""
    )
    migrate_error = models.CharField(max_length=500, blank=True, default="")
    sent_at = models.DateTimeField(null=True, blank=True)
    # removal of the other RMM's agent, see removal.py; null: not requested
    remove_requested_at = models.DateTimeField(null=True, blank=True)
    remove_state = models.CharField(
        max_length=20, choices=RemoveState.choices, blank=True, default=""
    )
    # when the state last changed; for a removed agent the time of removal
    remove_at = models.DateTimeField(null=True, blank=True)
    remove_reason = models.CharField(max_length=500, blank=True, default="")
    # set before the removal call goes out: its answer can get lost
    remove_tried_at = models.DateTimeField(null=True, blank=True)
    # outcome of the remote-control recovery after a removal on Windows
    recovery = models.CharField(max_length=500, blank=True, default="")

    class Meta:
        unique_together = (("source", "ref"),)

    def __str__(self) -> str:
        return self.hostname

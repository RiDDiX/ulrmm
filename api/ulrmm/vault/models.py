# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models
from django.db.models import Q

from logs.models import BaseAuditModel

# never change: stored secrets could no longer be decrypted
HKDF_INFO = b"vault.Credential.secret"
MAX_BODY_BYTES = 100 * 1024
SCOPES = ("client", "site", "agent")


class ScopedItem(BaseAuditModel):
    # exactly one of client, site and agent is set
    client = models.ForeignKey(
        "clients.Client",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="vault_%(class)ss",
    )
    site = models.ForeignKey(
        "clients.Site",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="vault_%(class)ss",
    )
    agent = models.ForeignKey(
        "agents.Agent",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="vault_%(class)ss",
    )

    class Meta:
        abstract = True
        constraints = [
            models.CheckConstraint(
                check=Q(client__isnull=False, site__isnull=True, agent__isnull=True)
                | Q(client__isnull=True, site__isnull=False, agent__isnull=True)
                | Q(client__isnull=True, site__isnull=True, agent__isnull=False),
                name="%(app_label)s_%(class)s_one_scope",
            )
        ]

    @property
    def scope(self) -> str:
        return next(s for s in SCOPES if getattr(self, f"{s}_id"))


class Credential(ScopedItem):
    name = models.CharField(max_length=80)
    username = models.CharField(max_length=255, blank=True, default="")
    # Fernet token from remote.utils.encrypt_secret. decrypted in the reveal view
    secret = models.TextField(blank=True, default="")
    url = models.CharField(max_length=500, blank=True, default="")
    notes = models.CharField(max_length=2000, blank=True, default="")

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(credential):
        from . import serializers

        return serializers.CredentialAuditSerializer(credential).data


class Document(ScopedItem):
    title = models.CharField(max_length=120)
    # plain text. show it as text, not through a markdown or html renderer
    body = models.TextField(blank=True, default="")
    pinned = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.title

    @staticmethod
    def serialize(document):
        from . import serializers

        return serializers.DocumentAuditSerializer(document).data

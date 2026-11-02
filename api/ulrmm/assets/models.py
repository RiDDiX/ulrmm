# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from logs.models import BaseAuditModel

# never change: stored keys could no longer be decrypted
HKDF_INFO = b"assets.License.key"


class License(BaseAuditModel):
    name = models.CharField(max_length=120)
    vendor = models.CharField(max_length=120, blank=True, default="")
    # Fernet token with HKDF_INFO, shown through the reveal view only
    key = models.TextField(blank=True, default="")
    # empty = no limit
    seats = models.PositiveIntegerField(null=True, blank=True)
    expires = models.DateField(null=True, blank=True)
    notes = models.CharField(max_length=2000, blank=True, default="")
    agents = models.ManyToManyField("agents.Agent", related_name="licenses", blank=True)
    # empty = a license for every client
    site = models.ForeignKey(
        "clients.Site",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="licenses",
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(lic):
        from . import serializers

        return serializers.LicenseAuditSerializer(lic).data

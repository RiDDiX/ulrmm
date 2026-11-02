# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid

from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from agents.models import Agent
from logs.models import BaseAuditModel
from ulrmm.constants import (
    AGENT_DEFER,
    AgentMonType,
    AppUpdatePolicy,
    CustomFieldType,
    GoArch,
)
from ulrmm.models import PermissionQuerySet

MAX_ENROLLMENTS = 100000


def _default_failing_checks_data():
    # referenced by migration 0020 by its dotted path
    return {"error": False, "warning": False}


def _changed(old, new, fields) -> bool:
    return any(getattr(old, f) != getattr(new, f) for f in fields)


def _drop_policy_cache(site_pks, workstation: bool, server: bool) -> None:
    # keys come from Agent._policy_cache_key; the pattern also hits other
    # sites whose pk ends the same way, which only costs a rebuild
    for pk in site_pks:
        if workstation:
            cache.delete_many_pattern(f"site_workstation_*{pk}_*")
        if server:
            cache.delete_many_pattern(f"site_server_*{pk}_*")


_TEMPLATE_FIELDS = ("alert_template_id", "workstation_policy_id", "server_policy_id")


class Client(BaseAuditModel):
    objects = PermissionQuerySet.as_manager()

    name = models.CharField(max_length=255, unique=True)
    block_policy_inheritance = models.BooleanField(default=False)
    failing_checks = models.JSONField(default=_default_failing_checks_data)
    workstation_policy = models.ForeignKey(
        "automation.Policy",
        related_name="workstation_clients",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    server_policy = models.ForeignKey(
        "automation.Policy",
        related_name="server_clients",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    alert_template = models.ForeignKey(
        "alerts.AlertTemplate",
        related_name="clients",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ("name",)

    def save(self, *args, **kwargs):
        # alerts.tasks imports agents, which imports this module
        from alerts.tasks import cache_agents_alert_template

        old = Client.objects.filter(pk=self.pk).first() if self.pk else None
        super().save(old, *args, **kwargs)
        if old is None:
            return

        if _changed(old, self, _TEMPLATE_FIELDS):
            cache_agents_alert_template.delay()

        block = old.block_policy_inheritance != self.block_policy_inheritance
        workstation = block or old.workstation_policy_id != self.workstation_policy_id
        server = block or old.server_policy_id != self.server_policy_id
        if workstation or server:
            site_pks = self.sites.values_list("pk", flat=True)
            _drop_policy_cache(site_pks, workstation, server)

    @property
    def live_agent_count(self) -> int:
        return Agent.objects.defer(*AGENT_DEFER).filter(site__client=self).count()

    def __str__(self):
        return self.name

    @staticmethod
    def serialize(client):
        from . import serializers

        return serializers.ClientAuditSerializer(client).data


class Site(BaseAuditModel):
    objects = PermissionQuerySet.as_manager()

    client = models.ForeignKey(Client, related_name="sites", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    block_policy_inheritance = models.BooleanField(default=False)
    failing_checks = models.JSONField(default=_default_failing_checks_data)
    workstation_policy = models.ForeignKey(
        "automation.Policy",
        related_name="workstation_sites",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    server_policy = models.ForeignKey(
        "automation.Policy",
        related_name="server_sites",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    alert_template = models.ForeignKey(
        "alerts.AlertTemplate",
        related_name="sites",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    app_updates = models.CharField(
        max_length=10,
        choices=AppUpdatePolicy.choices,
        default=AppUpdatePolicy.INHERIT,
    )

    class Meta:
        ordering = ("name",)
        unique_together = (("client", "name"),)

    def save(self, *args, **kwargs):
        from alerts.tasks import cache_agents_alert_template

        old = Site.objects.filter(pk=self.pk).first() if self.pk else None
        super().save(old, *args, **kwargs)
        if old is None:
            return

        moved = old.client_id != self.client_id
        if moved or _changed(old, self, _TEMPLATE_FIELDS):
            cache_agents_alert_template.delay()

        block = moved or old.block_policy_inheritance != self.block_policy_inheritance
        workstation = block or old.workstation_policy_id != self.workstation_policy_id
        server = block or old.server_policy_id != self.server_policy_id
        if workstation or server:
            _drop_policy_cache([self.pk], workstation, server)

    @property
    def live_agent_count(self) -> int:
        return self.agents.defer(*AGENT_DEFER).count()

    def __str__(self):
        return self.name

    @staticmethod
    def serialize(site):
        from . import serializers

        return serializers.SiteAuditSerializer(site).data


class Deployment(models.Model):
    objects = PermissionQuerySet.as_manager()

    uid = models.UUIDField(
        primary_key=False, default=uuid.uuid4, editable=False, unique=True
    )
    name = models.CharField(max_length=100, blank=True, default="")
    site = models.ForeignKey(
        "clients.Site", related_name="deploysites", on_delete=models.CASCADE
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="deployments",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    mon_type = models.CharField(
        max_length=255, choices=AgentMonType.choices, default=AgentMonType.SERVER
    )
    goarch = models.CharField(
        max_length=255, choices=GoArch.choices, default=GoArch.AMD64
    )
    expiry = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    # only deployments made before signed enrollment tokens carry a knox token
    auth_token = models.ForeignKey(
        "knox.AuthToken",
        related_name="deploytokens",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    token_key = models.CharField(max_length=255, blank=True, default="")
    install_flags = models.JSONField(null=True, blank=True)
    # agents that may enroll through this deployment, None for any number
    max_enrollments = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(MAX_ENROLLMENTS)],
    )

    def __str__(self):
        return f"{self.client} - {self.site} - {self.mon_type}"

    @property
    def client(self):
        return self.site.client


class InstallerToken(models.Model):
    site = models.ForeignKey(
        "clients.Site", related_name="installertokens", on_delete=models.CASCADE
    )
    auth_token = models.ForeignKey(
        "knox.AuthToken", related_name="installertokens", on_delete=models.CASCADE
    )


# custom field type -> column holding the value; every other type is a string
_VALUE_COLUMN = {
    CustomFieldType.MULTIPLE: "multiple_value",
    CustomFieldType.CHECKBOX: "bool_value",
}


class _CustomFieldValue(models.Model):
    string_value = models.TextField(null=True, blank=True)
    bool_value = models.BooleanField(blank=True, default=False)
    multiple_value = ArrayField(
        models.TextField(null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )

    class Meta:
        abstract = True

    def __str__(self):
        return self.field.name

    @property
    def value(self):
        column = _VALUE_COLUMN.get(self.field.type, "string_value")
        return getattr(self, column)

    def save_to_field(self, value) -> None:
        kind = self.field.type
        if kind not in CustomFieldType.values:
            return
        if kind == CustomFieldType.MULTIPLE:
            value = value.split(",")
        elif kind == CustomFieldType.CHECKBOX:
            value = bool(value)
        setattr(self, _VALUE_COLUMN.get(kind, "string_value"), value)
        self.save()


class ClientCustomField(_CustomFieldValue):
    client = models.ForeignKey(
        Client, related_name="custom_fields", on_delete=models.CASCADE
    )
    field = models.ForeignKey(
        "core.CustomField", related_name="client_fields", on_delete=models.CASCADE
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["client", "field"], name="unique_client_custom_field"
            )
        ]


class SiteCustomField(_CustomFieldValue):
    site = models.ForeignKey(
        Site, related_name="custom_fields", on_delete=models.CASCADE
    )
    field = models.ForeignKey(
        "core.CustomField", related_name="site_fields", on_delete=models.CASCADE
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["site", "field"], name="unique_site_custom_field"
            )
        ]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from logs.models import BaseAuditModel


class GroupKind(models.TextChoices):
    DYNAMIC = "dynamic", "Dynamic"
    STATIC = "static", "Static"


class Tag(BaseAuditModel):
    name = models.CharField(max_length=40, unique=True)
    color = models.CharField(max_length=7, default="#607d8b")
    agents = models.ManyToManyField("agents.Agent", related_name="tags", blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(tag):
        from . import serializers

        return serializers.TagSerializer(tag).data


class DeviceGroup(BaseAuditModel):
    name = models.CharField(max_length=80, unique=True)
    description = models.CharField(max_length=500, blank=True, default="")
    kind = models.CharField(
        max_length=10, choices=GroupKind.choices, default=GroupKind.DYNAMIC
    )
    # dynamic: {"match": "all"|"any", "conditions": [...]}, see rules.py
    rules = models.JSONField(default=dict, blank=True)
    # static only
    members = models.ManyToManyField(
        "agents.Agent", related_name="device_groups", blank=True
    )

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(group):
        from . import serializers

        return serializers.DeviceGroupAuditSerializer(group).data

    def agents(self) -> "models.QuerySet":
        """Matching agents, before the caller applies filter_by_role."""
        from agents.models import Agent

        from .rules import rules_q

        if self.kind == GroupKind.STATIC:
            return Agent.objects.filter(device_groups=self)
        return Agent.objects.filter(rules_q(self.rules))

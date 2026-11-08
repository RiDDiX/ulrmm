# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.forms.models import model_to_dict

from logs.models import BaseAuditModel


class Source(models.TextChoices):
    WINGET = "winget", "winget"
    BREW = "brew", "Homebrew"
    MAS = "mas", "Mac App Store"


class State(models.TextChoices):
    AVAILABLE = "available", "Available"
    EXCLUDED = "excluded", "Excluded"
    UPDATING = "updating", "Updating"
    FAILED = "failed", "Failed"
    DONE = "done", "Done"


class AppUpdate(models.Model):
    """An update the agent's package manager offers for an installed app."""

    agent = models.ForeignKey(
        "agents.Agent", related_name="appupdates", on_delete=models.CASCADE
    )
    source = models.CharField(max_length=10, choices=Source.choices)
    app_id = models.CharField(max_length=128)
    name = models.CharField(max_length=255)
    installed = models.CharField(max_length=100, blank=True, default="")
    # empty on an excluded row the agent no longer lists
    available = models.CharField(max_length=100, blank=True, default="")
    seen_at = models.DateTimeField()
    state = models.CharField(
        max_length=10, choices=State.choices, default=State.AVAILABLE
    )
    last_error = models.CharField(max_length=1500, blank=True, default="")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent", "source", "app_id"], name="appupdates_unique"
            )
        ]

    def __str__(self):
        return f"{self.app_id} {self.installed} -> {self.available}"


class AppUpdateScan(models.Model):
    agent = models.OneToOneField(
        "agents.Agent", related_name="appupdate_scan", on_delete=models.CASCADE
    )
    collected_at = models.DateTimeField()
    # why the last list failed, empty when it worked
    error = models.CharField(max_length=500, blank=True, default="")


class AppUpdateSettings(BaseAuditModel):
    """Singleton, pk 1."""

    enabled = models.BooleanField(default=False)
    # agent local time
    hour = models.PositiveSmallIntegerField(
        default=3, validators=[MinValueValidator(0), MaxValueValidator(23)]
    )
    # agents per run
    max_per_run = models.PositiveIntegerField(
        default=50, validators=[MinValueValidator(1), MaxValueValidator(1000)]
    )
    # app ids that are never updated automatically
    exclusions = models.JSONField(default=list, blank=True)

    def __str__(self):
        return "App update settings"

    @classmethod
    def load(cls) -> "AppUpdateSettings":
        return cls.objects.get_or_create(pk=1)[0]

    @staticmethod
    def serialize(obj):
        return model_to_dict(
            obj, fields=["enabled", "hour", "max_per_run", "exclusions"]
        )

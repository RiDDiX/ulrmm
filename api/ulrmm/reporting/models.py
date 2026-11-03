# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import json
import uuid
from contextlib import suppress
from typing import Any, Dict, Optional

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from core.utils import CoreSettingsNotFound
from logs.models import AuditLog, BaseAuditModel, DebugLog
from ulrmm.middleware import get_debug_info, get_username

from .storage import get_report_assets_fs


class ReportFormatType(models.TextChoices):
    MARKDOWN = "markdown", "Markdown"
    HTML = "html", "Html"
    PLAIN_TEXT = "plaintext", "Plain Text"


class ReportFormat(models.TextChoices):
    PDF = "pdf", "Pdf"
    HTML = "html", "Html"
    PLAIN_TEXT = "plaintext", "Plain Text"


def content_hash(value: Any) -> Optional[str]:
    # audit entries carry a hash of large text, not the text itself
    if value is None:
        return None
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(value.encode()).hexdigest()


class ReportHTMLTemplate(BaseAuditModel):
    name = models.CharField(max_length=200, unique=True)
    html = models.TextField()

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(template: "ReportHTMLTemplate") -> Dict[str, Any]:
        return {"name": template.name, "html_sha256": content_hash(template.html)}


class ReportTemplate(BaseAuditModel):
    name = models.CharField(max_length=200, unique=True)
    template_md = models.TextField()
    template_css = models.TextField(null=True, blank=True)
    template_html = models.ForeignKey(
        ReportHTMLTemplate,
        related_name="htmltemplate",
        on_delete=models.DO_NOTHING,
        null=True,
        blank=True,
    )
    type = models.CharField(
        max_length=15,
        choices=ReportFormatType.choices,
        default=ReportFormatType.MARKDOWN,
    )
    template_variables = models.TextField(blank=True, default="")
    depends_on = ArrayField(
        models.CharField(max_length=20, blank=True), blank=True, default=list
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(template: "ReportTemplate") -> Dict[str, Any]:
        return {
            "name": template.name,
            "type": template.type,
            "template_html": template.template_html_id,
            "depends_on": template.depends_on,
            "template_md_sha256": content_hash(template.template_md),
            "template_css_sha256": content_hash(template.template_css),
            "template_variables_sha256": content_hash(template.template_variables),
        }


class ReportAsset(models.Model):
    id = models.UUIDField(
        primary_key=True, unique=True, default=uuid.uuid4, editable=False
    )
    file = models.FileField(storage=get_report_assets_fs, unique=True)

    def __str__(self) -> str:
        return f"{self.id} - {self.file}"


class ReportDataQuery(BaseAuditModel):
    name = models.CharField(max_length=50, unique=True)
    json_query = models.JSONField()

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(query: "ReportDataQuery") -> Dict[str, Any]:
        return {"name": query.name, "json_query_sha256": content_hash(query.json_query)}


class ReportSchedule(BaseAuditModel):
    name = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    report_template = models.ForeignKey(
        ReportTemplate,
        related_name="reporttemplate_schedules",
        on_delete=models.CASCADE,
    )
    format = models.CharField(
        max_length=10, choices=ReportFormat.choices, default=ReportFormat.HTML
    )
    # DO_NOTHING: core refuses to delete a schedule that is still in use
    schedule = models.ForeignKey(
        "core.Schedule", related_name="schedule", on_delete=models.DO_NOTHING
    )
    dependencies = models.JSONField(default=dict, blank=True)
    email_recipients = ArrayField(models.EmailField(), blank=True, default=list)
    send_report_email = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    email_settings = models.JSONField(default=dict, blank=True)
    timezone = models.CharField(max_length=100, null=True, blank=True)
    # runs use this user's role scope; rows saved before owners existed run unscoped
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="report_schedules",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(schedule: "ReportSchedule") -> Dict[str, Any]:
        from . import serializers

        return serializers.ReportScheduleAuditSerializer(schedule).data


class ReportHistory(BaseAuditModel):
    report_template = models.ForeignKey(
        ReportTemplate,
        related_name="reporttemplate_history",
        on_delete=models.CASCADE,
    )
    # display text only; access is decided by user and schedule
    run_by = models.CharField(max_length=255, default="system")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="report_history",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    schedule = models.ForeignKey(
        ReportSchedule,
        related_name="history",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    report_data = models.TextField(blank=True, default="")
    error_data = models.TextField(null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.report_template.name} - {self.date_created}"


@receiver(pre_delete, sender=settings.AUTH_USER_MODEL)
def release_owned_schedules(sender, instance, **kwargs) -> None:
    # the schedule keeps running, unscoped like schedules saved before owners existed
    for schedule in ReportSchedule.objects.filter(owner=instance):
        before = ReportSchedule.serialize(schedule)
        schedule.owner = None
        AuditLog.audit_object_changed(
            get_username() or "system",
            "reportschedule",
            before,
            ReportSchedule.serialize(schedule),
            schedule.name,
            debug_info=get_debug_info(),
        )
        # never let the note block the user delete
        with suppress(CoreSettingsNotFound):
            DebugLog.warning(
                f"Report schedule {schedule.name} lost its owner {instance.username}"
                " (user deleted) and now runs unscoped"
            )

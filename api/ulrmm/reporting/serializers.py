# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
from typing import Any, Dict, Optional

from rest_framework import serializers

from ulrmm.constants import ALL_TIMEZONES

from .models import (
    ReportDataQuery,
    ReportFormat,
    ReportHistory,
    ReportHTMLTemplate,
    ReportSchedule,
    ReportTemplate,
)
from .utils import RESERVED_DEPENDENCIES, check_dependencies

AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")

EMAIL_TEXT_KEYS = ("subject", "body", "attachment_name", "attachment_extension")
ONE_LINE_KEYS = ("subject", "attachment_name")
EXTENSION_RE = re.compile(r"[A-Za-z0-9]{1,8}")


def validate_email_settings(value: Any) -> Dict[str, Any]:
    """Check the known keys of email_settings, keep any others as they are."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise serializers.ValidationError("email_settings must be an object")

    for key in EMAIL_TEXT_KEYS:
        if value.get(key) is not None and not isinstance(value[key], str):
            raise serializers.ValidationError(f"{key} must be text")
    for key in ONE_LINE_KEYS:
        if re.search(r"[\r\n]", value.get(key) or ""):
            raise serializers.ValidationError(f"{key} cannot contain line breaks")
    extension = value.get("attachment_extension")
    if extension and not EXTENSION_RE.fullmatch(extension):
        raise serializers.ValidationError(
            "attachment_extension must be 1 to 8 letters or digits"
        )
    link = value.get("include_report_link")
    if link is not None and not isinstance(link, bool):
        raise serializers.ValidationError("include_report_link must be true or false")
    return value


def validate_dependencies(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise serializers.ValidationError("dependencies must be an object")
    return value


class ReportTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportTemplate
        fields = "__all__"
        read_only_fields = AUDIT_FIELDS

    def validate_depends_on(self, value):
        # refused at save time; every run would fail on them otherwise
        reserved = [name for name in value if name in RESERVED_DEPENDENCIES]
        if reserved:
            raise serializers.ValidationError(
                f"{', '.join(reserved)} cannot be used as a dependency name"
            )
        return value


class ReportHTMLTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportHTMLTemplate
        fields = "__all__"
        read_only_fields = AUDIT_FIELDS


class ReportDataQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportDataQuery
        fields = "__all__"
        read_only_fields = AUDIT_FIELDS


class ReportScheduleSerializer(serializers.ModelSerializer):
    report_template_name = serializers.SerializerMethodField()
    schedule_name = serializers.SerializerMethodField()
    owner_name = serializers.SerializerMethodField()

    class Meta:
        model = ReportSchedule
        fields = tuple("""
            id name enabled report_template report_template_name format schedule
            schedule_name email_recipients dependencies send_report_email last_run
            email_settings timezone owner owner_name
            """.split())
        read_only_fields = ("last_run", "owner")

    def get_report_template_name(self, obj: ReportSchedule) -> str:
        return obj.report_template.name

    def get_schedule_name(self, obj: ReportSchedule) -> str:
        return obj.schedule.name

    def get_owner_name(self, obj: ReportSchedule) -> Optional[str]:
        return obj.owner.username if obj.owner else None

    def validate_dependencies(self, value):
        return validate_dependencies(value)

    def validate_email_settings(self, value):
        return validate_email_settings(value)

    def validate_timezone(self, value):
        # the runner would fall back to the default zone without a word
        if value and value not in ALL_TIMEZONES:
            raise serializers.ValidationError(f"{value} is not a known time zone")
        return value

    def validate(self, attrs):
        # the editor becomes the owner, so stored dependencies count as well
        dependencies = attrs.get(
            "dependencies", getattr(self.instance, "dependencies", None)
        )
        check_dependencies(dependencies, self.context["user"])
        return attrs


class ReportScheduleAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportSchedule
        fields = tuple("""
            name enabled report_template format schedule email_recipients
            send_report_email email_settings timezone owner
            """.split())


class ReportHistorySerializer(serializers.ModelSerializer):
    report_template_name = serializers.ReadOnlyField(source="report_template.name")
    report_template_type = serializers.ReadOnlyField(source="report_template.type")

    class Meta:
        model = ReportHistory
        fields = tuple("""
            id report_template report_template_name report_template_type run_by
            error_data date_created
            """.split())


class ReportFormatField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs.setdefault(
            "error_messages", {"invalid_choice": "Report format is incorrect."}
        )
        super().__init__(choices=ReportFormat.choices, **kwargs)


class ReportPreviewSerializer(serializers.Serializer):
    template_md = serializers.CharField(allow_blank=True, trim_whitespace=False)
    type = serializers.CharField()
    template_css = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, trim_whitespace=False
    )
    template_html = serializers.IntegerField(required=False, allow_null=True)
    template_variables = serializers.JSONField(allow_null=True)
    dependencies = serializers.JSONField(allow_null=True)
    format = ReportFormatField()
    debug = serializers.BooleanField(required=False, default=False)

    def validate_dependencies(self, value):
        return validate_dependencies(value or None)


class EmailReportSerializer(serializers.Serializer):
    format = ReportFormatField()
    dependencies = serializers.JSONField(required=False, default=dict)
    # an empty list sends to the default recipients from global settings
    email_recipients = serializers.ListField(
        child=serializers.EmailField(max_length=254), allow_empty=True
    )
    email_settings = serializers.JSONField(required=False, default=dict)

    def validate_dependencies(self, value):
        return validate_dependencies(value)

    def validate_email_settings(self, value):
        return validate_email_settings(value)

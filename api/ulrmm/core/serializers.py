# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from rest_framework import serializers

from branding.models import Branding
from logs.models import hmac_marker
from remote.utils import encrypt_secret
from ulrmm.constants import (
    ALL_TIMEZONES,
    CORE_SETTINGS_SECRET_FIELDS,
    MonthlyType,
    ScheduleType,
)

from .models import (
    CoreSettings,
    CustomField,
    DELL_API_INFO,
    GlobalKVStore,
    NVD_KEY_INFO,
    Schedule,
    URLAction,
)
from .utils import validate_image_data_uri

_NULLABLE_SECRETS = {"twilio_auth_token", "mesh_token", "ai_api_key"}


class HostedCoreMixin:
    """In hosted mode the Mesh credentials are managed by the platform and the
    server-side features are off. These overrides run before any secret is
    stripped from the output."""

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if getattr(settings, "HOSTED", False):
            ret["mesh_site"] = "n/a"
            ret["mesh_token"] = "n/a"
            ret["mesh_username"] = "n/a"
            ret["sync_mesh_with_rmm"] = True
            ret["enable_server_scripts"] = False
            ret["enable_server_webterminal"] = False
        return ret


class CoreSettingsSerializer(HostedCoreMixin, serializers.ModelSerializer):
    nvd_api_key = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=128
    )
    nvd_api_key_clear = serializers.BooleanField(write_only=True, required=False)
    dell_api_client_id = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=255
    )
    dell_api_client_secret = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=255
    )
    dell_api_client_id_clear = serializers.BooleanField(write_only=True, required=False)
    dell_api_client_secret_clear = serializers.BooleanField(
        write_only=True, required=False
    )
    smtp_host_password_clear = serializers.BooleanField(write_only=True, required=False)
    twilio_auth_token_clear = serializers.BooleanField(write_only=True, required=False)
    mesh_token_clear = serializers.BooleanField(write_only=True, required=False)
    ai_api_key_clear = serializers.BooleanField(write_only=True, required=False)

    class Meta:
        model = CoreSettings
        fields = "__all__"
        read_only_fields = ("sso_enabled", "block_local_user_logon")

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["all_timezones"] = ALL_TIMEZONES
        ret["nvd_api_key_set"] = bool(instance.nvd_api_key)
        ret["dell_api_client_id_set"] = bool(instance.dell_api_client_id)
        ret["dell_api_client_secret_set"] = bool(instance.dell_api_client_secret)
        for field in CORE_SETTINGS_SECRET_FIELDS:
            ret.pop(field, None)
            ret[f"{field}_set"] = bool(getattr(instance, field))
        return ret

    def validate(self, attrs):
        encrypted = (
            ("nvd_api_key", NVD_KEY_INFO),
            ("dell_api_client_id", DELL_API_INFO["dell_api_client_id"]),
            ("dell_api_client_secret", DELL_API_INFO["dell_api_client_secret"]),
        )
        for field, info in encrypted:
            if attrs.pop(f"{field}_clear", False):
                attrs[field] = ""
                continue
            value = attrs.get(field)
            if value and value.strip():
                attrs[field] = encrypt_secret(value.strip(), info)
            else:
                attrs.pop(field, None)

        for field in CORE_SETTINGS_SECRET_FIELDS:
            if attrs.pop(f"{field}_clear", False):
                attrs[field] = None if field in _NULLABLE_SECRETS else ""
                continue
            if not attrs.get(field):
                attrs.pop(field, None)

        for shell_field, custom_field in (
            ("default_shell_windows", "default_shell_windows_custom"),
            ("default_shell_linux", "default_shell_linux_custom"),
            ("default_shell_darwin", "default_shell_darwin_custom"),
            ("default_shell_freebsd", "default_shell_freebsd_custom"),
        ):
            selection = attrs.get(
                shell_field, getattr(self.instance, shell_field, None)
            )
            if selection == "custom":
                custom = attrs.get(
                    custom_field, getattr(self.instance, custom_field, "") or ""
                )
                if not (custom or "").strip():
                    raise serializers.ValidationError(
                        {custom_field: "Custom shell path is required."}
                    )
        return attrs


class CoreSerializer(HostedCoreMixin, serializers.ModelSerializer):
    """Audit-log representation: every secret is masked to an HMAC marker."""

    class Meta:
        model = CoreSettings
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        masked = list(CORE_SETTINGS_SECRET_FIELDS) + [
            "nvd_api_key",
            "dell_api_client_id",
            "dell_api_client_secret",
        ]
        for field in masked:
            ret[field] = hmac_marker(getattr(instance, field))
        return ret


class CustomFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomField
        fields = "__all__"


class KeyStoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = GlobalKVStore
        fields = "__all__"


class URLActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLAction
        fields = "__all__"


class ScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        stype = ret.get("schedule_type")
        mtype = ret.get("monthly_type")
        if stype == ScheduleType.DAILY:
            ret["run_time_weekdays"] = []
            ret["monthly_months_of_year"] = []
            ret["monthly_days_of_month"] = []
            ret["monthly_weeks_of_month"] = []
        elif stype == ScheduleType.WEEKLY:
            ret["monthly_months_of_year"] = []
            ret["monthly_days_of_month"] = []
            ret["monthly_weeks_of_month"] = []
        elif stype == ScheduleType.MONTHLY:
            if mtype == MonthlyType.DAYS:
                ret["monthly_weeks_of_month"] = []
                ret["run_time_weekdays"] = []
            elif mtype == MonthlyType.WEEKS:
                ret["monthly_days_of_month"] = []
        return ret


class ScheduleAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = "__all__"


class BrandingSerializer(serializers.ModelSerializer):
    support_url = serializers.URLField(
        required=False, allow_blank=True, allow_null=True, max_length=500
    )

    class Meta:
        model = Branding
        fields = "__all__"

    def validate(self, attrs):
        for field in ("logo", "favicon"):
            if field in attrs:
                try:
                    validate_image_data_uri(attrs[field] or "")
                except ValueError as e:
                    raise serializers.ValidationError({field: str(e)})
        return attrs


class PublicBrandingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Branding
        fields = ("product_name", "company_name", "support_url", "logo", "favicon")

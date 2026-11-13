# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from typing import Any, Optional

from django.core.cache import cache
from rest_framework import serializers

from logs.models import hmac_marker
from ulrmm.constants import (
    AGENT_CHECKS_CACHE_PREFIX,
    ALL_TIMEZONES,
    CustomFieldModel,
    TerminalModeChoices,
)
from winupdate.serializers import WinUpdatePolicySerializer

from .models import Agent, AgentCustomField, AgentHistory, Note
from .utils import nobody_logged_in

_NO_CHECKS = {
    "total": 0,
    "passing": 0,
    "failing": 0,
    "warning": 0,
    "info": 0,
    "pending": 0,
    "has_failing_checks": False,
}


def _tags(agent: Agent) -> list[dict[str, Any]]:
    # .all() so the prefetch of the table view is used
    return [{"id": t.id, "name": t.name, "color": t.color} for t in agent.tags.all()]


class AgentCustomFieldSerializer(serializers.ModelSerializer):
    value = serializers.ReadOnlyField()

    class Meta:
        model = AgentCustomField
        fields = tuple("""
            id field agent value string_value bool_value multiple_value
            """.split())
        extra_kwargs = {
            "string_value": {"write_only": True},
            "bool_value": {"write_only": True},
            "multiple_value": {"write_only": True},
        }

    def validate_field(self, field):
        # client and site fields have their own tables
        if field.model != CustomFieldModel.AGENT:
            raise serializers.ValidationError("This is not an agent custom field.")
        return field


class AgentSerializer(serializers.ModelSerializer):
    status = serializers.ReadOnlyField()
    cpu_model = serializers.ReadOnlyField()
    local_ips = serializers.ReadOnlyField()
    make_model = serializers.ReadOnlyField()
    physical_disks = serializers.ReadOnlyField()
    graphics = serializers.ReadOnlyField()
    checks = serializers.ReadOnlyField()
    wol_armed = serializers.ReadOnlyField()
    timezone = serializers.ReadOnlyField()
    client = serializers.ReadOnlyField(source="client.name")
    site_name = serializers.ReadOnlyField(source="site.name")
    patches_last_installed = serializers.ReadOnlyField()
    last_seen = serializers.ReadOnlyField()
    effective_name = serializers.ReadOnlyField()
    winupdatepolicy = serializers.SerializerMethodField()
    custom_fields = AgentCustomFieldSerializer(many=True, read_only=True)
    all_timezones = serializers.SerializerMethodField()
    applied_policies = serializers.SerializerMethodField()
    effective_patch_policy = serializers.SerializerMethodField()
    alert_template = serializers.SerializerMethodField()
    effective_default_shell = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    uninstall_code_set = serializers.SerializerMethodField()
    tamper_alert = serializers.SerializerMethodField()
    planned_offline = serializers.ReadOnlyField()

    class Meta:
        model = Agent
        exclude = ["id", "uninstall_code"]

    def get_all_timezones(self, obj) -> list[str]:
        return ALL_TIMEZONES

    def get_winupdatepolicy(self, obj) -> list[dict]:
        # an agent can hold more than one row, keep their order stable
        return WinUpdatePolicySerializer(
            obj.winupdatepolicy.order_by("pk"), many=True
        ).data

    def get_applied_policies(self, obj) -> dict[str, Optional[dict]]:
        from automation.serializers import PolicySerializer

        return {
            key: PolicySerializer(policy).data if policy else None
            for key, policy in obj.get_agent_policies().items()
        }

    def get_effective_patch_policy(self, obj) -> dict[str, Any]:
        return WinUpdatePolicySerializer(obj.get_patch_policy()).data

    def get_alert_template(self, obj) -> Optional[dict[str, Any]]:
        from alerts.serializers import AlertTemplateSerializer

        if not obj.alert_template:
            return None
        reveal = bool(self.context.get("reveal_env_vars"))
        return AlertTemplateSerializer(
            obj.alert_template, context={"reveal_env_vars": reveal}
        ).data

    def get_effective_default_shell(self, obj) -> str:
        return obj.effective_default_shell

    def get_tags(self, obj) -> list[dict[str, Any]]:
        return _tags(obj)

    def get_uninstall_code_set(self, obj) -> bool:
        return bool(obj.uninstall_code)

    def get_tamper_alert(self, obj) -> Optional[dict[str, Any]]:
        from alerts.models import Alert
        from notify.tamper import ALERT_TYPE

        alert = (
            Alert.objects.filter(agent=obj, alert_type=ALERT_TYPE, resolved=False)
            .order_by("-alert_time", "-pk")
            .only("id", "alert_time", "message")
            .first()
        )
        if alert is None:
            return None
        return {
            "id": alert.id,
            "alert_time": alert.alert_time,
            "message": alert.message,
        }


class AgentTableSerializer(serializers.ModelSerializer):
    alert_template = serializers.SerializerMethodField()
    effective_name = serializers.ReadOnlyField()
    site_name = serializers.ReadOnlyField(source="site.name")
    client_name = serializers.ReadOnlyField(source="site.client.name")
    pending_actions_count = serializers.SerializerMethodField()
    status = serializers.ReadOnlyField()
    checks = serializers.SerializerMethodField()
    logged_username = serializers.SerializerMethodField()
    italic = serializers.SerializerMethodField()
    policy = serializers.SerializerMethodField()
    has_patches_pending = serializers.SerializerMethodField()
    has_patches_failed = serializers.SerializerMethodField()
    cpu_model = serializers.ReadOnlyField()
    graphics = serializers.ReadOnlyField()
    local_ips = serializers.ReadOnlyField()
    make_model = serializers.ReadOnlyField()
    physical_disks = serializers.ReadOnlyField()
    serial_number = serializers.ReadOnlyField()
    wol_armed = serializers.ReadOnlyField()
    planned_offline = serializers.ReadOnlyField()
    custom_fields = AgentCustomFieldSerializer(many=True, read_only=True)
    tags = serializers.SerializerMethodField()

    class Meta:
        model = Agent
        fields = list("""
            agent_id alert_template hostname display_name effective_name site_name
            client_name monitoring_type description needs_reboot keep_awake_until
            keep_awake_ac
            pending_actions_count status overdue_text_alert overdue_email_alert
            overdue_dashboard_alert last_seen boot_time checks maintenance_mode
            logged_username italic policy block_policy_inheritance plat goarch
            has_patches_pending has_patches_failed version operating_system
            public_ip cpu_model graphics local_ips make_model physical_disks
            custom_fields serial_number wol_armed tags power_event power_event_at
            power_event_by planned_offline
            """.split())

    def get_alert_template(self, obj) -> Optional[dict[str, Any]]:
        template = obj.alert_template
        if not template:
            return None
        return {
            "name": template.name,
            "always_email": template.agent_always_email,
            "always_text": template.agent_always_text,
            "always_alert": template.agent_always_alert,
        }

    def get_pending_actions_count(self, obj) -> int:
        return getattr(obj, "_pending_actions_count", 0) or 0

    def get_checks(self, obj) -> dict[str, Any]:
        # core.tasks keeps this cache warm; the list view reads it in one call
        key = f"{AGENT_CHECKS_CACHE_PREFIX}{obj.pk}"
        found = self.context.get("checks")
        summary = found.get(key) if found is not None else cache.get(key)
        return summary if summary else dict(_NO_CHECKS)

    def get_logged_username(self, obj) -> str:
        if not nobody_logged_in(obj):
            return obj.logged_in_username
        if obj.is_online:
            return obj.last_logged_in_user
        return "-"

    def get_italic(self, obj) -> bool:
        return nobody_logged_in(obj) and obj.is_online

    def get_policy(self, obj) -> Optional[int]:
        return obj.policy_id

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # an agent without a policy has no "policy" key (contract)
        if ret.get("policy") is None:
            ret.pop("policy", None)
        return ret

    def get_has_patches_pending(self, obj) -> bool:
        return bool(getattr(obj, "has_patches_pending", False))

    def get_has_patches_failed(self, obj) -> bool:
        return bool(getattr(obj, "has_patches_failed", False))

    def get_tags(self, obj) -> list[dict[str, Any]]:
        return _tags(obj)


class AgentHostnameSerializer(serializers.ModelSerializer):
    effective_name = serializers.ReadOnlyField()
    client = serializers.ReadOnlyField(source="site.client.name")
    site = serializers.ReadOnlyField(source="site.name")

    class Meta:
        model = Agent
        fields = tuple("""
            id hostname display_name effective_name agent_id version client site
            """.split())


class AgentNoteSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source="user.username")
    agent_id = serializers.ReadOnlyField(source="agent.agent_id")

    class Meta:
        model = Note
        fields = ("pk", "entry_time", "agent", "user", "note", "username", "agent_id")
        extra_kwargs = {"agent": {"write_only": True}, "user": {"write_only": True}}

    def update(self, instance, validated_data):
        # a note keeps its agent and its author, only the text changes
        text = {k: v for k, v in validated_data.items() if k == "note"}
        return super().update(instance, text)


class AgentHistorySerializer(serializers.ModelSerializer):
    script_name = serializers.ReadOnlyField(source="script.name")

    class Meta:
        model = AgentHistory
        fields = "__all__"


class AgentHistoryResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentHistory
        fields = ("results", "script_results")


class AgentAuditSerializer(serializers.ModelSerializer):
    """Snapshot for the audit log. The uninstall code appears only as a
    keyed hash, so audit rows never hold the ciphertext."""

    class Meta:
        model = Agent
        exclude = ["disks", "services", "wmi_detail"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if "uninstall_code" in data:
            data["uninstall_code"] = hmac_marker(instance.uninstall_code)
        return data


class AgentTerminalDefaultsSerializer(serializers.ModelSerializer):
    resolved_default_shell = serializers.ReadOnlyField()
    effective_default_shell = serializers.ReadOnlyField()
    terminal_mode = serializers.SerializerMethodField()
    supports_new_terminal = serializers.SerializerMethodField()

    class Meta:
        model = Agent
        fields = tuple("""
            agent_id hostname plat default_shell resolved_default_shell
            effective_default_shell terminal_mode supports_new_terminal
            """.split())

    def get_terminal_mode(self, obj) -> str:
        core = self.context.get("core_settings")
        return str(getattr(core, "terminal_mode", None) or TerminalModeChoices.NEW)

    def get_supports_new_terminal(self, obj) -> bool:
        return bool(self.context.get("supports_new_terminal", False))

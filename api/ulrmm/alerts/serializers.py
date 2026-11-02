# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from typing import Any, Optional

from django.utils import timezone as djangotime
from rest_framework import serializers

from automation.serializers import PolicySerializer
from clients.serializers import ClientMinimumSerializer, SiteMinimumSerializer
from logs.models import mask_env_vars
from scripts.models import check_env_vars
from ulrmm.constants import AlertTemplateActionType

from .models import Alert, AlertTemplate

ENV_FIELDS = ("action_env_vars", "resolved_action_env_vars")
ENV_MASK = "********"


class AlertSerializer(serializers.ModelSerializer):
    hostname = serializers.ReadOnlyField()
    agent_id = serializers.ReadOnlyField(source="assigned_agent.agent_id")
    client = serializers.ReadOnlyField(source="client.name")
    site = serializers.ReadOnlyField(source="site.name")
    alert_time = serializers.ReadOnlyField()

    class Meta:
        model = Alert
        fields = "__all__"
        # what the server records (stamps, action output, links) is not editable
        read_only_fields = tuple("""
            network_device assigned_check assigned_task resolved_on email_sent
            resolved_email_sent sms_sent resolved_sms_sent action_run action_stdout
            action_stderr action_retcode action_execution_time resolved_action_run
            resolved_action_stdout resolved_action_stderr resolved_action_retcode
            resolved_action_execution_time
            """.split())

    @staticmethod
    def _stamp_resolution(data: dict, was_resolved: bool) -> None:
        if "resolved" not in data:
            return
        if not data["resolved"]:
            data["resolved_on"] = None
        elif not was_resolved:
            data["resolved_on"] = djangotime.now()

    def create(self, validated_data):
        self._stamp_resolution(validated_data, False)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # an alert stays with the agent it was raised for
        validated_data.pop("agent", None)
        self._stamp_resolution(validated_data, instance.resolved)
        return super().update(instance, validated_data)


def _masked(env_vars: Optional[list]) -> Optional[list]:
    if not env_vars:
        return env_vars
    return [
        f"{str(item).partition('=')[0]}={ENV_MASK}" if "=" in str(item) else ENV_MASK
        for item in env_vars
    ]


def _unmasked(field: str, submitted: Optional[list], stored: Optional[list]) -> Any:
    """A masked entry sent back means: keep the stored value of that name."""
    if not submitted:
        return submitted
    known = {
        item.partition("=")[0]: item
        for item in stored or []
        if isinstance(item, str) and "=" in item
    }
    result = []
    for item in submitted:
        name, sep, value = (
            item.partition("=") if isinstance(item, str) else ("", "", "")
        )
        if sep and value == ENV_MASK:
            if name not in known:
                raise serializers.ValidationError(
                    {field: f"{name[:64]} has no stored value to keep."}
                )
            result.append(known[name])
        else:
            result.append(item)
    return result


class _MaskedEnvVarsMixin:
    """Env var values are secrets: only callers that pass reveal_env_vars in
    the context (users who manage templates) get them in clear."""

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not self.context.get("reveal_env_vars"):
            for field in ENV_FIELDS:
                if field in data:
                    data[field] = _masked(data[field])
        return data


class AlertTemplateSerializer(_MaskedEnvVarsMixin, serializers.ModelSerializer):
    agent_settings = serializers.ReadOnlyField(source="has_agent_settings")
    check_settings = serializers.ReadOnlyField(source="has_check_settings")
    task_settings = serializers.ReadOnlyField(source="has_task_settings")
    core_settings = serializers.ReadOnlyField(source="has_core_settings")
    default_template = serializers.ReadOnlyField(source="is_default_template")
    action_name = serializers.SerializerMethodField()
    resolved_action_name = serializers.SerializerMethodField()
    applied_count = serializers.SerializerMethodField()

    class Meta:
        model = AlertTemplate
        fields = "__all__"
        read_only_fields = tuple(
            "created_by created_time modified_by modified_time".split()
        )

    @staticmethod
    def _name_of(obj: AlertTemplate, prefix: str) -> str:
        hook = getattr(obj, f"{prefix}action_rest")
        if (
            getattr(obj, f"{prefix}action_type") == AlertTemplateActionType.REST
            and hook
        ):
            return hook.name
        script = getattr(obj, f"{prefix}action")
        return script.name if script else ""

    def get_action_name(self, obj: AlertTemplate) -> str:
        return self._name_of(obj, "")

    def get_resolved_action_name(self, obj: AlertTemplate) -> str:
        return self._name_of(obj, "resolved_")

    def get_applied_count(self, obj: AlertTemplate) -> int:
        return obj.policies.count() + obj.clients.count() + obj.sites.count()

    def _current(self, attrs: dict, field: str) -> Any:
        if field in attrs:
            return attrs[field]
        return getattr(self.instance, field, None)

    def validate(self, attrs):
        for prefix in ("", "resolved_"):
            env_field = f"{prefix}action_env_vars"
            if env_field in attrs:
                script = self._current(attrs, f"{prefix}action")
                # the template's own stored values win over the script defaults
                attrs[env_field] = _unmasked(
                    env_field,
                    attrs[env_field],
                    [
                        *(getattr(script, "env_vars", None) or []),
                        *(getattr(self.instance, env_field, None) or []),
                    ],
                )
                check_env_vars(
                    attrs[env_field], self._current(attrs, f"{prefix}action")
                )

            # the chosen kind needs its target, else the action cannot run
            touched = {
                f"{prefix}action_type",
                f"{prefix}action",
                f"{prefix}action_rest",
            }
            if not touched & attrs.keys():
                continue
            kind = self._current(attrs, f"{prefix}action_type")
            script = self._current(attrs, f"{prefix}action")
            hook = self._current(attrs, f"{prefix}action_rest")
            if not (script or hook):
                continue
            if kind == AlertTemplateActionType.REST and not hook:
                raise serializers.ValidationError(
                    {f"{prefix}action_rest": "Select a web hook for this action."}
                )
            if kind != AlertTemplateActionType.REST and not script:
                raise serializers.ValidationError(
                    {f"{prefix}action": "Select a script for this action."}
                )
        return attrs


class AlertTemplateRelationSerializer(_MaskedEnvVarsMixin, serializers.ModelSerializer):
    policies = PolicySerializer(many=True, read_only=True)
    clients = ClientMinimumSerializer(many=True, read_only=True)
    sites = SiteMinimumSerializer(many=True, read_only=True)

    class Meta:
        model = AlertTemplate
        fields = "__all__"


class AlertTemplateAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertTemplate
        fields = "__all__"

    def to_representation(self, instance):
        # audit rows never hold env var values
        data = super().to_representation(instance)
        for field in ENV_FIELDS:
            data[field] = mask_env_vars(data.get(field))
        return data

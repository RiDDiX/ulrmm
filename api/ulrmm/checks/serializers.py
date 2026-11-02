# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import math
import re
from typing import Any, Optional

import validators as _validators
from rest_framework import serializers

from autotasks.models import AutomatedTask
from logs.models import mask_env_vars
from scripts.models import Script, check_env_vars
from scripts.serializers import keep_masked_env_vars
from scripts.serializers import ScriptCheckSerializer
from metrics.state import SERIES
from ulrmm.constants import AgentPlat, CheckType, MetricOp

from .health import (
    DEFAULT_RUN_INTERVAL,
    DEFAULT_THRESHOLDS,
    HEALTH_CHECK_TYPES,
    MIN_RUN_INTERVAL,
)
from .models import Check, CheckHistory, CheckResult

ENV_MASK = "********"

# never written through the API: the server stamps or derives them
CHECK_READ_ONLY = tuple("""
    created_by created_time modified_by modified_time
    overridden_by_policy managed_by_policy
    """.split())
# fixed once the check exists
CHECK_IMMUTABLE = ("agent", "policy", "check_type")

UNIT_RE = re.compile(r"[A-Za-z0-9@._:\\-]+")
CONTAINER_RE = re.compile(r"[A-Za-z0-9@._:/\\-]{1,255}")
UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".target",
    ".mount",
    ".automount",
    ".path",
    ".swap",
    ".slice",
    ".scope",
    ".device",
)
MAX_METRIC_LABELS = 4
MAX_LABEL_VALUE = 64


class AssignedTaskField(serializers.ModelSerializer):
    # the checks table shows the count and the name, nothing more
    class Meta:
        model = AutomatedTask
        fields = ("id", "name", "enabled")


class CheckResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckResult
        fields = "__all__"


def _masked_env_vars(env_vars: Optional[list]) -> Optional[list]:
    if not env_vars:
        return env_vars
    return [
        f"{str(item).partition('=')[0]}={ENV_MASK}" if "=" in str(item) else ENV_MASK
        for item in env_vars
    ]


class CheckSerializer(serializers.ModelSerializer):
    readable_desc = serializers.ReadOnlyField()
    assignedtasks = AssignedTaskField(many=True, read_only=True)
    alert_template = serializers.SerializerMethodField()
    check_result = serializers.SerializerMethodField()

    class Meta:
        model = Check
        fields = "__all__"
        read_only_fields = CHECK_READ_ONLY

    def get_alert_template(self, obj: Check) -> Optional[dict[str, Any]]:
        template = obj.agent.alert_template if obj.agent else None
        if not template:
            return None
        return {
            "name": template.name,
            "always_email": template.check_always_email,
            "always_text": template.check_always_text,
            "always_alert": template.check_always_alert,
        }

    def get_check_result(self, obj: Check) -> dict[str, Any]:
        if isinstance(obj.check_result, CheckResult):
            return CheckResultSerializer(obj.check_result).data
        return {}

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # values may be credentials: shown only to those who may edit them
        if not self.context.get("reveal_env_vars"):
            data["env_vars"] = _masked_env_vars(data.get("env_vars"))
        return data

    def _current(self, attrs: dict, name: str) -> Any:
        if name in attrs:
            return attrs[name]
        return getattr(self.instance, name, None)

    def _owner(self, attrs: dict) -> dict[str, Any]:
        if attrs.get("agent"):
            return {"agent": attrs["agent"]}
        return {"policy": attrs.get("policy")}

    def validate(self, attrs):
        creating = self.instance is None

        if creating:
            if bool(attrs.get("agent")) == bool(attrs.get("policy")):
                raise serializers.ValidationError(
                    "A check belongs to either an agent or a policy."
                )
        else:
            for name in CHECK_IMMUTABLE:
                attrs.pop(name, None)

        if "env_vars" in attrs:
            script = self._current(attrs, "script")
            # masked values keep the stored one, the check's own over the script's
            attrs["env_vars"] = keep_masked_env_vars(
                attrs["env_vars"],
                [
                    *(getattr(script, "env_vars", None) or []),
                    *(getattr(self.instance, "env_vars", None) or []),
                ],
            )
            check_env_vars(attrs["env_vars"], script)

        check_type = self._current(attrs, "check_type") or CheckType.DISK_SPACE
        if check_type in HEALTH_CHECK_TYPES:
            self._validate_health(attrs, check_type)

        validate = getattr(self, f"_validate_{check_type}", None)
        if validate:
            validate(attrs, creating)
        return attrs

    def _exists(self, attrs: dict, **lookup) -> bool:
        return Check.objects.filter(**self._owner(attrs), **lookup).exists()

    def _thresholds(self, attrs: dict) -> tuple[int, int]:
        warn = self._current(attrs, "warning_threshold") or 0
        err = self._current(attrs, "error_threshold") or 0
        if not warn and not err:
            raise serializers.ValidationError(
                "Warning threshold or Error Threshold must be set"
            )
        return warn, err

    def _validate_diskspace(self, attrs: dict, creating: bool) -> None:
        disk = self._current(attrs, "disk")
        if not disk:
            raise serializers.ValidationError({"disk": "Choose a drive."})
        if creating and self._exists(attrs, check_type=CheckType.DISK_SPACE, disk=disk):
            raise serializers.ValidationError(
                f"A disk check for Drive {disk} already exists!"
            )
        warn, err = self._thresholds(attrs)
        # free space: the error level is the lower one
        if warn > 0 and err > 0 and warn < err:
            raise serializers.ValidationError(
                "Warning threshold must be greater than Error Threshold"
            )

    def _validate_load(self, attrs: dict, creating: bool, kind: str) -> None:
        if creating and self._exists(attrs, check_type=kind):
            raise serializers.ValidationError(
                f"A {kind} check for this agent already exists"
            )
        warn, err = self._thresholds(attrs)
        if warn > 0 and err > 0 and warn > err:
            raise serializers.ValidationError(
                "Warning threshold must be less than Error Threshold"
            )

    def _validate_cpuload(self, attrs: dict, creating: bool) -> None:
        self._validate_load(attrs, creating, CheckType.CPU_LOAD)

    def _validate_memory(self, attrs: dict, creating: bool) -> None:
        self._validate_load(attrs, creating, CheckType.MEMORY)

    def _validate_ping(self, attrs: dict, creating: bool) -> None:
        target = self._current(attrs, "ip") or ""
        # the agent hands this to its ping tool, nothing but a host is allowed
        valid = not target.startswith("-") and (
            _validators.ipv4(target)
            or _validators.ipv6(target)
            or _validators.domain(target)
        )
        if not valid:
            raise serializers.ValidationError(
                "Please enter a valid IP address or domain name"
            )

    def _validate_script(self, attrs: dict, creating: bool) -> None:
        if not self._current(attrs, "script"):
            raise serializers.ValidationError({"script": "Choose a script."})

    def _validate_winsvc(self, attrs: dict, creating: bool) -> None:
        if not self._current(attrs, "svc_name"):
            raise serializers.ValidationError({"svc_name": "Choose a service."})

    def _validate_eventlog(self, attrs: dict, creating: bool) -> None:
        if not self._current(attrs, "log_name"):
            raise serializers.ValidationError({"log_name": "Choose an event log."})

    def _validate_systemd(self, attrs: dict, creating: bool) -> None:
        unit = self._current(attrs, "svc_name") or ""
        if not unit:
            raise serializers.ValidationError({"svc_name": "Enter a systemd unit."})
        if not UNIT_RE.fullmatch(unit) or unit.startswith("-"):
            raise serializers.ValidationError(
                {
                    "svc_name": "Unit names may contain letters, digits and @ . _ : - "
                    "and must not start with -"
                }
            )
        agent = self._current(attrs, "agent")
        # rc.d names have no suffix; the agent strips one a policy check adds
        freebsd = getattr(agent, "plat", None) == AgentPlat.FREEBSD
        if not freebsd and not unit.endswith(UNIT_SUFFIXES):
            unit += ".service"
        if len(unit) > 255:
            raise serializers.ValidationError({"svc_name": "Unit name too long."})
        if "svc_name" in attrs or creating:
            attrs["svc_name"] = unit
        if creating and self._exists(
            attrs, check_type=CheckType.SYSTEMD, svc_name=unit
        ):
            raise serializers.ValidationError(
                f"A systemd check for {unit} already exists"
            )

    def _validate_container(self, attrs: dict, creating: bool) -> None:
        name = self._current(attrs, "container") or ""
        if not CONTAINER_RE.fullmatch(name) or name.startswith("-"):
            raise serializers.ValidationError(
                {"container": "Enter a container, VM name or id."}
            )
        kind = self._current(attrs, "container_kind") or ""
        if creating and self._exists(
            attrs, check_type=CheckType.CONTAINER, container=name, container_kind=kind
        ):
            raise serializers.ValidationError(
                f"A container check for {name} already exists"
            )

    def _validate_metric(self, attrs: dict, creating: bool) -> None:
        name = self._current(attrs, "metric")
        if name not in SERIES:
            raise serializers.ValidationError({"metric": "Choose a metric."})
        labels = self._current(attrs, "metric_labels") or {}
        if not isinstance(labels, dict) or len(labels) > MAX_METRIC_LABELS:
            raise serializers.ValidationError({"metric_labels": "Invalid labels."})
        for key, value in labels.items():
            if (
                key not in SERIES[name]
                or not isinstance(value, str)
                or not 0 < len(value) <= MAX_LABEL_VALUE
                or any(ord(c) < 32 or ord(c) == 127 for c in value)
            ):
                raise serializers.ValidationError(
                    {"metric_labels": f"Invalid label {key}."}
                )
        for key in SERIES[name]:
            if key not in labels:
                raise serializers.ValidationError(
                    {"metric_labels": f"Missing label {key}, use * for any."}
                )
        attrs["metric_labels"] = labels

        warn = self._current(attrs, "metric_warning")
        err = self._current(attrs, "metric_error")
        if warn is None and err is None:
            raise serializers.ValidationError(
                "Warning threshold or Error Threshold must be set"
            )
        if any(v is not None and not math.isfinite(v) for v in (warn, err)):
            raise serializers.ValidationError("Thresholds must be numbers")
        if warn is not None and err is not None:
            below = self._current(attrs, "metric_op") == MetricOp.BELOW
            if below and warn <= err:
                raise serializers.ValidationError(
                    "Warning threshold must be greater than Error Threshold"
                )
            if not below and warn >= err:
                raise serializers.ValidationError(
                    "Warning threshold must be less than Error Threshold"
                )
        if creating and self._exists(
            attrs, check_type=CheckType.METRIC, metric=name, metric_labels=labels
        ):
            raise serializers.ValidationError(
                f"A metric check for {name} with these labels already exists"
            )

    def _validate_health_duplicate(self, attrs: dict, creating: bool) -> None:
        kind = self._current(attrs, "check_type")
        if creating and self._exists(attrs, check_type=kind):
            raise serializers.ValidationError(
                f"A {kind} check for this agent already exists"
            )

    _validate_security = _validate_health_duplicate
    _validate_hwhealth = _validate_health_duplicate

    def _validate_health(self, attrs: dict, check_type: str) -> None:
        creating = self.instance is None
        if creating:
            warn, err = DEFAULT_THRESHOLDS[check_type]
            attrs.setdefault("warning_threshold", warn)
            attrs.setdefault("error_threshold", err)

        if creating or "run_interval" in attrs:
            interval = attrs.get("run_interval") or 0
            if not interval:
                attrs["run_interval"] = DEFAULT_RUN_INTERVAL
            elif interval < MIN_RUN_INTERVAL:
                raise serializers.ValidationError(
                    f"Run interval must be at least {MIN_RUN_INTERVAL} seconds"
                )

        # days old / percent worn: the error level is the higher one
        warn = self._current(attrs, "warning_threshold") or 0
        err = self._current(attrs, "error_threshold") or 0
        if warn and err and warn >= err:
            raise serializers.ValidationError(
                "Warning threshold must be less than Error Threshold"
            )


class CheckRunnerGetSerializer(serializers.ModelSerializer):
    script = ScriptCheckSerializer(read_only=True)
    script_args = serializers.SerializerMethodField()
    env_vars = serializers.SerializerMethodField()

    class Meta:
        model = Check
        exclude = tuple("""
            policy overridden_by_policy name email_alert text_alert fails_b4_alert
            svc_display_name svc_policy_mode created_by created_time modified_by
            modified_time dashboard_alert metric metric_labels metric_op
            metric_warning metric_error metric_samples
            """.split())

    def _agent(self, obj: Check):
        return self.context.get("agent") or obj.agent

    def get_script_args(self, obj: Check) -> list:
        if obj.check_type != CheckType.SCRIPT:
            return []
        return Script.parse_script_args(
            agent=self._agent(obj), shell=obj.script.shell, args=obj.script_args
        )

    def get_env_vars(self, obj: Check) -> list:
        if obj.check_type != CheckType.SCRIPT:
            return []
        return Script.parse_script_env_vars(
            agent=self._agent(obj), shell=obj.script.shell, env_vars=obj.env_vars
        )


class CheckHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckHistory
        fields = ("x", "y", "results")


class CheckAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Check
        fields = "__all__"

    def to_representation(self, instance):
        # the audit log keeps the names, never the values
        data = super().to_representation(instance)
        data["env_vars"] = mask_env_vars(data["env_vars"])
        return data

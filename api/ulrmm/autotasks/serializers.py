# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
from typing import Any, Optional

from django.conf import settings
from django.utils import timezone as djangotime
from rest_framework import serializers

from checks.serializers import _masked_env_vars
from logs.models import mask_env_vars
from scripts.models import Script, check_env_vars
from scripts.serializers import keep_masked_env_vars
from ulrmm.constants import AgentPlat, TaskType

from .models import AutomatedTask, TaskResult

# what the agent stores per run; the request cap is 10 MB, a row does not need it
RESULT_OUTPUT_CAP = 1024 * 1024
MAX_ACTION_TIMEOUT = 86400
DEFAULT_ACTION_TIMEOUT = 30
MAX_SHELL_LENGTH = 255

# the dashboard's own rule: 1-3 digits and a unit
DURATION = re.compile(r"\d{1,3}[DHMSdhms]")
DURATION_SECONDS = {"D": 86400, "H": 3600, "M": 60, "S": 1}

# limits the Windows agent enforces on a scheduled task
BITMASK_LIMITS = {
    "run_time_bit_weekdays": 0x7F,
    "monthly_months_of_year": 0xFFF,
    "monthly_weeks_of_month": 0x1F,
    "monthly_days_of_month": 0xFFFFFFFF,
}

# required per task type, besides run_time_date
SCHEDULE_FIELDS = {
    TaskType.DAILY: ("daily_interval",),
    TaskType.WEEKLY: ("weekly_interval", "run_time_bit_weekdays"),
    TaskType.MONTHLY: ("monthly_months_of_year", "monthly_days_of_month"),
    TaskType.MONTHLY_DOW: (
        "monthly_months_of_year",
        "monthly_weeks_of_month",
        "run_time_bit_weekdays",
    ),
}
CALENDAR_TYPES = (*SCHEDULE_FIELDS, TaskType.RUN_ONCE)

# an edit that does not name a task type leaves the schedule alone
SCHEDULE_KEYS = tuple("""
    run_time_date expire_date daily_interval weekly_interval run_time_bit_weekdays
    monthly_months_of_year monthly_days_of_month monthly_weeks_of_month
    assigned_check
    """.split())

OWNER_FIELDS = ("agent", "policy")

NO_ACTIONS = "There must be at least one action configured"
BAD_ACTION_TYPE = "Each action must have a type field of either 'script' or 'cmd'"
SCRIPT_ACTION_NEEDS = {
    "script": "A script action type must have a 'script' field with primary key of script",
    "script_args": "A script action type must have a 'script_args' field with an array of arguments",
    "timeout": "A script action type must have a 'timeout' field",
}
CMD_ACTION_NEEDS = {
    "command": "A command action type must have a 'command' field",
    "timeout": "A command action type must have a 'timeout' field",
}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _seconds(duration: str) -> int:
    return int(duration[:-1]) * DURATION_SECONDS[duration[-1].upper()]


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def _check_timeout(action: dict) -> None:
    timeout = action["timeout"]
    if not _is_int(timeout) or not 1 <= timeout <= MAX_ACTION_TIMEOUT:
        raise serializers.ValidationError(
            f"An action timeout must be a number of seconds from 1 to {MAX_ACTION_TIMEOUT}"
        )


def _check_script_action(action: dict) -> None:
    for key, message in SCRIPT_ACTION_NEEDS.items():
        if key not in action:
            raise serializers.ValidationError(message)

    pk = action["script"]
    # older rows may store the pk as text; keep them editable, store an int
    if isinstance(pk, str) and pk.isascii() and pk.isdigit():
        pk = action["script"] = int(pk)
    script = Script.objects.filter(pk=pk).first() if _is_int(pk) else None
    if script is None:
        raise serializers.ValidationError(f"Script {str(pk)[:20]} does not exist")
    if not _is_string_list(action["script_args"]):
        raise serializers.ValidationError("Script arguments must be a list of text")
    _check_timeout(action)

    env_vars = action.get("env_vars")
    if env_vars is not None and not _is_string_list(env_vars):
        raise serializers.ValidationError(
            "Environment variables must be a list of NAME=value"
        )
    if env_vars is not None:
        # masked script defaults sent back by the web keep the stored value
        env_vars = action["env_vars"] = keep_masked_env_vars(env_vars, script.env_vars)
    check_env_vars(env_vars, script)


def _check_cmd_action(action: dict, position: int = 1) -> None:
    for key, message in CMD_ACTION_NEEDS.items():
        if key not in action:
            raise serializers.ValidationError(message)

    command = action["command"]
    if not isinstance(command, str) or not command.strip():
        raise serializers.ValidationError("A command action needs a command to run")
    _check_timeout(action)

    # a missing shell falls back to the platform default when the agent asks
    shell = action.get("shell")
    if shell == "custom":
        # the form's placeholder choice, never an interpreter. Older forms stored
        # it, so the message names the action to replace
        raise serializers.ValidationError(
            f"Action {position}: enter the path of the custom shell"
        )
    if shell is not None and (
        not isinstance(shell, str)
        or not shell.strip()
        or len(shell) > MAX_SHELL_LENGTH
        or _has_control_chars(shell)
    ):
        raise serializers.ValidationError("A command action needs a valid shell")


class TaskResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskResult
        fields = "__all__"
        read_only_fields = ("agent", "task")


class TaskResultAgentSerializer(serializers.ModelSerializer):
    """What an agent may report about a run. Status, sync and lock state
    belong to the server."""

    class Meta:
        model = TaskResult
        fields = ("stdout", "stderr", "retcode", "execution_time")

    def _capped(self, value: Optional[str]) -> Optional[str]:
        return value[:RESULT_OUTPUT_CAP] if value else value

    def validate_stdout(self, value: Optional[str]) -> Optional[str]:
        return self._capped(value)

    def validate_stderr(self, value: Optional[str]) -> Optional[str]:
        return self._capped(value)


class TaskSerializer(serializers.ModelSerializer):
    check_name = serializers.ReadOnlyField(source="assigned_check.readable_desc")
    schedule = serializers.ReadOnlyField()
    alert_template = serializers.SerializerMethodField()
    task_result = serializers.SerializerMethodField()
    run_time_date = serializers.DateTimeField(required=False)
    expire_date = serializers.DateTimeField(allow_null=True, required=False)

    class Meta:
        model = AutomatedTask
        fields = "__all__"
        # stamped by the server; the scheduled task name is always generated
        read_only_fields = (
            "created_by",
            "modified_by",
            "managed_by_policy",
            "run_time_minute",
            "win_task_name",
        )

    def get_alert_template(self, obj: AutomatedTask) -> Optional[dict[str, Any]]:
        template = obj.agent.alert_template if obj.agent else None
        if not template:
            return None
        return {
            "name": template.name,
            "always_email": template.task_always_email,
            "always_text": template.task_always_text,
            "always_alert": template.task_always_alert,
        }

    def get_task_result(self, obj: AutomatedTask) -> dict[str, Any]:
        if isinstance(obj.task_result, TaskResult):
            return TaskResultSerializer(obj.task_result).data
        return {}

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # values may be credentials: shown only to those who may edit them
        if not self.context.get("reveal_env_vars") and isinstance(
            data.get("actions"), list
        ):
            data["actions"] = [
                (
                    {**action, "env_vars": _masked_env_vars(action["env_vars"])}
                    if isinstance(action, dict) and "env_vars" in action
                    else action
                )
                for action in data["actions"]
            ]
        return data

    def validate_actions(self, value: Any) -> list:
        if not isinstance(value, list) or not value:
            raise serializers.ValidationError(NO_ACTIONS)
        for position, action in enumerate(value, 1):
            kind = action.get("type") if isinstance(action, dict) else None
            if kind == "script":
                _check_script_action(action)
            elif kind == "cmd":
                _check_cmd_action(action, position)
            else:
                raise serializers.ValidationError(BAD_ACTION_TYPE)
        return value

    def validate_task_type(self, value: str) -> str:
        if value == TaskType.SCHEDULED:
            raise serializers.ValidationError("Scheduled tasks are no longer supported")
        return value

    def validate_task_instance_policy(self, value: int) -> int:
        if not 0 <= value <= 3:
            raise serializers.ValidationError("Must be a value from 0 to 3")
        return value

    def _check_bitmask(self, name: str, value: Optional[int]) -> Optional[int]:
        if value is not None and not 1 <= value <= BITMASK_LIMITS[name]:
            raise serializers.ValidationError(
                f"Must be a value from 1 to {BITMASK_LIMITS[name]}"
            )
        return value

    def validate_run_time_bit_weekdays(self, value):
        return self._check_bitmask("run_time_bit_weekdays", value)

    def validate_monthly_months_of_year(self, value):
        return self._check_bitmask("monthly_months_of_year", value)

    def validate_monthly_weeks_of_month(self, value):
        return self._check_bitmask("monthly_weeks_of_month", value)

    def validate_monthly_days_of_month(self, value):
        return self._check_bitmask("monthly_days_of_month", value)

    def _check_duration(self, value: Optional[str]) -> Optional[str]:
        if value and not DURATION.fullmatch(value):
            raise serializers.ValidationError(
                "Valid values are 1-3 digits followed by D, H, M or S"
            )
        return value

    def validate_random_task_delay(self, value):
        return self._check_duration(value)

    def validate_task_repetition_interval(self, value):
        return self._check_duration(value)

    def validate_task_repetition_duration(self, value):
        return self._check_duration(value)

    def _current(self, attrs: dict, name: str) -> Any:
        if name in attrs:
            return attrs[name]
        return getattr(self.instance, name, None)

    def validate(self, attrs: dict) -> dict:
        creating = self.instance is None
        if creating:
            self._check_new_task(attrs)
        else:
            self._keep_owner(attrs)

        self._check_repetition(attrs)

        if not creating and "task_type" not in attrs:
            for key in SCHEDULE_KEYS:
                attrs.pop(key, None)
            return attrs

        self._check_schedule(attrs)
        return attrs

    def _check_new_task(self, attrs: dict) -> None:
        if bool(attrs.get("agent")) == bool(attrs.get("policy")):
            raise serializers.ValidationError(
                "A task belongs to either an agent or a policy."
            )
        if not attrs.get("task_type"):
            raise serializers.ValidationError({"task_type": "This field is required."})
        if not attrs.get("actions"):
            raise serializers.ValidationError({"actions": NO_ACTIONS})

    def _keep_owner(self, attrs: dict) -> None:
        for name in OWNER_FIELDS:
            if name in attrs and attrs[name] != getattr(self.instance, name):
                raise serializers.ValidationError(
                    {name: f"The {name} of a task cannot be changed."}
                )
            attrs.pop(name, None)

    def _check_repetition(self, attrs: dict) -> None:
        if not (
            "task_repetition_interval" in attrs or "task_repetition_duration" in attrs
        ):
            return
        interval = self._current(attrs, "task_repetition_interval")
        duration = self._current(attrs, "task_repetition_duration")
        if not interval:
            return
        if not duration:
            raise serializers.ValidationError(
                "A repeating task needs a repeat duration as well"
            )
        if _seconds(duration) < _seconds(interval):
            raise serializers.ValidationError(
                "Repetition duration must be greater than repetition interval"
            )

    def _check_schedule(self, attrs: dict) -> None:
        task_type = self._current(attrs, "task_type")
        start = self._current(attrs, "run_time_date")
        expire = self._current(attrs, "expire_date")

        if attrs.get("expire_date") and attrs["expire_date"] < djangotime.now():
            raise serializers.ValidationError("Expires date/time is in the past")

        if task_type in CALENDAR_TYPES:
            if not start:
                raise serializers.ValidationError(
                    f"run_time_date is required for task_type '{task_type}'"
                )
            if expire and expire <= start:
                raise serializers.ValidationError(
                    "Expires date/time must be after the start date/time"
                )

        for field in SCHEDULE_FIELDS.get(task_type, ()):
            if not self._current(attrs, field):
                raise serializers.ValidationError(
                    f"{field} is required for task_type '{task_type}'"
                )

        check = attrs.get("assigned_check")
        if task_type == TaskType.CHECK_FAILURE and not self._current(
            attrs, "assigned_check"
        ):
            raise serializers.ValidationError(
                "assigned_check is required for task_type 'checkfailure'"
            )
        if check and not self._check_belongs_to_owner(attrs, check):
            raise serializers.ValidationError(
                {
                    "assigned_check": "The check must belong to the task's agent or policy."
                }
            )

    def _check_belongs_to_owner(self, attrs: dict, check) -> bool:
        policy = self._current(attrs, "policy")
        if policy:
            return check.policy_id == policy.pk
        agent = self._current(attrs, "agent")
        if not agent:
            return False
        if check.agent_id == agent.pk:
            return True
        # a check the agent inherits from one of its policies
        return bool(check.policy_id) and check.pk in {
            inherited.pk for inherited in agent.get_checks_with_policies()
        }


class TaskGOGetSerializer(serializers.ModelSerializer):
    task_actions = serializers.SerializerMethodField()

    class Meta:
        model = AutomatedTask
        fields = ("id", "continue_on_error", "enabled", "task_actions")

    def get_task_actions(self, obj: AutomatedTask) -> list[dict[str, Any]]:
        agent = self.context["agent"]
        actions = [a for a in obj.actions or [] if isinstance(a, dict)]
        script_pks = {a.get("script") for a in actions if a.get("type") == "script"} - {
            None
        }
        scripts = Script.objects.in_bulk([pk for pk in script_pks if str(pk).isdigit()])
        default_shell = {AgentPlat.WINDOWS: "cmd", AgentPlat.FREEBSD: "/bin/sh"}.get(
            agent.plat, "/bin/bash"
        )

        out = []
        for action in actions:
            timeout = action.get("timeout") or DEFAULT_ACTION_TIMEOUT
            if action.get("type") == "cmd":
                shell = action.get("shell") or default_shell
                command = str(action.get("command") or "")
                out.append(
                    {
                        "type": "cmd",
                        "command": Script.parse_script_args(
                            agent, shell=shell, args=[command]
                        )[0],
                        "shell": shell,
                        "timeout": timeout,
                    }
                )
            elif action.get("type") == "script":
                pk = action.get("script")
                script = scripts.get(int(pk)) if str(pk).isdigit() else None
                if script is None:
                    # the run goes on without it; the stored task stays as it is
                    continue
                out.append(
                    {
                        "type": "script",
                        "script_name": script.name,
                        "code": script.code,
                        "script_args": Script.parse_script_args(
                            agent, shell=script.shell, args=action.get("script_args")
                        ),
                        "shell": script.shell,
                        "timeout": timeout,
                        "run_as_user": script.run_as_user,
                        "env_vars": Script.parse_script_env_vars(
                            agent, shell=script.shell, env_vars=action.get("env_vars")
                        ),
                        "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
                        "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
                    }
                )
        return out


class TaskAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomatedTask
        fields = "__all__"

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if isinstance(data.get("actions"), list):
            data["actions"] = [
                (
                    {**action, "env_vars": mask_env_vars(action["env_vars"])}
                    if isinstance(action, dict) and "env_vars" in action
                    else action
                )
                for action in data["actions"]
            ]
        return data

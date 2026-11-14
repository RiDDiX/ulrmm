# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import math
from statistics import mean
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Optional

from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import IntegrityError, models, transaction
from django.utils import timezone as djangotime
from rest_framework.exceptions import ValidationError

from logs.models import BaseAuditModel, DebugLog
from ulrmm.constants import (
    CHECKS_NON_EDITABLE_FIELDS,
    POLICY_CHECK_FIELDS_TO_COPY,
    AlertSeverity,
    CheckStatus,
    CheckType,
    ContainerKind,
    DebugLogType,
    EvtLogFailWhen,
    EvtLogNames,
    EvtLogTypes,
    MetricOp,
)
from ulrmm.helpers import has_script_actions, has_webhook
from ulrmm.models import PermissionQuerySet

from . import health
from .constants import CHECK_RESULT_DEFER

if TYPE_CHECKING:
    from agents.models import Agent
    from alerts.models import Alert, AlertTemplate
    from automation.models import Policy

# rolling window of cpu / memory samples the average is taken over
LOAD_SAMPLES = 15

# limits on what an agent may store through a check result
OUTPUT_CAP = 64 * 1024
TEXT_CAP = 4 * 1024
MAX_EVENTS = 1000
HISTORY_TEXT = 60
INT64_LIMIT = 2**63


class Check(BaseAuditModel):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(
        "agents.Agent",
        related_name="agentchecks",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="policychecks",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    overridden_by_policy = models.BooleanField(default=False)
    name = models.CharField(max_length=255, null=True, blank=True)
    check_type = models.CharField(
        max_length=50, choices=CheckType.choices, default=CheckType.DISK_SPACE
    )
    email_alert = models.BooleanField(default=False)
    text_alert = models.BooleanField(default=False)
    dashboard_alert = models.BooleanField(default=False)
    fails_b4_alert = models.PositiveIntegerField(default=1)
    run_interval = models.PositiveIntegerField(blank=True, default=0)
    alert_severity = models.CharField(
        max_length=15,
        choices=AlertSeverity.choices,
        default=AlertSeverity.WARNING,
        null=True,
        blank=True,
    )

    # diskspace, cpuload, memory, security and hwhealth
    error_threshold = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(99)],
        null=True,
        blank=True,
        default=0,
    )
    warning_threshold = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(99)],
        null=True,
        blank=True,
        default=0,
    )

    # diskspace
    # a drive letter on windows, a mount path on linux and macos
    disk = models.CharField(max_length=255, null=True, blank=True)

    # ping
    ip = models.CharField(max_length=255, null=True, blank=True)

    # script
    script = models.ForeignKey(
        "scripts.Script",
        related_name="script",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    script_args = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    env_vars = ArrayField(
        models.TextField(null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    info_return_codes = ArrayField(
        models.BigIntegerField(),
        null=True,
        blank=True,
        default=list,
    )
    warning_return_codes = ArrayField(
        models.BigIntegerField(),
        null=True,
        blank=True,
        default=list,
    )
    success_return_codes = ArrayField(
        models.PositiveBigIntegerField(),
        null=True,
        blank=True,
        default=list,
    )
    timeout = models.PositiveIntegerField(null=True, blank=True)

    # windows service
    svc_name = models.CharField(max_length=255, null=True, blank=True)
    svc_display_name = models.CharField(max_length=255, null=True, blank=True)
    pass_if_start_pending = models.BooleanField(null=True, blank=True)
    pass_if_svc_not_exist = models.BooleanField(default=False)
    restart_if_stopped = models.BooleanField(null=True, blank=True)
    svc_policy_mode = models.CharField(max_length=20, null=True, blank=True)

    # event log
    log_name = models.CharField(
        max_length=255, choices=EvtLogNames.choices, null=True, blank=True
    )
    event_id = models.IntegerField(null=True, blank=True)
    event_id_is_wildcard = models.BooleanField(default=False)
    event_type = models.CharField(
        max_length=255, choices=EvtLogTypes.choices, null=True, blank=True
    )
    event_source = models.CharField(max_length=255, null=True, blank=True)
    event_message = models.TextField(null=True, blank=True)
    fail_when = models.CharField(
        max_length=255, choices=EvtLogFailWhen.choices, null=True, blank=True
    )
    search_last_days = models.PositiveIntegerField(null=True, blank=True)
    number_of_events_b4_alert = models.PositiveIntegerField(
        null=True, blank=True, default=1
    )

    # container; also uses pass_if_svc_not_exist. systemd uses the service fields
    container = models.CharField(max_length=255, null=True, blank=True)
    container_kind = models.CharField(
        max_length=16, choices=ContainerKind.choices, blank=True, default=""
    )

    # metric, judged by the server from the agent's state pushes
    metric = models.CharField(max_length=64, null=True, blank=True)
    metric_labels = models.JSONField(default=dict, blank=True)
    metric_op = models.CharField(
        max_length=8, choices=MetricOp.choices, default=MetricOp.ABOVE
    )
    metric_warning = models.FloatField(null=True, blank=True)
    metric_error = models.FloatField(null=True, blank=True)
    metric_samples = models.PositiveSmallIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(60)]
    )

    # no longer set; post_update_tasks still removes rows that carry it
    managed_by_policy = models.BooleanField(default=False)

    # Agent.add_check_results() puts this agent's CheckResult here. Read-only
    # stand-in for "never ran", so no instance can mutate a shared default.
    check_result = MappingProxyType({})

    def __str__(self) -> str:
        if self.agent_id or not self.policy_id:
            return self.readable_desc
        return f"{self.policy.name} - {self.readable_desc}"

    def threshold_text(self, unit: str) -> str:
        text = ""
        if self.warning_threshold:
            text += f" Warning Threshold: {self.warning_threshold}{unit}"
        if self.error_threshold:
            text += f" Error Threshold: {self.error_threshold}{unit}"
        return text

    @property
    def readable_desc(self) -> str:
        display = self.get_check_type_display()
        kind = self.check_type

        if kind == CheckType.DISK_SPACE:
            return f"{display}: Drive {self.disk} - {self.threshold_text('%')}"
        if kind in (CheckType.CPU_LOAD, CheckType.MEMORY):
            return f"{display} - {self.threshold_text('%')}"
        if kind in (CheckType.PING, CheckType.EVENT_LOG):
            return f"{display}: {self.name}"
        if kind == CheckType.WINSVC:
            return f"{display}: {self.svc_display_name}"
        if kind == CheckType.SYSTEMD:
            return f"{display}: {self.svc_name}"
        if kind == CheckType.CONTAINER:
            return f"{display}: {self.container}"
        if kind == CheckType.METRIC:
            from metrics.state import series_key

            limits = "/".join(
                "-" if value is None else f"{value:g}"
                for value in (self.metric_warning, self.metric_error)
            )
            series = series_key(self.metric or "", self.metric_labels or {})
            return f"{display}: {series} {self.metric_op} {limits}"
        if kind == CheckType.SCRIPT:
            return f"{display}: {self.script.name if self.script else 'n/a'}"
        if kind in health.HEALTH_CHECK_TYPES:
            text = self.threshold_text(" days" if kind == CheckType.SECURITY else "%")
            return f"{display} -{text}" if text else display
        return "n/a"

    @staticmethod
    def serialize(check: "Check") -> dict[str, Any]:
        from . import serializers

        return serializers.CheckAuditSerializer(check).data

    @staticmethod
    def non_editable_fields() -> list[str]:
        return CHECKS_NON_EDITABLE_FIELDS

    def _forget_cached_checks(self) -> None:
        # the cached policy merge is rebuilt from the database, so the keys go
        # only once the write is visible to other connections
        if self.policy_id:

            def forget() -> None:
                cache.delete_many_pattern("agent_*_checks")

        elif self.agent_id:
            key = f"agent_{self.agent.agent_id}_checks"

            def forget() -> None:
                cache.delete(key)

        else:
            return
        transaction.on_commit(forget)

    def save(self, *args, **kwargs) -> None:
        super().save(*args, **kwargs)
        self._forget_cached_checks()

    def delete(self, *args, **kwargs):
        deleted = super().delete(*args, **kwargs)
        self._forget_cached_checks()
        return deleted

    def create_policy_check(self, policy: "Policy") -> None:
        copy = Check(
            policy=policy,
            **{field: getattr(self, field) for field in POLICY_CHECK_FIELDS_TO_COPY},
        )
        copy.save()
        for task in self.assignedtasks.order_by("pk"):  # type: ignore
            task.create_policy_task(policy=policy, assigned_check=copy)

    def should_create_alert(
        self, alert_template: "Optional[AlertTemplate]" = None
    ) -> bool:
        if self.dashboard_alert or self.email_alert or self.text_alert:
            return True
        if alert_template and (
            alert_template.check_always_alert
            or alert_template.check_always_email
            or alert_template.check_always_text
        ):
            return True
        return has_webhook(alert_template, "check") or has_script_actions(
            alert_template, "check"
        )

    def add_check_history(
        self, value: int, agent_id: str, more_info: Any = None
    ) -> None:
        CheckHistory.objects.create(
            check_id=self.pk, y=value, results=more_info, agent_id=agent_id
        )


def _field(data: dict, key: str) -> Any:
    if key not in data:
        raise ValidationError(f"{key} is missing")
    return data[key]


def _number(data: dict, key: str) -> float:
    value = _field(data, key)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ValidationError(f"{key} must be a number")
    return value


def _percent(data: dict, key: str) -> float:
    return min(max(_number(data, key), 0), 100)


def _text(data: dict, key: str, cap: int) -> str:
    value = data.get(key)
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValidationError(f"{key} must be text")
    return str(value)[:cap]


def _status(data: dict) -> str:
    value = _field(data, "status")
    if value not in (CheckStatus.PASSING, CheckStatus.FAILING):
        raise ValidationError("status must be passing or failing")
    return value


def _event(entry: dict) -> dict:
    return {
        key: value[:TEXT_CAP] if isinstance(value, str) else value
        for key, value in entry.items()
        if value is None or isinstance(value, (str, int, float, bool))
    }


def clean_result(check_type: str, data: Any) -> dict[str, Any]:
    """Checks one agent result body against its check type.

    Returns only the values handle_check uses, typed and capped. Raises a
    ValidationError (400) before anything is stored. Cleaning a cleaned
    result returns it unchanged.
    """
    if not isinstance(data, dict):
        raise ValidationError("result must be an object")

    if check_type in (CheckType.CPU_LOAD, CheckType.MEMORY):
        return {"percent": round(_percent(data, "percent"))}

    if check_type == CheckType.DISK_SPACE:
        exists = _field(data, "exists")
        if not isinstance(exists, bool):
            raise ValidationError("exists must be true or false")
        if not exists:
            return {"exists": False}
        return {
            "exists": True,
            "percent_used": _percent(data, "percent_used"),
            "more_info": _text(data, "more_info", TEXT_CAP),
        }

    if check_type == CheckType.SCRIPT:
        retcode = _field(data, "retcode")
        if (
            isinstance(retcode, bool)
            or not isinstance(retcode, int)
            or not -INT64_LIMIT <= retcode < INT64_LIMIT
        ):
            raise ValidationError("retcode must be a 64-bit integer")
        return {
            "stdout": _text(data, "stdout", OUTPUT_CAP),
            "stderr": _text(data, "stderr", OUTPUT_CAP),
            "retcode": retcode,
            "runtime": max(_number(data, "runtime"), 0),
        }

    if check_type == CheckType.PING:
        return {"status": _status(data), "output": _text(data, "output", TEXT_CAP)}

    if check_type in (CheckType.WINSVC, CheckType.SYSTEMD, CheckType.CONTAINER):
        return {
            "status": _status(data),
            "more_info": _text(data, "more_info", TEXT_CAP),
        }

    if check_type == CheckType.EVENT_LOG:
        log = _field(data, "log")
        if log is None:
            log = []
        if not isinstance(log, list):
            raise ValidationError("log must be a list")
        # every entry counts, the stored copy is cut in handle_check
        return {"log": [_event(e) if isinstance(e, dict) else {} for e in log]}

    if check_type == CheckType.METRIC:
        raise ValidationError("metric checks are evaluated by the server")

    if check_type in health.HEALTH_CHECK_TYPES:
        # untrusted by design, health.evaluate copes with any shape
        return {"health": data.get("health")}

    return {}


class CheckResult(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    assigned_check = models.ForeignKey(
        "checks.Check",
        related_name="checkresults",
        on_delete=models.CASCADE,
    )
    agent = models.ForeignKey(
        "agents.Agent",
        related_name="checkresults",
        on_delete=models.CASCADE,
    )
    status = models.CharField(
        max_length=100, choices=CheckStatus.choices, default=CheckStatus.PENDING
    )
    alert_severity = models.CharField(
        max_length=15,
        choices=AlertSeverity.choices,
        null=True,
        blank=True,
    )
    more_info = models.TextField(null=True, blank=True)
    last_run = models.DateTimeField(null=True, blank=True)
    fail_count = models.PositiveIntegerField(default=0)
    # legacy column, nothing writes it
    outage_history = models.JSONField(null=True, blank=True)
    extra_details = models.JSONField(null=True, blank=True)
    stdout = models.TextField(null=True, blank=True)
    stderr = models.TextField(null=True, blank=True)
    retcode = models.BigIntegerField(null=True, blank=True)
    execution_time = models.CharField(max_length=100, null=True, blank=True)
    history = ArrayField(
        models.IntegerField(blank=True), null=True, blank=True, default=list
    )

    class Meta:
        unique_together = (("agent", "assigned_check"),)

    def __str__(self) -> str:
        return str(self.assigned_check)

    def save(self, *args, **kwargs) -> None:
        from alerts.models import RESULT_SEVERITY_CHECKS

        # a result of a computed-severity type always carries one
        if (
            not self.alert_severity
            and self.assigned_check.check_type in RESULT_SEVERITY_CHECKS
        ):
            self.alert_severity = AlertSeverity.WARNING
        super().save(*args, **kwargs)

    @property
    def history_info(self) -> Optional[str]:
        if self.assigned_check.check_type in (CheckType.CPU_LOAD, CheckType.MEMORY):
            return ", ".join(f"{x}%" for x in (self.history or [])[-6:])
        return None

    def get_or_create_alert_if_needed(
        self, alert_template: "Optional[AlertTemplate]"
    ) -> "Optional[Alert]":
        from alerts.models import Alert

        check = self.assigned_check
        return Alert.create_or_return_check_alert(
            check,
            agent=self.agent,
            alert_severity=self.alert_severity,
            skip_create=not check.should_create_alert(alert_template),
        )

    def _set_verdict(self, failing: bool, severity: Optional[str] = None) -> None:
        if failing:
            self.status = CheckStatus.FAILING
            if severity:
                self.alert_severity = severity
        else:
            self.status = CheckStatus.PASSING

    def _failed(self) -> int:
        # history graphs plot a failing run as 1
        return int(self.status == CheckStatus.FAILING)

    def _over(self, value: float, check: Check) -> None:
        # cpu and memory: above a threshold is bad
        if check.error_threshold and value > check.error_threshold:
            self._set_verdict(True, AlertSeverity.ERROR)
        elif check.warning_threshold and value > check.warning_threshold:
            self._set_verdict(True, AlertSeverity.WARNING)
        else:
            self._set_verdict(False)

    def _under(self, value: float, check: Check) -> None:
        # disk: free space below a threshold is bad
        if check.error_threshold and value < check.error_threshold:
            self._set_verdict(True, AlertSeverity.ERROR)
        elif check.warning_threshold and value < check.warning_threshold:
            self._set_verdict(True, AlertSeverity.WARNING)
        else:
            self._set_verdict(False)

    def _metric(self, value: float, check: Check) -> None:
        below = check.metric_op == MetricOp.BELOW

        def beyond(limit: Optional[float]) -> bool:
            if limit is None:
                return False
            return value < limit if below else value > limit

        if beyond(check.metric_error):
            self._set_verdict(True, AlertSeverity.ERROR)
        elif beyond(check.metric_warning):
            self._set_verdict(True, AlertSeverity.WARNING)
        else:
            self._set_verdict(False)

    def handle_check(self, data: Any, check: Check, agent: "Agent") -> str:
        """Applies one agent result, stores it and raises or resolves the alert."""
        from alerts.models import Alert

        kind = check.check_type
        if kind != CheckType.METRIC:
            data = clean_result(kind, data)

        if kind in (CheckType.CPU_LOAD, CheckType.MEMORY):
            sample = data["percent"]
            self.history = ((self.history or []) + [sample])[-LOAD_SAMPLES:]
            average = int(mean(self.history))
            label = "Memory Usage" if kind == CheckType.MEMORY else "CPU Load"
            self.more_info = f"Average {label}: {average}%"
            self._over(average, check)
            check.add_check_history(sample, agent.agent_id)
            fields = ["history", "more_info"]

        elif kind == CheckType.DISK_SPACE:
            if data["exists"]:
                free = 100 - round(data["percent_used"])
                self._under(free, check)
                self.more_info = data["more_info"]
                check.add_check_history(free, agent.agent_id)
            else:
                self._set_verdict(True, AlertSeverity.ERROR)
                self.more_info = f"Disk {check.disk} does not exist"
            fields = ["more_info"]

        elif kind == CheckType.SCRIPT:
            self.stdout = data["stdout"]
            self.stderr = data["stderr"]
            self.retcode = retcode = data["retcode"]
            self.execution_time = "{:.4f}".format(data["runtime"])
            if retcode in (check.info_return_codes or []):
                self._set_verdict(True, AlertSeverity.INFO)
            elif retcode in (check.warning_return_codes or []):
                self._set_verdict(True, AlertSeverity.WARNING)
            elif retcode in (check.success_return_codes or []):
                self._set_verdict(False)
            else:
                self._set_verdict(retcode != 0, AlertSeverity.ERROR)
            check.add_check_history(
                self._failed(),
                agent.agent_id,
                {
                    "retcode": retcode,
                    "stdout": self.stdout[:HISTORY_TEXT],
                    "stderr": self.stderr[:HISTORY_TEXT],
                    "execution_time": self.execution_time,
                },
            )
            fields = ["stdout", "stderr", "retcode", "execution_time"]

        elif kind in (
            CheckType.PING,
            CheckType.WINSVC,
            CheckType.SYSTEMD,
            CheckType.CONTAINER,
        ):
            # the agent decides these, the severity stays the check's
            self.status = data["status"]
            self.more_info = data["output" if kind == CheckType.PING else "more_info"]
            check.add_check_history(
                self._failed(), agent.agent_id, self.more_info[:HISTORY_TEXT]
            )
            fields = ["more_info"]

        elif kind == CheckType.METRIC:
            value = data.get("value")
            if value is None:
                self._set_verdict(True, AlertSeverity.ERROR)
                self.more_info = text = "Not reported"
            else:
                self._metric(value, check)
                text = f"{round(value, 2):g}"
                self.more_info = f"Average of {data.get('samples', 1)} samples: {text}"
            check.add_check_history(self._failed(), agent.agent_id, text)
            fields = ["more_info"]

        elif kind == CheckType.EVENT_LOG:
            log = data["log"]
            found = len(log)
            enough = bool(log) and found >= (check.number_of_events_b4_alert or 1)
            if check.fail_when == EvtLogFailWhen.CONTAINS:
                self._set_verdict(enough)
            elif check.fail_when == EvtLogFailWhen.NOT_CONTAINS:
                self._set_verdict(not enough)
            self.extra_details = {"log": log[:MAX_EVENTS]}
            check.add_check_history(
                self._failed(), agent.agent_id, f"Events Found:{found}"
            )
            fields = ["extra_details"]

        elif kind in health.HEALTH_CHECK_TYPES:
            status, severity, text = health.evaluate(
                kind,
                agent.plat,
                data["health"],
                check.warning_threshold,
                check.error_threshold,
                lambda: agent.make_model,
            )
            self.status = status
            if severity is not None:
                self.alert_severity = severity
            self.more_info = text
            check.add_check_history(self._failed(), agent.agent_id, text[:HISTORY_TEXT])
            fields = ["more_info"]

        else:
            fields = []

        self.last_run = djangotime.now()

        if self.status == CheckStatus.FAILING:
            self.fail_count += 1
            self.save(
                update_fields=fields
                + ["status", "fail_count", "alert_severity", "last_run"]
            )
            if self.fail_count >= check.fails_b4_alert:
                Alert.handle_alert_failure(self)

        elif self.status == CheckStatus.PASSING:
            self.fail_count = 0
            self.save(
                update_fields=fields
                + ["status", "fail_count", "alert_severity", "last_run"]
            )
            if Alert.objects.filter(
                assigned_check=check, agent=agent, resolved=False
            ).exists():
                Alert.handle_alert_resolve(self)

        else:
            # no verdict this run (event log check without a fail condition)
            self.save(update_fields=fields + ["last_run"])

        return self.status

    # --- notifications -------------------------------------------------

    def _subject(self, state: str) -> str:
        agent = self.agent
        return (
            f"{agent.client.name}, {agent.site.name}, {agent.hostname} - {self} {state}"
        )

    def _average(self) -> str:
        return f"{int(mean(self.history))}%" if self.history else "unknown"

    def _disk_free(self, check: Check) -> Optional[float]:
        for disk in self.agent.disks or []:
            if isinstance(disk, dict) and disk.get("device") == check.disk:
                percent = disk.get("percent")
                if isinstance(percent, (int, float)) and not isinstance(percent, bool):
                    return 100 - percent
        return None

    def _failure_body(self, subject: str, short: bool) -> str:
        check = self.assigned_check
        kind = check.check_type

        if kind == CheckType.DISK_SPACE:
            free = self._disk_free(check)
            if free is None:
                return f"{subject} - Disk {check.disk} does not exist"
            return f"{subject} - Free: {free}%, {check.threshold_text('%')}"

        if kind == CheckType.SCRIPT:
            if short:
                return f"{subject} - Return code: {self.retcode}"
            return (
                f"{subject} - Return code: {self.retcode}\n"
                f"Stdout:{self.stdout}\nStderr: {self.stderr}"
            )

        if kind == CheckType.PING:
            return subject if short else self.more_info or ""

        if kind in (CheckType.CPU_LOAD, CheckType.MEMORY):
            label = (
                "Average CPU utilization"
                if kind == CheckType.CPU_LOAD
                else "Average memory usage"
            )
            return (
                f"{subject} - {label}: {self._average()}, {check.threshold_text('%')}"
            )

        if kind == CheckType.WINSVC:
            return f"{subject} - Status: {self.more_info}"

        if kind in (
            *health.HEALTH_CHECK_TYPES,
            CheckType.SYSTEMD,
            CheckType.CONTAINER,
            CheckType.METRIC,
        ):
            return f"{subject} - {self.more_info}"

        if kind == CheckType.EVENT_LOG:
            if short:
                return subject
            what = f"Event ID {check.event_id}"
            if check.event_source:
                what += f", source {check.event_source}"
            if check.event_message:
                what += f", containing string {check.event_message}"
            body = f"{what} was found in the {check.log_name} log\n\n"
            log = (self.extra_details or {}).get("log") or []
            for entry in log:
                if isinstance(entry, dict) and entry.get("message"):
                    body += f"{entry['message']}\n"
            return body

        return subject

    def send_email(self) -> tuple[str, bool]:
        from core.utils import get_core_settings

        subject = self._subject("Failed")
        return get_core_settings().send_mail(
            subject,
            self._failure_body(subject, short=False),
            alert_template=self.agent.alert_template,
        )

    def send_sms(self) -> tuple[str, bool]:
        from core.utils import get_core_settings

        subject = self._subject("Failed")
        return get_core_settings().send_sms(
            self._failure_body(subject, short=True),
            alert_template=self.agent.alert_template,
        )

    def send_resolved_email(self) -> tuple[str, bool]:
        from core.utils import get_core_settings

        agent = self.agent
        body = f"{agent.client.name}, {agent.site.name}, {agent.hostname} - {self} is now back to normal"
        return get_core_settings().send_mail(
            self._subject("Resolved"), body, alert_template=agent.alert_template
        )

    def send_resolved_sms(self) -> tuple[str, bool]:
        from core.utils import get_core_settings

        return get_core_settings().send_sms(
            self._subject("Resolved"), alert_template=self.agent.alert_template
        )


def apply_result(check: Check, agent: "Agent", payload: Any) -> str:
    """Stores one result and runs the check's tasks when it fails."""
    results = CheckResult.objects.defer(*CHECK_RESULT_DEFER)
    try:
        with transaction.atomic():
            result, _ = results.get_or_create(assigned_check=check, agent=agent)
    except IntegrityError:
        # the first two results of a check arrived at the same time
        result = results.get(assigned_check=check, agent=agent)

    # a failure leaves no history row behind, so a resent result starts clean;
    # mail, text and notification jobs are queued on commit
    with transaction.atomic():
        status = result.handle_check(payload, check, agent)

    # the stored result and alert outweigh a task the agent was not sent
    if status == CheckStatus.FAILING:
        for task in check.assignedtasks.all():
            if not task.enabled:
                continue
            try:
                if task.policy_id:
                    task.run_win_task(agent)
                else:
                    task.run_win_task()
            except Exception as e:
                DebugLog.warning(
                    agent=agent,
                    log_type=DebugLogType.AGENT_ISSUES,
                    message=f"Unable to run task {task.name} for the failing "
                    f"check {check}: {e}",
                )
    return status


class CheckHistory(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    # Check.pk by value: history outlives its check and is pruned by age
    check_id = models.PositiveIntegerField(default=0)
    agent_id = models.CharField(max_length=200, null=True, blank=True)
    x = models.DateTimeField(auto_now_add=True)
    y = models.PositiveIntegerField(null=True, blank=True, default=None)
    results = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return str(self.x)

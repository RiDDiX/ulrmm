# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import random
import re
import string
from typing import TYPE_CHECKING, Any, Optional, Union

from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import DatabaseError, IntegrityError, models, transaction
from django.utils import timezone as djangotime

from logs.models import BaseAuditModel
from ulrmm.constants import (
    FIELDS_TRIGGER_TASK_UPDATE_AGENT,
    POLICY_TASK_FIELDS_TO_COPY,
    AgentPlat,
    AlertSeverity,
    TaskRunStatus,
    TaskStatus,
    TaskSyncStatus,
    TaskType,
)
from ulrmm.helpers import has_script_actions, has_webhook
from ulrmm.logger import logger
from ulrmm.models import PermissionQuerySet
from ulrmm.utils import (
    bitdays_to_string,
    bitmonthdays_to_string,
    bitmonths_to_string,
    bitweeks_to_string,
    convert_to_iso_duration,
)

if TYPE_CHECKING:
    from agents.models import Agent
    from alerts.models import Alert, AlertTemplate
    from automation.models import Policy
    from checks.models import Check

_ON_DEMAND_TYPES = {
    TaskType.CHECK_FAILURE,
    TaskType.MANUAL,
    TaskType.ONBOARDING,
    TaskType.SCHEDULED,
}
# task types the Windows Task Scheduler runs on a calendar
CALENDAR_TYPES = tuple(kind for kind in TaskType if kind not in _ON_DEMAND_TYPES)

LAST_DAY_OF_MONTH = 0x80000000
NATS_TIMEOUT = 10
TASK_NOT_FOUND_ON_AGENT = "The system cannot find the file specified"
POLICY_TASK_NEEDS_AGENT = "agent parameter needs to be passed with policy task"
# every version generated <letters>_ followed by 35 random letters
GENERATED_TASK_NAME = re.compile(r"[A-Za-z]+_[A-Za-z]{35}")


def generate_task_name() -> str:
    from ulrmm.agent_ident import agent_task_prefix

    tail = "".join(random.choices(string.ascii_letters, k=35))
    return f"{agent_task_prefix()}{tail}"


def default_task_supported_platforms() -> list[str]:
    return [AgentPlat.WINDOWS]


def _calendar_fields(prefix: str, moment) -> dict[str, int]:
    return {
        f"{prefix}_year": moment.year,
        f"{prefix}_month": moment.month,
        f"{prefix}_day": moment.day,
        f"{prefix}_hour": moment.hour,
        f"{prefix}_min": moment.minute,
    }


class AutomatedTask(BaseAuditModel):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(
        "agents.Agent",
        related_name="autotasks",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="autotasks",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    custom_field = models.ForeignKey(
        "core.CustomField",
        related_name="autotasks",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    # [{"type": "script", "script": pk, "timeout": s, "script_args": [], "env_vars": []}
    #  | {"type": "cmd", "command": str, "shell": str, "timeout": s}]
    actions = models.JSONField(default=list)
    assigned_check = models.ForeignKey(
        "checks.Check",
        related_name="assignedtasks",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=255)
    collector_all_output = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    continue_on_error = models.BooleanField(default=True)
    alert_severity = models.CharField(
        max_length=30, choices=AlertSeverity.choices, default=AlertSeverity.INFO
    )
    email_alert = models.BooleanField(default=False)
    text_alert = models.BooleanField(default=False)
    dashboard_alert = models.BooleanField(default=False)

    task_type = models.CharField(
        max_length=100, choices=TaskType.choices, default=TaskType.MANUAL
    )
    win_task_name = models.CharField(
        max_length=255, unique=True, blank=True, default=generate_task_name
    )
    # floating wall clock time: the endpoint reads the stored components as local
    run_time_date = models.DateTimeField(null=True, blank=True)
    expire_date = models.DateTimeField(null=True, blank=True)
    daily_interval = models.PositiveSmallIntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(1), MaxValueValidator(255)],
    )
    run_time_bit_weekdays = models.IntegerField(null=True, blank=True)
    weekly_interval = models.PositiveSmallIntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(1), MaxValueValidator(52)],
    )
    run_time_minute = models.CharField(
        max_length=5, null=True, blank=True
    )  # deprecated
    monthly_days_of_month = models.PositiveBigIntegerField(blank=True, null=True)
    monthly_months_of_year = models.PositiveIntegerField(blank=True, null=True)
    monthly_weeks_of_month = models.PositiveSmallIntegerField(blank=True, null=True)
    task_repetition_duration = models.CharField(max_length=10, null=True, blank=True)
    task_repetition_interval = models.CharField(max_length=10, null=True, blank=True)
    stop_task_at_duration_end = models.BooleanField(blank=True, default=False)
    random_task_delay = models.CharField(max_length=10, null=True, blank=True)
    remove_if_not_scheduled = models.BooleanField(default=False)
    run_asap_after_missed = models.BooleanField(default=False)
    task_instance_policy = models.PositiveSmallIntegerField(blank=True, default=1)
    task_supported_platforms = ArrayField(
        models.CharField(max_length=30, choices=AgentPlat.choices),
        default=default_task_supported_platforms,
    )

    # deprecated, post_update_tasks still clears rows carrying it
    managed_by_policy = models.BooleanField(default=False)

    # not a column: Agent.add_task_results() puts this agent's TaskResult here
    task_result: "Union[TaskResult, dict]" = {}

    def __str__(self) -> str:
        return self.name

    @property
    def schedule(self) -> Optional[str]:
        try:
            return self._describe_schedule()
        except (AttributeError, TypeError):
            # half filled legacy rows must not break the task list
            return None

    def _describe_schedule(self) -> Optional[str]:
        kind = self.task_type
        if kind == TaskType.MANUAL:
            return "Manual"
        if kind == TaskType.CHECK_FAILURE:
            return "Every time check fails"
        if kind == TaskType.ONBOARDING:
            return "Onboarding: Runs once on task creation."
        if kind == TaskType.RUN_ONCE:
            return f'Run once on {self.run_time_date.strftime("%m/%d/%Y %I:%M%p")}'

        at = self.run_time_date.strftime("%I:%M%p")
        if kind == TaskType.DAILY:
            if self.daily_interval == 1:
                return f"Daily at {at}"
            return f"Every {self.daily_interval} days at {at}"
        if kind == TaskType.WEEKLY:
            days = bitdays_to_string(self.run_time_bit_weekdays)
            if self.weekly_interval == 1:
                return f"{days} at {at}"
            return f"{days} at {at} every {self.weekly_interval} weeks"
        if kind == TaskType.MONTHLY:
            months = bitmonths_to_string(self.monthly_months_of_year)
            days = bitmonthdays_to_string(self.monthly_days_of_month)
            return f"Runs on {months} on days {days} at {at}"
        if kind == TaskType.MONTHLY_DOW:
            months = bitmonths_to_string(self.monthly_months_of_year)
            weeks = bitweeks_to_string(self.monthly_weeks_of_month)
            days = bitdays_to_string(self.run_time_bit_weekdays)
            return f"Runs on {months} on {weeks} on {days} at {at}"
        return None

    @property
    def fields_that_trigger_task_update_on_agent(self) -> list[str]:
        # switching the trigger kind changes the endpoint copy as well
        return [*FIELDS_TRIGGER_TASK_UPDATE_AGENT, "task_type"]

    @staticmethod
    def serialize(task: "AutomatedTask") -> dict[str, Any]:
        from . import serializers

        return serializers.TaskAuditSerializer(task).data

    def _forget_policy_task_cache(self) -> None:
        # Agent.get_tasks_from_policies() caches policy tasks per site and agent
        if not self.policy_id:
            return

        def forget() -> None:
            cache.delete_many_pattern("agent_*_tasks")

        forget()
        # again once committed, a reader may have cached the old rows meanwhile
        transaction.on_commit(forget)

    def save(self, *args, **kwargs) -> None:
        before = None
        if self.pk:
            before = type(self).objects.filter(pk=self.pk).first()

        super().save(old_model=before, *args, **kwargs)
        self._forget_policy_task_cache()

        if before and any(
            getattr(self, field) != getattr(before, field)
            for field in self.fields_that_trigger_task_update_on_agent
        ):
            self._mark_windows_copies_stale()

    def _mark_windows_copies_stale(self) -> None:
        # posix agents are scheduled by the server and hold no copy; actions are
        # fetched fresh on every run and never need a resync
        stale = TaskResult.objects.filter(task=self, agent__plat=AgentPlat.WINDOWS)
        if self.policy_id:
            # not created on that agent yet, the sync job must create, not modify
            stale = stale.exclude(sync_status=TaskSyncStatus.INITIAL)
        stale.update(sync_status=TaskSyncStatus.NOT_SYNCED)

    def delete(self, *args, **kwargs):
        deleted = super().delete(*args, **kwargs)
        self._forget_policy_task_cache()
        return deleted

    def create_policy_task(
        self, policy: "Policy", assigned_check: "Optional[Check]" = None
    ) -> "AutomatedTask":
        # agent and win_task_name are never copied, the copy gets its own name
        return AutomatedTask.objects.create(
            policy=policy,
            assigned_check=assigned_check,
            **{field: getattr(self, field) for field in POLICY_TASK_FIELDS_TO_COPY},
        )

    def has_own_task_name(self) -> bool:
        """Only names this server generated are created, changed or removed on
        an endpoint; anything else may be a foreign scheduled task.

        Rows from earlier versions keep the prefix they were generated with,
        so the generated shape counts as well as the current prefix.
        """
        from ulrmm.agent_ident import agent_task_prefix

        name = self.win_task_name or ""
        prefix = agent_task_prefix()
        if prefix and name.startswith(prefix):
            return True
        return GENERATED_TASK_NAME.fullmatch(name) is not None

    def generate_nats_task_payload(self) -> dict[str, Any]:
        kind = self.task_type
        if kind == TaskType.MANUAL:
            start_when_available = False
        elif kind == TaskType.RUN_ONCE:
            start_when_available = True
        else:
            start_when_available = self.run_asap_after_missed

        payload: dict[str, Any] = {
            "pk": self.pk,
            "name": self.win_task_name,
            # the endpoint runs check failure tasks on demand only
            "trigger": TaskType.MANUAL if kind == TaskType.CHECK_FAILURE else kind,
            "type": "rmm",
            "enabled": self.enabled,
            "overwrite_task": True,
            "multiple_instances": self.task_instance_policy or 0,
            "delete_expired_task_after": (
                self.remove_if_not_scheduled if self.expire_date else False
            ),
            "start_when_available": start_when_available,
        }
        if kind not in CALENDAR_TYPES:
            return payload

        if not self.run_time_date:
            self.run_time_date = djangotime.now()
        payload.update(_calendar_fields("start", self.run_time_date))
        if self.expire_date:
            payload.update(_calendar_fields("expire", self.expire_date))

        if self.random_task_delay:
            payload["random_delay"] = convert_to_iso_duration(self.random_task_delay)
        if self.task_repetition_interval and self.task_repetition_duration:
            payload["repetition_interval"] = convert_to_iso_duration(
                self.task_repetition_interval
            )
            payload["repetition_duration"] = convert_to_iso_duration(
                self.task_repetition_duration
            )
            payload["stop_at_duration_end"] = self.stop_task_at_duration_end

        if kind == TaskType.DAILY:
            payload["day_interval"] = self.daily_interval
        elif kind == TaskType.WEEKLY:
            payload["week_interval"] = self.weekly_interval
            payload["days_of_week"] = self.run_time_bit_weekdays
        elif kind == TaskType.MONTHLY:
            days = self.monthly_days_of_month
            last_day = days >= LAST_DAY_OF_MONTH
            payload["days_of_month"] = days - LAST_DAY_OF_MONTH if last_day else days
            payload["run_on_last_day_of_month"] = last_day
            payload["months_of_year"] = self.monthly_months_of_year
        elif kind == TaskType.MONTHLY_DOW:
            payload["days_of_week"] = self.run_time_bit_weekdays
            payload["months_of_year"] = self.monthly_months_of_year
            payload["weeks_of_month"] = self.monthly_weeks_of_month
        return payload

    # --- endpoint sync --------------------------------------------------------

    def _target_agent(self, agent: "Optional[Agent]") -> "Optional[Agent]":
        return agent if self.policy_id else self.agent

    def _result_on(self, agent: "Agent") -> "TaskResult":
        # the sync job may insert the same pair at the same moment
        try:
            with transaction.atomic():
                result, _ = TaskResult.objects.get_or_create(agent=agent, task=self)
        except IntegrityError:
            result = TaskResult.objects.get(agent=agent, task=self)
        return result

    def _no_target(self) -> str:
        if self.policy_id:
            return POLICY_TASK_NEEDS_AGENT
        return "task has no agent"

    def _set_sync(self, result: "TaskResult", status: str) -> None:
        result.sync_status = status
        result.save(update_fields=["sync_status"])

    def _push_schedule(self, agent: "Optional[Agent]", failed_status: str) -> str:
        target = self._target_agent(agent)
        if target is None:
            return self._no_target()

        result = self._result_on(target)
        if target.is_posix:
            self._set_sync(result, TaskSyncStatus.SYNCED)
            return "ok"

        if not self.has_own_task_name():
            logger.error(
                f"Refusing to schedule task {self.pk} on {target.hostname}: "
                f"'{self.win_task_name}' is not an agent task name"
            )
            self._set_sync(result, failed_status)
            return "invalid task name"

        message = {
            "func": "schedtask",
            "schedtaskpayload": self.generate_nats_task_payload(),
        }
        reply = asyncio.run(target.nats_cmd(message, timeout=NATS_TIMEOUT))
        if reply == "ok":
            self._set_sync(result, TaskSyncStatus.SYNCED)
            return "ok"

        self._set_sync(result, failed_status)
        logger.error(
            f"Unable to schedule task {self.name} on {target.hostname}: {reply}"
        )
        return "timeout"

    def create_task_on_agent(self, agent: "Optional[Agent]" = None) -> str:
        return self._push_schedule(agent, TaskSyncStatus.INITIAL)

    def modify_task_on_agent(self, agent: "Optional[Agent]" = None) -> str:
        return self._push_schedule(agent, TaskSyncStatus.NOT_SYNCED)

    def delete_task_on_agent(self, agent: "Optional[Agent]" = None) -> str:
        target = self._target_agent(agent)
        if target is None:
            return self._no_target()

        if target.is_posix:
            self.delete()
            return "ok"

        if not self.has_own_task_name():
            # never remove a scheduled task this server did not create
            logger.warning(
                f"Task {self.pk} removed without touching {target.hostname}: "
                f"'{self.win_task_name}' is not an agent task name"
            )
            self.delete()
            return "ok"

        message = {
            "func": "delschedtask",
            "schedtaskpayload": {"name": self.win_task_name},
        }
        reply = asyncio.run(target.nats_cmd(message, timeout=NATS_TIMEOUT))
        if reply == "ok" or (
            isinstance(reply, str) and TASK_NOT_FOUND_ON_AGENT in reply
        ):
            self.delete()
            return "ok"

        try:
            self._set_sync(self._result_on(target), TaskSyncStatus.PENDING_DELETION)
        except DatabaseError:
            # the task went away in the meantime
            pass
        logger.error(f"Unable to delete task {self.name} on {target.hostname}: {reply}")
        return "timeout"

    def run_win_task(self, agent: "Optional[Agent]" = None) -> str:
        target = self._target_agent(agent)
        if target is None:
            return self._no_target()

        self._result_on(target)
        asyncio.run(target.nats_cmd({"func": "runtask", "taskpk": self.pk}, wait=False))
        return "ok"

    def should_create_alert(
        self, alert_template: "Optional[AlertTemplate]" = None
    ) -> bool:
        if self.dashboard_alert or self.email_alert or self.text_alert:
            return True
        if alert_template and (
            alert_template.task_always_alert
            or alert_template.task_always_email
            or alert_template.task_always_text
        ):
            return True
        return has_webhook(alert_template, "task") or has_script_actions(
            alert_template, "task"
        )


class TaskResult(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(
        "agents.Agent",
        related_name="taskresults",
        on_delete=models.CASCADE,
    )
    task = models.ForeignKey(
        "autotasks.AutomatedTask",
        related_name="taskresults",
        on_delete=models.CASCADE,
    )
    retcode = models.BigIntegerField(null=True, blank=True)
    stdout = models.TextField(null=True, blank=True)
    stderr = models.TextField(null=True, blank=True)
    execution_time = models.CharField(max_length=100, default="0.0000")
    last_run = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=30, choices=TaskStatus.choices, default=TaskStatus.PENDING
    )
    sync_status = models.CharField(
        max_length=100, choices=TaskSyncStatus.choices, default=TaskSyncStatus.INITIAL
    )
    # set by the posix scheduler so a slow minute does not start a run twice
    locked_at = models.DateTimeField(null=True, blank=True)
    run_status = models.CharField(
        max_length=30, choices=TaskRunStatus.choices, null=True, blank=True
    )

    class Meta:
        unique_together = (("agent", "task"),)

    def __str__(self) -> str:
        return str(self.task)

    def get_or_create_alert_if_needed(
        self, alert_template: "Optional[AlertTemplate]"
    ) -> "Optional[Alert]":
        from alerts.models import Alert

        wanted = self.task.should_create_alert(alert_template)
        return Alert.create_or_return_task_alert(
            self.task, agent=self.agent, skip_create=not wanted
        )

    def save_collector_results(self) -> None:
        from logs.models import DebugLog
        from ulrmm.constants import CustomFieldModel, DebugLogType

        field = self.task.custom_field
        owners = {
            CustomFieldModel.AGENT: lambda: self.agent,
            CustomFieldModel.CLIENT: lambda: self.agent.client,
            CustomFieldModel.SITE: lambda: self.agent.site,
        }
        if field.model not in owners:
            DebugLog.warning(
                agent=self.agent,
                log_type=DebugLogType.SCRIPTING,
                message=f"Collector field {field.name} has an unknown model "
                f"{field.model}, result not saved",
            )
            return

        output = (self.stdout or "").strip()
        if not self.task.collector_all_output:
            output = output.split("\n")[-1].strip()
        field.get_or_create_field_value(owners[field.model]()).save_to_field(output)

    def _subject(self, outcome: str) -> str:
        agent = self.agent
        return (
            f"{agent.client.name}, {agent.site.name}, {agent.hostname} - "
            f"{self.task.name} {outcome}"
        )

    def _body(self, subject: str) -> str:
        return (
            f"{subject} - Return code: {self.retcode}\n"
            f"Stdout:{self.stdout}\nStderr: {self.stderr}"
        )

    def _mail(self, outcome: str) -> tuple[str, bool]:
        from core.utils import get_core_settings

        subject = self._subject(outcome)
        return get_core_settings().send_mail(
            subject, self._body(subject), alert_template=self.agent.alert_template
        )

    def _text(self, outcome: str) -> tuple[str, bool]:
        from core.utils import get_core_settings

        return get_core_settings().send_sms(
            self._body(self._subject(outcome)),
            alert_template=self.agent.alert_template,
        )

    def send_email(self) -> tuple[str, bool]:
        return self._mail("Failed")

    def send_sms(self) -> tuple[str, bool]:
        return self._text("Failed")

    def send_resolved_email(self) -> tuple[str, bool]:
        return self._mail("Resolved")

    def send_resolved_sms(self) -> tuple[str, bool]:
        return self._text("Resolved")

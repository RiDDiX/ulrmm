# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import asyncio
import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from django.contrib.postgres.fields import ArrayField
from django.db import IntegrityError, connection, models, transaction
from django.db.models import F, Q
from django.utils import timezone as djangotime

from logs.models import BaseAuditModel, DebugLog
from ulrmm.constants import (
    ONLINE_AGENTS,
    AgentHistoryType,
    AgentMonType,
    AlertSeverity,
    AlertTemplateActionType,
    AlertType,
    CheckType,
    DebugLogType,
    ScriptShell,
)
from ulrmm.models import PermissionQuerySet
from ulrmm.utils import RE_DB_VALUE, _quote_str, format_shell_bool, get_db_value

if TYPE_CHECKING:
    from agents.models import Agent
    from autotasks.models import AutomatedTask, TaskResult
    from checks.models import Check, CheckResult
    from clients.models import Client, Site
    from core.models import CoreSettings
    from netmon.models import NetworkDevice
    from scripts.models import Script

    AlertSource = Union[Agent, CheckResult, TaskResult, NetworkDevice]

# check types whose severity comes from the latest result, not the check
RESULT_SEVERITY_CHECKS = frozenset(
    {
        CheckType.MEMORY,
        CheckType.CPU_LOAD,
        CheckType.DISK_SPACE,
        CheckType.SCRIPT,
        CheckType.SECURITY,
        CheckType.HW_HEALTH,
        CheckType.METRIC,
    }
)

SEVERITY_RANK = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.ERROR: 2,
}

# AlertTemplate column family (agent_*, check_*, task_*) behind each alert type
TEMPLATE_FAMILY = {
    AlertType.AVAILABILITY: "agent",
    AlertType.CHECK: "check",
    AlertType.TASK: "task",
    AlertType.NETWORK: "check",
}

NOTIFICATION_STAMPS = (
    "email_sent",
    "sms_sent",
    "resolved_email_sent",
    "resolved_sms_sent",
)

# pg_advisory_xact_lock(int4, int4) namespace for "one open alert per subject"
_SUBJECT_LOCK_SPACE = 0x41_4C_00


def _lock_subject(kind: int, *ids: int) -> None:
    key = 0
    for value in ids:
        key = (key * 1_000_003 + int(value)) & 0x7FFF_FFFF
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s, %s)", [_SUBJECT_LOCK_SPACE + kind, key]
        )


def _muted(severity: str, core: "CoreSettings") -> bool:
    """Global switches that silence info / warning alerts."""
    if severity == AlertSeverity.INFO:
        return not core.notify_on_info_alerts
    if severity == AlertSeverity.WARNING:
        return not core.notify_on_warning_alerts
    return False


def _severities(template: "AlertTemplate", family: str, channel: str) -> list[str]:
    """Severities a template lets through on a channel (dashboard, email, text)."""
    if family == "agent":
        return [AlertSeverity.ERROR]
    chosen = getattr(template, f"{family}_{channel}_alert_severity")
    if chosen:
        return chosen
    if channel == "dashboard" and family == "check":
        return [AlertSeverity.ERROR, AlertSeverity.WARNING, AlertSeverity.INFO]
    return [AlertSeverity.ERROR, AlertSeverity.WARNING]


def _answers_ping(agent: "Agent") -> bool:
    return asyncio.run(agent.nats_cmd({"func": "ping"}, timeout=1)) == "pong"


STAND_INS = 3


def _stand_in_agent(agent: "Agent") -> "Optional[Agent]":
    """A reachable agent of the same site, then of the same client. Only the
    first few that checked in lately are pinged, all at once."""
    from agents.models import Agent

    others = (
        Agent.objects.exclude(pk=agent.pk)
        .only(*ONLINE_AGENTS)
        .order_by(F("last_seen").desc(nulls_last=True), "pk")
    )
    site = agent.site
    online = (
        candidate
        for candidates in (
            others.filter(site_id=site.pk),
            others.filter(site__client_id=site.client_id).exclude(site_id=site.pk),
        )
        for candidate in candidates.iterator()
        if candidate.is_online
    )
    picked = list(itertools.islice(online, STAND_INS))
    if not picked:
        return None

    async def ping():
        return await asyncio.gather(
            *(c.nats_cmd({"func": "ping"}, timeout=1) for c in picked),
            return_exceptions=True,
        )

    answers = asyncio.run(ping())
    return next((c for c, a in zip(picked, answers) if a == "pong"), None)


def _run_script_for(
    agent: "Agent",
    script: "Script",
    args: list[str],
    env_vars: list[str],
    timeout: int,
    history_pk: int,
) -> Any:
    from scripts.models import Script

    runner = agent
    if not _answers_ping(agent):
        runner = _stand_in_agent(agent)
        if runner is None:
            return "Unable to find an online agent"
        # agent placeholders still describe the agent that alerted
        args = Script.parse_script_args(agent, script.shell, args)
        env_vars = Script.parse_script_env_vars(agent, script.shell, env_vars)

    return runner.run_script(
        scriptpk=script.pk,
        args=args,
        timeout=timeout,
        wait=True,
        history_pk=history_pk,
        full=True,
        run_on_any=False,
        run_as_user=False,
        env_vars=env_vars,
    )


@dataclass
class _Source:
    """What the failure and resolve handlers read from the alerting object."""

    family: str
    template: Optional["AlertTemplate"]
    maintenance: bool
    severity: Optional[str]
    email: bool
    text: bool
    dashboard: bool
    # resolved notifications that apply even without a template
    email_on_resolved: bool
    text_on_resolved: bool
    tasks: tuple[Any, Any, Any, Any]  # failure email/sms, resolved email/sms
    find_open: Callable[[], Optional["Alert"]]


def _source_of(instance: Any) -> Optional[_Source]:
    from agents.models import Agent
    from autotasks.models import TaskResult
    from checks.models import CheckResult
    from netmon.models import NetworkDevice
    from notify.dispatch import in_maintenance

    if isinstance(instance, Agent):
        from agents import tasks as t

        return _Source(
            family="agent",
            template=instance.alert_template,
            maintenance=in_maintenance(instance),
            severity=AlertSeverity.ERROR,
            email=instance.overdue_email_alert,
            text=instance.overdue_text_alert,
            dashboard=instance.overdue_dashboard_alert,
            email_on_resolved=instance.overdue_email_alert,
            text_on_resolved=instance.overdue_text_alert,
            tasks=(
                t.agent_outage_email_task,
                t.agent_outage_sms_task,
                t.agent_recovery_email_task,
                t.agent_recovery_sms_task,
            ),
            find_open=lambda: Alert.create_or_return_availability_alert(
                instance, skip_create=True
            ),
        )

    if isinstance(instance, CheckResult):
        from checks import tasks as t

        check = instance.assigned_check
        agent = instance.agent
        if check.check_type in RESULT_SEVERITY_CHECKS:
            severity = instance.alert_severity
        else:
            severity = check.alert_severity
        return _Source(
            family="check",
            template=agent.alert_template,
            maintenance=in_maintenance(agent),
            severity=severity,
            email=check.email_alert,
            text=check.text_alert,
            dashboard=check.dashboard_alert,
            email_on_resolved=False,
            text_on_resolved=False,
            tasks=(
                t.handle_check_email_alert_task,
                t.handle_check_sms_alert_task,
                t.handle_resolved_check_email_alert_task,
                t.handle_resolved_check_sms_alert_task,
            ),
            find_open=lambda: Alert.create_or_return_check_alert(
                check,
                agent=agent,
                alert_severity=instance.alert_severity,
                skip_create=True,
            ),
        )

    if isinstance(instance, TaskResult):
        from autotasks import tasks as t

        task = instance.task
        agent = instance.agent
        return _Source(
            family="task",
            template=agent.alert_template,
            maintenance=in_maintenance(agent),
            severity=task.alert_severity,
            email=task.email_alert,
            text=task.text_alert,
            dashboard=task.dashboard_alert,
            email_on_resolved=False,
            text_on_resolved=False,
            tasks=(
                t.handle_task_email_alert,
                t.handle_task_sms_alert,
                t.handle_resolved_task_email_alert,
                t.handle_resolved_task_sms_alert,
            ),
            find_open=lambda: Alert.create_or_return_task_alert(
                task, agent=agent, skip_create=True
            ),
        )

    if isinstance(instance, NetworkDevice):
        from netmon import tasks as t

        def find_open() -> Optional[Alert]:
            if instance.maintenance_mode:
                return None
            return Alert.objects.filter(network_device=instance, resolved=False).last()

        return _Source(
            family="check",
            template=instance.get_alert_template(),
            maintenance=instance.maintenance_mode,
            severity=instance.alert_severity,
            email=instance.email_alert,
            text=instance.text_alert,
            dashboard=instance.dashboard_alert,
            email_on_resolved=instance.email_alert,
            text_on_resolved=instance.text_alert,
            tasks=(
                t.network_alert_email_task,
                t.network_alert_sms_task,
                t.network_resolved_email_task,
                t.network_resolved_sms_task,
            ),
            find_open=find_open,
        )

    return None


class Alert(models.Model):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(
        "agents.Agent",
        related_name="agent",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    assigned_check = models.ForeignKey(
        "checks.Check",
        related_name="alert",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    assigned_task = models.ForeignKey(
        "autotasks.AutomatedTask",
        related_name="alert",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    network_device = models.ForeignKey(
        "netmon.NetworkDevice",
        related_name="alerts",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    alert_type = models.CharField(
        max_length=20, choices=AlertType.choices, default=AlertType.AVAILABILITY
    )
    message = models.TextField(null=True, blank=True)
    alert_time = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    snoozed = models.BooleanField(default=False)
    snooze_until = models.DateTimeField(null=True, blank=True)
    resolved = models.BooleanField(default=False)
    resolved_on = models.DateTimeField(null=True, blank=True)
    severity = models.CharField(
        max_length=30, choices=AlertSeverity.choices, default=AlertSeverity.INFO
    )
    email_sent = models.DateTimeField(null=True, blank=True)
    resolved_email_sent = models.DateTimeField(null=True, blank=True)
    sms_sent = models.DateTimeField(null=True, blank=True)
    resolved_sms_sent = models.DateTimeField(null=True, blank=True)
    hidden = models.BooleanField(default=False)
    action_run = models.DateTimeField(null=True, blank=True)
    action_stdout = models.TextField(null=True, blank=True)
    action_stderr = models.TextField(null=True, blank=True)
    action_retcode = models.BigIntegerField(null=True, blank=True)
    action_execution_time = models.CharField(max_length=100, null=True, blank=True)
    resolved_action_run = models.DateTimeField(null=True, blank=True)
    resolved_action_stdout = models.TextField(null=True, blank=True)
    resolved_action_stderr = models.TextField(null=True, blank=True)
    resolved_action_retcode = models.BigIntegerField(null=True, blank=True)
    resolved_action_execution_time = models.CharField(
        max_length=100, null=True, blank=True
    )

    class Meta:
        # one open alert per agent and check / task
        constraints = [
            models.UniqueConstraint(
                fields=["agent", "assigned_check"],
                condition=Q(resolved=False),
                name="unique_open_check_alert",
            ),
            models.UniqueConstraint(
                fields=["agent", "assigned_task"],
                condition=Q(resolved=False),
                name="unique_open_task_alert",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.alert_type} - {self.message}"

    # values for serializers and {{alert.*}} placeholders

    @property
    def assigned_agent(self) -> "Optional[Agent]":
        return self.agent

    @property
    def site(self) -> "Optional[Site]":
        if self.agent:
            return self.agent.site
        if self.network_device:
            return self.network_device.site
        return None

    @property
    def client(self) -> "Optional[Client]":
        site = self.site
        return site.client if site else None

    @property
    def hostname(self) -> Optional[str]:
        if self.agent:
            return self.agent.hostname
        if self.network_device:
            return self.network_device.name
        return None

    @property
    def get_result(self) -> "Optional[Union[CheckResult, TaskResult]]":
        if self.alert_type == AlertType.CHECK and self.assigned_check:
            return self.assigned_check.checkresults.filter(agent=self.agent).first()
        if self.alert_type == AlertType.TASK and self.assigned_task:
            return self.assigned_task.taskresults.filter(agent=self.agent).first()
        return None

    def resolve(self) -> None:
        changes = {
            "resolved": True,
            "resolved_on": djangotime.now(),
            "snoozed": False,
            "snooze_until": None,
        }
        for field, value in changes.items():
            setattr(self, field, value)
        self.save(update_fields=list(changes))

    def parse_script_args(
        self,
        args: Optional[list[str]],
        shell: Optional[str] = None,
        quotes: bool = True,
    ) -> list[str]:
        """Fills {{...}} placeholders from this alert. Unknown ones stay for
        the agent side. Values are quoted for the target shell."""
        if not args:
            return []

        quote = quotes and shell != ScriptShell.CMD

        def fill(match) -> str:
            value = get_db_value(
                string=f"{match.group(2)}.{match.group(3)}", instance=self
            )
            if value is None:
                return match.group(1)
            if isinstance(value, bool) and shell:
                return format_shell_bool(value, shell)
            return _quote_str(str(value), shell, quote)

        return [RE_DB_VALUE.sub(fill, arg) for arg in args]

    # one open alert per subject

    @classmethod
    def _open_or_create(
        cls,
        lock: tuple[int, ...],
        subject: dict[str, Any],
        skip_create: bool,
        build: Callable[[], dict[str, Any]],
    ) -> Optional[Alert]:
        # serialized per subject; older duplicates are resolved, the newest kept
        with transaction.atomic():
            _lock_subject(*lock)
            open_alerts = list(
                cls.objects.filter(resolved=False, **subject).order_by("pk")
            )
            if not open_alerts:
                if skip_create:
                    return None
                try:
                    with transaction.atomic():
                        return cls.objects.create(hidden=True, **subject, **build())
                except IntegrityError:
                    # reopened outside the lock (alert edit): that one is the open alert
                    return cls.objects.filter(resolved=False, **subject).last()

            *older, newest = open_alerts
            for alert in older:
                alert.resolve()
            return newest

    @classmethod
    def create_or_return_availability_alert(
        cls, agent: "Agent", skip_create: bool = False
    ) -> Optional[Alert]:
        if agent.maintenance_mode:
            return None

        return cls._open_or_create(
            (1, agent.pk),
            {"agent": agent, "alert_type": AlertType.AVAILABILITY},
            skip_create,
            lambda: {
                "severity": AlertSeverity.ERROR,
                "message": f"{agent.hostname} in {agent.client.name}, {agent.site.name} is overdue.",
            },
        )

    @classmethod
    def create_or_return_check_alert(
        cls,
        check: "Check",
        agent: "Agent",
        alert_severity: Optional[str] = None,
        skip_create: bool = False,
    ) -> Optional[Alert]:
        if agent.maintenance_mode:
            return None

        def build() -> dict[str, Any]:
            if check.check_type in RESULT_SEVERITY_CHECKS:
                severity = alert_severity or check.alert_severity
            else:
                severity = check.alert_severity
            return {
                "alert_type": AlertType.CHECK,
                "severity": severity or AlertSeverity.INFO,
                "message": f"{agent.hostname} has a {check.check_type} check: {check.readable_desc} that failed.",
            }

        return cls._open_or_create(
            (2, check.pk, agent.pk),
            {"assigned_check": check, "agent": agent},
            skip_create,
            build,
        )

    @classmethod
    def create_or_return_task_alert(
        cls,
        task: "AutomatedTask",
        agent: "Agent",
        skip_create: bool = False,
    ) -> Optional[Alert]:
        if agent.maintenance_mode:
            return None

        return cls._open_or_create(
            (3, task.pk, agent.pk),
            {"assigned_task": task, "agent": agent},
            skip_create,
            lambda: {
                "alert_type": AlertType.TASK,
                "severity": task.alert_severity or AlertSeverity.INFO,
                "message": f"{agent.hostname} has task: {task.name} that failed.",
            },
        )

    # notification stamps, claimed before sending

    @classmethod
    def claim_notification(
        cls, pk: int, field: str, alert_interval: Optional[float] = None
    ) -> Optional[datetime]:
        """Stamps `field` when that notification is due and returns the stamp.

        None means do not send: already sent (and the interval has not passed),
        claimed by a concurrent task, the alert is gone, or an outage
        notification for an alert that is resolved by now.
        """
        if field not in NOTIFICATION_STAMPS:
            raise ValueError(f"{field} is not a notification stamp")

        now = djangotime.now()
        due = Q(**{f"{field}__isnull": True})
        rows = cls.objects.filter(pk=pk)
        if not field.startswith("resolved_"):
            rows = rows.filter(resolved=False)
            if alert_interval:
                due |= Q(**{f"{field}__lt": now - timedelta(days=alert_interval)})

        return now if rows.filter(due).update(**{field: now}) == 1 else None

    @classmethod
    def release_notification(
        cls, pk: int, field: str, stamp: datetime, previous: Optional[datetime]
    ) -> None:
        """Gives a claim back after the send failed, so a later run retries."""
        if field not in NOTIFICATION_STAMPS:
            raise ValueError(f"{field} is not a notification stamp")
        cls.objects.filter(pk=pk, **{field: stamp}).update(**{field: previous})

    # failure / resolve handling

    def _sync_severity(self, severity: Optional[str]) -> None:
        # an open alert keeps its peak, so a flapping check mails once per escalation
        if not severity or SEVERITY_RANK.get(severity, 0) <= SEVERITY_RANK.get(
            self.severity, 0
        ):
            return
        # an escalation is news, the earlier mail or text does not cover it
        self.severity = severity
        self.email_sent = None
        self.sms_sent = None
        self.save(update_fields=["severity", "email_sent", "sms_sent"])

    @classmethod
    def handle_alert_failure(cls, instance: "AlertSource") -> None:
        from core.models import CoreSettings
        from notify.dispatch import notify_alert

        source = _source_of(instance)
        if source is None or source.maintenance:
            return None

        alert = instance.get_or_create_alert_if_needed(source.template)
        if alert is None:
            return None

        alert._sync_severity(source.severity)
        notify_alert(alert)

        core = CoreSettings.objects.first()
        template, family = source.template, source.family

        def always(channel: str) -> bool:
            return bool(template and getattr(template, f"{family}_always_{channel}"))

        if source.dashboard or always("alert"):
            visible = not template or alert.severity in _severities(
                template, family, "dashboard"
            )
            if visible and alert.hidden:
                alert.hidden = False
                alert.save(update_fields=["hidden"])

        # snoozed: the alert stays current, nobody gets paged
        if alert.snoozed:
            return None

        email = source.email or always("email")
        text = source.text or always("text")
        if _muted(alert.severity, core):
            email = text = False

        interval = (
            getattr(template, f"{family}_periodic_alert_days") if template else None
        )
        email_task, sms_task, _, _ = source.tasks

        if (
            email
            and core.email_is_configured
            and (
                not template or alert.severity in _severities(template, family, "email")
            )
        ):
            email_task.delay(pk=alert.pk, alert_interval=interval)

        if (
            text
            and core.sms_is_configured
            and (
                not template or alert.severity in _severities(template, family, "text")
            )
        ):
            sms_task.delay(pk=alert.pk, alert_interval=interval)

        if template and not alert.action_run:
            alert._start_action(resolved=False, inline=family == "agent", core=core)
        return None

    @classmethod
    def handle_alert_resolve(cls, instance: "AlertSource") -> None:
        from core.models import CoreSettings
        from notify.dispatch import notify_alert

        source = _source_of(instance)
        if source is None:
            return None

        # only an alert that is open gets resolved, none is made for it
        alert = source.find_open()
        if alert is None or source.maintenance:
            return None

        alert.resolve()
        notify_alert(alert, resolved=True)

        core = CoreSettings.objects.first()
        template, family = source.template, source.family
        _, _, email_task, sms_task = source.tasks

        def wanted(channel: str, stamp: str) -> bool:
            on_resolved = getattr(source, f"{channel}_on_resolved") or bool(
                template and getattr(template, f"{family}_{channel}_on_resolved")
            )
            # nobody heard about the failure, the recovery is no news either
            if (
                not on_resolved
                or not getattr(alert, f"{stamp}_sent")
                or getattr(alert, f"resolved_{stamp}_sent")
                or _muted(alert.severity, core)
            ):
                return False
            return not template or alert.severity in _severities(
                template, family, channel
            )

        if core.email_is_configured and wanted("email", "email"):
            email_task.delay(pk=alert.pk)

        if core.sms_is_configured and wanted("text", "sms"):
            sms_task.delay(pk=alert.pk)

        if template and not alert.resolved_action_run:
            alert._start_action(resolved=True, inline=family == "agent", core=core)
        return None

    # template actions

    def _action_source(self) -> "tuple[Optional[AlertTemplate], Optional[Agent]]":
        if self.network_device:
            return self.network_device.get_alert_template(), None
        if self.agent:
            return self.agent.alert_template, self.agent
        return None, None

    def _due_action(
        self,
        template: "AlertTemplate",
        agent: "Optional[Agent]",
        resolved: bool,
        core: "CoreSettings",
    ) -> Optional[str]:
        """The kind of action the template has for this alert, if it runs."""
        family = TEMPLATE_FAMILY.get(self.alert_type)
        if not family or not getattr(template, f"{family}_script_actions"):
            return None

        pre = "resolved_" if resolved else ""
        script = getattr(template, f"{pre}action")
        hook = getattr(template, f"{pre}action_rest")
        if not (script or hook):
            return None

        kind = getattr(template, f"{pre}action_type")
        if kind == AlertTemplateActionType.SCRIPT:
            return kind if script and agent else None
        if kind == AlertTemplateActionType.SERVER:
            return kind if script else None
        if kind == AlertTemplateActionType.REST:
            # web hooks follow the info / warning switches like mail and text
            return None if _muted(self.severity, core) else kind
        return None

    def _start_action(self, resolved: bool, inline: bool, core: "CoreSettings") -> None:
        template, agent = self._action_source()
        if template is None or not self._due_action(template, agent, resolved, core):
            return

        if inline:
            # agent outages and their recovery are handled in a worker already
            self.run_action(resolved=resolved)
            return

        from .tasks import run_alert_action_task

        pre = "resolved_" if resolved else ""
        timeout = getattr(template, f"{pre}action_timeout") or 0
        transaction.on_commit(
            lambda: run_alert_action_task.apply_async(
                (self.pk, resolved),
                soft_time_limit=timeout + 120,
                time_limit=timeout + 150,
            )
        )

    def run_action(self, resolved: bool = False) -> None:
        """Runs the template's failure or resolved action, at most once."""
        from core.models import CoreSettings

        template, agent = self._action_source()
        if template is None:
            return
        kind = self._due_action(template, agent, resolved, CoreSettings.objects.first())
        if kind is None:
            return

        stamp = f"{'resolved_' if resolved else ''}action_run"
        now = djangotime.now()
        claimed = Alert.objects.filter(pk=self.pk, **{f"{stamp}__isnull": True}).update(
            **{stamp: now}
        )
        if not claimed:
            return
        setattr(self, stamp, now)

        try:
            result = self._execute_action(kind, template, agent, resolved)
        except Exception as e:
            result = f"{type(e).__name__}: {e}"
        self._record_action(kind, template, agent, resolved, result)

    def _execute_action(
        self,
        kind: str,
        template: "AlertTemplate",
        agent: "Optional[Agent]",
        resolved: bool,
    ) -> Any:
        from core.utils import run_server_script, run_url_rest_action

        pre = "resolved_" if resolved else ""

        if kind == AlertTemplateActionType.REST:
            hook = getattr(template, f"{pre}action_rest")
            if hook is None:
                return "no web hook is selected for this action"
            text, status = run_url_rest_action(action_id=hook.pk, instance=self)
            return {
                "stdout": text,
                "stderr": "",
                "execution_time": 0,
                "retcode": status,
            }

        script = getattr(template, f"{pre}action")
        args = self.parse_script_args(
            getattr(template, f"{pre}action_args"), script.shell
        )
        env_vars = self.parse_script_args(
            getattr(template, f"{pre}action_env_vars"), script.shell, quotes=False
        )
        timeout = getattr(template, f"{pre}action_timeout")

        if kind == AlertTemplateActionType.SERVER:
            outcome = run_server_script(
                body=script.script_body,
                shell=script.shell,
                args=args,
                env_vars=env_vars,
                timeout=timeout,
            )
            keys = ("stdout", "stderr", "execution_time", "retcode")
            return dict(zip(keys, outcome))

        from agents.models import AgentHistory

        history = AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.SCRIPT_RUN,
            script=script,
            username="alert-action-resolved" if resolved else "alert-action-failure",
        )
        return _run_script_for(agent, script, args, env_vars, timeout, history.pk)

    def _record_action(
        self,
        kind: str,
        template: "AlertTemplate",
        agent: "Optional[Agent]",
        resolved: bool,
        result: Any,
    ) -> None:
        pre = "resolved_" if resolved else ""
        if isinstance(result, dict):
            try:
                elapsed = float(result.get("execution_time") or 0)
            except (TypeError, ValueError):
                elapsed = 0.0
            values = {
                "retcode": result.get("retcode"),
                "stdout": result.get("stdout"),
                "stderr": result.get("stderr"),
                "execution_time": "{:.4f}".format(elapsed),
            }
        else:
            label = "Resolved" if resolved else "Failure"
            if kind == AlertTemplateActionType.SCRIPT:
                DebugLog.error(
                    agent=agent,
                    log_type=DebugLogType.SCRIPTING,
                    message=(
                        f"{label} action: {getattr(template, f'{pre}action').name} "
                        f"failed to run on any agent for {agent.hostname}({agent.pk}) "
                        f"{label.lower()} alert"
                    ),
                )
            else:
                target = getattr(
                    template,
                    (
                        f"{pre}action_rest"
                        if kind == AlertTemplateActionType.REST
                        else f"{pre}action"
                    ),
                )
                DebugLog.error(
                    log_type=DebugLogType.SCRIPTING,
                    message=(
                        f"{label} action: {target.name if target else 'none'} "
                        f"failed to run on server for {label.lower()} alert"
                    ),
                )
            # recorded as a failed run, so it is not retried on every check-in
            values = {
                "retcode": 1,
                "stdout": "",
                "stderr": str(result),
                "execution_time": "0.0000",
            }

        values = {f"{pre}action_{key}": value for key, value in values.items()}
        Alert.objects.filter(pk=self.pk).update(**values)
        for key, value in values.items():
            setattr(self, key, value)


class AlertTemplate(BaseAuditModel):
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    action_type = models.CharField(
        max_length=10,
        choices=AlertTemplateActionType.choices,
        default=AlertTemplateActionType.SCRIPT,
    )
    action = models.ForeignKey(
        "scripts.Script",
        related_name="alert_template",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action_rest = models.ForeignKey(
        "core.URLAction",
        related_name="url_action_alert_template",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action_args = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    action_env_vars = ArrayField(
        models.TextField(null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    action_timeout = models.PositiveIntegerField(default=15)

    resolved_action_type = models.CharField(
        max_length=10,
        choices=AlertTemplateActionType.choices,
        default=AlertTemplateActionType.SCRIPT,
    )
    resolved_action = models.ForeignKey(
        "scripts.Script",
        related_name="resolved_alert_template",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    resolved_action_rest = models.ForeignKey(
        "core.URLAction",
        related_name="resolved_url_action_alert_template",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    resolved_action_args = ArrayField(
        models.CharField(max_length=255, null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    resolved_action_env_vars = ArrayField(
        models.TextField(null=True, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    resolved_action_timeout = models.PositiveIntegerField(default=15)

    # recipient and sender overrides for the global settings
    email_recipients = ArrayField(
        models.CharField(max_length=100, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    text_recipients = ArrayField(
        models.CharField(max_length=100, blank=True),
        null=True,
        blank=True,
        default=list,
    )
    email_from = models.EmailField(null=True, blank=True)

    # agent availability
    agent_email_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    agent_text_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    agent_always_email = models.BooleanField(null=True, blank=True, default=None)
    agent_always_text = models.BooleanField(null=True, blank=True, default=None)
    agent_always_alert = models.BooleanField(null=True, blank=True, default=None)
    agent_periodic_alert_days = models.PositiveIntegerField(
        null=True, blank=True, default=0
    )
    agent_script_actions = models.BooleanField(null=True, blank=True, default=True)

    # checks
    check_email_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    check_text_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    check_dashboard_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    check_email_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    check_text_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    check_always_email = models.BooleanField(null=True, blank=True, default=None)
    check_always_text = models.BooleanField(null=True, blank=True, default=None)
    check_always_alert = models.BooleanField(null=True, blank=True, default=None)
    check_periodic_alert_days = models.PositiveIntegerField(
        null=True, blank=True, default=0
    )
    check_script_actions = models.BooleanField(null=True, blank=True, default=True)

    # automated tasks
    task_email_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    task_text_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    task_dashboard_alert_severity = ArrayField(
        models.CharField(max_length=25, blank=True, choices=AlertSeverity.choices),
        blank=True,
        default=list,
    )
    task_email_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    task_text_on_resolved = models.BooleanField(null=True, blank=True, default=False)
    task_always_email = models.BooleanField(null=True, blank=True, default=None)
    task_always_text = models.BooleanField(null=True, blank=True, default=None)
    task_always_alert = models.BooleanField(null=True, blank=True, default=None)
    task_periodic_alert_days = models.PositiveIntegerField(
        null=True, blank=True, default=0
    )
    task_script_actions = models.BooleanField(null=True, blank=True, default=True)

    # exclusions
    exclude_workstations = models.BooleanField(null=True, blank=True, default=False)
    exclude_servers = models.BooleanField(null=True, blank=True, default=False)
    excluded_sites = models.ManyToManyField(
        "clients.Site", related_name="alert_exclusions", blank=True
    )
    excluded_clients = models.ManyToManyField(
        "clients.Client", related_name="alert_exclusions", blank=True
    )
    excluded_agents = models.ManyToManyField(
        "agents.Agent", related_name="alert_exclusions", blank=True
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(alert_template: "AlertTemplate") -> dict[str, Any]:
        from . import serializers

        return serializers.AlertTemplateAuditSerializer(alert_template).data

    def is_agent_excluded(self, agent: "Agent") -> bool:
        if (
            agent.monitoring_type == AgentMonType.WORKSTATION
            and self.exclude_workstations
        ):
            return True
        if agent.monitoring_type == AgentMonType.SERVER and self.exclude_servers:
            return True
        return (
            self.excluded_agents.filter(pk=agent.pk).exists()
            or self.excluded_sites.filter(pk=agent.site_id).exists()
            or self.excluded_clients.filter(pk=agent.site.client_id).exists()
        )

    def _family_configured(self, family: str) -> bool:
        return any(
            getattr(self, f"{family}_{setting}", None)
            for setting in (
                "email_alert_severity",
                "text_alert_severity",
                "dashboard_alert_severity",
                "email_on_resolved",
                "text_on_resolved",
                "always_email",
                "always_text",
                "always_alert",
                "periodic_alert_days",
            )
        )

    @property
    def has_agent_settings(self) -> bool:
        return self._family_configured("agent")

    @property
    def has_check_settings(self) -> bool:
        return self._family_configured("check")

    @property
    def has_task_settings(self) -> bool:
        return self._family_configured("task")

    @property
    def has_core_settings(self) -> bool:
        return bool(self.email_from or self.email_recipients or self.text_recipients)

    @property
    def is_default_template(self) -> bool:
        return self.default_alert_template.exists()

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import hmac
import json
import re
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlsplit

from django.conf import settings
from django.db import models, transaction

from core.utils import CoreSettingsNotFound, get_core_settings
from ulrmm.constants import (
    AuditActionType,
    AuditObjType,
    DebugLogLevel,
    DebugLogType,
    PAAction,
    PAStatus,
)
from ulrmm.middleware import get_debug_info, get_username
from ulrmm.models import PermissionQuerySet

if TYPE_CHECKING:
    from agents.models import Agent

SERVER_NAME = "UniversalLocal RMM Server"
TOO_LARGE = {
    "error": "value too large to store in audit log. "
    "Check documentation for configuring AUDIT_MAX_VALUE_BYTES"
}
NOT_JSON = {"error": "could not process audit value"}

# keys of a serialised model that hold NAME=value lists
ENV_KEYS = ("env_vars", "action_env_vars", "resolved_action_env_vars")
MASKED_ENV = re.compile(r"^[^=]*=hmac:[0-9a-f]{16}$")

LEVEL_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def get_debug_level() -> str:
    try:
        return get_core_settings().agent_debug_level
    except CoreSettingsNotFound:
        # no settings row yet (first boot, empty db): log everything
        return "info"


def _digest(text: str) -> str:
    mac = hmac.new(settings.SECRET_KEY.encode(), text.encode(), hashlib.sha256)
    return mac.hexdigest()[:16]


def hmac_marker(value: Any) -> Optional[str]:
    """Stable stand-in for a secret: equal values give equal markers."""
    if not value:
        return None
    return f"hmac:{_digest(str(value))}"


def mask_env_vars(env_vars: Any) -> Any:
    if not isinstance(env_vars, (list, tuple)):
        return "***" if env_vars else env_vars
    masked = []
    for item in env_vars:
        if isinstance(item, str) and "=" in item:
            name, _, value = item.partition("=")
            masked.append(f"{name}=hmac:{_digest(value)}")
        else:
            masked.append("***")
    return masked


_PLACEHOLDER = re.compile(r"(\{\{[^{}]*\}\})")


def mask_script_args(args: Any) -> Any:
    """Literal parts of script args become markers, {{...}} stays readable."""
    if not isinstance(args, (list, tuple)):
        return "***" if args else args
    return [
        (
            "".join(
                p if not p.strip() or _PLACEHOLDER.fullmatch(p) else hmac_marker(p)
                for p in _PLACEHOLDER.split(arg)
            )
            if isinstance(arg, str)
            else "***"
        )
        for arg in args
    ]


def _mask_env_keys(values: Any) -> Any:
    """Returns a copy with plaintext env var lists masked, else the input."""
    if not isinstance(values, dict):
        return values
    result = values
    for key in ENV_KEYS:
        items = values.get(key)
        if not isinstance(items, (list, tuple)):
            continue
        if all(isinstance(i, str) and MASKED_ENV.match(i) for i in items):
            continue
        if result is values:
            result = dict(values)
        result[key] = mask_env_vars(items)
    return result


def _clip(value: Any) -> Any:
    if value and len(value) > 255:
        return value[:253] + ".."
    return value


def _origin(url: Any) -> str:
    # scheme and host only: paths and query strings of webhooks carry tokens
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname
    except ValueError:
        host = None
    if not host:
        return "(no host)"
    return f"{parts.scheme}://{host}" if parts.scheme else host


def _get_or_none(model, **lookup):
    try:
        return model.objects.get(**lookup)
    except (model.DoesNotExist, ValueError, TypeError):
        return None


def _name_or_pk(model, pk, render) -> str:
    if pk is None:
        return "#?"
    obj = _get_or_none(model, pk=pk)
    return render(obj) if obj is not None else f"#{pk}"


class AuditLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=255)
    agent = models.CharField(max_length=255, null=True, blank=True)
    agent_id = models.CharField(max_length=255, null=True, blank=True)
    entry_time = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=100, choices=AuditActionType.choices)
    object_type = models.CharField(max_length=100, choices=AuditObjType.choices)
    before_value = models.JSONField(null=True, blank=True)
    after_value = models.JSONField(null=True, blank=True)
    message = models.CharField(max_length=255, null=True, blank=True)
    debug_info = models.JSONField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["entry_time"]),
            models.Index(fields=["agent_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.username} {self.action} {self.object_type}"

    def save(self, *args, **kwargs):
        if not self.pk:
            self._limit_new_row()
        return super().save(*args, **kwargs)

    def _limit_new_row(self) -> None:
        for column in ("username", "agent", "agent_id"):
            value = getattr(self, column)
            if value is not None:
                setattr(self, column, _clip(str(value)))
        self.message = _clip(self.message)

        limit = getattr(settings, "AUDIT_MAX_VALUE_BYTES", 512 * 1024)
        for column in ("before_value", "after_value", "debug_info"):
            try:
                size = len(json.dumps(getattr(self, column)).encode("utf-8"))
            except Exception:
                setattr(self, column, dict(NOT_JSON))
                continue
            if size > limit:
                setattr(self, column, dict(TOO_LARGE))

    @staticmethod
    def _agent_entry(username, agent: "Agent", debug_info, **columns) -> None:
        AuditLog.objects.create(
            username=username,
            debug_info={} if debug_info is None else debug_info,
            agent=agent.hostname,
            agent_id=agent.agent_id,
            object_type=AuditObjType.AGENT,
            **columns,
        )

    @staticmethod
    def audit_mesh_session(
        username, agent, debug_info=None, session="a remote session"
    ) -> None:
        AuditLog._agent_entry(
            username,
            agent,
            debug_info,
            action=AuditActionType.REMOTE_SESSION,
            message=f"{username} initiated {session} to {agent.hostname}.",
        )

    @staticmethod
    def audit_raw_command(username, agent, cmd, shell, debug_info=None) -> None:
        AuditLog._agent_entry(
            username,
            agent,
            debug_info,
            action=AuditActionType.EXEC_COMMAND,
            message=f"{username} issued {shell} command on {agent.hostname}.",
            after_value=cmd,
        )

    @staticmethod
    def audit_power_action(username, agent, action, debug_info=None) -> None:
        # notify.tamper reads after_value["mode"] to tell planned outages apart
        AuditLog._agent_entry(
            username,
            agent,
            debug_info,
            action=AuditActionType.EXEC_COMMAND,
            message=f"{username} executed {action} on {agent.hostname}",
            after_value={"mode": action},
        )

    @staticmethod
    def audit_service_action(username, agent, name, action, debug_info=None) -> None:
        AuditLog._agent_entry(
            username,
            agent,
            debug_info,
            action=AuditActionType.MODIFY,
            message=f"{username} executed service {action} {name} on {agent.hostname}",
            after_value={"service": name, "action": action},
        )

    @staticmethod
    def _object_entry(username, object_type, action, verb, name, ident, **values):
        is_agent = object_type == AuditObjType.AGENT and isinstance(ident, dict)
        AuditLog.objects.create(
            username=username,
            agent=ident.get("hostname") if is_agent else None,
            agent_id=ident.get("agent_id") if is_agent else None,
            object_type=object_type,
            action=action,
            message=f"{username} {verb} {object_type} {name}",
            **values,
        )

    @staticmethod
    def audit_object_changed(
        username, object_type, before, after, name="", debug_info=None
    ) -> None:
        AuditLog._object_entry(
            username,
            object_type,
            AuditActionType.MODIFY,
            "modified",
            name,
            before,
            before_value=before,
            after_value=after,
            debug_info={} if debug_info is None else debug_info,
        )

    @staticmethod
    def audit_object_add(username, object_type, after, name="", debug_info=None):
        AuditLog._object_entry(
            username,
            object_type,
            AuditActionType.ADD,
            "added",
            name,
            after,
            after_value=after,
            debug_info={} if debug_info is None else debug_info,
        )

    @staticmethod
    def audit_object_delete(username, object_type, before, name="", debug_info=None):
        AuditLog._object_entry(
            username,
            object_type,
            AuditActionType.DELETE,
            "deleted",
            name,
            before,
            before_value=before,
            debug_info={} if debug_info is None else debug_info,
        )

    @staticmethod
    def _script_entry(username, agent, message_end, debug_info, **values) -> None:
        host, host_id = (
            (agent.hostname, agent.agent_id) if agent else (SERVER_NAME, "N/A")
        )
        AuditLog.objects.create(
            username=username,
            message=f"{username} {message_end} {host}",
            agent=host,
            agent_id=host_id,
            debug_info={} if debug_info is None else debug_info,
            object_type=AuditObjType.AGENT,
            action=AuditActionType.EXEC_SCRIPT,
            **values,
        )

    @staticmethod
    def audit_script_run(username, script, agent, debug_info=None) -> None:
        AuditLog._script_entry(
            username, agent, f'ran script: "{script}" on', debug_info
        )

    @staticmethod
    def audit_test_script_run(
        username, before_value, after_value, agent, debug_info=None
    ) -> None:
        if isinstance(before_value, dict) and "env_vars" in before_value:
            before_value = {
                **before_value,
                "env_vars": mask_env_vars(before_value["env_vars"]),
            }
        # the output holds whatever the script printed, keys included
        if isinstance(after_value, dict):
            summary = {
                k: after_value[k]
                for k in ("retcode", "execution_time")
                if k in after_value
            }
            for k in ("stdout", "stderr"):
                if isinstance(after_value.get(k), str):
                    summary[f"{k}_bytes"] = len(after_value[k].encode())
            after_value = summary
        AuditLog._script_entry(
            username,
            agent,
            "tested a script on",
            debug_info,
            before_value=before_value,
            after_value=after_value,
        )

    @staticmethod
    def _user_entry(username, action, text, debug_info) -> None:
        AuditLog.objects.create(
            username=username,
            object_type=AuditObjType.USER,
            action=action,
            message=f"{username} {text}",
            debug_info={} if debug_info is None else debug_info,
        )

    @staticmethod
    def audit_user_failed_login(username, debug_info=None) -> None:
        AuditLog._user_entry(
            username,
            AuditActionType.FAILED_LOGIN,
            "failed to login: Credentials were rejected",
            debug_info,
        )

    @staticmethod
    def audit_user_failed_twofactor(username, debug_info=None) -> None:
        AuditLog._user_entry(
            username,
            AuditActionType.FAILED_LOGIN,
            "failed to login: Two Factor token rejected",
            debug_info,
        )

    @staticmethod
    def audit_user_login_successful(username, debug_info=None) -> None:
        AuditLog._user_entry(
            username, AuditActionType.LOGIN, "logged in successfully", debug_info
        )

    @staticmethod
    def audit_user_login_successful_sso(username, provider, debug_info=None) -> None:
        AuditLog._user_entry(
            username,
            AuditActionType.LOGIN,
            f"logged in successfully through SSO Provider {provider}",
            debug_info,
        )

    @staticmethod
    def _url_entry(username, text, instance, pattern, debug_info) -> None:
        from agents.models import Agent

        is_agent = isinstance(instance, Agent)
        kind = type(instance).__name__
        if instance is None:
            label = "None"
        else:
            label = instance.hostname if is_agent else instance.name
        AuditLog.objects.create(
            username=username,
            agent=instance.hostname if is_agent else None,
            agent_id=instance.agent_id if is_agent else None,
            object_type=kind.lower(),
            action=AuditActionType.URL_ACTION,
            message=f"{username} {text} on {kind}: {label}",
            debug_info={**(debug_info or {}), "pattern": hmac_marker(pattern)},
        )

    @staticmethod
    def audit_url_action(username, urlaction, instance, debug_info=None) -> None:
        AuditLog._url_entry(
            username,
            f"ran url action: {urlaction.name} ({_origin(urlaction.pattern)})",
            instance,
            urlaction.pattern,
            debug_info,
        )

    @staticmethod
    def audit_url_action_test(
        username, url, body, headers, instance_type, instance_id, debug_info=None
    ) -> None:
        from agents.models import Agent
        from clients.models import Client, Site

        lookups = {
            "agent": (Agent, "agent_id"),
            "site": (Site, "pk"),
            "client": (Client, "pk"),
        }
        instance = None
        if instance_type in lookups:
            model, field = lookups[instance_type]
            instance = _get_or_none(model, **{field: instance_id})

        info = {
            **(debug_info or {}),
            "body": hmac_marker(body),
            "headers": hmac_marker(headers),
        }
        AuditLog._url_entry(
            username, f"tested url action: {_origin(url)}", instance, url, info
        )

    @staticmethod
    def audit_bulk_action(
        username, action, affected, agent_pks, offline, debug_info=None
    ) -> None:
        from agents.models import Agent
        from clients.models import Client, Site
        from groups.models import DeviceGroup
        from scripts.models import Script

        hostnames: list = []
        target = affected.get("target")
        if target == "all":
            where = "on all agents"
        elif target == "client":
            client = _name_or_pk(Client, affected.get("client"), lambda c: c.name)
            where = f"on all agents within client: {client}"
        elif target == "site":
            site = _name_or_pk(
                Site, affected.get("site"), lambda s: f"{s.client.name} - {s.name}"
            )
            where = f"on all agents within site: {site}"
        elif target == "group":
            group = _name_or_pk(DeviceGroup, affected.get("group"), lambda g: g.name)
            where = f"on device group: {group}"
        elif target == "agents":
            where = "on multiple agents"
            hostnames = list(
                Agent.objects.filter(pk__in=agent_pks)
                .order_by("pk")
                .values_list("hostname", flat=True)
            )
        else:
            where = ""

        if action == "script":
            script = _name_or_pk(Script, affected.get("script"), lambda s: s.name)
            action = f"script: {script}"

        # callers keep their dict; mode/target stay top level for notify.tamper
        stored = dict(affected)
        if "env_vars" in stored:
            stored["env_vars"] = mask_env_vars(stored["env_vars"])
        if "args" in stored:
            stored["args"] = mask_script_args(stored["args"])
        if hostnames:
            stored["agent_hostnames"] = hostnames
        stored["agents_sent_to"] = len(agent_pks)
        stored["offline_skipped"] = offline

        sent = f", sent to {len(agent_pks)} agents"
        if offline:
            sent += f", {offline} offline skipped"

        AuditLog.objects.create(
            username=username,
            object_type=AuditObjType.BULK,
            action=AuditActionType.BULK_ACTION,
            message=f"{username} executed bulk {action} {where}{sent}",
            after_value=stored,
            debug_info={} if debug_info is None else debug_info,
        )


class DebugLog(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    entry_time = models.DateTimeField(auto_now_add=True)
    agent = models.ForeignKey(
        "agents.Agent",
        related_name="debuglogs",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    log_level = models.CharField(
        max_length=50, choices=DebugLogLevel.choices, default=DebugLogLevel.INFO
    )
    log_type = models.CharField(
        max_length=50,
        choices=DebugLogType.choices,
        default=DebugLogType.SYSTEM_ISSUES,
    )
    message = models.TextField(null=True, blank=True)

    class Meta:
        # agent_id already has the index of its foreign key
        indexes = [models.Index(fields=["entry_time"])]

    @classmethod
    def _write(cls, level, message, agent, log_type) -> None:
        if LEVEL_RANK[level] < LEVEL_RANK.get(get_debug_level(), 99):
            return
        cls.objects.create(
            log_level=level, agent=agent, log_type=log_type, message=message
        )

    @classmethod
    def info(cls, message, agent=None, log_type=DebugLogType.SYSTEM_ISSUES) -> None:
        cls._write("info", message, agent, log_type)

    @classmethod
    def warning(cls, message, agent=None, log_type=DebugLogType.SYSTEM_ISSUES):
        cls._write("warning", message, agent, log_type)

    @classmethod
    def error(cls, message, agent=None, log_type=DebugLogType.SYSTEM_ISSUES) -> None:
        cls._write("error", message, agent, log_type)

    @classmethod
    def critical(cls, message, agent=None, log_type=DebugLogType.SYSTEM_ISSUES):
        cls._write("critical", message, agent, log_type)


class PendingAction(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(
        "agents.Agent",
        related_name="pendingactions",
        on_delete=models.CASCADE,
    )
    entry_time = models.DateTimeField(auto_now_add=True)
    action_type = models.CharField(
        max_length=255, choices=PAAction.choices, null=True, blank=True
    )
    status = models.CharField(
        max_length=255, choices=PAStatus.choices, default=PAStatus.PENDING
    )
    details = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.agent.hostname} - {self.action_type}"

    def _details(self) -> dict:
        # malformed rows must not break the list or the cancel
        return self.details if isinstance(self.details, dict) else {}

    @property
    def due(self) -> Optional[str]:
        if self.action_type == PAAction.SCHED_REBOOT:
            return self._details().get("time")
        if self.action_type == PAAction.AGENT_UPDATE:
            return "Next update cycle"
        if self.action_type in (PAAction.CHOCO_INSTALL, PAAction.WINGET_INSTALL):
            return "ASAP"
        return "On next checkin"

    @property
    def description(self) -> Optional[str]:
        kind = self.action_type
        if kind == PAAction.SCHED_REBOOT:
            return "Device pending reboot"
        if kind == PAAction.AGENT_UPDATE:
            version = self._details().get("version")
            return f"Agent update to {version}" if version else "Agent update"
        if kind in (PAAction.CHOCO_INSTALL, PAAction.WINGET_INSTALL):
            name = self._details().get("name")
            return f"{name} software install" if name else "Software install"
        if kind in (
            PAAction.RUN_CMD,
            PAAction.RUN_SCRIPT,
            PAAction.RUN_PATCH_SCAN,
            PAAction.RUN_PATCH_INSTALL,
        ):
            return str(kind)
        return None


class BaseAuditModel(models.Model):
    created_by = models.CharField(max_length=255, null=True, blank=True)
    created_time = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    modified_by = models.CharField(max_length=255, null=True, blank=True)
    modified_time = models.DateTimeField(auto_now=True, null=True, blank=True)

    class Meta:
        abstract = True

    def serialize(self):
        # concrete models override this; a model without one audits None
        return None

    def save(self, old_model=None, *args, **kwargs) -> None:
        username = get_username()
        if not username:
            super().save(*args, **kwargs)
            return

        model = type(self)
        object_type = model.__name__.lower()
        # serialised before the stamps change, so an untouched row stays equal
        after = _mask_env_keys(model.serialize(self))

        if not self.created_by:
            self.created_by = username
        self.modified_by = username

        exists = bool(self.pk) and model.objects.filter(pk=self.pk).exists()
        before = None
        if exists:
            source = old_model
            if source is None:
                source = model.objects.get(pk=self.pk)
            before = _mask_env_keys(model.serialize(source))

        # one transaction: no change without its audit row
        with transaction.atomic():
            super().save(*args, **kwargs)

            # written after the row so a failed save leaves no audit entry
            if not exists:
                AuditLog.audit_object_add(
                    username,
                    object_type,
                    _mask_env_keys(model.serialize(self)),
                    str(self),
                    debug_info=get_debug_info(),
                )
            elif before != after:
                AuditLog.audit_object_changed(
                    username,
                    object_type,
                    before,
                    after,
                    str(self),
                    debug_info=get_debug_info(),
                )

    def delete(self, *args, **kwargs):
        username = get_username()
        if username:
            # taken before the delete clears the pk and cascades children
            before = _mask_env_keys(type(self).serialize(self))
            name = str(self)

        # one transaction: no change without its audit row
        with transaction.atomic():
            result = super().delete(*args, **kwargs)

            if username:
                AuditLog.audit_object_delete(
                    username,
                    type(self).__name__.lower(),
                    before,
                    name,
                    debug_info=get_debug_info(),
                )
        return result

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import asyncio
import hashlib
import random
import re
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Optional, Union

import msgpack
import nats
import requests
import validators
from asgiref.sync import sync_to_async
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import models, transaction
from django.db.models import Count, F, Prefetch
from django.utils import timezone as djangotime
from nats.errors import NoRespondersError
from nats.errors import TimeoutError as NatsTimeoutError
from packaging.version import InvalidVersion
from packaging.version import Version as PkgVersion

from agents.utils import (
    calculate_agent_checks,
    get_agent_artifact_sha256,
    get_agent_url,
    is_posix_abs_path,
    is_windows_path,
    strip_relation_caches_for_cache,
)
from core.models import TZ_CHOICES
from core.utils import _b64_to_hex, get_core_settings, send_command_with_mesh
from deploy import envelope
from deploy.signing import sign_agent_update
from logs.models import BaseAuditModel, DebugLog, PendingAction
from ulrmm.agent_ident import (
    UnknownAgentIdentity,
    agent_artifact_for,
    agent_ident_for,
    nix_rc_name,
)
from ulrmm.constants import (
    AGENT_STATUS_OFFLINE,
    AGENT_STATUS_ONLINE,
    AGENT_STATUS_OVERDUE,
    AGENT_TBL_PEND_ACTION_CNT_CACHE_PREFIX,
    DARWIN_TOKENS,
    FREEBSD_TOKENS,
    LINUX_TOKENS,
    ONLINE_AGENTS,
    WINDOWS_TOKENS,
    AgentHistoryType,
    AgentMonType,
    AgentPlat,
    AgentTerminalShellChoices,
    AppUpdatePolicy,
    CheckType,
    CustomFieldType,
    DebugLogType,
    GoArch,
    PAAction,
    PAStatus,
)
from ulrmm.helpers import agent_ver, has_script_actions, has_webhook, setup_nats_options
from ulrmm.logger import logger
from ulrmm.models import PermissionQuerySet

if TYPE_CHECKING:
    from alerts.models import Alert, AlertTemplate
    from automation.models import Policy
    from autotasks.models import AutomatedTask
    from checks.models import Check
    from clients.models import Client
    from winupdate.models import WinUpdatePolicy

# HKDF info of the uninstall code ciphertext. Changing it makes every stored
# code unreadable.
UNINSTALL_CODE_INFO = b"agents.Agent.uninstall_code"

# AgentPlat is imported by the consumers and tests from here
__all__ = [
    "Agent",
    "AgentCustomField",
    "AgentHistory",
    "AgentPlat",
    "Note",
    "UNINSTALL_CODE_INFO",
]

# seconds the failed patch mail waits for the other results of the run
PATCH_FAIL_MAIL_DELAY = 120
# a power event older than this before last_seen belongs to an earlier silence
POWER_EVENT_SLACK = djangotime.timedelta(minutes=2)

_SEVERITY_LABELS = {
    "critical": "Critical",
    "important": "Important",
    "moderate": "Moderate",
    "low": "Low",
    "other": "",
}
_KB_VERSION_RE = re.compile(r"\((?:Version|Versão)\s+([^)]+)\)")
_SHELL_TOKENS = frozenset({"cmd", "powershell", "bash", "sh"})
_TEMPLATE_KEYS = ("site_policy", "client_policy")
_MIN_RUN_INTERVAL = 15
# the cap of the web edit form
_MAX_CHECK_INTERVAL = 86400
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
SELF_BUILT_SHA_TTL = 30 * 24 * 60 * 60
SELF_BUILT_FAIL_TTL = 5 * 60
SELF_BUILT_MAX_SIZE = 512 * 1024 * 1024


def _download_sha256(url: str) -> str:
    digest, size = hashlib.sha256(), 0
    try:
        with requests.get(url, stream=True, timeout=(15, 300)) as r:
            if r.status_code != 200 or not r.url.startswith("https://"):
                return ""
            for chunk in r.iter_content(1024 * 1024):
                size += len(chunk)
                if size > SELF_BUILT_MAX_SIZE:
                    return ""
                digest.update(chunk)
    except requests.RequestException:
        return ""
    return digest.hexdigest() if size else ""


def self_built_sha256(url: str, version: str, *, fetch: bool = True) -> str:
    """sha256 of an agent build under SELF_BUILT_AGENTS_URL, downloaded once
    per (url, version); "" when it cannot be fetched over https, and for five
    minutes after that. fetch=False only reads what is cached."""
    key = "selfbuilt_sha256:" + hashlib.sha256(f"{url}\0{version}".encode()).hexdigest()
    cached = cache.get(key)
    if isinstance(cached, str) and _SHA256_HEX.fullmatch(cached):
        return cached
    if not fetch or not url.startswith("https://") or cache.get(key + ":failed"):
        return ""
    value = _download_sha256(url)
    if value:
        cache.set(key, value, SELF_BUILT_SHA_TTL)
    else:
        # every agent of an update run would download it again
        cache.set(key + ":failed", 1, SELF_BUILT_FAIL_TTL)
    return value


def _first(entries, key: str):
    """WMI rows are lists of small dicts; the first one holding `key` wins."""
    for entry in entries:
        if isinstance(entry, dict) and key in entry:
            return entry[key]
    raise KeyError(key)


def _shell_for(plat: str, choice, custom) -> str:
    """Validated shell for a platform; falls back instead of failing."""
    if plat == AgentPlat.WINDOWS:
        fallback, tokens, path_ok = "cmd", WINDOWS_TOKENS, is_windows_path
    elif plat == AgentPlat.LINUX:
        fallback, tokens, path_ok = "bash", LINUX_TOKENS, is_posix_abs_path
    elif plat == AgentPlat.DARWIN:
        fallback, tokens, path_ok = "bash", DARWIN_TOKENS, is_posix_abs_path
    elif plat == AgentPlat.FREEBSD:
        fallback, tokens, path_ok = "sh", FREEBSD_TOKENS, is_posix_abs_path
    else:
        return "cmd"

    choice = (choice or "").strip().lower()
    if choice == AgentTerminalShellChoices.CUSTOM:
        path = (custom or "").strip()
        return path if path_ok(path) else fallback
    return choice if choice in tokens else fallback


class Agent(BaseAuditModel):
    class Meta:
        indexes = [models.Index(fields=["monitoring_type"])]

    objects = PermissionQuerySet.as_manager()

    version = models.CharField(default="0.1.0", max_length=255)
    operating_system = models.CharField(null=True, blank=True, max_length=255)
    plat = models.CharField(
        max_length=255, choices=AgentPlat.choices, default=AgentPlat.WINDOWS
    )
    goarch = models.CharField(
        max_length=255, choices=GoArch.choices, null=True, blank=True
    )
    hostname = models.CharField(max_length=255)
    # name shown on the dashboard and in MeshCentral, hostname when empty
    display_name = models.CharField(max_length=64, blank=True, default="")
    agent_id = models.CharField(max_length=200, unique=True)
    # which build registered; only this server's identity gets artifacts
    agent_ident = models.CharField(max_length=255, blank=True, default="")

    # written by natsapi with raw SQL: names and types are fixed
    last_seen = models.DateTimeField(null=True, blank=True)
    services = models.JSONField(null=True, blank=True)
    public_ip = models.CharField(null=True, max_length=255)
    total_ram = models.IntegerField(null=True, blank=True)
    disks = models.JSONField(null=True, blank=True)
    boot_time = models.FloatField(null=True, blank=True)
    logged_in_username = models.CharField(null=True, blank=True, max_length=255)
    last_logged_in_user = models.CharField(null=True, blank=True, max_length=255)
    needs_reboot = models.BooleanField(default=False)
    wmi_detail = models.JSONField(null=True, blank=True)

    monitoring_type = models.CharField(
        max_length=30, choices=AgentMonType.choices, default=AgentMonType.SERVER
    )
    description = models.CharField(null=True, blank=True, max_length=255)
    mesh_node_id = models.CharField(null=True, blank=True, max_length=255)
    overdue_email_alert = models.BooleanField(default=False)
    overdue_text_alert = models.BooleanField(default=False)
    overdue_dashboard_alert = models.BooleanField(default=False)
    offline_time = models.PositiveIntegerField(default=4)
    overdue_time = models.PositiveIntegerField(default=30)
    check_interval = models.PositiveIntegerField(default=120)
    keep_awake_until = models.DateTimeField(null=True, blank=True)
    # macOS: never sleeps on AC power, lid closed included; the agent keeps it
    keep_awake_ac = models.BooleanField(default=False)
    # orderly shutdown, restart or sleep announced by the agent or sent from
    # here; natsapi writes them with raw SQL too
    power_event = models.CharField(max_length=32, blank=True, default="")
    power_event_at = models.DateTimeField(null=True, blank=True)
    power_event_by = models.CharField(max_length=255, blank=True, default="")
    network_info = models.JSONField(default=dict, blank=True)
    app_updates = models.CharField(
        max_length=10, choices=AppUpdatePolicy.choices, default=AppUpdatePolicy.INHERIT
    )

    # asset record
    asset_tag = models.CharField(max_length=64, blank=True, default="")
    purchase_date = models.DateField(null=True, blank=True)
    purchase_price = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True
    )
    vendor = models.CharField(max_length=120, blank=True, default="")
    warranty_end = models.DateField(null=True, blank=True)
    warranty_status = models.JSONField(default=dict, blank=True)
    lifecycle_notes = models.CharField(max_length=2000, blank=True, default="")

    # Fernet token (UNINSTALL_CODE_INFO), never serialized in clear
    uninstall_code = models.TextField(blank=True, default="")
    tamper_alerted_at = models.DateTimeField(null=True, blank=True)

    choco_installed = models.BooleanField(default=False)
    patches_last_installed = models.DateTimeField(null=True, blank=True)
    time_zone = models.CharField(
        max_length=255, choices=TZ_CHOICES, null=True, blank=True
    )
    maintenance_mode = models.BooleanField(default=False)
    block_policy_inheritance = models.BooleanField(default=False)
    alert_template = models.ForeignKey(
        "alerts.AlertTemplate",
        related_name="agents",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    site = models.ForeignKey(
        "clients.Site", related_name="agents", on_delete=models.RESTRICT
    )
    policy = models.ForeignKey(
        "automation.Policy",
        related_name="agents",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    default_shell = models.CharField(
        max_length=32,
        choices=AgentTerminalShellChoices.choices,
        default=AgentTerminalShellChoices.USE_GLOBAL,
    )
    default_shell_custom = models.CharField(max_length=512, blank=True, default="")

    def __str__(self) -> str:
        return self.hostname

    def save(self, *args, **kwargs) -> None:
        # a new site, monitoring type or policy can change the alert template;
        # set_alert_template saves again, the flag stops the recursion
        moved = False
        if self.pk and not getattr(self, "_recalculating_template", False):
            stored = (
                type(self)
                .objects.filter(pk=self.pk)
                .values(
                    "monitoring_type",
                    "site_id",
                    "policy_id",
                    "block_policy_inheritance",
                )
                .first()
            )
            if stored and (
                stored["monitoring_type"] != self.monitoring_type
                or stored["site_id"] != self.site_id
                or stored["policy_id"] != self.policy_id
                or stored["block_policy_inheritance"] != self.block_policy_inheritance
            ):
                moved = True
                self._recalculating_template = True
                try:
                    self.set_alert_template()
                finally:
                    self._recalculating_template = False

        super().save(*args, **kwargs)
        if moved:
            # the policy merges are rebuilt from the database, so the keys go
            # only once the new assignment is visible to other connections
            key = f"agent_{self.agent_id}_*"
            transaction.on_commit(lambda: cache.delete_many_pattern(key))

    @staticmethod
    def serialize(agent: "Agent") -> dict[str, Any]:
        from . import serializers

        return serializers.AgentAuditSerializer(agent).data

    # simple facts

    @property
    def client(self) -> "Client":
        return self.site.client

    @property
    def effective_name(self) -> str:
        return self.display_name or self.hostname

    @property
    def is_posix(self) -> bool:
        return self.plat in (AgentPlat.LINUX, AgentPlat.DARWIN, AgentPlat.FREEBSD)

    @property
    def timezone(self) -> str:
        return self.time_zone or get_core_settings().default_time_zone

    @property
    def arch(self) -> Optional[str]:
        # deprecated, still read by patches.mirror and post_update_tasks
        if self.is_posix:
            return self.goarch
        os_name = self.operating_system or ""
        if "64 bit" in os_name or "64bit" in os_name:
            return "64"
        if "32 bit" in os_name or "32bit" in os_name:
            return "32"
        return None

    @property
    def is_online(self) -> bool:
        # status == online without the alert template lookup overdue needs
        return bool(self.last_seen) and djangotime.now() - self.last_seen <= (
            djangotime.timedelta(minutes=self.offline_time)
        )

    @property
    def power_event_applies(self) -> bool:
        # the event belongs to the current silence, a later check-in ends it;
        # core.stats.power_event_q is the same test in SQL
        return bool(
            self.power_event
            and self.power_event_at
            and (
                not self.last_seen
                or self.power_event_at >= self.last_seen - POWER_EVENT_SLACK
            )
        )

    @property
    def planned_offline(self) -> bool:
        return not self.is_online and self.power_event_applies

    def record_power_event(self, kind: str, by: str) -> None:
        self.power_event, self.power_event_by = kind, by[:255]
        self.power_event_at = djangotime.now()
        type(self).objects.filter(pk=self.pk).update(
            power_event=self.power_event,
            power_event_at=self.power_event_at,
            power_event_by=self.power_event_by,
        )

    @property
    def status(self) -> str:
        if not self.last_seen:
            return AGENT_STATUS_OFFLINE
        if self.is_online:
            return AGENT_STATUS_ONLINE
        silent_for = djangotime.now() - self.last_seen
        if silent_for < djangotime.timedelta(minutes=self.overdue_time):
            return AGENT_STATUS_OFFLINE
        # shut down, restarted or put to sleep on purpose: quiet until it is back
        if self.power_event_applies:
            return AGENT_STATUS_OFFLINE
        # a silent agent nobody is alerted about is just switched off
        if not self.should_create_alert(self.alert_template):
            return AGENT_STATUS_OFFLINE
        return AGENT_STATUS_OVERDUE

    @property
    def effective_default_shell(self) -> str:
        own = self.default_shell
        if own and own != AgentTerminalShellChoices.USE_GLOBAL:
            return _shell_for(self.plat, self.default_shell, self.default_shell_custom)

        try:
            core = get_core_settings()
        except Exception:
            return _shell_for(self.plat, "", "")

        suffix = {
            AgentPlat.WINDOWS: "windows",
            AgentPlat.LINUX: "linux",
            AgentPlat.DARWIN: "darwin",
            AgentPlat.FREEBSD: "freebsd",
        }.get(self.plat)
        if suffix is None:
            return "cmd"
        return _shell_for(
            self.plat,
            getattr(core, f"default_shell_{suffix}", ""),
            getattr(core, f"default_shell_{suffix}_custom", ""),
        )

    @property
    def resolved_default_shell(self) -> str:
        shell = self.effective_default_shell.lower()
        return shell if shell in _SHELL_TOKENS else "custom"

    @property
    def checks(self) -> dict[str, Any]:
        return calculate_agent_checks(self)

    @property
    def pending_actions_count(self) -> int:
        key = f"{AGENT_TBL_PEND_ACTION_CNT_CACHE_PREFIX}{self.pk}"
        cached = cache.get(key)
        if cached is not None:
            return cached
        pending = self.pendingactions.filter(status=PAStatus.PENDING).count()
        cache.set(key, pending, 600)
        return pending

    @property
    def hex_mesh_node_id(self) -> str:
        with suppress(Exception):
            return _b64_to_hex(self.mesh_node_id)
        return "error"

    # hardware summary from agent-reported data (untrusted)

    @property
    def cpu_model(self) -> list[str]:
        try:
            if self.is_posix:
                return self.wmi_detail["cpus"]
            models_ = []
            for cpu in self.wmi_detail["cpu"]:
                name = _first(cpu, "Name")
                try:
                    cores = _first(cpu, "NumberOfCores")
                    threads = _first(cpu, "NumberOfLogicalProcessors")
                except KeyError:
                    cores = threads = None
                if cores and threads:
                    models_.append(f"{name}, {cores}C/{threads}T")
                else:
                    models_.append(name)
            return models_
        except Exception:
            return ["unknown cpu model"]

    @property
    def graphics(self) -> str:
        if self.is_posix:
            try:
                gpus = self.wmi_detail["gpus"]
                return ", ".join(gpus) if gpus else "No graphics cards"
            except Exception:
                return "Error getting graphics cards"

        try:
            names = []
            remote_adapter = False
            for gpu in self.wmi_detail["graphics"]:
                caption = _first(gpu, "Caption")
                if "microsoft remote display adapter" in caption.lower():
                    remote_adapter = True
                    continue
                names.append(caption)
            if not names and remote_adapter:
                return "Microsoft Remote Display Adapter"
            return ", ".join(names)
        except Exception:
            return "Graphics info requires agent v1.4.14"

    @property
    def local_ips(self) -> str:
        failed = "error getting local ips"
        try:
            if self.is_posix:
                return ", ".join(self.wmi_detail["local_ips"])
            ips = []
            for adapter in self.wmi_detail["network_config"]:
                try:
                    addresses = _first(adapter, "IPAddress")
                except KeyError:
                    continue
                if not addresses:
                    continue
                ips.extend(ip for ip in addresses if validators.ipv4(ip))
            return ", ".join(ips) if ips else failed
        except Exception:
            return failed

    @property
    def make_model(self) -> str:
        if self.is_posix:
            try:
                return self.wmi_detail["make_model"]
            except Exception:
                return "error getting make/model"

        try:
            product = self.wmi_detail["comp_sys_prod"][0]
            system = self.wmi_detail["comp_sys"][0]
            make = _first(product, "Vendor")
            model = _first(system, "Model")
            if "to be filled" in model.lower():
                board = self.wmi_detail["base_board"][0]
                make = _first(board, "Manufacturer")
                model = _first(board, "Product")
            if make.lower() == "lenovo":
                family = _first(system, "SystemFamily")
                if "to be filled" not in family.lower():
                    model = family
            return f"{make} {model}"
        except Exception:
            pass

        try:
            return _first(self.wmi_detail["comp_sys_prod"][0], "Version")
        except Exception:
            return "unknown make/model"

    @property
    def physical_disks(self) -> list[str]:
        if self.is_posix:
            try:
                return self.wmi_detail["disks"]
            except Exception:
                return ["unknown disk"]

        disks = []
        try:
            for disk in self.wmi_detail["disk"]:
                interface = _first(disk, "InterfaceType")
                if interface == "USB":
                    continue
                size = round(int(_first(disk, "Size")) / 1_073_741_824)
                disks.append(f"{_first(disk, 'Caption')} {size:,}GB {interface}")
        except Exception:
            disks = ["unknown disk"]
        return disks

    @property
    def serial_number(self) -> str:
        wmi = self.wmi_detail
        with suppress(Exception):
            if self.is_posix:
                return wmi["serialnumber"]
            return _first(wmi["bios"][0], "SerialNumber")
        return ""

    @property
    def appliance(self) -> str:
        """Appliance OS the agent reports, such as TrueNAS, else ""."""
        wmi = self.wmi_detail if isinstance(self.wmi_detail, dict) else {}
        found = wmi.get("appliance")
        name = found.get("name") if isinstance(found, dict) else ""
        return name if isinstance(name, str) else ""

    @property
    def wol_armed(self) -> Optional[bool]:
        """True/False once the agent reports its power health, None before."""
        wmi = self.wmi_detail if isinstance(self.wmi_detail, dict) else {}
        nics = wmi.get("nics")
        nics = nics if isinstance(nics, list) else []
        health = wmi.get("health")
        health = health if isinstance(health, dict) else {}
        power = health.get("power")
        power = power if isinstance(power, dict) else {}

        if power.get("womp_ac") is True:
            return True
        if any(isinstance(nic, dict) and nic.get("wol") == "on" for nic in nics):
            return True
        return False if health else None

    # lookups

    @classmethod
    def online_agents(cls, min_version: str = "") -> "list[Agent]":
        floor = agent_ver(min_version) if min_version else None
        return [
            agent
            for agent in cls.objects.only(*ONLINE_AGENTS)
            if agent.is_online and (floor is None or agent_ver(agent.version) >= floor)
        ]

    def is_supported_script(self, platforms: list) -> bool:
        return not platforms or self.plat.lower() in platforms

    # policies

    def get_agent_policies(self) -> "dict[str, Optional[Policy]]":
        from autotasks.models import AutomatedTask
        from checks.models import Check

        mon_type = self.monitoring_type
        site_policy = getattr(self.site, f"{mon_type}_policy", None)
        client_policy = getattr(self.client, f"{mon_type}_policy", None)
        default_policy = getattr(get_core_settings(), f"{mon_type}_policy", None)

        found = [
            p for p in (self.policy, site_policy, client_policy, default_policy) if p
        ]
        if found:
            models.prefetch_related_objects(
                found,
                Prefetch("excluded_agents", queryset=Agent.objects.only("pk")),
                "excluded_sites",
                "excluded_clients",
                # pk order: get_policy_checks keeps the first of equal checks
                Prefetch(
                    "policychecks",
                    queryset=Check.objects.select_related("script").order_by("pk"),
                ),
                Prefetch("autotasks", queryset=AutomatedTask.objects.order_by("pk")),
            )

        def applies(policy) -> bool:
            return bool(policy) and not policy.is_agent_excluded(self)

        agent_blocks = self.block_policy_inheritance
        site_blocks = agent_blocks or self.site.block_policy_inheritance
        client_blocks = site_blocks or self.client.block_policy_inheritance

        return {
            "agent_policy": self.policy if applies(self.policy) else None,
            "site_policy": (
                site_policy if applies(site_policy) and not agent_blocks else None
            ),
            "client_policy": (
                client_policy if applies(client_policy) and not site_blocks else None
            ),
            "default_policy": (
                default_policy
                if applies(default_policy) and not client_blocks
                else None
            ),
        }

    def _policy_cache_key(self, kind: str) -> str:
        # always per agent: get_agent_policies drops the policies that exclude
        # this agent, so agents of one site can merge differently
        return f"agent_{self.agent_id}_{kind}"

    def get_checks_from_policies(self) -> "list[Check]":
        from automation.models import Policy

        key = self._policy_cache_key("checks")
        cached = cache.get(key)
        if isinstance(cached, list):
            return cached

        # get_policy_checks marks the agent checks a policy overrides again;
        # one transaction, so no reader sees them all active in between
        with transaction.atomic():
            self.agentchecks.update(overridden_by_policy=False)
            checks = Policy.get_policy_checks(self)
        cache.set(key, strip_relation_caches_for_cache(checks), 600)
        return checks

    def get_tasks_from_policies(self) -> "list[AutomatedTask]":
        from automation.models import Policy

        key = self._policy_cache_key("tasks")
        cached = cache.get(key)
        if isinstance(cached, list):
            return cached

        tasks = Policy.get_policy_tasks(self)
        cache.set(key, strip_relation_caches_for_cache(tasks), 600)
        return tasks

    def add_check_results(self, checks: "list[Check]") -> "list[Check]":
        results = {r.assigned_check_id: r for r in self.checkresults.all()}
        for check in checks:
            if check.pk in results:
                check.check_result = results[check.pk]
        return checks

    def add_task_results(self, tasks: "list[AutomatedTask]") -> "list[AutomatedTask]":
        results = {r.task_id: r for r in self.taskresults.all()}
        for task in tasks:
            if task.pk in results:
                task.task_result = results[task.pk]
        return tasks

    def get_checks_with_policies(
        self, exclude_overridden: bool = False
    ) -> "list[Check]":
        # policy first: it refreshes the overridden flags read below
        from_policies = self.get_checks_from_policies()
        own = self.agentchecks.select_related("script").order_by("pk")
        if exclude_overridden:
            own = own.filter(overridden_by_policy=False)
        return self.add_check_results(list(own) + list(from_policies))

    def get_tasks_with_policies(self) -> "list[AutomatedTask]":
        from_policies = self.get_tasks_from_policies()
        own = list(self.autotasks.order_by("pk"))
        return self.add_task_results(own + list(from_policies))

    def check_run_interval(self, checks: "Optional[list[Check]]" = None) -> int:
        # rows saved before the edit form had a lower bound may hold 0
        interval = max(self.check_interval, _MIN_RUN_INTERVAL)
        if checks is None:
            checks = self.get_checks_with_policies(exclude_overridden=True)
        for check in checks:
            # metric checks run on the state push, not on the agent's schedule
            if check.check_type == CheckType.METRIC:
                continue
            if check.run_interval and check.run_interval < interval:
                interval = max(check.run_interval, _MIN_RUN_INTERVAL)
        low, high = getattr(settings, "CHECK_INTERVAL_JITTER", (1, 60))
        return interval + random.randint(low, high)

    # scripts

    def _first_answering(self, candidates) -> "Optional[Agent]":
        for agent in candidates:
            if agent.pk == self.pk or not agent.is_online:
                continue
            if asyncio.run(agent.nats_cmd({"func": "ping"}, timeout=1)) == "pong":
                return agent
        return None

    def run_script(
        self,
        scriptpk: int,
        args: list[str] = [],
        timeout: int = 120,
        full: bool = False,
        wait: bool = False,
        run_on_any: bool = False,
        history_pk: int = 0,
        run_as_user: bool = False,
        env_vars: list[str] = [],
        wait_timeout: int = 0,
    ) -> Any:
        from scripts.models import Script

        script = Script.objects.get(pk=scriptpk)
        # the script's own setting wins over the caller
        if script.run_as_user:
            run_as_user = True

        data: dict[str, Any] = {
            "func": "runscriptfull" if full else "runscript",
            "timeout": timeout,
            "script_args": script.parse_script_args(self, script.shell, args),
            "payload": {"code": script.code, "shell": script.shell},
            "run_as_user": run_as_user,
            "env_vars": script.parse_script_env_vars(self, script.shell, env_vars),
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }
        if history_pk != 0:
            data["id"] = history_pk

        runner: Optional[Agent] = self
        if run_on_any:
            if asyncio.run(self.nats_cmd({"func": "ping"}, timeout=1)) != "pong":
                # stand-ins stay inside the customer: same site, then same client
                others = Agent.objects.only(*ONLINE_AGENTS).order_by("pk")
                runner = self._first_answering(
                    others.filter(site_id=self.site_id)
                ) or self._first_answering(
                    others.filter(site__client_id=self.site.client_id).exclude(
                        site_id=self.site_id
                    )
                )
            if runner is None:
                return "Unable to find an online agent"

        if wait:
            return asyncio.run(
                runner.nats_cmd(data, timeout=wait_timeout or timeout, wait=True)
            )

        asyncio.run(runner.nats_cmd(data, wait=False))
        return "ok"

    # patching

    def get_patch_policy(self) -> "WinUpdatePolicy":
        from winupdate.models import WinUpdatePolicy

        own = self.winupdatepolicy.order_by("pk").first()
        if own is None:
            own = WinUpdatePolicy.objects.create(agent=self)

        base = None
        for policy in self.get_agent_policies().values():
            if policy and policy.active:
                base = policy.winupdatepolicy.order_by("pk").first()
                if base is not None:
                    break
        if base is None:
            return own

        # agent overrides on top of the policy, kept in memory only
        for field in ("critical", "important", "moderate", "low", "other", "drivers"):
            if getattr(own, field) != "inherit":
                setattr(base, field, getattr(own, field))
        if own.reboot_after_install != "inherit":
            base.reboot_after_install = own.reboot_after_install
        if own.run_time_frequency != "inherit":
            base.run_time_frequency = own.run_time_frequency
            base.run_time_hour = own.run_time_hour
            base.run_time_days = own.run_time_days
            base.run_time_day = own.run_time_day
        if not own.reprocess_failed_inherit:
            base.reprocess_failed = own.reprocess_failed
            base.reprocess_failed_times = own.reprocess_failed_times
            base.email_if_fail = own.email_if_fail
        return base

    def approve_updates(self) -> None:
        policy = self.get_patch_policy()
        severities = [
            label
            for field, label in _SEVERITY_LABELS.items()
            if getattr(policy, field) == "approve"
        ]
        if not severities:
            return
        # an ignored update is an operator decision and stays ignored
        updates = self.winupdates.filter(
            severity__in=severities, installed=False
        ).exclude(action__in=("approve", "ignore"))
        # drivers only when the policy includes them, inherit at the top means no
        if policy.drivers != "include":
            updates = updates.exclude(is_driver=True)
        updates.update(action="approve")

    def get_approved_update_guids(self, automatic: bool = False) -> list[str]:
        updates = self.winupdates.filter(action="approve", installed=False)
        if automatic:
            # the failed patch options limit the schedule and maintenance
            # windows only, Install now always sends every approved update
            policy = self.get_patch_policy()
            if not policy.reprocess_failed:
                updates = updates.exclude(result="failed")
            else:
                updates = updates.exclude(fail_count__gt=policy.reprocess_failed_times)
        return list(updates.values_list("guid", flat=True))

    def handle_patch_reboot(self, needs_reboot: bool) -> bool:
        self.needs_reboot = needs_reboot
        self.save(update_fields=["needs_reboot"])

        mode = self.get_patch_policy().reboot_after_install
        if mode == "always" or (mode == "required" and needs_reboot):
            asyncio.run(self.nats_cmd({"func": "rebootnow"}, wait=False))
            self.record_power_event("restart", "rmm: patch reboot")
            DebugLog.info(
                agent=self,
                log_type=DebugLogType.WIN_UPDATES,
                message=f"{self.hostname} is rebooting after updates were installed.",
            )
            return True
        return False

    def set_update_result(self, guid: str, success: bool) -> bool:
        from winupdate.installing import clear_installing

        clear_installing(self.pk, [guid])
        updates = self.winupdates.filter(guid=guid)
        if not updates.exists():
            return False

        if success:
            updates.update(
                result="success",
                downloaded=True,
                installed=True,
                date_installed=djangotime.now(),
                fail_count=0,
            )
        else:
            updates.update(result="failed", fail_count=F("fail_count") + 1)
            self._queue_patch_failed_email()
        self.delete_superseded_updates()
        return True

    def _queue_patch_failed_email(self) -> None:
        from winupdate.tasks import patch_failed_email_task

        if self.maintenance_mode or not self.get_patch_policy().email_if_fail:
            return
        # the agent reports every update on its own, one mail covers the run
        if cache.add(f"patch-failed-email-{self.pk}", 1, PATCH_FAIL_MAIL_DELAY * 2):
            patch_failed_email_task.apply_async(
                (self.pk,), countdown=PATCH_FAIL_MAIL_DELAY
            )

    def delete_superseded_updates(self) -> None:
        """Keep only the newest version of updates that share a KB."""
        try:
            kbs = (
                self.winupdates.order_by()
                .values("kb")
                .annotate(rows=Count("pk"))
                .filter(rows__gt=1)
                .values_list("kb", flat=True)
            )
            for kb in list(kbs):
                # driver updates have no KB, they are not versions of each other
                if kb is None:
                    continue
                with suppress(Exception):
                    self._drop_older_versions(kb)
        except Exception:
            pass

    def _drop_older_versions(self, kb: str) -> None:
        versions = {}
        for pk, title in self.winupdates.filter(kb=kb).values_list("pk", "title"):
            match = _KB_VERSION_RE.search(title or "")
            if not match:
                return
            try:
                versions[pk] = PkgVersion(match.group(1).strip())
            except InvalidVersion:
                return
        newest = max(versions, key=versions.__getitem__)
        self.winupdates.filter(pk__in=[pk for pk in versions if pk != newest]).delete()

    # alerting

    def set_alert_template(self) -> "Optional[AlertTemplate]":
        core = get_core_settings()

        def usable(template) -> bool:
            return (
                bool(template)
                and template.is_active
                and not (template.is_agent_excluded(self))
            )

        chosen = None
        for key, policy in self.get_agent_policies().items():
            if key == "default_policy" and usable(core.alert_template):
                chosen = core.alert_template
                break
            if policy and policy.active and usable(policy.alert_template):
                chosen = policy.alert_template
                break
            if key in _TEMPLATE_KEYS:
                owner = self.site if key == "site_policy" else self.client
                if usable(owner.alert_template):
                    chosen = owner.alert_template
                    break

        self.alert_template = chosen
        Agent.objects.filter(pk=self.pk).update(alert_template=chosen)
        return chosen

    def get_or_create_alert_if_needed(
        self, alert_template: "Optional[AlertTemplate]"
    ) -> "Optional[Alert]":
        from alerts.models import Alert

        skip = not self.should_create_alert(alert_template)
        return Alert.create_or_return_availability_alert(self, skip_create=skip)

    def should_create_alert(
        self, alert_template: "Optional[AlertTemplate]" = None
    ) -> bool:
        own = (
            self.overdue_dashboard_alert,
            self.overdue_email_alert,
            self.overdue_text_alert,
        )
        if any(own):
            return True
        if not alert_template:
            return False
        always = (
            alert_template.agent_always_alert,
            alert_template.agent_always_email,
            alert_template.agent_always_text,
        )
        return (
            any(always)
            or has_webhook(alert_template, "agent")
            or has_script_actions(alert_template, "agent")
        )

    def _outage_subject(self, what: str) -> str:
        return f"{self.client.name}, {self.site.name}, {self.hostname} - {what}"

    def send_outage_email(self) -> tuple[str, bool]:
        return get_core_settings().send_mail(
            self._outage_subject("data overdue"),
            (
                f"Data has not been received from client {self.client.name}, "
                f"site {self.site.name}, agent {self.hostname} within the "
                "expected time."
            ),
            alert_template=self.alert_template,
        )

    def send_recovery_email(self) -> tuple[str, bool]:
        return get_core_settings().send_mail(
            self._outage_subject("data received"),
            (
                f"Data has been received from client {self.client.name}, "
                f"site {self.site.name}, agent {self.hostname} after an "
                "interruption in data transmission."
            ),
            alert_template=self.alert_template,
        )

    def send_outage_sms(self) -> tuple[str, bool]:
        return get_core_settings().send_sms(
            self._outage_subject("data overdue"), alert_template=self.alert_template
        )

    def send_recovery_sms(self) -> tuple[str, bool]:
        return get_core_settings().send_sms(
            self._outage_subject("data received"), alert_template=self.alert_template
        )

    # recovery and self-update

    def _windows_recover_command(self, ident: dict, agent_url: str) -> str:
        def ps(value: str) -> str:
            return "'" + str(value).replace("'", "''") + "'"

        name = agent_artifact_for(self, settings.LATEST_AGENT_VER)
        sha256 = ""
        with suppress(Exception):
            # a request must not wait for a download, the cached hash only
            sha256 = self._update_sha256(get_agent_url(agent=self), fetch=False)

        lines = [
            f"$dir = Join-Path $env:ProgramData {ps(ident['identWinRegKey'])}",
            "New-Item -ItemType Directory -Force -Path $dir | Out-Null",
            f"$file = Join-Path $dir {ps(name)}",
            f"Invoke-WebRequest -UseBasicParsing -Uri {ps(agent_url)} -OutFile $file",
        ]
        if sha256:
            # never run a download that is not this server's build
            lines.append(
                f"if ((Get-FileHash -Algorithm SHA256 $file).Hash -ne {ps(sha256)})"
                " { Remove-Item -Force $file; exit 1 }"
            )
        lines.append("Start-Process -FilePath $file -ArgumentList '/VERYSILENT' -Wait")
        return "; ".join(lines)

    def recover(
        self, mode: str, mesh_uri: str, wait: bool = True, agent_url: str = ""
    ) -> tuple[str, bool]:
        if mode == "agent":
            ident = agent_ident_for(self)
            if self.plat == AgentPlat.LINUX:
                cmd, shell = f"systemctl restart {ident['identNixSvc']}", 3
            elif self.plat == AgentPlat.DARWIN:
                label = ident["identMacPlistLabel"]
                cmd, shell = f"launchctl kickstart -k system/{label}", 3
            elif self.plat == AgentPlat.FREEBSD:
                # a plain restart does nothing for a service not enabled in rc.conf
                cmd, shell = f"service {nix_rc_name(ident)} onerestart", 3
            else:
                cmd, shell = self._windows_recover_command(ident, agent_url), 2
            asyncio.run(
                send_command_with_mesh(cmd, mesh_uri, self.mesh_node_id, shell, 0)
            )
            return "ok", False

        if mode == "mesh":
            data = {"func": "recover", "payload": {"mode": "mesh"}}
            if not wait:
                asyncio.run(self.nats_cmd(data, timeout=20, wait=False))
                return "ok", False
            reply = asyncio.run(self.nats_cmd(data, timeout=60))
            if reply == "ok":
                return "ok", False
            return str(reply), True

        return "invalid", True

    def _update_sha256(self, url: str, *, fetch: bool = True) -> str:
        if getattr(settings, "SELF_BUILT_AGENTS_URL", ""):
            return self_built_sha256(url, settings.LATEST_AGENT_VER, fetch=fetch)
        return get_agent_artifact_sha256(agent=self)

    def do_update(self, *, force: bool = False) -> str:
        if not self.goarch:
            note = f"Unable to determine arch on {self.hostname}({self.agent_id}). Skipping agent update."
            DebugLog.warning(
                agent=self, log_type=DebugLogType.AGENT_ISSUES, message=note
            )
            return "noarch"

        if agent_ver(self.version) <= agent_ver("1.3.0"):
            return "not supported"

        try:
            url = get_agent_url(agent=self)
        except UnknownAgentIdentity as e:
            DebugLog.warning(
                agent=self, log_type=DebugLogType.AGENT_ISSUES, message=str(e)
            )
            return "unknown ident"
        except ValueError:
            DebugLog.warning(
                agent=self,
                log_type=DebugLogType.AGENT_ISSUES,
                message=f"Invalid plat/goarch on {self.hostname}({self.agent_id}). Skipping agent update.",
            )
            return "noarch"

        sha256 = self._update_sha256(url)
        if not sha256:
            artifact = agent_ident_for(self)["identArtifact"]
            where = (
                "Could not download and hash the self-built"
                if getattr(settings, "SELF_BUILT_AGENTS_URL", "")
                else "No local build of the"
            )
            DebugLog.warning(
                agent=self,
                log_type=DebugLogType.AGENT_ISSUES,
                message=f"{where} '{artifact}' agent for {self.hostname}. Skipping agent update.",
            )
            return "no artifact"

        version = settings.LATEST_AGENT_VER
        try:
            sig = sign_agent_update(self.agent_id, url, version, sha256)
        except ImproperlyConfigured:
            DebugLog.warning(
                agent=self,
                log_type=DebugLogType.AGENT_ISSUES,
                message=f"ENROLL_SIGNING_KEY is not set, the update for {self.hostname} cannot be signed. Skipping agent update.",
            )
            return "unsigned"
        # unix agents ignore the name, it is always .exe-suffixed
        inno = agent_artifact_for(self, version, force_exe=True)

        if not force:
            # one pending update action per agent, also with parallel callers
            with transaction.atomic():
                list(
                    Agent.objects.select_for_update()
                    .filter(pk=self.pk)
                    .values_list("pk", flat=True)
                )
                self.pendingactions.filter(
                    action_type=PAAction.AGENT_UPDATE, status=PAStatus.PENDING
                ).delete()
                PendingAction.objects.create(
                    agent=self,
                    action_type=PAAction.AGENT_UPDATE,
                    details={"url": url, "version": version, "inno": inno},
                )

        data = {
            "func": "agentupdate",
            "payload": {
                "url": url,
                "version": version,
                "inno": inno,
                "sha256": sha256,
                "sig": sig,
            },
        }
        asyncio.run(self.nats_cmd(data, wait=False))
        return "created"

    # NATS

    async def nats_cmd(
        self, data: dict, timeout: int = 30, wait: bool = True
    ) -> Union[Any, str, None]:
        try:
            nc = await nats.connect(**setup_nats_options())
        except Exception:
            return "natsdown"

        try:
            if not wait:
                try:
                    await envelope.publish(nc, self.agent_id, msgpack.dumps(data))
                except envelope.Refused as e:
                    logger.warning("NATS send to %s refused: %s", self.agent_id, e)
                    return None
                await nc.flush()
                return None

            try:
                raw = await envelope.request(
                    nc, self.agent_id, msgpack.dumps(data), timeout
                )
            except (NatsTimeoutError, NoRespondersError):
                # no responders: the agent is not connected
                return "timeout"
            except envelope.Refused as e:
                return e.answer

            try:
                return msgpack.loads(raw)
            except Exception as e:
                logger.error("undecodable NATS reply from %s: %s", self.agent_id, e)
                return str(e)
        finally:
            await nc.close()

    async def nats_stream_cmd(
        self,
        data: dict,
        timeout: int = 30,
        stop_evt=None,
        output_subject: str = "",
        group: str = "",
    ) -> None:
        layer = get_channel_layer()
        payload = data.get("payload") if isinstance(data, dict) else None
        cmd_id = payload.get("cmd_id", "") if isinstance(payload, dict) else ""

        async def emit(**fields) -> None:
            await layer.group_send(
                group, {"type": "stream_output", "cmd_id": cmd_id, **fields}
            )

        sealed = await envelope.amode(self.agent_id) != envelope.LEGACY
        try:
            nc = await nats.connect(**setup_nats_options())
        except Exception as e:
            await emit(output=f"[ERROR] Could not connect to NATS: {e}")
            return

        ctx = None

        async def on_frame(msg) -> None:
            try:
                raw = msg.data
                if sealed:
                    try:
                        raw = envelope.open_frame(self.agent_id, msg.subject, raw, ctx)
                    except envelope.Refused as e:
                        await sync_to_async(envelope.event)(self.agent_id, str(e))
                        return
                frame = msgpack.loads(raw)
                if isinstance(frame, str):
                    fields = {"output": frame}
                elif isinstance(frame, dict):
                    fields = {}
                    if isinstance(frame.get("line"), str):
                        fields["output"] = frame["line"]
                    if frame.get("done") is True:
                        fields["done"] = True
                    if "exit_code" in frame:
                        fields["exit_code"] = frame["exit_code"]
                else:
                    fields = {"output": str(frame)}
                await emit(**fields)
            except Exception as e:
                await emit(output=f"[ERROR] {e}")

        sub = None
        try:
            try:
                # subscribe first: a command that ends at once sends a single
                # done frame, which must not arrive before the subscription is up
                sub = await nc.subscribe(output_subject, cb=on_frame)
                ctx = await envelope.publish(nc, self.agent_id, msgpack.dumps(data))
                await nc.flush()
            except Exception as e:
                await emit(output=f"[ERROR] NATS publish/subscribe failed: {e}")
                return

            waiters = [asyncio.ensure_future(asyncio.sleep(timeout))]
            if stop_evt is not None:
                waiters.append(asyncio.ensure_future(stop_evt.wait()))
            _, pending = await asyncio.wait(
                waiters, return_when=asyncio.FIRST_COMPLETED
            )
            for waiter in pending:
                waiter.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            closers = [nc.close] if sub is None else [sub.unsubscribe, nc.close]
            for close in closers:
                with suppress(Exception):
                    await close()


class Note(models.Model):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(Agent, related_name="notes", on_delete=models.CASCADE)
    # the reverse name is odd, but other code relies on it
    user = models.ForeignKey(
        "accounts.User",
        related_name="user",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    note = models.TextField(null=True, blank=True)
    entry_time = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.agent.hostname


_TRUE_TEXT = frozenset({"true", "1", "yes", "on"})


def _as_checkbox(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_TEXT
    return bool(value)


class AgentCustomField(models.Model):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(
        Agent, related_name="custom_fields", on_delete=models.CASCADE
    )
    field = models.ForeignKey(
        "core.CustomField", related_name="agent_fields", on_delete=models.CASCADE
    )
    string_value = models.TextField(null=True, blank=True)
    bool_value = models.BooleanField(blank=True, default=False)
    multiple_value = ArrayField(
        models.TextField(null=True, blank=True), null=True, blank=True, default=list
    )

    class Meta:
        unique_together = (("agent", "field"),)

    def __str__(self) -> str:
        return self.field.name

    @property
    def value(self) -> Union[list, bool, str, None]:
        if self.field.type == CustomFieldType.MULTIPLE:
            return self.multiple_value
        if self.field.type == CustomFieldType.CHECKBOX:
            return self.bool_value
        return self.string_value

    def save_to_field(self, value) -> None:
        kind = self.field.type
        if kind == CustomFieldType.MULTIPLE:
            self.multiple_value = value.split(",")
        elif kind == CustomFieldType.CHECKBOX:
            # collector output is text: "false" and "0" must not become True
            self.bool_value = _as_checkbox(value)
        elif kind in CustomFieldType.values:
            # text, number, single and datetime are all kept as strings
            self.string_value = value
        else:
            return
        self.save()


class AgentHistory(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey(Agent, related_name="history", on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
    type = models.CharField(
        max_length=50,
        choices=AgentHistoryType.choices,
        default=AgentHistoryType.CMD_RUN,
    )
    command = models.TextField(null=True, blank=True, default="")
    username = models.CharField(max_length=255, default="system")
    results = models.TextField(null=True, blank=True)
    script = models.ForeignKey(
        "scripts.Script",
        null=True,
        blank=True,
        related_name="history",
        on_delete=models.SET_NULL,
    )
    script_results = models.JSONField(null=True, blank=True)
    custom_field = models.ForeignKey(
        "core.CustomField",
        null=True,
        blank=True,
        related_name="history",
        on_delete=models.SET_NULL,
    )
    collector_all_output = models.BooleanField(default=False)
    save_to_agent_note = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.agent.hostname} - {self.type}"

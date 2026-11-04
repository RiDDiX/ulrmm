# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import zoneinfo
from enum import Enum

from django.conf import settings
from django.db import models


class MeshAgentIdent(Enum):
    WIN32 = 3
    WIN64 = 4
    LINUX32 = 5
    LINUX64 = 6
    LINUX_ARM_64 = 26
    LINUX_ARM_HF = 25
    FREEBSD64 = 30
    DARWIN_UNIVERSAL = 10005

    def __str__(self):
        return str(self.value)


# cache keys
CORESETTINGS_CACHE_KEY = "core_settings"
CORE_BRANDING_CACHE_KEY = "core_branding"
ULRMM_LATEST_VER_CACHE_KEY = "ulrmm_latest_ver"
ROLE_CACHE_PREFIX = "role_"
AGENT_TBL_PEND_ACTION_CNT_CACHE_PREFIX = "agent_tbl_pendingactions_"
AGENT_CHECKS_CACHE_PREFIX = "agent_checks_data_"
# kept out of clear_entire_cache so a flush never cancels an enrolment or step-up
TOTP_PENDING_CACHE_PREFIX = "totp_pending_"
CONSOLE_STEPUP_CACHE_PREFIX = "console_stepup_"

# agent status
AGENT_STATUS_ONLINE = "online"
AGENT_STATUS_OFFLINE = "offline"
AGENT_STATUS_OVERDUE = "overdue"

REDIS_LOCK_EXPIRE = 60 * 60 * 2

# distributed lock names (one holder per cluster)
RESOLVE_ALERTS_LOCK = "resolve-alerts-lock-key"
SYNC_SCHED_TASK_LOCK = "sync-sched-tasks-lock-key"
AGENT_OUTAGES_LOCK = "agent-outages-task-lock-key"
ORPHANED_WIN_TASK_LOCK = "orphaned-win-task-lock-key"
SYNC_MESH_PERMS_TASK_LOCK = "sync-mesh-perms-lock-key"
CACHE_DB_FIELDS_TASK_LOCK = "cache-db-fields-task-lock-key"
NETMON_POLL_LOCK = "netmon-poll-lock-key"
SCHED_TASK_RUNNER_LOCK = "sched-task-runner-lock-key"

ULRMM_WS_MAX_SIZE = getattr(settings, "ULRMM_WS_MAX_SIZE", 100 * 2**20)
ULRMM_MAX_REQUEST_SIZE = getattr(settings, "ULRMM_MAX_REQUEST_SIZE", 10 * 2**20)

# model labels that must never leak through template/variable resolution or reports
CREDENTIAL_MODEL_LABELS = frozenset(
    {
        "accounts.User",
        "accounts.APIKey",
        "authtoken.Token",
        "knox.AuthToken",
        "remote.RustDeskPeer",
        "netmon.NetworkDevice",
        "encryption.RecoveryKey",
        "vault.Credential",
        "vault.Document",
        "discovery.Scan",
        "notify.Channel",
        "assets.License",
        "integrations.UniFiController",
        "integrations.OpnsenseFirewall",
    }
)

# CoreSettings columns stored encrypted at rest
CORE_SETTINGS_SECRET_FIELDS = (
    "smtp_host_password",
    "twilio_auth_token",
    "mesh_token",
    "ai_api_key",
)

_AUDIT_STAMP_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")

AGENT_TABLE_DEFER = ("services", *_AUDIT_STAMP_FIELDS)
AGENT_DEFER = ("wmi_detail", *AGENT_TABLE_DEFER)
# minimal column set needed to compute an agent's online/offline/overdue status
ONLINE_AGENTS = tuple(
    "pk agent_id last_seen overdue_time offline_time version plat"
    " overdue_email_alert overdue_text_alert overdue_dashboard_alert"
    " alert_template".split()
)

# a change to any of these on an AutomatedTask means the agent copy must be resynced
FIELDS_TRIGGER_TASK_UPDATE_AGENT = """
    run_time_bit_weekdays run_time_date expire_date daily_interval
    weekly_interval enabled remove_if_not_scheduled run_asap_after_missed
    monthly_days_of_month monthly_months_of_year monthly_weeks_of_month
    task_repetition_duration task_repetition_interval stop_task_at_duration_end
    random_task_delay task_instance_policy
""".split()

# fields copied from a policy task down onto each generated agent task
POLICY_TASK_FIELDS_TO_COPY = """
    alert_severity email_alert text_alert dashboard_alert name actions
    run_time_bit_weekdays run_time_date expire_date daily_interval
    weekly_interval task_type enabled remove_if_not_scheduled
    run_asap_after_missed custom_field collector_all_output
    monthly_days_of_month monthly_months_of_year monthly_weeks_of_month
    task_repetition_duration task_repetition_interval stop_task_at_duration_end
    random_task_delay task_instance_policy continue_on_error
    task_supported_platforms
""".split()

CHECKS_NON_EDITABLE_FIELDS = [
    "check_type",
    "overridden_by_policy",
    *_AUDIT_STAMP_FIELDS,
]

POLICY_CHECK_FIELDS_TO_COPY = """
    check_type warning_threshold error_threshold alert_severity name
    run_interval disk fails_b4_alert ip script script_args env_vars
    success_return_codes info_return_codes warning_return_codes timeout
    svc_name svc_display_name svc_policy_mode pass_if_start_pending
    pass_if_svc_not_exist restart_if_stopped log_name event_id
    event_id_is_wildcard event_type event_source event_message fail_when
    search_last_days number_of_events_b4_alert email_alert text_alert
    dashboard_alert container container_kind metric metric_labels metric_op
    metric_warning metric_error metric_samples
""".split()


def _bit_table(names):
    return {name: 1 << shift for shift, name in enumerate(names)}


# weekday / month / week-of-month bit tables. Insertion order matters: the
# string renderers walk these dicts in order.
WEEK_DAYS = _bit_table(
    ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
)
MONTHS = _bit_table(
    (
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    )
)
WEEKS = _bit_table(
    ("First Week", "Second Week", "Third Week", "Fourth Week", "Last Week")
)

# Python weekday (Monday=0) -> WEEK_DAYS bit (Sunday is bit 0)
WEEKDAY_TO_BIT = {weekday: 1 << ((weekday + 1) % 7) for weekday in range(7)}

MONTH_DAYS = {str(day): 1 << (day - 1) for day in range(1, 32)}
MONTH_DAYS["Last Day"] = 0x80000000

ALL_TIMEZONES = sorted(zoneinfo.available_timezones())


class GoArch(models.TextChoices):
    AMD64 = "amd64", "amd64"
    i386 = "386", "386"
    ARM64 = "arm64", "arm64"
    ARM32 = "arm", "arm"


class CustomFieldModel(models.TextChoices):
    CLIENT = "client", "Client"
    SITE = "site", "Site"
    AGENT = "agent", "Agent"


class CustomFieldType(models.TextChoices):
    TEXT = "text", "Text"
    NUMBER = "number", "Number"
    SINGLE = "single", "Single"
    MULTIPLE = "multiple", "Multiple"
    CHECKBOX = "checkbox", "Checkbox"
    DATETIME = "datetime", "DateTime"


class TaskSyncStatus(models.TextChoices):
    SYNCED = "synced", "Synced With Agent"
    NOT_SYNCED = "notsynced", "Waiting On Agent Checkin"
    PENDING_DELETION = "pendingdeletion", "Pending Deletion on Agent"
    INITIAL = "initial", "Initial Task Sync"


class TaskStatus(models.TextChoices):
    PASSING = "passing", "Passing"
    FAILING = "failing", "Failing"
    PENDING = "pending", "Pending"


class TaskRunStatus(models.TextChoices):
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"


class TaskType(models.TextChoices):
    DAILY = "daily", "Daily"
    WEEKLY = "weekly", "Weekly"
    MONTHLY = "monthly", "Monthly"
    MONTHLY_DOW = "monthlydow", "Monthly Day of Week"
    CHECK_FAILURE = "checkfailure", "On Check Failure"
    MANUAL = "manual", "Manual"
    RUN_ONCE = "runonce", "Run Once"
    ONBOARDING = "onboarding", "Onboarding"
    SCHEDULED = "scheduled", "Scheduled"  # deprecated


class AlertSeverity(models.TextChoices):
    INFO = "info", "Informational"
    WARNING = "warning", "Warning"
    ERROR = "error", "Error"


class AlertType(models.TextChoices):
    AVAILABILITY = "availability", "Availability"
    CHECK = "check", "Check"
    TASK = "task", "Task"
    CUSTOM = "custom", "Custom"
    NETWORK = "network", "Network"
    AGENT = "agent", "Agent"


class AlertTemplateActionType(models.TextChoices):
    SCRIPT = "script", "Script"
    SERVER = "server", "Server"
    REST = "rest", "Rest"


class AgentHistoryType(models.TextChoices):
    TASK_RUN = "task_run", "Task Run"
    SCRIPT_RUN = "script_run", "Script Run"
    CMD_RUN = "cmd_run", "CMD Run"
    APP_UPDATE = "app_update", "App Update"


class AppUpdatePolicy(models.TextChoices):
    INHERIT = "inherit", "Inherit"
    ON = "on", "On"
    OFF = "off", "Off"


class AgentMonType(models.TextChoices):
    SERVER = "server", "Server"
    WORKSTATION = "workstation", "Workstation"


class AgentPlat(models.TextChoices):
    WINDOWS = "windows", "Windows"
    LINUX = "linux", "Linux"
    DARWIN = "darwin", "macOS"
    FREEBSD = "freebsd", "FreeBSD"


class ClientTreeSort(models.TextChoices):
    ALPHA_FAIL = "alphafail", "Move failing clients to the top"
    ALPHA = "alpha", "Sort alphabetically"


class AgentTableTabs(models.TextChoices):
    SERVER = "server", "Servers"
    WORKSTATION = "workstation", "Workstations"
    MIXED = "mixed", "Mixed"


class AgentDblClick(models.TextChoices):
    DEVICE_PAGE = "devicepage", "Device page"
    EDIT_AGENT = "editagent", "Edit Agent"
    TAKE_CONTROL = "takecontrol", "Take Control"
    REMOTE_BG = "remotebg", "Remote Background"
    URL_ACTION = "urlaction", "URL Action"


class ScriptShell(models.TextChoices):
    POWERSHELL = "powershell", "Powershell"
    CMD = "cmd", "Batch (CMD)"
    PYTHON = "python", "Python"
    SHELL = "shell", "Shell"
    NUSHELL = "nushell", "Nushell"
    DENO = "deno", "Deno"


class ScriptType(models.TextChoices):
    USER_DEFINED = "userdefined", "User Defined"
    BUILT_IN = "builtin", "Built In"


class EvtLogNames(models.TextChoices):
    APPLICATION = "Application", "Application"
    SYSTEM = "System", "System"
    SECURITY = "Security", "Security"


class EvtLogTypes(models.TextChoices):
    INFO = "INFO", "Information"
    WARNING = "WARNING", "Warning"
    ERROR = "ERROR", "Error"
    AUDIT_SUCCESS = "AUDIT_SUCCESS", "Success Audit"
    AUDIT_FAILURE = "AUDIT_FAILURE", "Failure Audit"


class EvtLogFailWhen(models.TextChoices):
    CONTAINS = "contains", "Log contains"
    NOT_CONTAINS = "not_contains", "Log does not contain"


class CheckStatus(models.TextChoices):
    PASSING = "passing", "Passing"
    FAILING = "failing", "Failing"
    PENDING = "pending", "Pending"


class PAStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    COMPLETED = "completed", "Completed"


class PAAction(models.TextChoices):
    SCHED_REBOOT = "schedreboot", "Scheduled Reboot"
    AGENT_UPDATE = "agentupdate", "Agent Update"
    CHOCO_INSTALL = "chocoinstall", "Chocolatey Software Install"
    RUN_CMD = "runcmd", "Run Command"
    RUN_SCRIPT = "runscript", "Run Script"
    RUN_PATCH_SCAN = "runpatchscan", "Run Patch Scan"
    RUN_PATCH_INSTALL = "runpatchinstall", "Run Patch Install"
    WINGET_INSTALL = "wingetinstall", "Winget Software Install"


class CheckType(models.TextChoices):
    DISK_SPACE = "diskspace", "Disk Space Check"
    PING = "ping", "Ping Check"
    CPU_LOAD = "cpuload", "CPU Load Check"
    MEMORY = "memory", "Memory Check"
    WINSVC = "winsvc", "Service Check"
    SCRIPT = "script", "Script Check"
    EVENT_LOG = "eventlog", "Event Log Check"
    SECURITY = "security", "Security Check"
    HW_HEALTH = "hwhealth", "Hardware Health Check"
    SYSTEMD = "systemd", "Systemd Unit Check"
    CONTAINER = "container", "Container Check"
    METRIC = "metric", "Metric Threshold Check"


class ContainerKind(models.TextChoices):
    DOCKER = "docker", "Docker"
    PODMAN = "podman", "Podman"
    LXC = "lxc", "LXC"
    LXD = "lxd", "LXD"
    INCUS = "incus", "Incus"
    PVE_QEMU = "pve-qemu", "Proxmox VM"
    PVE_LXC = "pve-lxc", "Proxmox Container"
    HYPERV = "hyperv", "Hyper-V"


class MetricOp(models.TextChoices):
    ABOVE = "above", "Above"
    BELOW = "below", "Below"


class AuditActionType(models.TextChoices):
    LOGIN = "login", "User Login"
    FAILED_LOGIN = "failed_login", "Failed User Login"
    DELETE = "delete", "Delete Object"
    MODIFY = "modify", "Modify Object"
    ADD = "add", "Add Object"
    VIEW = "view", "View Object"
    CHECK_RUN = "check_run", "Check Run"
    TASK_RUN = "task_run", "Task Run"
    AGENT_INSTALL = "agent_install", "Agent Install"
    REMOTE_SESSION = "remote_session", "Remote Session"
    EXEC_SCRIPT = "execute_script", "Execute Script"
    EXEC_COMMAND = "execute_command", "Execute Command"
    BULK_ACTION = "bulk_action", "Bulk Action"
    URL_ACTION = "url_action", "URL Action"


class AuditObjType(models.TextChoices):
    USER = "user", "User"
    SCRIPT = "script", "Script"
    AGENT = "agent", "Agent"
    POLICY = "policy", "Policy"
    WINUPDATE = "winupdatepolicy", "Patch Policy"
    CLIENT = "client", "Client"
    SITE = "site", "Site"
    CHECK = "check", "Check"
    AUTOTASK = "automatedtask", "Automated Task"
    CORE = "coresettings", "Core Settings"
    BULK = "bulk", "Bulk"
    ALERT_TEMPLATE = "alerttemplate", "Alert Template"
    ROLE = "role", "Role"
    URL_ACTION = "urlaction", "URL Action"
    KEYSTORE = "keystore", "Global Key Store"
    CUSTOM_FIELD = "customfield", "Custom Field"
    NETWORK_DEVICE = "networkdevice", "Network Device"
    SOFTWARE_PACKAGE = "softwarepackage", "Software Package"
    BASELINE = "baseline", "Software Baseline"
    TAG = "tag", "Tag"
    DEVICE_GROUP = "devicegroup", "Device Group"
    CREDENTIAL = "credential", "Credential"
    DOCUMENT = "document", "Document"
    DISCOVERY = "discovery", "Discovery"


class DebugLogLevel(models.TextChoices):
    INFO = "info", "Info"
    WARN = "warning", "Warning"
    ERROR = "error", "Error"
    CRITICAL = "critical", "Critical"


class DebugLogType(models.TextChoices):
    AGENT_UPDATE = "agent_update", "Agent Update"
    AGENT_ISSUES = "agent_issues", "Agent Issues"
    WIN_UPDATES = "win_updates", "Windows Updates"
    SYSTEM_ISSUES = "system_issues", "System Issues"
    SCRIPTING = "scripting", "Scripting"


class URLActionType(models.TextChoices):
    WEB = "web", "Web"
    REST = "rest", "Rest"


class URLActionRestMethod(models.TextChoices):
    GET = "get", "Get"
    POST = "post", "Post"
    PUT = "put", "Put"
    DELETE = "delete", "Delete"
    PATCH = "patch", "Patch"


class ScheduleType(models.TextChoices):
    DAILY = "daily", "Daily"
    WEEKLY = "weekly", "Weekly"
    MONTHLY = "monthly", "Monthly"


class MonthlyType(models.TextChoices):
    WEEKS = "weeks", "Weeks"
    DAYS = "days", "Days"


class TerminalShellChoices(models.TextChoices):
    CMD = "cmd", "cmd"
    POWERSHELL = "powershell", "powershell"
    BASH = "bash", "bash"
    SH = "sh", "sh"
    CUSTOM = "custom", "custom"


class WindowsTerminalShellChoices(models.TextChoices):
    CMD = "cmd", "cmd"
    POWERSHELL = "powershell", "powershell"
    CUSTOM = "custom", "custom"


class LinuxTerminalShellChoices(models.TextChoices):
    BASH = "bash", "bash"
    CUSTOM = "custom", "custom"


class DarwinTerminalShellChoices(models.TextChoices):
    BASH = "bash", "bash"
    CUSTOM = "custom", "custom"


class FreeBSDTerminalShellChoices(models.TextChoices):
    SH = "sh", "sh"
    BASH = "bash", "bash"
    CUSTOM = "custom", "custom"


class AgentTerminalShellChoices(models.TextChoices):
    USE_GLOBAL = "use_global", "Use global default"
    CMD = "cmd", "cmd"
    POWERSHELL = "powershell", "powershell"
    BASH = "bash", "bash"
    SH = "sh", "sh"
    CUSTOM = "custom", "custom"


class TerminalModeChoices(models.TextChoices):
    NEW = "new", "Use new terminal"
    LEGACY = "legacy", "Use legacy terminal"


# shells valid per platform (membership works with plain strings too)
WINDOWS_TOKENS = {TerminalShellChoices.CMD, TerminalShellChoices.POWERSHELL}
LINUX_TOKENS = {TerminalShellChoices.BASH}
DARWIN_TOKENS = {TerminalShellChoices.BASH}
# base FreeBSD has no bash, it comes from pkg
FREEBSD_TOKENS = {TerminalShellChoices.SH, TerminalShellChoices.BASH}

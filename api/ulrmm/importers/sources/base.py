# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""What every source delivers, and the checks on it.

A source turns the other RMM's API into one dict:

    clients:       [{ref, name, custom_fields: {name: value},
                     sites: [{ref, name, custom_fields}]}]
    custom_fields: [{model: client|site|agent, name, type, options}]
    scripts:       [{name, description, shell, category, args, env_vars, body,
                     timeout, platforms, run_as_user, syntax}]
    snippets:      [{name, desc, code, shell}]
    keystore:      [{name, value}]
    devices:       [{ref, site_ref, hostname, serial, plat, goarch,
                     monitoring_type, os_name, description, notes: [str],
                     custom_fields, policy, patch_policy, settings, checks,
                     tasks, excluded_policies, excluded_templates}]

Sources that read more also deliver (others leave them out):

    url_actions:      [{name, desc, pattern, action_type, rest_method,
                        rest_body, rest_headers}]
    alert_templates:  [{name, default, fields, action, resolved_action,
                        action_rest, resolved_action_rest, lost,
                        excluded_clients, excluded_sites}]; lost names the
                        action slots set over there whose script or URL
                        action is not in the source's lists
    policies:         [{name, desc, active, enforced, alert_template,
                        patch_policy, checks, tasks, excluded_clients,
                        excluded_sites}]
    roles:            [{name, superuser, perms, unknown, clients, sites}]
    users:            [{username, email, first_name, last_name, role}]
    report_html, report_queries, report_templates: the reporting module's rows

Clients and sites name their server_policy, workstation_policy and
alert_template. Other objects are referenced by name as well: scripts as
{name, shell}, sites as [client, site], devices by ref, a task's check by the
check's ref. A check is {ref, desc, script, fields}, a task {ref, name,
fields, actions, assigned_check, custom_field}; fields holds the model
fields both sides share.

validate() is the trust boundary: the answer comes from another server, so
every value is type checked and cut to the column sizes before it is stored."""

import json
import math

import requests
from django.contrib.postgres.fields import ArrayField
from django.db import models

from accounts.models import Role
from agents.models import Agent
from alerts.models import AlertTemplate
from autotasks.models import AutomatedTask
from checks.models import Check
from reporting.models import ReportFormatType
from ulrmm.constants import (
    POLICY_CHECK_FIELDS_TO_COPY,
    POLICY_TASK_FIELDS_TO_COPY,
    AgentMonType,
    AgentPlat,
    CustomFieldModel,
    CustomFieldType,
    GoArch,
    ScriptShell,
    URLActionRestMethod,
    URLActionType,
)
from ulrmm.utils import BodyTooLarge, capped_json
from winupdate.models import WinUpdatePolicy

TIMEOUT = 30
# more than any fleet this importer is meant for; a bigger answer is refused
MAX_ITEMS = 20000
MAX_BODY = 1_000_000
MAX_JSON = 100_000

AUDIT_FIELDS = {"id", "created_by", "created_time", "modified_by", "modified_time"}
CHECK_FIELDS = [f for f in POLICY_CHECK_FIELDS_TO_COPY if f != "script"]
TASK_FIELDS = [
    f for f in POLICY_TASK_FIELDS_TO_COPY if f not in ("actions", "custom_field")
]
BITMASKS = (
    "run_time_bit_weekdays",
    "monthly_days_of_month",
    "monthly_months_of_year",
    "monthly_weeks_of_month",
)
# what the link step may set on an agent that still has the default
AGENT_SETTINGS = (
    "time_zone",
    "check_interval",
    "offline_time",
    "overdue_time",
    "overdue_email_alert",
    "overdue_text_alert",
    "overdue_dashboard_alert",
    "maintenance_mode",
    "block_policy_inheritance",
)


def plain_fields(model, skip=()) -> list[str]:
    return [
        f.name
        for f in model._meta.concrete_fields
        if not f.is_relation and f.name not in AUDIT_FIELDS and f.name not in skip
    ]


TEMPLATE_FIELDS = plain_fields(AlertTemplate, skip=("name",))
PATCH_FIELDS = plain_fields(WinUpdatePolicy)
ROLE_PERMS = [
    f.name
    for f in Role._meta.concrete_fields
    if isinstance(f, models.BooleanField) and f.name.startswith("can_")
]


class SourceError(Exception):
    pass


class NotFound(SourceError):
    pass


class Source:
    """One other RMM. Subclasses set KIND and SECRETS and implement fetch;
    push is only there when the source can run a command on a device."""

    KIND = ""
    # names of the secret fields the source needs
    SECRETS: tuple = ()
    # platforms push() can send an installer to
    PUSH_PLATS: tuple = ()
    # whether remove() can take the source's own agent off a device
    REMOVES = False
    # the import parts fetch() delivers
    PARTS: tuple = (
        "clients",
        "custom_fields",
        "scripts",
        "snippets",
        "keystore",
        "devices",
    )

    def __init__(self, url: str, verify_tls: bool, options: dict, secrets: dict):
        self.base = url.rstrip("/")
        self.verify = verify_tls
        self.options = options or {}
        self.secrets = secrets or {}
        self.session = requests.Session()

    def fetch(self) -> dict:
        raise NotImplementedError

    def push(self, ref: str, plat: str, command: str, url: str = "") -> None:
        """Runs command on the device. url is the bare installer link for
        sources that can only hand a parameter to a script of their own."""
        raise SourceError("This source cannot run commands on its devices.")

    def device(self, ref: str) -> dict:
        """The source's live view of one device."""
        raise SourceError("This source cannot read a single device.")

    def remove(self, ref: str, hostname: str) -> None:
        """Uninstalls the source's agent from the device. Returns only when
        the source confirmed it."""
        raise SourceError("This source cannot remove its agent.")

    def call(self, method: str, path: str, timeout: int = TIMEOUT, **kwargs):
        """JSON of one request on the https base. Redirects are refused, so a
        key never goes to another host."""
        url = path if path.startswith("https://") else self.base + path
        try:
            r = self.session.request(
                method,
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=self.verify,
                stream=True,
                **kwargs,
            )
        except requests.RequestException as e:
            raise SourceError(f"{path}: {type(e).__name__}")
        if r.status_code >= 300:
            # refused below, the body is never read
            r.close()
        if 300 <= r.status_code < 400:
            raise SourceError(f"{path} answered with a redirect")
        if r.status_code in (401, 403):
            raise SourceError(f"{path}: the key or login was refused ({r.status_code})")
        if r.status_code == 404:
            raise NotFound(f"{path} answered 404")
        if r.status_code >= 400:
            raise SourceError(f"{path} answered {r.status_code}")
        if r.status_code == 204:
            r.close()
            return None
        try:
            return capped_json(r, 50 * MAX_BODY)
        except BodyTooLarge:
            raise SourceError(f"{path} answered with too much data")
        except requests.RequestException as e:
            raise SourceError(f"{path}: {type(e).__name__}")
        except ValueError:
            raise SourceError(f"{path} did not answer with JSON")


def _str(value, limit: int) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value).replace("\x00", "")[:limit]


def _name(value, limit: int) -> str:
    return " ".join(_str(value, limit * 2).split())[:limit]


def _list(value, what: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SourceError(f"{what} is not a list")
    if len(value) > MAX_ITEMS:
        raise SourceError(f"more than {MAX_ITEMS} {what}")
    return [v for v in value if isinstance(v, dict)]


def _strings(value, limit: int, count: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_str(v, limit) for v in value[:count] if v is not None]


def _fields(value) -> dict:
    # custom field values by field name; lists stay lists (multiple choice)
    if not isinstance(value, dict):
        return {}
    ret = {}
    for k, v in list(value.items())[:200]:
        key = _name(k, 100)
        if not key or v is None or v == "":
            continue
        if isinstance(v, bool):
            ret[key] = v
        elif isinstance(v, list):
            ret[key] = _strings(v, 255)
        else:
            ret[key] = _str(v, 10_000)
    return ret


def _choice(value, choices, default: str) -> str:
    value = _str(value, 30).lower()
    return value if value in choices else default


def _int(value):
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) < 2**63:
        return value
    return None


def _value(field, value):
    """value checked against a model field; None when it does not fit"""
    if value is None:
        return None
    if isinstance(field, ArrayField):
        if not isinstance(value, list):
            return None
        items = (_value(field.base_field, v) for v in value[:100])
        return [v for v in items if v is not None]
    if isinstance(field, models.BooleanField):
        return value if isinstance(value, bool) else None
    if isinstance(field, models.IntegerField):
        return _int(value)
    if isinstance(field, models.FloatField):
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        return float(value) if ok and math.isfinite(value) else None
    if isinstance(field, models.JSONField):
        return _json(value)
    if isinstance(field, models.DateTimeField):
        return _str(value, 40) if isinstance(value, str) else None
    if isinstance(field, models.CharField):
        return _str(value, field.max_length or 255) if isinstance(value, str) else None
    if isinstance(field, models.TextField):
        return _str(value, MAX_BODY) if isinstance(value, str) else None
    return None


def _json(value):
    if not isinstance(value, (dict, list)):
        return None
    try:
        return value if len(json.dumps(value)) <= MAX_JSON else None
    except (TypeError, ValueError):
        return None


def _clean(model, names, row) -> dict:
    # the fields both sides share; what is missing or does not fit is left out
    if not isinstance(row, dict):
        return {}
    ret = {}
    for name in names:
        value = _value(model._meta.get_field(name), row.get(name))
        if value is not None:
            ret[name] = value
    return ret


ACTION_SLOTS = ("action", "resolved_action", "action_rest", "resolved_action_rest")


def _script(value):
    if not isinstance(value, dict) or not (name := _name(value.get("name"), 255)):
        return None
    return {"name": name, "shell": _choice(value.get("shell"), ScriptShell.values, "")}


def _names(value, limit: int = 255) -> list[str]:
    return [n for n in (_name(v, limit) for v in _strings(value, limit * 2)) if n]


def _pairs(value) -> list[list[str]]:
    # [client, site] names
    if not isinstance(value, list):
        return []
    ret = []
    for v in value[:MAX_ITEMS]:
        if isinstance(v, list) and len(v) == 2:
            pair = [_name(v[0], 255), _name(v[1], 255)]
            if all(pair):
                ret.append(pair)
    return ret


def _action(a) -> dict | None:
    kind = a.get("type") if isinstance(a, dict) else None
    common = {"timeout": _int(a.get("timeout")) if kind else None}
    if kind == "script":
        return {
            "type": "script",
            "script": _script(a.get("script")),
            "name": _name(a.get("name"), 255),
            "script_args": _strings(a.get("script_args"), 255),
            "env_vars": _strings(a.get("env_vars"), 1000),
            "run_as_user": a.get("run_as_user") is True,
            **common,
        }
    if kind == "cmd":
        return {
            "type": "cmd",
            "command": _str(a.get("command"), 10_000),
            "shell": _str(a.get("shell"), 255) or None,
            "run_as_user": a.get("run_as_user") is True,
            **common,
        }
    return None


def _checks(value) -> list[dict]:
    ret = []
    for c in _list(value, "checks"):
        fields = _clean(Check, CHECK_FIELDS, c.get("fields"))
        if fields.get("check_type"):
            ret.append(
                {
                    "ref": _str(c.get("ref"), 40),
                    "desc": _name(c.get("desc"), 255) or fields["check_type"],
                    "script": _script(c.get("script")),
                    "fields": fields,
                }
            )
    return ret


def _tasks(value) -> list[dict]:
    ret = []
    for t in _list(value, "tasks"):
        fields = _clean(AutomatedTask, TASK_FIELDS, t.get("fields"))
        if not fields.get("name"):
            continue
        for name in BITMASKS:
            # the other side keeps 0 in the masks a task type does not use
            if fields.get(name) == 0:
                del fields[name]
        actions = t.get("actions") if isinstance(t.get("actions"), list) else []
        ret.append(
            {
                "ref": _str(t.get("ref"), 40),
                "name": _name(fields["name"], 255),
                "fields": fields,
                "actions": [a for a in map(_action, actions[:100]) if a],
                "assigned_check": _str(t.get("assigned_check"), 40),
                "custom_field": _name(t.get("custom_field"), 100),
            }
        )
    return ret


def _patch(value) -> dict | None:
    return _clean(WinUpdatePolicy, PATCH_FIELDS, value) or None


def _unique(rows, key: str) -> list[dict]:
    seen, ret = set(), []
    for row in rows:
        if row[key] and row[key].lower() not in seen:
            seen.add(row[key].lower())
            ret.append(row)
    return ret


def _more(data) -> dict:
    """The parts beyond clients, scripts and devices."""
    url_actions = _unique(
        (
            {
                "name": _name(u.get("name"), 255),
                "desc": _str(u.get("desc"), 10_000),
                "pattern": _str(u.get("pattern"), 10_000),
                "action_type": _choice(
                    u.get("action_type"), URLActionType.values, "web"
                ),
                "rest_method": _choice(
                    u.get("rest_method"), URLActionRestMethod.values, "post"
                ),
                "rest_body": _str(u.get("rest_body"), MAX_BODY),
                "rest_headers": _str(u.get("rest_headers"), MAX_BODY),
            }
            for u in _list(data.get("url_actions"), "URL actions")
        ),
        "name",
    )

    templates = _unique(
        (
            {
                "name": _name(t.get("name"), 100),
                "default": t.get("default") is True,
                "fields": _clean(AlertTemplate, TEMPLATE_FIELDS, t.get("fields")),
                "action": _script(t.get("action")),
                "resolved_action": _script(t.get("resolved_action")),
                "action_rest": _name(t.get("action_rest"), 255),
                "resolved_action_rest": _name(t.get("resolved_action_rest"), 255),
                "lost": [s for s in _strings(t.get("lost"), 40) if s in ACTION_SLOTS],
                "excluded_clients": _names(t.get("excluded_clients")),
                "excluded_sites": _pairs(t.get("excluded_sites")),
            }
            for t in _list(data.get("alert_templates"), "alert templates")
        ),
        "name",
    )

    policies = _unique(
        (
            {
                "name": _name(p.get("name"), 255),
                "desc": _name(p.get("desc"), 255),
                "active": p.get("active") is True,
                "enforced": p.get("enforced") is True,
                "alert_template": _name(p.get("alert_template"), 100),
                "patch_policy": _patch(p.get("patch_policy")),
                "checks": _checks(p.get("checks")),
                "tasks": _tasks(p.get("tasks")),
                "excluded_clients": _names(p.get("excluded_clients")),
                "excluded_sites": _pairs(p.get("excluded_sites")),
            }
            for p in _list(data.get("policies"), "policies")
        ),
        "name",
    )

    roles = []
    for r in _list(data.get("roles"), "roles"):
        fields = r.get("fields") if isinstance(r.get("fields"), dict) else {}
        theirs = {
            k for k, v in fields.items() if k.startswith("can_") and isinstance(v, bool)
        }
        roles.append(
            {
                "name": _name(r.get("name"), 255),
                "superuser": fields.get("is_superuser") is True,
                "perms": {k: fields[k] for k in ROLE_PERMS if k in theirs},
                "unknown": len(theirs - set(ROLE_PERMS)),
                "clients": _names(r.get("clients")),
                "sites": _pairs(r.get("sites")),
            }
        )

    users = _unique(
        (
            {
                "username": _name(u.get("username"), 150),
                "email": _name(u.get("email"), 254),
                "first_name": _name(u.get("first_name"), 150),
                "last_name": _name(u.get("last_name"), 150),
                "role": _name(u.get("role"), 255),
            }
            for u in _list(data.get("users"), "users")
        ),
        "username",
    )

    html = _unique(
        (
            {"name": _name(h.get("name"), 200), "html": _str(h.get("html"), MAX_BODY)}
            for h in _list(data.get("report_html"), "report HTML templates")
        ),
        "name",
    )
    queries = _unique(
        (
            {"name": _name(q.get("name"), 50), "json_query": _json(q.get("json_query"))}
            for q in _list(data.get("report_queries"), "report data queries")
        ),
        "name",
    )
    reports = _unique(
        (
            {
                "name": _name(t.get("name"), 200),
                "template_md": _str(t.get("template_md"), MAX_BODY),
                "template_css": _str(t.get("template_css"), MAX_BODY),
                "type": _choice(t.get("type"), ReportFormatType.values, "markdown"),
                "template_variables": _str(t.get("template_variables"), MAX_BODY),
                "depends_on": _strings(t.get("depends_on"), 20),
                "template_html": _name(t.get("template_html"), 200),
            }
            for t in _list(data.get("report_templates"), "report templates")
        ),
        "name",
    )
    return {
        "url_actions": url_actions,
        "alert_templates": templates,
        "policies": policies,
        "roles": _unique(roles, "name"),
        "users": users,
        "report_html": html,
        "report_queries": [q for q in queries if q["json_query"] is not None],
        "report_templates": reports,
    }


def _assigned(row) -> dict:
    return {
        "server_policy": _name(row.get("server_policy"), 255),
        "workstation_policy": _name(row.get("workstation_policy"), 255),
        "alert_template": _name(row.get("alert_template"), 100),
    }


def validate(data) -> dict:
    if not isinstance(data, dict):
        raise SourceError("the source gave no data")
    clients, seen = [], set()
    for c in _list(data.get("clients"), "clients"):
        name = _name(c.get("name"), 255)
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        sites, site_names = [], set()
        for s in _list(c.get("sites"), "sites"):
            sname = _name(s.get("name"), 255)
            if not sname or sname.lower() in site_names:
                continue
            site_names.add(sname.lower())
            sites.append(
                {
                    "ref": _str(s.get("ref"), 255),
                    "name": sname,
                    "custom_fields": _fields(s.get("custom_fields")),
                    **_assigned(s),
                }
            )
        clients.append(
            {
                "ref": _str(c.get("ref"), 255),
                "name": name,
                "custom_fields": _fields(c.get("custom_fields")),
                "sites": sites,
                **_assigned(c),
            }
        )

    fields = []
    for f in _list(data.get("custom_fields"), "custom fields"):
        name = _name(f.get("name"), 100)
        model = _choice(f.get("model"), CustomFieldModel.values, "")
        if name and model:
            fields.append(
                {
                    "model": model,
                    "name": name,
                    "type": _choice(f.get("type"), CustomFieldType.values, "text"),
                    "options": _strings(f.get("options"), 255),
                }
            )

    scripts = []
    for s in _list(data.get("scripts"), "scripts"):
        name = _name(s.get("name"), 255)
        if not name:
            continue
        timeout = s.get("timeout")
        scripts.append(
            {
                "name": name,
                "description": _str(s.get("description"), 10_000),
                "shell": _choice(s.get("shell"), ScriptShell.values, "powershell"),
                "category": _name(s.get("category"), 100),
                "args": _strings(s.get("args"), 1000),
                "env_vars": _strings(s.get("env_vars"), 1000),
                "body": _str(s.get("body"), MAX_BODY),
                "timeout": (
                    timeout
                    if isinstance(timeout, int)
                    and not isinstance(timeout, bool)
                    and 1 <= timeout <= 86400
                    else 90
                ),
                "platforms": [
                    p for p in _strings(s.get("platforms"), 20) if p in AgentPlat.values
                ],
                "run_as_user": s.get("run_as_user") is True,
                "syntax": _str(s.get("syntax"), 10_000),
            }
        )

    snippets = []
    for s in _list(data.get("snippets"), "snippets"):
        name = _name(s.get("name"), 40)
        if name:
            snippets.append(
                {
                    "name": name,
                    "desc": _name(s.get("desc"), 50),
                    "code": _str(s.get("code"), MAX_BODY),
                    "shell": _choice(s.get("shell"), ScriptShell.values, "powershell"),
                }
            )

    keystore = []
    for k in _list(data.get("keystore"), "keystore entries"):
        name = _name(k.get("name"), 25)
        if name:
            keystore.append({"name": name, "value": _str(k.get("value"), 10_000)})

    devices, refs = [], set()
    for d in _list(data.get("devices"), "devices"):
        ref = _str(d.get("ref"), 255)
        hostname = _name(d.get("hostname"), 255)
        if not ref or not hostname or ref in refs:
            continue
        refs.add(ref)
        devices.append(
            {
                "ref": ref,
                "site_ref": _str(d.get("site_ref"), 255),
                "hostname": hostname,
                "serial": _name(d.get("serial"), 255),
                "plat": _choice(d.get("plat"), AgentPlat.values, ""),
                "goarch": _choice(d.get("goarch"), GoArch.values, ""),
                "monitoring_type": _choice(
                    d.get("monitoring_type"), AgentMonType.values, ""
                ),
                "os_name": _name(d.get("os_name"), 255),
                "description": _str(d.get("description"), 255),
                "notes": [n for n in _strings(d.get("notes"), 10_000) if n.strip()],
                "custom_fields": _fields(d.get("custom_fields")),
                "policy": _name(d.get("policy"), 255),
                "patch_policy": _patch(d.get("patch_policy")),
                "settings": _clean(Agent, AGENT_SETTINGS, d.get("settings")),
                "checks": _checks(d.get("checks")),
                "tasks": _tasks(d.get("tasks")),
                "excluded_policies": _names(d.get("excluded_policies")),
                "excluded_templates": _names(d.get("excluded_templates"), 100),
            }
        )

    return {
        "clients": clients,
        "custom_fields": fields,
        "scripts": scripts,
        "snippets": snippets,
        "keystore": keystore,
        "devices": devices,
        **_more(data),
    }

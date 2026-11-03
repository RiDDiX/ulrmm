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
                     custom_fields}]

validate() is the trust boundary: the answer comes from another server, so
every value is type checked and cut to the column sizes before it is stored."""

import requests

from ulrmm.constants import (
    AgentMonType,
    AgentPlat,
    CustomFieldModel,
    CustomFieldType,
    GoArch,
    ScriptShell,
)

TIMEOUT = 30
# more than any fleet this importer is meant for; a bigger answer is refused
MAX_ITEMS = 20000
MAX_BODY = 1_000_000


class SourceError(Exception):
    pass


class Source:
    """One other RMM. Subclasses set KIND and SECRETS and implement fetch;
    push is only there when the source can run a command on a device."""

    KIND = ""
    # names of the secret fields the source needs
    SECRETS: tuple = ()
    # platforms push() can send an installer to
    PUSH_PLATS: tuple = ()

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
                **kwargs,
            )
        except requests.RequestException as e:
            raise SourceError(f"{path}: {type(e).__name__}")
        if 300 <= r.status_code < 400:
            raise SourceError(f"{path} answered with a redirect")
        if r.status_code in (401, 403):
            raise SourceError(f"{path}: the key or login was refused ({r.status_code})")
        if r.status_code >= 400:
            raise SourceError(f"{path} answered {r.status_code}")
        if r.status_code == 204 or not r.content:
            return None
        if len(r.content) > 50 * MAX_BODY:
            raise SourceError(f"{path} answered with too much data")
        try:
            return r.json()
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
                }
            )
        clients.append(
            {
                "ref": _str(c.get("ref"), 255),
                "name": name,
                "custom_fields": _fields(c.get("custom_fields")),
                "sites": sites,
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
            }
        )

    return {
        "clients": clients,
        "custom_fields": fields,
        "scripts": scripts,
        "snippets": snippets,
        "keystore": keystore,
        "devices": devices,
    }

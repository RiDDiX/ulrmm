# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Detection rules: whether a baseline item really is installed on an agent.

inventory  {"name": regex, "version_min"?}    the agent's software inventory
file       {"path", "version_min"?}           a file, its version on Windows
registry   {"key", "value"?, "version_min"?}  an HKLM key or value, Windows
none       the exit code only, the item counts as unverified
"""

import asyncio
import json
import re

from django.conf import settings
from rest_framework import serializers

from ulrmm.constants import AgentPlat

TYPES = ("inventory", "file", "registry", "none")
SCRIPTS = {
    AgentPlat.WINDOWS: settings.BASE_DIR
    / "software"
    / "scripts"
    / "detect_windows.ps1",
    "posix": settings.BASE_DIR / "software" / "scripts" / "detect_posix.sh",
}
SCRIPT_TIMEOUT = 60
MARKER = "ULRMM-DET "

_REG_RE = re.compile(r"(?:HKLM:?|HKEY_LOCAL_MACHINE)\\(.+)", re.IGNORECASE)
_WIN_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%\\).+")


def _short(value, limit: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= limit
        and value.isprintable()
    )


def clean(value, plat: str) -> dict | None:
    """The rule as stored, None for the source default."""
    if value is None or value == {}:
        return None
    if not isinstance(value, dict) or value.get("type") not in TYPES:
        raise serializers.ValidationError(
            "type must be inventory, file, registry or none."
        )
    kind = value["type"]
    windows = plat == AgentPlat.WINDOWS
    rule = {"type": kind}
    if kind == "inventory":
        name = value.get("name")
        if not _short(name, 255):
            raise serializers.ValidationError(
                "Give the name as a regular expression of at most 255 characters."
            )
        try:
            re.compile(name)
        except re.error as e:
            raise serializers.ValidationError(
                f"The name is not a valid regular expression: {e}."
            ) from None
        rule["name"] = name
    elif kind == "file":
        path = value.get("path")
        if not _short(path, 260) or not (
            _WIN_PATH_RE.fullmatch(path) if windows else path.startswith("/")
        ):
            raise serializers.ValidationError("Give the full path of the file.")
        rule["path"] = path
    elif kind == "registry":
        if not windows:
            raise serializers.ValidationError("Registry rules are for Windows only.")
        key = value.get("key")
        if not _short(key, 255) or not _REG_RE.fullmatch(key):
            raise serializers.ValidationError(
                "Give a key below HKLM, like HKLM:\\SOFTWARE\\Vendor\\App."
            )
        rule["key"] = key
        name = value.get("value")
        if name not in (None, ""):
            if not _short(name, 255):
                raise serializers.ValidationError(
                    "The value name has at most 255 characters."
                )
            rule["value"] = name

    floor = value.get("version_min")
    if floor not in (None, ""):
        if kind == "none":
            raise serializers.ValidationError("A rule without a check has no version.")
        if kind == "file" and not windows:
            raise serializers.ValidationError("File versions are read on Windows only.")
        if not _short(floor, 64) or not re.search(r"\d", floor):
            raise serializers.ValidationError("version_min needs a version number.")
        rule["version_min"] = floor
    return rule


def name_rule(name: str) -> dict:
    """Inventory rule for a catalog or package name. Parts in brackets and
    separators are left out: 7zip finds 7-Zip 24.08 (x64)."""
    base = re.sub(r"\s*\([^)]*\)", "", name).strip() or name
    chars = [re.escape(c.lower()) for c in base if c.isalnum()]
    return {"type": "inventory", "name": r"[\W_]*".join(chars) or re.escape(name)}


def version_key(version: str) -> tuple[int, ...]:
    # numbers only and no dpkg epoch: 1:2.30-1ubuntu1 compares as 2.30.1.1
    return tuple(int(n) for n in re.findall(r"\d+", re.sub(r"^\s*\d+:", "", version)))


def new_enough(version: str, floor: str | None) -> bool:
    return not floor or (bool(version) and version_key(version) >= version_key(floor))


def in_inventory(rule: dict, software) -> tuple[bool, str]:
    """(found, version). A match below version_min gives its version."""
    pattern = re.compile(rule["name"], re.IGNORECASE)
    seen = ""
    for item in software if isinstance(software, list) else []:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not pattern.search(name):
            continue
        version = item.get("version")
        version = version if isinstance(version, str) else ""
        if new_enough(version, rule.get("version_min")):
            return True, version
        seen = seen or version
    return False, seen


def payload(agent, rule: dict) -> dict:
    windows = agent.plat == AgentPlat.WINDOWS
    key = rule.get("key", "")
    if m := _REG_RE.fullmatch(key):
        key = "Registry::HKEY_LOCAL_MACHINE\\" + m.group(1)
    env = {
        "DET_TYPE": rule["type"],
        "DET_PATH": rule.get("path", ""),
        "DET_KEY": key,
        "DET_VALUE": rule.get("value", ""),
    }
    script = SCRIPTS[AgentPlat.WINDOWS if windows else "posix"]
    return {
        "func": "runscriptfull",
        "timeout": SCRIPT_TIMEOUT,
        "payload": {
            "code": script.read_text(),
            "shell": "powershell" if windows else "shell",
        },
        "run_as_user": False,
        "env_vars": [f"{k}={v}" for k, v in env.items()],
    }


def parse(out) -> tuple[bool, str] | None:
    if not isinstance(out, dict):
        return None
    stdout = str(out.get("stdout") or "")
    line = next((s for s in reversed(stdout.splitlines()) if s.startswith(MARKER)), "")
    try:
        res = json.loads(line[len(MARKER) :])
    except (ValueError, RecursionError):
        return None
    if not isinstance(res, dict) or not isinstance(res.get("found"), bool):
        return None
    version = res.get("version")
    return res["found"], version[:255] if isinstance(version, str) else ""


def on_agent(agent, rule: dict) -> tuple[bool | None, str]:
    got = parse(
        asyncio.run(agent.nats_cmd(payload(agent, rule), timeout=SCRIPT_TIMEOUT + 30))
    )
    if got is None:
        return None, ""
    found, version = got
    return found and new_enough(version, rule.get("version_min")), version


def refresh_inventory(agent) -> list | None:
    """The agent's software list read fresh, None when it did not answer."""
    from winupdate.tasks import posix_refresh_task

    from .models import InstalledSoftware
    from .views import _save_inventory

    if agent.is_posix:
        if posix_refresh_task(agent.pk, "inventory") != "ok":
            return None
    else:
        reply = asyncio.run(agent.nats_cmd({"func": "softwarelist"}, timeout=15))
        if not isinstance(reply, list) or not all(isinstance(i, dict) for i in reply):
            return None
        _save_inventory(agent, reply)
    row = InstalledSoftware.latest_for(agent)
    return row.software if row and isinstance(row.software, list) else []


def detect(agent, rule: dict, inventory) -> tuple[bool | None, str]:
    """(installed, version). None: no answer now, or a rule without a check.
    inventory() returns the refreshed software list or None."""
    if rule["type"] == "none":
        return None, ""
    if rule["type"] == "inventory":
        software = inventory()
        if software is None:
            return None, ""
        return in_inventory(rule, software)
    return on_agent(agent, rule)

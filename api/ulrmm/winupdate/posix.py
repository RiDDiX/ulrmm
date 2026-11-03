# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
Linux/macOS/FreeBSD package inventory and patching through posix_packages.sh,
executed on the agent with runscriptfull.
"""

import asyncio
import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.conf import settings
from ulrmm.agent_ident import agent_ident

if TYPE_CHECKING:
    from agents.models import Agent

POSIX_SCRIPT_TIMEOUTS = {
    "inventory": 600,
    "scan": 900,
    "refresh": 1500,
    "install": 3600,
    "remove": 900,
}

SCRIPT_PATH = Path(__file__).with_name("posix_packages.sh")

SCRIPT_ENV_VARS = [
    "LC_ALL=C",
    "LANG=C",
    "DEBIAN_FRONTEND=noninteractive",
    "NEEDRESTART_MODE=a",
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
]

SEVERITIES = ("Critical", "Important", "Moderate", "Low")

# guid prefixes, keep in sync with valid_guid() in posix_packages.sh
PACKAGE_MANAGERS = (
    "apt",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "apk",
    "flatpak",
    "snap",
    "brew",
    "brew-cask",
    "softwareupdate",
    "pkg",
)
NAME_RE = re.compile(r"[A-Za-z0-9._+@~-]+")
LABEL_RE = re.compile(r"[A-Za-z0-9._+@~,() -]+")
ARCH_RE = re.compile(r"[A-Za-z0-9_]*")
VERSION_RE = re.compile(r"[A-Za-z0-9._+~:^,-]*")
DPKG_REMOVE_NAME_RE = re.compile(r"[A-Za-z0-9._+@~-]+(?::[A-Za-z0-9][A-Za-z0-9_-]*)?")
REMOVABLE_SOURCES = {
    "linux": ("dpkg", "rpm", "pacman", "apk", "flatpak", "snap"),
    "darwin": ("brew", "brew-cask", "app"),
    "freebsd": ("pkg",),
}

# Package names that can disable management, boot, the base system, or remote access.
PROTECTED_REMOVE_TARGETS = (
    "dpkg",
    "apt",
    "rpm",
    "dnf",
    "dnf5",
    "yum",
    "zypper",
    "libzypp",
    "pacman",
    "apk-tools",
    "systemd",
    "systemd-sysv",
    "init",
    "glibc",
    "libc6",
    "musl",
    "busybox",
    "alpine-base",
    "bash",
    "coreutils",
    "util-linux",
    "filesystem",
    "base",
    "sudo",
    "openssh-server",
    "openssh",
    # every kernel flavour - nothing depends on them, so no package manager
    # refuses on its own (linux-virt, linux-hardened, kernel-core, ...)
    "kernel*",
    "linux*",
    "snapd",
    "core",
    "core18",
    "core20",
    "core22",
    "core24",
    "bare",
    "flatpak",
    "pkg",
    # FreeBSD base system packages (pkgbase)
    "freebsd-*",
)

# appliances that update themselves as a whole; posix_packages.sh refuses too
MANAGED_BY = {"TrueNAS": "package updates are managed by TrueNAS"}

# agents.models.Agent.delete_superseded_updates parses "(Version x)" from titles
SUPERSEDED_TITLE_RE = re.compile(r"\((Version|Versão)", re.IGNORECASE)

DATE_FMT = "%Y-%m-%d %H:%M:%S +0000 UTC"


def managed_reason(agent: "Agent") -> str:
    """Why package actions are refused on this agent, "" when they are not."""
    return MANAGED_BY.get(agent.appliance, "") if agent.is_posix else ""


def get_packages_script() -> str:
    return SCRIPT_PATH.read_text()


def build_script_payload(mode: str, args: list[str] | None = None) -> dict:
    if mode not in POSIX_SCRIPT_TIMEOUTS:
        raise ValueError(f"invalid mode {mode}")

    return {
        "func": "runscriptfull",
        "timeout": POSIX_SCRIPT_TIMEOUTS[mode],
        "script_args": [mode, *(args or [])],
        "payload": {"code": get_packages_script(), "shell": "shell"},
        "run_as_user": False,
        "env_vars": list(SCRIPT_ENV_VARS),
        "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
        "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
    }


def run_packages_script(
    agent: "Agent",
    mode: str,
    args: list[str] | None = None,
    payload: dict | None = None,
) -> dict | str:
    """Returns the agent reply, or an error string. Never raises."""
    try:
        if payload is None:
            payload = build_script_payload(mode, args)
        r = asyncio.run(agent.nats_cmd(payload, timeout=payload["timeout"] + 30))
    except Exception as e:
        return str(e) or type(e).__name__
    return r if isinstance(r, dict) else str(r)


def is_valid_guid(guid: str) -> bool:
    if not isinstance(guid, str) or len(guid) > 255:
        return False

    parts = guid.split(":", 3)
    if len(parts) != 4:
        return False

    manager, name, arch, version = parts
    if manager == "softwareupdate":
        name_ok = LABEL_RE.fullmatch(name) and not name.startswith(("-", " "))
    elif manager in PACKAGE_MANAGERS:
        name_ok = NAME_RE.fullmatch(name) and not name.startswith("-")
    else:
        return False

    return bool(name_ok and ARCH_RE.fullmatch(arch) and VERSION_RE.fullmatch(version))


def is_valid_remove_target(source: str, target: str, plat: str) -> bool:
    if source not in REMOVABLE_SOURCES.get(plat, ()) or not isinstance(target, str):
        return False
    if source == "app":
        if len(target) > 1024 or not target.startswith("/Applications/"):
            return False
        name = target.removeprefix("/Applications/").removesuffix(".app")
        return bool(
            target.endswith(".app")
            and name
            and not name.startswith(".")
            and "/" not in name
            and not any(ord(char) < 32 or ord(char) == 127 for char in name)
        )
    if len(target) > 255 or target.startswith("-"):
        return False
    regex = DPKG_REMOVE_NAME_RE if source == "dpkg" else NAME_RE
    return bool(regex.fullmatch(target))


def is_protected_remove_target(target: str) -> bool:
    name = target.rsplit(":", 1)[0].lower()
    # the agent itself must not be uninstalled as if it were software
    ident = agent_ident()
    protected = PROTECTED_REMOVE_TARGETS + tuple(
        {
            ident[key].removesuffix(".service").lower()
            for key in (
                "identSvcName",
                "identNixBin",
                "identNixSvc",
                "identArtifact",
            )
        }
    )
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in protected)


@dataclass
class ParsedPackages:
    software: list[dict] = field(default_factory=list)
    updates: list[dict] = field(default_factory=list)
    reboot_required: bool | None = None
    install_results: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # pkg audit JSON on FreeBSD, None when the scan did not run it
    audit: dict | None = None


def _human_size(value: str) -> str:
    if not re.fullmatch(r"[0-9]{1,20}", value):
        return ""

    size = float(value)
    if size < 1000:
        return f"{int(size)} B"
    for unit in ("kB", "MB", "GB", "TB"):
        size /= 1000
        if size < 1000:
            break
    return f"{size:.1f} {unit}"


def _epoch_date(value: str) -> str:
    if not re.fullmatch(r"[0-9]{1,12}", value) or int(value) == 0:
        return ""
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(DATE_FMT)
    except (OverflowError, OSError, ValueError):
        return ""


def _software(rec: list[str]) -> dict | None:
    fields = (rec + [""] * 10)[1:10]
    source, name, version, publisher, size, epoch, location, src, src_ver = fields
    if not name:
        return None

    item = {
        "name": name,
        "version": version,
        "publisher": publisher,
        "install_date": _epoch_date(epoch),
        "size": _human_size(size),
        "source": source,
        "location": location,
        "uninstall": "",
    }
    # source package, when dpkg, rpm or apk sent one
    if src:
        item["source_name"] = src
        item["source_version"] = src_ver
    return item


def _update(rec: list[str], errors: list[str]) -> dict | None:
    fields = (rec + [""] * 9)[1:9]
    manager, name, arch, current, new, severity, category, advisory = fields
    if manager not in PACKAGE_MANAGERS or not name:
        return None

    guid = f"{manager}:{name}:{arch}:{new}"
    if len(guid) > 255:
        errors.append(f"{manager}-skipped: update identifier too long for {name[:100]}")
        return None
    # never stored when the install command could not accept it, reported under a
    # key that does not protect the manager's other rows from stale cleanup
    if not is_valid_guid(guid):
        errors.append(
            f"{manager}-skipped: unsupported characters in update for {name[:100]}"
        )
        return None

    description = f"{current} -> {new}"
    if category:
        description += f" ({category})"

    return {
        "guid": guid,
        "kb": name[:100],
        "title": SUPERSEDED_TITLE_RE.sub(r"[\1", name),
        "severity": severity if severity in SEVERITIES else "",
        "categories": [category] if category else [],
        "kb_article_ids": [i for i in advisory.split(",") if i],
        "description": description,
        "manager": manager,
        "name": name,
        "arch": arch,
        "current": current,
        "new": new,
    }


def _macos_date(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime(DATE_FMT)
    except ValueError:
        return ""


def _macos_apps(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []

    apps = data.get("SPApplicationsDataType") if isinstance(data, dict) else None
    if not isinstance(apps, list):
        return []

    ret = []
    for app in apps:
        if not isinstance(app, dict) or not isinstance(app.get("_name"), str):
            continue

        publisher = str(app.get("obtained_from", ""))
        signed_by = app.get("signed_by")
        if isinstance(signed_by, list) and signed_by and isinstance(signed_by[0], str):
            if signed_by[0].startswith("Developer ID Application: "):
                publisher = signed_by[0].removeprefix("Developer ID Application: ")
                publisher = re.sub(r"\s*\([A-Z0-9]+\)$", "", publisher)
        if publisher == "apple":
            publisher = "Apple"

        ret.append(
            {
                "name": app["_name"],
                "version": str(app.get("version", "")),
                "publisher": publisher,
                "install_date": _macos_date(app.get("lastModified")),
                "size": "",
                "source": "app",
                "location": str(app.get("path", "")),
                "uninstall": "",
            }
        )
    return ret


def _pkg_audit(text: str) -> dict | None:
    """package name -> {"version", "issues"} from pkg audit -Rjson-compact."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    packages = data.get("packages", {}) if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return None
    return {
        name: entry
        for name, entry in packages.items()
        if isinstance(name, str)
        and isinstance(entry, dict)
        and isinstance(entry.get("version"), str)
        and isinstance(entry.get("issues"), list)
    }


def parse_packages_output(stdout: str) -> ParsedPackages:
    ret = ParsedPackages()
    if not isinstance(stdout, str):
        return ret

    guids = set()
    json_lines: list[str] | None = None
    block = ""

    for line in stdout.split("\n"):
        line = line.rstrip("\r")

        if json_lines is not None:
            if line in (f"{block}\tEND", f"{block} END"):
                text = "\n".join(json_lines)
                if block == "J":
                    ret.software.extend(_macos_apps(text))
                else:
                    ret.audit = _pkg_audit(text)
                json_lines = None
            else:
                json_lines.append(line)
            continue

        rec = line.split("\t")
        kind = rec[0]

        if line in ("J\tBEGIN", "J BEGIN", "A\tBEGIN", "A BEGIN"):
            block, json_lines = line[0], []
        elif kind == "S" and len(rec) >= 4:
            if item := _software(rec):
                ret.software.append(item)
        elif kind == "U" and len(rec) >= 6:
            item = _update(rec, ret.errors)
            if item and item["guid"] not in guids:
                guids.add(item["guid"])
                ret.updates.append(item)
        elif kind == "R" and len(rec) == 2 and rec[1] in ("0", "1"):
            ret.reboot_required = bool(ret.reboot_required) or rec[1] == "1"
        elif kind == "I" and len(rec) >= 3 and re.fullmatch(r"-?[0-9]{1,5}", rec[2]):
            ret.install_results.append(
                {
                    "guid": rec[1],
                    "exit_code": int(rec[2]),
                    "message": "\t".join(rec[3:]),
                }
            )
        elif kind == "E" and len(rec) >= 3:
            ret.errors.append(f"{rec[1]}: {' '.join(rec[2:])}")

    # like apt's -security origin: an update of a vulnerable package
    for update in ret.updates:
        if (
            update["manager"] == "pkg"
            and update["name"] in (ret.audit or {})
            and not update["severity"]
        ):
            update["severity"] = "Important"
            update["categories"] = ["security"]
    return ret

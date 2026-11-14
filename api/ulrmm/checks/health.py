# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Verdicts for the security and hardware health checks.

The agent collects one health document per run (also stored as
``wmi_detail["health"]``) and sends it with every security and hwhealth
result. It is untrusted input: every reader below tolerates wrong types and
caps lengths, and ``evaluate`` never raises.
"""

import math
from typing import Any, Callable, Optional

SECURITY = "security"
HW_HEALTH = "hwhealth"
HEALTH_CHECK_TYPES = (SECURITY, HW_HEALTH)

# (warning, error): Defender signature age in days, battery wear in percent
DEFAULT_THRESHOLDS = {SECURITY: (3, 7), HW_HEALTH: (20, 30)}
DEFAULT_RUN_INTERVAL = 900
MIN_RUN_INTERVAL = 300

MAX_LIST = 64
MAX_STR = 128
MAX_REASONS = 8
MAX_TEXT = 1000

PASSING = "passing"
FAILING = "failing"
WARNING = "warning"
ERROR = "error"

GOOD_BATTERY = {"", "good", "normal"}
# platforms whose security section is shown, never judged
REPORT_ONLY = {"linux": "Linux", "freebsd": "FreeBSD"}

# sections a report must carry before its verdict means anything
SECTIONS = {
    SECURITY: (("av", list), ("firewall", dict)),
    HW_HEALTH: (("disks", list),),
}

# collector errors that leave a hole in exactly what the check judges
GAP_ERRORS = {
    SECURITY: ("security center",),
    HW_HEALTH: (
        "MSFT_PhysicalDisk",
        "system_profiler",
        "smartctl --scan",
        "smartctl /",
        "nvme",
    ),
}

# the collector found no smartctl, so disks it would have read are not listed
NO_SMARTCTL = "smartctl not installed"
NO_SMARTCTL_TEXT = "disk health not read: smartctl is not installed"
# maker or model strings of hypervisors, as DMI or WMI name them; a virtual
# machine has no disks of its own to read, so it gets no such line
VM_MAKERS = (
    "qemu",
    "kvm",
    "vmware",
    "virtualbox",
    "innotek",
    "xen",
    "bochs",
    "bhyve",
    "parallels",
    "hyper-v",
    "virtual machine",
    # the chassis maker VMware reports
    "no enclosure",
    "openstack",
    "amazon ec2",
    "google compute engine",
    # Hetzner vServer, DigitalOcean Droplet, Alibaba Cloud ECS
    "vserver",
    "droplet",
    "alibaba cloud",
    "nutanix ahv",
    "ovirt",
    # Cloud Hypervisor, RHEV Hypervisor
    "hypervisor",
)

Problems = list[tuple[str, str]]


def is_virtual(make_model: Any) -> bool:
    """True when the stored make and model name a hypervisor."""
    name = _s(make_model, 256).lower()
    return any(maker in name for maker in VM_MAKERS)


def _virtual(make_model: Callable[[], Any]) -> bool:
    try:
        return is_virtual(make_model())
    except Exception:
        # an unreadable make and model counts as a physical host
        return False


def run_interval(check_type: str, interval: int, fallback: int) -> int:
    """Seconds between runs. Health checks are expensive on the endpoint, so
    they get their own default and floor instead of the agent interval."""
    if check_type in HEALTH_CHECK_TYPES:
        return max(interval or DEFAULT_RUN_INTERVAL, MIN_RUN_INTERVAL)
    return interval or fallback


def _s(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _b(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _n(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _c(value: Any) -> Optional[float]:
    # anything outside this range is a sensor quirk, not a temperature
    value = _n(value)
    if value is None or not -40 <= value <= 150:
        return None
    return value


def _dicts(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)][:MAX_LIST]


def _d(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _temp(problems: Problems, name: str, c: Any, warn_c: Any, crit_c: Any) -> None:
    c, warn_c, crit_c = _c(c), _c(warn_c), _c(crit_c)
    if c is None:
        return
    if crit_c is not None and crit_c > 0 and c >= crit_c:
        problems.append((ERROR, f"{name} {c:g} C at critical limit {crit_c:g} C"))
    elif warn_c is not None and warn_c > 0 and c >= warn_c:
        problems.append((WARNING, f"{name} {c:g} C at warning limit {warn_c:g} C"))


def _av_names(entries: list[dict]) -> str:
    return ", ".join(_s(e.get("name"), 40) for e in entries) or "none"


def _security(
    plat: str, health: dict, warn: Any, err: Any
) -> tuple[Problems, list[str]]:
    problems: Problems = []
    notes: list[str] = []

    av = _dicts(health.get("av"))
    enabled = [e for e in av if e.get("enabled") is True]
    names = _av_names(enabled)
    firewall_on = _b(_d(health.get("firewall")).get("enabled"))

    if plat in REPORT_ONLY:
        state = {True: "on", False: "off"}.get(firewall_on, "unknown")
        return [], [
            f"{REPORT_ONLY[plat]}, not alerted: antivirus {names}, firewall {state}"
        ]

    if plat == "windows":
        defender = _d(health.get("defender"))
        wsc = [e for e in av if e.get("src") == "wsc"]
        defender_on = defender.get("av") is True and defender.get("rtp") is True

        if wsc:
            # Security Center knows every product, its word wins over Defender's
            if not enabled:
                problems.append((ERROR, "no antivirus enabled"))
            elif all(e.get("up_to_date") is False for e in enabled):
                problems.append(
                    (WARNING, f"antivirus definitions out of date: {names}")
                )
        elif defender_on:
            names = "Microsoft Defender"
        elif defender.get("mode") == "Normal":
            problems.append((ERROR, "Defender real-time protection off"))
        else:
            # server editions have no Security Center to ask
            notes.append("antivirus state unknown (no Security Center)")

        in_use = any(
            "defender" in _s(e.get("name"), MAX_STR).lower() for e in enabled
        ) or (not wsc and defender_on)
        age = _n(defender.get("sig_age_days"))
        if in_use and not defender:
            problems.append((WARNING, "Defender status not read"))
        elif in_use and age is not None:
            if err and age > err:
                problems.append((ERROR, f"Defender signatures {age:g} days old"))
            elif warn and age > warn:
                problems.append((WARNING, f"Defender signatures {age:g} days old"))
    elif plat == "darwin" and not enabled:
        problems.append((ERROR, "XProtect missing"))

    if firewall_on is False:
        problems.append((ERROR, "firewall off"))
    elif firewall_on is None:
        problems.append((WARNING, "firewall state unknown"))

    notes.insert(0, f"antivirus {names}")
    return problems, notes


def _hardware(health: dict, warn: Any, err: Any) -> tuple[Problems, list[str]]:
    problems: Problems = []
    disks = _dicts(health.get("disks"))

    for i, disk in enumerate(disks):
        name = _s(disk.get("name"), 64) or f"disk {i}"
        if (
            disk.get("health") == "failing"
            or disk.get("smart") == "failed"
            or _n(disk.get("critical_warning"))
        ):
            problems.append((ERROR, f"{name} failing"))
        elif disk.get("health") == "warning":
            problems.append((WARNING, f"{name} reports a health warning"))
        _temp(
            problems,
            name,
            disk.get("temp_c"),
            disk.get("temp_warn_c"),
            disk.get("temp_crit_c"),
        )

    for sensor in _dicts(health.get("temps")):
        _temp(
            problems,
            _s(sensor.get("name"), 64) or "sensor",
            sensor.get("c"),
            sensor.get("warn_c"),
            sensor.get("crit_c"),
        )

    battery = _d(health.get("battery"))
    capacity = _n(battery.get("max_capacity_pct"))
    if capacity is not None and 0 <= capacity <= 200:
        wear = max(0, 100 - capacity)
        if err and wear >= err:
            problems.append((ERROR, f"battery wear {wear:g}%"))
        elif warn and wear >= warn:
            problems.append((WARNING, f"battery wear {wear:g}%"))
    condition = _s(battery.get("condition"), 32)
    if condition.strip().lower() not in GOOD_BATTERY:
        problems.append((WARNING, f"battery condition {condition}"))

    return problems, [f"{len(disks)} disk(s)"]


def evaluate(
    check_type: str,
    plat: str,
    health: Any,
    warn: Any,
    err: Any,
    make_model: Callable[[], Any] = lambda: "",
) -> tuple[str, Optional[str], str]:
    """Returns (status, severity or None when passing, text for more_info).
    ``make_model`` gives the device's stored make and model; it is only read
    when a hardware report lists no disk because smartctl is missing."""
    if health is None:
        return FAILING, WARNING, "no health report, agent update required"
    version = health.get("v") if isinstance(health, dict) else None
    if not isinstance(version, int):
        return FAILING, WARNING, "malformed health report"

    kind = SECURITY if check_type == SECURITY else HW_HEALTH
    raw_errors = health.get("errors")
    errors = [
        e[:MAX_STR]
        for e in (raw_errors[:MAX_LIST] if isinstance(raw_errors, list) else [])
        if isinstance(e, str) and e
    ]

    # Linux and FreeBSD security is shown, never alerted on: nothing is required
    judged = kind == HW_HEALTH or plat in ("windows", "darwin")

    missing = [
        name
        for name, container in SECTIONS[kind]
        if not isinstance(health.get(name), container)
    ]
    if judged and missing:
        why = "; ".join(errors[:MAX_REASONS]) or "no " + ", ".join(missing)
        return FAILING, WARNING, f"health report incomplete: {why}"[:MAX_TEXT]

    try:
        if kind == SECURITY:
            problems, notes = _security(plat, health, warn, err)
        else:
            problems, notes = _hardware(health, warn, err)
    except Exception:
        return FAILING, WARNING, "malformed health report"

    if judged:
        problems += [
            (WARNING, f"not read: {e}")
            for e in errors
            if e.startswith(GAP_ERRORS[kind])
        ]

    extra = []
    if (
        kind == HW_HEALTH
        and NO_SMARTCTL in errors
        and not _dicts(health.get("disks"))
        and not _virtual(make_model)
    ):
        extra.append(NO_SMARTCTL_TEXT)

    if not problems:
        return PASSING, None, ("OK: " + "; ".join(notes + extra))[:MAX_TEXT]

    problems.sort(key=lambda p: p[0] != ERROR)
    severity = ERROR if problems[0][0] == ERROR else WARNING
    text = "; ".join([t for _, t in problems[:MAX_REASONS]] + extra)
    return FAILING, severity, text[:MAX_TEXT]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Driver inventory of Windows agents: POST /api/v3/<agentid>/drivers/ body."""

import datetime as dt
import re
from typing import Any

MAX_BODY = 1024 * 1024
MAX_DRIVERS = 2048
MAX_PROBLEMS = 256
MAX_ERRORS = 8
STALE = dt.timedelta(days=3)

# third-party driver packages in the driver store, inbox drivers have real names
OEM_INF_RE = re.compile(r"oem\d{1,5}\.inf", re.IGNORECASE)
# removing a driver of these classes can leave the machine unbootable
BOOT_CLASSES = frozenset(
    c.lower()
    for c in (
        "SCSIAdapter",
        "HDC",
        "DiskDrive",
        "Volume",
        "VolumeSnapshot",
        "System",
        "Processor",
        "Computer",
    )
)

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

# key: character limit
DRIVER_FIELDS = {
    "device": 255,
    "class": 64,
    "manufacturer": 255,
    "provider": 255,
    "version": 64,
    "date": 10,
    "inf": 64,
    "device_id": 255,
}
PROBLEM_FIELDS = {"name": 255, "device_id": 255, "class": 64}


def _str(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _date(value) -> str:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        return ""
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return ""
    return value


def _driver(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    row = {k: _str(item.get(k), limit) for k, limit in DRIVER_FIELDS.items()}
    if not row["inf"]:
        return None
    row["date"] = _date(item.get("date"))
    signed = item.get("signed")
    row["signed"] = signed if isinstance(signed, bool) else None
    return row


def _problem(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    code = item.get("code")
    # 45 is "not connected", not a fault
    if isinstance(code, bool) or not isinstance(code, int) or not 1 <= code <= 99:
        return None
    if code == 45:
        return None
    row = {k: _str(item.get(k), limit) for k, limit in PROBLEM_FIELDS.items()}
    row["code"] = code
    return row


def _items(value, clean, limit: int) -> list:
    if not isinstance(value, list):
        return []
    rows = (clean(i) for i in value[:limit])
    return [r for r in rows if r is not None]


def clean_drivers(body: Any) -> dict:
    """Typed and capped copy of the body; ValueError when it is not an object."""
    if not isinstance(body, dict):
        raise ValueError("drivers must be an object")
    errors = body.get("errors")
    return {
        "drivers": _items(body.get("drivers"), _driver, MAX_DRIVERS),
        "problems": _items(body.get("problems"), _problem, MAX_PROBLEMS),
        "errors": [
            e[:128]
            for e in (errors if isinstance(errors, list) else [])[:MAX_ERRORS]
            if isinstance(e, str)
        ],
    }


def boot_infs(drivers: list) -> set[str]:
    """INF names that a boot-critical device uses."""
    return {
        str(d.get("inf", "")).lower()
        for d in drivers
        if str(d.get("class", "")).lower() in BOOT_CLASSES
    }


def removable(inf: str, blocked: set[str]) -> bool:
    return bool(OEM_INF_RE.fullmatch(inf or "")) and inf.lower() not in blocked

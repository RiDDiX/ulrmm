# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""State pushes of the agent (POST /api/v3/<agentid>/state/).

The body is untrusted: clean_state keeps only the keys below, typed and
capped, and drops anything else.
"""

import datetime as dt
import math
import re
from typing import Any, Optional

from django.db import transaction
from django.utils import timezone as djangotime

from ulrmm.constants import CheckType, ContainerKind, MetricOp

from .models import AgentState, Sample
from .tasks import MB, disk_usage

MAX_BODY = 256 * 1024
INT_MAX = 2**63 - 1
# a push sooner than this after the last sample only refreshes the state
SAMPLE_GAP = 60
MAX_VALUES = 256
LABEL_CAP = 64
LABEL_BAD = re.compile(r"[{}=,\x00-\x1f\x7f]")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Str:
    def __init__(self, cap: int, choices=None, null: bool = False):
        self.cap, self.choices, self.null = cap, choices, null

    def __call__(self, value):
        if not isinstance(value, str):
            raise ValueError
        if self.choices is not None:
            if value not in self.choices:
                raise ValueError
            return value
        return CONTROL.sub("", value)[: self.cap]


class Int:
    def __init__(self, null: bool = False):
        self.null = null

    def __call__(self, value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError
        if not 0 <= value <= INT_MAX:
            raise ValueError
        return value


class Num:
    """Finite number; out of range is dropped, or clamped with clamp=True."""

    def __init__(self, lo=None, hi=None, clamp: bool = False, null: bool = False):
        self.lo, self.hi, self.clamp, self.null = lo, hi, clamp, null

    def __call__(self, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError
        value = float(value)
        if not math.isfinite(value):
            raise ValueError
        if self.lo is not None and value < self.lo:
            if not self.clamp:
                raise ValueError
            value = self.lo
        if self.hi is not None and value > self.hi:
            if not self.clamp:
                raise ValueError
            value = self.hi
        return value


class Bool:
    def __init__(self, null: bool = False):
        self.null = null

    def __call__(self, value):
        if not isinstance(value, bool):
            raise ValueError
        return value


class List:
    def __init__(self, item, cap: int, size: Optional[int] = None):
        self.item, self.cap, self.size, self.null = item, cap, size, False

    def __call__(self, value):
        if not isinstance(value, list):
            raise ValueError
        if self.size is not None and len(value) != self.size:
            raise ValueError
        out = []
        for entry in value:
            if len(out) >= self.cap:
                break
            try:
                out.append(self.item(entry))
            except ValueError:
                continue
        return out


class Obj:
    def __init__(self, fields: dict, null: bool = False):
        self.fields, self.null = fields, null

    def __call__(self, value):
        if not isinstance(value, dict):
            raise ValueError
        out = {}
        for key, rule in self.fields.items():
            if key not in value:
                continue
            if value[key] is None:
                if rule.null:
                    out[key] = None
                continue
            try:
                out[key] = rule(value[key])
            except ValueError:
                continue
        return out


class Sources:
    null = False

    def __call__(self, value):
        if not isinstance(value, dict):
            raise ValueError
        return {
            kind: status
            for kind, status in value.items()
            if kind in ContainerKind.values and status in ("ok", "denied", "error")
        }


PCT = Num(0, 100, clamp=True)
RATE = Num(0, 1e12)
FLOAT = Num()

SCHEMA = Obj(
    {
        "v": Int(),
        "ts": Int(),
        "dt": Num(0, 1e9, null=True),
        "errors": List(Str(128), 16),
        "perf": Obj(
            {
                "cpu_pct": PCT,
                "mem_total": Int(),
                "mem_used": Int(),
                "swap_pct": PCT,
                "load": List(Num(0, 1e6), 3, size=3),
            }
        ),
        "system": Obj(
            {
                "manager": Str(16, ("systemd", "openrc", "launchd", "rc.d", "")),
                "units_total": Int(),
                "units_failed": Int(),
                "units": List(
                    Obj(
                        {
                            "name": Str(255),
                            "active": Str(24),
                            "sub": Str(24),
                            "enabled": Bool(null=True),
                            "description": Str(128),
                        }
                    ),
                    128,
                ),
                "mounts": List(
                    Obj(
                        {
                            "mount": Str(255),
                            "device": Str(255),
                            "fs": Str(32),
                            "ro": Bool(),
                            "stale": Bool(),
                            "size": Int(),
                            "used": Int(),
                            "used_pct": PCT,
                            "inode_pct": Num(0, 100, clamp=True, null=True),
                        }
                    ),
                    32,
                ),
                "time": Obj(
                    {
                        "synced": Bool(null=True),
                        "source": Str(16, ("chrony", "timesyncd", "ntpd", "kernel")),
                        "server": Str(255),
                        "offset_ms": Num(-1e7, 1e7, null=True),
                    }
                ),
                "raid": List(
                    Obj(
                        {
                            "kind": Str(
                                16, ("md", "zfs", "storcli", "gmirror", "graid")
                            ),
                            "name": Str(64),
                            "level": Str(32),
                            "state": Str(32),
                            "health": Str(16, ("ok", "degraded", "failed", "unknown")),
                            "devices": Int(null=True),
                            "failed": Int(null=True),
                            "sync_pct": Num(0, 100, clamp=True, null=True),
                        }
                    ),
                    32,
                ),
                "sensors": List(
                    Obj(
                        {
                            "kind": Str(8, ("temp", "fan", "volt")),
                            "source": Str(8, ("hwmon", "ipmi", "sysctl")),
                            "name": Str(64),
                            "value": FLOAT,
                            "unit": Str(4, ("C", "rpm", "V")),
                            "warn": Num(null=True),
                            "crit": Num(null=True),
                            "status": Str(16),
                        }
                    ),
                    64,
                ),
            }
        ),
        "net": Obj(
            {
                "ifaces": List(
                    Obj(
                        {
                            "name": Str(64),
                            "kind": Str(
                                8, ("ether", "wifi", "bond", "bridge", "vlan", "other")
                            ),
                            "state": Str(8, ("up", "down", "unknown")),
                            "speed_mbps": Int(null=True),
                            "duplex": Str(4, ("full", "half"), null=True),
                            "mac": Str(32),
                            "mtu": Int(null=True),
                            "addrs": List(Str(64), 16),
                            "master": Str(64, null=True),
                            "members": List(Str(64), 32),
                            "rx_bytes": Int(),
                            "tx_bytes": Int(),
                            "rx_packets": Int(),
                            "tx_packets": Int(),
                            "rx_errors": Int(),
                            "tx_errors": Int(),
                            "rx_drops": Int(),
                            "tx_drops": Int(),
                            "rate": Obj(
                                {
                                    "rx_bps": RATE,
                                    "tx_bps": RATE,
                                    "rx_pps": RATE,
                                    "tx_pps": RATE,
                                    "err_ps": RATE,
                                    "drop_ps": RATE,
                                },
                                null=True,
                            ),
                        }
                    ),
                    32,
                )
            }
        ),
        "containers": Obj(
            {
                "sources": Sources(),
                "items": List(
                    Obj(
                        {
                            "kind": Str(16, ContainerKind.values),
                            "id": Str(64),
                            "name": Str(128),
                            "image": Str(255),
                            "state": Str(
                                16,
                                (
                                    "running",
                                    "paused",
                                    "restarting",
                                    "stopped",
                                    "exited",
                                    "created",
                                    "unknown",
                                ),
                            ),
                            "status": Str(128),
                            "restarts": Int(null=True),
                            # docker counts every core as 100
                            "cpu_pct": Num(0, 1e4, clamp=True, null=True),
                            "mem_used": Int(null=True),
                            "mem_limit": Int(null=True),
                            "net_rx": Int(null=True),
                            "net_tx": Int(null=True),
                            "uptime": Int(null=True),
                            "node": Str(64, null=True),
                        }
                    ),
                    128,
                ),
                "cluster": Obj(
                    {
                        "name": Str(64),
                        "quorate": Bool(),
                        "nodes": Int(),
                        "online": Int(),
                    },
                    null=True,
                ),
            }
        ),
    }
)

TEMP_RANGE = (-40, 150)


def clean_state(body: Any) -> dict:
    """The typed and capped copy of a state body; raises ValueError when the
    body is not an object."""
    state = SCHEMA(body)
    for sensor in state.get("system", {}).get("sensors", []):
        value = sensor.get("value")
        if sensor.get("kind") == "temp" and value is not None:
            if not TEMP_RANGE[0] <= value <= TEMP_RANGE[1]:
                del sensor["value"]
    return state


# name: label keys. Nothing outside this list is ever stored.
SERIES = {
    "cpu.pct": (),
    "mem.pct": (),
    "swap.pct": (),
    "load.1": (),
    "load.5": (),
    "load.15": (),
    "disk.used_pct": ("mount",),
    "disk.inode_pct": ("mount",),
    "net.rx_bps": ("if",),
    "net.tx_bps": ("if",),
    "net.err_ps": ("if",),
    "net.drop_ps": ("if",),
    "temp.c": ("sensor",),
    "time.offset_ms": (),
    "ctr.cpu_pct": ("kind", "name"),
    "ctr.mem_bytes": ("kind", "name"),
    "vm.total": ("kind",),
    "vm.running": ("kind",),
}
MAX_MOUNTS = 16
MAX_IFACES = 16
MAX_TEMPS = 16
MAX_CONTAINERS = 32


def label_value(value: Any) -> str:
    return LABEL_BAD.sub("_", str(value)[:LABEL_CAP])


def series_key(name: str, labels: dict) -> str:
    if not labels:
        return name
    pairs = ",".join(f"{k}={label_value(labels[k])}" for k in sorted(labels))
    return f"{name}{{{pairs}}}"


def parse_key(key: str) -> tuple[str, dict]:
    name, _, rest = key.partition("{")
    labels = {}
    if rest.endswith("}"):
        for pair in rest[:-1].split(","):
            k, _, v = pair.partition("=")
            labels[k] = v
    return name, labels


def series(state: dict) -> dict[str, float]:
    out: dict[str, float] = {}

    def put(name: str, value: Any, labels: Optional[dict] = None) -> None:
        if value is not None and len(out) < MAX_VALUES:
            out[series_key(name, labels or {})] = round(float(value), 3)

    perf = state.get("perf", {})
    put("cpu.pct", perf.get("cpu_pct"))
    total, used = perf.get("mem_total"), perf.get("mem_used")
    if total and used is not None:
        put("mem.pct", min(used * 100 / total, 100))
    put("swap.pct", perf.get("swap_pct"))
    load = perf.get("load")
    if load:
        for name, value in zip(("load.1", "load.5", "load.15"), load):
            put(name, value)

    system = state.get("system", {})
    mounts = [
        m for m in system.get("mounts", []) if "mount" in m and not m.get("stale")
    ]
    for mount in mounts[:MAX_MOUNTS]:
        labels = {"mount": mount["mount"]}
        put("disk.used_pct", mount.get("used_pct"), labels)
        put("disk.inode_pct", mount.get("inode_pct"), labels)
    temps = [
        s
        for s in system.get("sensors", [])
        if s.get("kind") == "temp" and "name" in s and "value" in s
    ]
    for sensor in temps[:MAX_TEMPS]:
        put("temp.c", sensor["value"], {"sensor": sensor["name"]})
    put("time.offset_ms", system.get("time", {}).get("offset_ms"))

    ifaces = [i for i in state.get("net", {}).get("ifaces", []) if "name" in i]
    ifaces = [i for i in ifaces if i.get("rate")][:MAX_IFACES]
    for iface in ifaces:
        rate = iface["rate"]
        for name in ("rx_bps", "tx_bps", "err_ps", "drop_ps"):
            put(f"net.{name}", rate.get(name), {"if": iface["name"]})

    items = [i for i in state.get("containers", {}).get("items", []) if "kind" in i]
    running = [i for i in items if i.get("state") == "running" and "name" in i]
    for item in running[:MAX_CONTAINERS]:
        labels = {"kind": item["kind"], "name": item["name"]}
        put("ctr.cpu_pct", item.get("cpu_pct"), labels)
        put("ctr.mem_bytes", item.get("mem_used"), labels)
    counts: dict[str, list[int]] = {}
    for item in items:
        count = counts.setdefault(item["kind"], [0, 0])
        count[0] += 1
        count[1] += item.get("state") == "running"
    for kind in sorted(counts):
        put("vm.total", counts[kind][0], {"kind": kind})
        put("vm.running", counts[kind][1], {"kind": kind})
    return out


def _agent_ts(state: dict) -> Optional[dt.datetime]:
    ts = state.get("ts")
    if ts is None:
        return None
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _mb(perf: dict) -> tuple[Optional[int], Optional[int]]:
    total, used = perf.get("mem_total"), perf.get("mem_used")
    # the columns hold megabytes in a 32-bit integer
    if total is None or used is None or not MB <= total < 2**31 * MB:
        return None, None
    return total // MB, min(used, total) // MB


def ingest(agent, state: dict) -> Optional[Sample]:
    """Stores a cleaned state; returns the new sample, None within SAMPLE_GAP."""
    now = djangotime.now()
    with transaction.atomic():
        # the state row stays locked to the end, so a second push of the
        # agent waits and then sees this sample (the first insert of the row
        # is retried by update_or_create)
        AgentState.objects.update_or_create(
            agent=agent,
            defaults={"received": now, "agent_ts": _agent_ts(state), "data": state},
        )
        recent = now - dt.timedelta(seconds=SAMPLE_GAP)
        if Sample.objects.filter(agent=agent, ts__gt=recent).exists():
            return None

        perf = state.get("perf", {})
        mem_total, mem_used = _mb(perf)
        sample = Sample.objects.create(
            agent=agent,
            ts=now,
            cpu=perf.get("cpu_pct"),
            mem_total=mem_total,
            mem_used=mem_used,
            disks=disk_usage(agent.disks),
            values=series(state),
        )
    evaluate_metric_checks(agent, sample)
    return sample


MAX_SAMPLES = 60
# pushes come every few minutes with jitter, a run interval should not skip one
DUE_SLACK = 30


def _matches(check, name: str, labels: dict) -> bool:
    if name != check.metric:
        return False
    wanted = check.metric_labels if isinstance(check.metric_labels, dict) else {}
    for key, value in wanted.items():
        if value != "*" and labels.get(key) != label_value(value):
            return False
    return True


def metric_value(check, rows: list[dict]) -> tuple[Optional[float], int]:
    """(average, samples) of the worst matching series. rows are Sample.values,
    newest first; a series missing from the newest row is not reported."""
    if not rows:
        return None, 0
    worst, count = None, 0
    want = max(1, min(check.metric_samples or 1, MAX_SAMPLES))
    for key in rows[0]:
        if not _matches(check, *parse_key(key)):
            continue
        values = [row[key] for row in rows if key in row][:want]
        average = sum(values) / len(values)
        if (
            worst is None
            or (check.metric_op == MetricOp.BELOW and average < worst)
            or (check.metric_op != MetricOp.BELOW and average > worst)
        ):
            worst, count = average, len(values)
    return worst, count


def _due(check, now) -> bool:
    result = check.check_result
    last_run = getattr(result, "last_run", None)
    if not check.run_interval or not last_run:
        return True
    return last_run <= now - dt.timedelta(seconds=check.run_interval - DUE_SLACK)


def evaluate_metric_checks(agent, sample: Sample) -> None:
    from checks.models import Check, apply_result

    if not Check.objects.filter(check_type=CheckType.METRIC).exists():
        return
    now = djangotime.now()
    checks = [
        check
        for check in agent.get_checks_with_policies(exclude_overridden=True)
        if check.check_type == CheckType.METRIC and _due(check, now)
    ]
    if not checks:
        return

    older = (
        Sample.objects.filter(agent=agent, ts__lt=sample.ts)
        .exclude(values={})
        .order_by("-ts")
        .values_list("values", flat=True)
    )
    rows = [sample.values, *older[: MAX_SAMPLES - 1]]
    for check in checks:
        value, count = metric_value(check, rows)
        apply_result(check, agent, {"value": value, "samples": count})

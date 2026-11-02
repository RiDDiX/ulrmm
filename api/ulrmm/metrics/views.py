# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json

from django.db.models import Avg, Count, F, Max
from django.db.models.fields.json import KeyTextTransform
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response

from agents.models import Agent
from agents.permissions import AgentPerms
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm, _has_perm_on_agent_or_hidden

from .models import AgentState, Sample
from .state import SERIES, parse_key, series_key

# range: (seconds, bucket seconds), at most 300 buckets each
RANGES = {
    "1h": (3600, 300),
    "6h": (6 * 3600, 300),
    "24h": (24 * 3600, 300),
    "7d": (7 * 86400, 3600),
    "30d": (30 * 86400, 3 * 3600),
}


def _avg(values: list) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def downsample(rows, step: int) -> list[dict]:
    """Bucket averages, one pass.

    Rows are (ts, cpu, mem_used, mem_total, disks), sorted by ts.
    """
    buckets: dict[int, tuple] = {}
    for ts, cpu, used, total, disks in rows:
        key = int(ts.timestamp()) // step * step
        b_cpu, b_mem, b_used, b_total, b_disks = buckets.setdefault(
            key, ([], [], [], [], {})
        )
        if cpu is not None:
            b_cpu.append(cpu)
        if used is not None and total:
            b_mem.append(used * 100 / total)
            b_used.append(used)
            b_total.append(total)
        for mount, percent in disks.items():
            b_disks.setdefault(mount, []).append(percent)

    return [
        {
            "ts": dt.datetime.fromtimestamp(key, dt.timezone.utc).isoformat(),
            "cpu": _avg(b_cpu),
            "mem_percent": _avg(b_mem),
            "mem_used": round(sum(b_used) / len(b_used)) if b_used else None,
            "mem_total": round(sum(b_total) / len(b_total)) if b_total else None,
            "disks": {mount: _avg(values) for mount, values in b_disks.items()},
        }
        for key, (b_cpu, b_mem, b_used, b_total, b_disks) in buckets.items()
    ]


def _since(seconds: int) -> dt.datetime:
    return djangotime.now() - dt.timedelta(seconds=seconds)


class AgentMetricsPerms(BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_list_agents") and _has_perm_on_agent_or_hidden(
            r.user, view.kwargs["agent_id"]
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentMetricsPerms])
def agent_metrics(request, agent_id):
    agent = get_object_or_404(Agent.objects.only("pk"), agent_id=agent_id)
    name = request.query_params.get("range", "24h")
    if name not in RANGES:
        return notify_error(f"range must be one of {', '.join(RANGES)}")

    seconds, step = RANGES[name]
    rows = list(
        Sample.objects.filter(agent=agent, ts__gte=_since(seconds))
        .order_by("ts")
        .values_list("ts", "cpu", "mem_used", "mem_total", "disks")
    )
    cpu = [row[1] for row in rows if row[1] is not None]
    mem = [row[2] * 100 / row[3] for row in rows if row[2] is not None and row[3]]
    return Response(
        {
            "range": name,
            "step_seconds": step,
            "points": downsample(rows, step),
            "summary": {
                "cpu_avg": _avg(cpu),
                "cpu_max": max(cpu, default=None),
                "mem_avg": _avg(mem),
                "mem_max": round(max(mem), 1) if mem else None,
                "samples": len(rows),
            },
        }
    )


# older than this the overview marks the state as stale
STATE_STALE = 20 * 60
STATE_SECTIONS = ("perf", "system", "net", "containers")


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentMetricsPerms])
def agent_state(request, agent_id):
    agent = get_object_or_404(Agent.objects.only("pk"), agent_id=agent_id)
    state = AgentState.objects.filter(agent=agent).first()
    if state is None:
        return Response(status=204)
    data = state.data if isinstance(state.data, dict) else {}
    return Response(
        {
            "received": state.received.isoformat(),
            "agent_ts": state.agent_ts.isoformat() if state.agent_ts else None,
            "stale": state.received < _since(STATE_STALE),
            **{key: data[key] for key in STATE_SECTIONS if key in data},
        }
    )


def _labels(text: str) -> dict | None:
    try:
        labels = json.loads(text) if text else {}
    except ValueError:
        return None
    if not isinstance(labels, dict):
        return None
    if not all(isinstance(v, str) and v and v != "*" for v in labels.values()):
        return None
    return labels


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentMetricsPerms])
def agent_series(request, agent_id):
    agent = get_object_or_404(Agent.objects.only("pk"), agent_id=agent_id)
    samples = Sample.objects.filter(agent=agent).exclude(values={})
    name = request.query_params.get("name")
    if not name:
        newest = samples.order_by("-ts").values_list("values", flat=True).first()
        catalog = []
        for key in sorted(newest or {}):
            series, labels = parse_key(key)
            catalog.append({"key": key, "name": series, "labels": labels})
        return Response({"series": catalog})

    range_name = request.query_params.get("range", "24h")
    if name not in SERIES or range_name not in RANGES:
        return notify_error("unknown metric or range")
    labels = _labels(request.query_params.get("labels", ""))
    if labels is None or set(labels) != set(SERIES[name]):
        return notify_error("labels do not fit the metric")

    key = series_key(name, labels)
    seconds, step = RANGES[range_name]
    rows = (
        samples.filter(ts__gte=_since(seconds))
        .annotate(value=KeyTextTransform(key, "values"))
        .exclude(value=None)
        .order_by("ts")
        .values_list("ts", "value")
    )
    buckets: dict[int, list[float]] = {}
    for ts, value in rows:
        try:
            number = float(value)
        except ValueError:
            continue
        buckets.setdefault(int(ts.timestamp()) // step * step, []).append(number)
    return Response(
        {
            "key": key,
            "range": range_name,
            "step_seconds": step,
            "points": [
                {
                    "ts": dt.datetime.fromtimestamp(
                        bucket, dt.timezone.utc
                    ).isoformat(),
                    "avg": round(sum(values) / len(values), 3),
                    "max": round(max(values), 3),
                }
                for bucket, values in buckets.items()
            ],
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentPerms])
def fleet(request):
    name = request.query_params.get("range", "24h")
    metric = request.query_params.get("metric", "cpu")
    try:
        limit = min(max(int(request.query_params.get("limit", 10)), 1), 50)
    except ValueError:
        return notify_error("limit must be a number")
    if name not in RANGES or metric not in ("cpu", "mem"):
        return notify_error("unknown range or metric")

    if metric == "cpu":
        value, present = F("cpu"), {"cpu__isnull": False}
    else:
        value, present = F("mem_used") * 100.0 / F("mem_total"), {"mem_total__gt": 0}

    rows = (
        Sample.objects.filter(
            ts__gte=_since(RANGES[name][0]),
            agent__in=Agent.objects.filter_by_role(request.user),  # type: ignore
            **present,
        )
        .values(
            "agent__agent_id",
            "agent__hostname",
            "agent__display_name",
            "agent__site__name",
            "agent__site__client__name",
        )
        .annotate(avg=Avg(value), max=Max(value), samples=Count("pk"))
        .order_by("-avg", "agent__hostname")[:limit]
    )
    return Response(
        {
            "range": name,
            "metric": metric,
            "agents": [
                {
                    "agent_id": row["agent__agent_id"],
                    "hostname": row["agent__hostname"],
                    "display_name": row["agent__display_name"],
                    "client": row["agent__site__client__name"],
                    "site": row["agent__site__name"],
                    "avg": round(row["avg"], 1),
                    "max": round(row["max"], 1),
                    "samples": row["samples"],
                }
                for row in rows
            ],
        }
    )

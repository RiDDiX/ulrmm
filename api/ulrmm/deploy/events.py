# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Security events: refused certificates and connections, pin and update
problems agents report. Repeats of one event are counted, not stored again."""

import datetime as dt
import hashlib
import ipaddress
import logging
import re

from django.core.cache import cache
from django.db.models import F
from django.utils import timezone as djangotime

from .models import SecurityEvent, SecurityEventKind, SecurityEventSeverity

logger = logging.getLogger("ulrmm")

MERGE_WINDOW = dt.timedelta(minutes=10)
WRITE_EVERY = 10
MAX_DETAIL = 500
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value))) if value else None
    except ValueError:
        return None


def clean_detail(value) -> str:
    return " ".join(_CTRL.sub(" ", str(value or "")).split())[:MAX_DETAIL]


def record(kind, severity, *, agent=None, agent_id="", ip=None, detail="") -> None:
    """Stores the event or counts it on the same one of the last 10 minutes.
    Never raises; at most one write per event every 10 seconds."""
    try:
        if kind not in SecurityEventKind.values:
            raise ValueError(f"unknown kind {kind}")
        if severity not in SecurityEventSeverity.values:
            raise ValueError(f"unknown severity {severity}")
        if agent is not None and not agent_id:
            agent_id = agent.agent_id
        agent_id = str(agent_id or "")[:255]
        ip = _ip(ip)
        detail = clean_detail(detail)
        key = (
            "secevent:"
            + hashlib.sha256(
                "\0".join((kind, agent_id, ip or "", detail)).encode()
            ).hexdigest()
        )
        if not cache.add(key, 1, WRITE_EVERY):
            return
        now = djangotime.now()
        same = SecurityEvent.objects.filter(
            kind=kind,
            agent_uid=agent_id,
            source_ip=ip,
            detail=detail,
            last_seen__gte=now - MERGE_WINDOW,
        )
        pk = same.order_by("-pk").values_list("pk", flat=True).first()
        if pk is not None:
            SecurityEvent.objects.filter(pk=pk).update(
                count=F("count") + 1, last_seen=now
            )
            return
        SecurityEvent.objects.create(
            kind=kind,
            severity=severity,
            agent=agent,
            agent_uid=agent_id,
            source_ip=ip,
            detail=detail,
            first_seen=now,
            last_seen=now,
        )
    except Exception as e:
        logger.warning(f"security event {kind} not recorded: {type(e).__name__}")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Takes the other RMM's agent off a device that runs ours.

The other server's removal sends the uninstall without waiting and deletes
its row at once; a device that is offline there keeps the old agent for
good. So the removal is sent only when the device is linked here, has
checked in here since the installer was sent (or, installed by hand, since
the request) and is online here, the other
server shows it online, and both sides show the same machine. Until then it
waits and remove_task tries again, for REMOVE_DAYS at most. A row is claimed
(state "sending") before the call, and the time of the call is kept. The
documented answer marks it removed; so does the other side no longer
listing a device a call was tried for, whose answer got lost."""

import datetime as dt
import ipaddress
import re

from django.db import transaction
from django.db.models import TextField
from django.db.models.functions import Cast, Lower, Trim
from django.utils import timezone as djangotime

from agents.models import Agent
from logs.models import AuditLog, DebugLog
from ulrmm.constants import (
    AGENT_STATUS_ONLINE,
    AgentPlat,
    AuditActionType,
    AuditObjType,
)

from .link import short
from .models import ImportedDevice, RemoveState
from .sources import SourceError
from .sources.base import NotFound

REMOVE_DAYS = 7
# the old uninstaller takes the remote-control agent along on Windows
RECOVERY_DELAY = 300
# a claim this old belongs to a worker that stopped
STALE_CLAIM = dt.timedelta(hours=1)
WAITING = (RemoveState.WAITING_HERE, RemoveState.WAITING_THERE)
# serials with JSON escapes would slip past the text search in _serial_unique
SERIAL_RE = re.compile(r"[A-Za-z0-9 ._:/-]+")
# what firmware reports when nobody set a serial number
FILLER_SERIALS = {
    "to be filled by o.e.m.",
    "default string",
    "system serial number",
    "chassis serial number",
    "serial number",
    "none",
    "not specified",
    "not applicable",
    "not available",
    "n/a",
    "na",
    "unknown",
    "invalid",
    "oem",
    "empty",
    "0123456789",
    "123456789",
}
GONE = "the other server no longer lists the device"


def _audit(username: str, message: str, **after) -> None:
    AuditLog.objects.create(
        username=username,
        object_type=AuditObjType.AGENT,
        action=AuditActionType.DELETE,
        message=message[:255],
        after_value=after,
    )


def request(source, ids, username: str) -> int:
    """Asks for the removal on the chosen devices. A device whose old agent
    was removed, or whose removal is being sent, is left alone."""
    now = djangotime.now()
    with transaction.atomic():
        rows = list(
            ImportedDevice.objects.select_for_update()
            .filter(source=source, pk__in=ids)
            .exclude(remove_state__in=(RemoveState.REMOVED, RemoveState.SENDING))
            .values_list("pk", "hostname")
        )
        ImportedDevice.objects.filter(pk__in=[pk for pk, _ in rows]).update(
            remove_requested_at=now,
            remove_state=RemoveState.WAITING_HERE,
            remove_at=now,
            remove_reason="",
            recovery="",
        )
        if rows:
            _audit(
                username,
                f"{username} asked to remove the old agent from {len(rows)} "
                f"devices of {source.name}",
                source=source.name,
                devices=[h for _, h in rows],
            )
    return len(rows)


def withdraw(source, ids, username: str) -> int:
    """Withdraws the removal where it was not sent yet."""
    now = djangotime.now()
    with transaction.atomic():
        rows = list(
            ImportedDevice.objects.select_for_update()
            .filter(source=source, pk__in=ids, remove_state__in=WAITING)
            .values_list("pk", "hostname")
        )
        ImportedDevice.objects.filter(pk__in=[pk for pk, _ in rows]).update(
            remove_requested_at=None,
            remove_state=RemoveState.NONE,
            remove_at=now,
            remove_reason=f"withdrawn by {username}"[:500],
        )
        if rows:
            _audit(
                username,
                f"{username} withdrew the removal of the old agent from "
                f"{len(rows)} devices of {source.name}",
                source=source.name,
                devices=[h for _, h in rows],
            )
    return len(rows)


def _claim(device, now) -> bool:
    return bool(
        ImportedDevice.objects.filter(
            pk=device.pk, remove_state__in=WAITING, remove_requested_at__isnull=False
        ).update(remove_state=RemoveState.SENDING, remove_at=now)
    )


def _release(device, state: str, reason: str, now, **fields) -> None:
    ImportedDevice.objects.filter(
        pk=device.pk, remove_state=RemoveState.SENDING
    ).update(remove_state=state, remove_reason=reason[:500], remove_at=now, **fields)


def _here(device, agent) -> str:
    if agent is None:
        return "not linked to an agent here yet"
    # an agent installed by hand and linked by name: the request is the mark
    since = device.sent_at or device.remove_requested_at
    if not agent.last_seen or agent.last_seen <= since:
        if device.sent_at:
            return "no check-in here since the installer was sent"
        return "no check-in here since the removal was requested"
    if agent.status != AGENT_STATUS_ONLINE:
        return "offline here"
    return ""


def _ipv4(text) -> set:
    """Local IPv4 addresses of an agent's local_ips text ("a, b/24, ...")."""
    found = set()
    for part in str(text or "").split(","):
        try:
            ip = ipaddress.ip_address(part.strip().split("/")[0])
        except ValueError:
            continue
        if ip.version == 4 and not (ip.is_loopback or ip.is_link_local):
            found.add(ip)
    return found


def _serial(agent) -> str:
    return str(agent.serial_number or "").strip().lower()


def _filler(serial: str) -> bool:
    return len(serial) < 5 or len(set(serial)) == 1 or serial in FILLER_SERIALS


def _serial_unique(serial: str, agent, device) -> bool:
    """No other agent here and no other device of the source has it."""
    if not SERIAL_RE.fullmatch(serial):
        return False
    # the text search narrows down, the agent's own reading decides
    others = (
        Agent.objects.exclude(pk=agent.pk)
        .annotate(raw=Cast("wmi_detail", TextField()))
        .filter(raw__icontains=serial)
        .only("pk", "plat", "wmi_detail")
    )
    if any(_serial(a) == serial for a in others):
        return False
    return not (
        ImportedDevice.objects.filter(source_id=device.source_id)
        .exclude(pk=device.pk)
        .annotate(s=Lower(Trim("serial")))
        .filter(s=serial)
        .exists()
    )


def same_machine(detail: dict, agent, device) -> str:
    """Why the other server's device is not proven to be the agent here."""
    if short(str(detail.get("hostname") or "")) != short(agent.hostname):
        return "the host names differ on both sides"
    if detail.get("plat") != agent.plat:
        return "the platforms differ on both sides"
    wmi = detail.get("wmi_detail")
    theirs = Agent(plat=agent.plat, wmi_detail=wmi if isinstance(wmi, dict) else {})
    serial = _serial(theirs)
    if (
        not _filler(serial)
        and serial == _serial(agent)
        and _serial_unique(serial, agent, device)
    ):
        return ""
    # bridge addresses repeat on many hosts behind one public address, so one
    # common address proves nothing; all of them have to match
    public = str(detail.get("public_ip") or "").strip()
    local = _ipv4(agent.local_ips)
    if (
        public
        and public == str(agent.public_ip or "").strip()
        and local
        and local == _ipv4(detail.get("local_ips"))
    ):
        return ""
    return (
        "not proven to be the same machine: no serial number only this machine "
        "has, and the public address and the local IPv4 addresses are not the "
        "same on both sides"
    )


def step(device, client) -> str:
    """One try for one device; returns the state it is left in."""
    now = djangotime.now()
    if device.remove_requested_at is None:
        return ""
    expired = device.remove_requested_at < now - dt.timedelta(days=REMOVE_DAYS)
    if expired and device.remove_tried_at is None:
        ImportedDevice.objects.filter(pk=device.pk, remove_state__in=WAITING).update(
            remove_state=RemoveState.NOT_REMOVED,
            remove_reason=(
                device.remove_reason or f"not removed within {REMOVE_DAYS} days"
            ),
            remove_at=now,
        )
        return RemoveState.NOT_REMOVED
    if not _claim(device, now):
        # withdrawn, or another worker has it
        return ""
    try:
        return _send(device, client, now, expired)
    except Exception as e:
        DebugLog.error(message=f"removal of the old agent on {device}: {e!r}"[:1000])
        why = f"unexpected error: {type(e).__name__}"
        _release(device, RemoveState.WAITING_THERE, why, now)
        return RemoveState.WAITING_THERE


def _removed(device, agent, now, reason: str = "") -> str:
    plat = agent.plat if agent else device.plat
    windows = plat == AgentPlat.WINDOWS
    _release(
        device,
        RemoveState.REMOVED,
        reason,
        now,
        recovery="pending" if windows else "",
    )
    if windows:
        from .tasks import recover_task

        try:
            recover_task.apply_async((device.pk,), countdown=RECOVERY_DELAY)
        except Exception as e:
            ImportedDevice.objects.filter(pk=device.pk).update(
                recovery=f"failed: not scheduled ({type(e).__name__})"
            )
    return RemoveState.REMOVED


def _send(device, client, now, expired: bool) -> str:
    agent = (
        Agent.objects.filter(pk=device.agent_id).first() if device.agent_id else None
    )
    tried = device.remove_tried_at is not None
    here = _here(device, agent)
    if here and not tried:
        _release(device, RemoveState.WAITING_HERE, here, now)
        return RemoveState.WAITING_HERE

    def wait(why: str) -> str:
        if expired:
            why = device.remove_reason or why
            _release(device, RemoveState.NOT_REMOVED, why, now)
            return RemoveState.NOT_REMOVED
        _release(device, RemoveState.WAITING_THERE, why, now)
        return RemoveState.WAITING_THERE

    # a call that was tried may have taken effect, so the other side is asked
    # first: a device it no longer lists lost the old agent
    try:
        detail = client.device(device.ref)
    except NotFound:
        if tried:
            return _removed(device, agent, now, f"{GONE}, its answer was lost")
        _release(device, RemoveState.NOT_REMOVED, GONE, now)
        return RemoveState.NOT_REMOVED
    except SourceError as e:
        return wait(str(e))
    if expired:
        return wait(f"not removed within {REMOVE_DAYS} days")
    if here:
        _release(device, RemoveState.WAITING_HERE, here, now)
        return RemoveState.WAITING_HERE
    if detail.get("status") != "online":
        return wait("offline on the other server")
    if why := same_machine(detail, agent, device):
        return wait(why)

    ImportedDevice.objects.filter(pk=device.pk).update(remove_tried_at=now)
    try:
        client.remove(device.ref, str(detail.get("hostname")))
    except SourceError as e:
        error = str(e)
    except Exception as e:
        error = f"unexpected error: {type(e).__name__}"
    else:
        error = ""
    _audit(
        "importer",
        f"importer sent the removal of the old agent to {device.hostname}"
        + (f": {error}" if error else ""),
        source=device.source.name,
        device=device.hostname,
        agent_id=agent.agent_id,
        confirmed=not error,
    )
    if error:
        return wait(error)
    return _removed(device, agent, now)


def end_stale_claims() -> int:
    """A worker that stopped during a removal leaves its claim behind. The
    next round asks the other side first: a device it no longer lists was
    removed, one it still lists never got the call."""
    return ImportedDevice.objects.filter(
        remove_state=RemoveState.SENDING,
        remove_at__lt=djangotime.now() - STALE_CLAIM,
    ).update(
        remove_state=RemoveState.WAITING_THERE,
        remove_reason="the removal was interrupted",
    )


def recover(device) -> str:
    """The existing remote-control recovery for the linked agent."""
    if device.agent is None:
        return "no agent is linked here"
    try:
        message, failed = device.agent.recover("mesh", "")
    except Exception as e:
        return f"failed: {type(e).__name__}"
    return f"failed: {message}" if failed else "ok"

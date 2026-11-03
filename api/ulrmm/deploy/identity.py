# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Agent identities (Ed25519 identity key, X25519 sealing key, NATS nkey):
registration, rotation and the emergency actions on them."""

import base64
import binascii
import datetime as dt
import hashlib
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone as djangotime

from . import events, pki
from .models import (
    AgentCredential,
    AgentIdentity,
    IdentityState,
    MtlsMode,
    SecurityEventKind,
    SecurityEventSeverity,
)
from .tokens import b64, clock_refused, ed_ok, now_ms, ts_of

logger = logging.getLogger("ulrmm")

IDREG_MSG = b"ulrmm-idreg-v1\0"
IDROT_MSG = b"ulrmm-idrot-v1\0"
PREV_KEY_TIME = dt.timedelta(minutes=10)
RELEASE_TIME = dt.timedelta(hours=24)
MAX_CAPS = 8
MAX_CAP = 16
ROTATABLE = ("session", "cert", "token", "identity")
CONFLICT = {"detail": "identity already registered"}


def nkey_public(text: str) -> bytes:
    """The Ed25519 public key of a NATS user nkey ("U..."); ValueError."""
    if not isinstance(text, str) or len(text) != 56 or text[0] != "U":
        raise ValueError("nkey invalid")
    try:
        raw = base64.b32decode(text)
    except (binascii.Error, ValueError):
        raise ValueError("nkey invalid")
    # nkeys PrefixByteUser (20 << 3), CRC16/XMODEM little endian
    if raw[0] != 0xA0:
        raise ValueError("nkey invalid")
    if binascii.crc_hqx(raw[:33], 0) != int.from_bytes(raw[33:], "little"):
        raise ValueError("nkey invalid")
    return raw[1:33]


def kid_of(ed_raw: bytes) -> str:
    return hashlib.sha256(ed_raw).hexdigest()[:16]


def _keys_message(prefix, agent_id, ed_raw, x_raw, nkey, ts) -> bytes:
    return (
        prefix
        + agent_id.encode()
        + b"\0"
        + ed_raw
        + x_raw
        + nkey.encode()
        + ts.to_bytes(8, "big")
    )


def registration_message(agent_id, ed_raw, x_raw, nkey, ts) -> bytes:
    return _keys_message(IDREG_MSG, agent_id, ed_raw, x_raw, nkey, ts)


def rotation_message(agent_id, ed_raw, x_raw, nkey, ts) -> bytes:
    return _keys_message(IDROT_MSG, agent_id, ed_raw, x_raw, nkey, ts)


def _parse(data: dict):
    """(fields, None) or (None, the 400 body)."""

    def bad(name):
        return None, {"detail": f"{name} invalid"}

    ed_raw, x_raw = b64(data.get("ed25519"), 32), b64(data.get("x25519"), 32)
    if ed_raw is None:
        return bad("ed25519")
    if x_raw is None or x_raw == bytes(32):
        return bad("x25519")
    nkey = data.get("nkey")
    try:
        nkey_raw = nkey_public(nkey)
    except ValueError:
        return bad("nkey")
    ts = ts_of(data.get("ts"))
    if ts is None:
        return bad("ts")
    sig, nsig = b64(data.get("sig"), 64), b64(data.get("nsig"), 64)
    if sig is None:
        return bad("sig")
    if nsig is None:
        return bad("nsig")
    caps = data.get("caps", [])
    if (
        not isinstance(caps, list)
        or len(caps) > MAX_CAPS
        or not all(isinstance(c, str) and 0 < len(c) <= MAX_CAP for c in caps)
    ):
        return bad("caps")
    idreg = data.get("idreg", "")
    idreg_raw = b""
    if idreg != "":
        idreg_raw = b64(idreg, 64)
        if idreg_raw is None:
            return bad("idreg")
    return {
        "ed_raw": ed_raw,
        "x_raw": x_raw,
        "nkey": nkey,
        "nkey_raw": nkey_raw,
        "ts": ts,
        "sig": sig,
        "nsig": nsig,
        "caps": list(caps),
        "idreg": idreg_raw,
    }, None


def _verify_nkey(nkey_raw: bytes, sig: bytes, message: bytes) -> bool:
    return ed_ok(base64.b64encode(nkey_raw).decode(), sig, message)


def _cert_refused(agent, request) -> bool:
    if pki.mtls_mode() == MtlsMode.OFF:
        return False
    seen = pki.active_certs().filter(agent=agent).exclude(last_seen=None)
    if not seen.exists():
        return False
    fingerprint = pki.presented(request)
    return not (fingerprint and seen.filter(fingerprint_sha1=fingerprint).exists())


def _forget(agent_id: str) -> None:
    from . import envelope

    envelope.forget(agent_id)


def _changed(agent_id: str) -> None:
    """After the commit: drop cached sessions, render NATS again."""
    from ulrmm.utils import reload_nats

    def run():
        try:
            _forget(agent_id)
        except Exception as e:
            logger.warning(f"envelope forget {agent_id}: {type(e).__name__}")
        reload_nats()

    transaction.on_commit(run)


def answer(ident, pin_seq: int) -> dict:
    return {
        "kid": ident.kid,
        "state": ident.state,
        "sec2": pki.security_settings().sec2_mode,
        "pin_seq": pin_seq,
        "rotate": list(ident.rotate_pending),
        "now_ms": now_ms(),
    }


def _pin_seq() -> int:
    from . import signing

    try:
        return signing.current_pinset().seq
    except Exception:
        return 0


def _apply_keys(ident, fields, now) -> None:
    ident.ed25519 = base64.b64encode(fields["ed_raw"]).decode()
    ident.x25519 = base64.b64encode(fields["x_raw"]).decode()
    ident.nkey = fields["nkey"]
    ident.kid = kid_of(fields["ed_raw"])
    ident.caps = fields["caps"]


def _decide(agent, fields, now):
    """(status, body, event kind or None, old kid) inside the transaction."""
    ident = AgentIdentity.objects.select_for_update().filter(agent=agent).first()
    new_kid = kid_of(fields["ed_raw"])
    if ident is not None and ident.state == IdentityState.BLOCKED:
        return 403, {"detail": "blocked"}, None, ""
    if ident is None:
        ident = AgentIdentity(agent=agent, registered_at=now)
        _apply_keys(ident, fields, now)
        ident.save()
        return 201, ident, SecurityEventKind.IDENTITY_REGISTERED, ""
    ed_b64 = base64.b64encode(fields["ed_raw"]).decode()
    x_b64 = base64.b64encode(fields["x_raw"]).decode()
    if (ident.ed25519, ident.x25519, ident.nkey) == (ed_b64, x_b64, fields["nkey"]):
        if ident.state == IdentityState.QUARANTINED:
            return 403, {"detail": "quarantined"}, None, ""
        ident.caps = fields["caps"]
        ident.save(update_fields=["caps"])
        return 200, ident, None, ""
    old_kid = ident.kid
    if fields["idreg"]:
        message = rotation_message(
            agent.agent_id,
            fields["ed_raw"],
            fields["x_raw"],
            fields["nkey"],
            fields["ts"],
        )
        if ident.state == IdentityState.ACTIVE and ed_ok(
            ident.ed25519, fields["idreg"], message
        ):
            ident.prev_ed25519, ident.prev_until = ident.ed25519, now + PREV_KEY_TIME
            _apply_keys(ident, fields, now)
            ident.rotated_at = now
            ident.rotate_pending = [r for r in ident.rotate_pending if r != "identity"]
            ident.save()
            return 200, ident, SecurityEventKind.IDENTITY_ROTATED, old_kid
    elif (
        ident.state == IdentityState.QUARANTINED
        and ident.release_until
        and ident.release_until > now
    ):
        # reset identity: new keys, no link to the old ones. release_until
        # stays so the following identity grant works without a token.
        _apply_keys(ident, fields, now)
        ident.prev_ed25519, ident.prev_until = "", None
        ident.state = IdentityState.ACTIVE
        ident.quarantined_at, ident.reason = None, ""
        ident.registered_at, ident.rotated_at = now, None
        ident.save()
        return 201, ident, SecurityEventKind.IDENTITY_REGISTERED, old_kid
    return 409, CONFLICT, SecurityEventKind.IDENTITY_CONFLICT, old_kid or new_kid


def register(agent, data: dict, request) -> tuple[int, dict]:
    """POST /api/v3/<agentid>/identity/ (contract T3.1)."""
    from ulrmm.helpers import get_client_ip
    from logs.models import DebugLog

    if not hasattr(data, "get"):
        return 400, {"detail": "body invalid"}
    fields, bad = _parse(data)
    if bad:
        return 400, bad
    if refused := clock_refused(fields["ts"]):
        return refused
    message = registration_message(
        agent.agent_id, fields["ed_raw"], fields["x_raw"], fields["nkey"], fields["ts"]
    )
    if not ed_ok(
        base64.b64encode(fields["ed_raw"]).decode(), fields["sig"], message
    ) or not _verify_nkey(fields["nkey_raw"], fields["nsig"], message):
        return 400, {"detail": "signature"}
    ip = get_client_ip(request.META)
    if _cert_refused(agent, request):
        events.record(
            SecurityEventKind.CERT_REFUSED,
            SecurityEventSeverity.WARNING,
            agent=agent,
            ip=ip,
            detail="identity registration without the current client certificate",
        )
        return 403, {"detail": "identity needs the current client certificate"}
    now = djangotime.now()
    new_kid = kid_of(fields["ed_raw"])
    try:
        with transaction.atomic():
            status, result, kind, old_kid = _decide(agent, fields, now)
            if isinstance(result, AgentIdentity) and kind is not None:
                AgentCredential.objects.filter(agent=agent).update(legacy_nats="")
                _changed(agent.agent_id)
    except IntegrityError:
        events.record(
            SecurityEventKind.IDENTITY_CONFLICT,
            SecurityEventSeverity.HIGH,
            agent=agent,
            ip=ip,
            detail=f"nkey of kid {new_kid} belongs to another agent",
        )
        return 409, {"detail": "nkey in use"}
    if kind == SecurityEventKind.IDENTITY_CONFLICT:
        events.record(
            kind,
            SecurityEventSeverity.HIGH,
            agent=agent,
            ip=ip,
            detail=f"kid {old_kid} registered, {new_kid} offered",
        )
    if not isinstance(result, AgentIdentity):
        return status, result
    if kind is not None:
        events.record(
            kind,
            SecurityEventSeverity.INFO,
            agent=agent,
            ip=ip,
            detail=f"kid {old_kid} -> {result.kid}" if old_kid else f"kid {result.kid}",
        )
        DebugLog.info(
            agent=agent,
            message=f"{agent.hostname} registered identity {result.kid}",
        )
    return status, answer(result, _pin_seq())


# emergency actions


def _locked(agent):
    return AgentIdentity.objects.select_for_update().filter(agent=agent).first()


def quarantine(agent, reason: str, *, ip=None) -> AgentIdentity:
    """Identity quarantined (blocked when the agent never registered one),
    credential and certificates revoked, NATS user removed."""
    now = djangotime.now()
    reason = events.clean_detail(reason)[:200]
    with transaction.atomic():
        ident = _locked(agent)
        if ident is None:
            ident = AgentIdentity(
                agent=agent, state=IdentityState.BLOCKED, registered_at=now
            )
        elif ident.state != IdentityState.BLOCKED:
            ident.state = IdentityState.QUARANTINED
        ident.quarantined_at, ident.reason, ident.release_until = now, reason, None
        ident.save()
        AgentCredential.objects.filter(agent=agent, revoked_at=None).update(
            revoked_at=now
        )
        pki.revoke(agent)
        _changed(agent.agent_id)
    events.record(
        SecurityEventKind.QUARANTINED,
        SecurityEventSeverity.HIGH,
        agent=agent,
        ip=ip,
        detail=reason or "quarantined",
    )
    return ident


def release(agent) -> AgentIdentity | None:
    """Same keys active again; the agent fetches new tokens with its
    identity signature inside the release window. None: nothing to release."""
    now = djangotime.now()
    with transaction.atomic():
        ident = _locked(agent)
        if ident is None or ident.state != IdentityState.QUARANTINED or not ident.nkey:
            return None
        ident.state = IdentityState.ACTIVE
        ident.quarantined_at = None
        ident.release_until = now + RELEASE_TIME
        ident.save()
        _changed(agent.agent_id)
    events.record(
        SecurityEventKind.RELEASED,
        SecurityEventSeverity.INFO,
        agent=agent,
        detail=f"kid {ident.kid}",
    )
    return ident


def reset_identity(agent) -> AgentIdentity | None:
    """Stays quarantined; for 24 h the agent may register new keys."""
    now = djangotime.now()
    with transaction.atomic():
        ident = _locked(agent)
        if ident is None or ident.state == IdentityState.BLOCKED:
            return None
        if ident.state == IdentityState.ACTIVE:
            ident.quarantined_at = now
            AgentCredential.objects.filter(agent=agent, revoked_at=None).update(
                revoked_at=now
            )
            pki.revoke(agent)
        ident.state = IdentityState.QUARANTINED
        ident.release_until = now + RELEASE_TIME
        ident.save()
        _changed(agent.agent_id)
    events.record(
        SecurityEventKind.ROTATION_FORCED,
        SecurityEventSeverity.HIGH,
        agent=agent,
        detail=f"identity {ident.kid} reset, new keys within 24 h",
    )
    return ident


def block(agent, reason: str = "") -> AgentIdentity:
    now = djangotime.now()
    with transaction.atomic():
        ident = _locked(agent) or AgentIdentity(agent=agent, registered_at=now)
        ident.state = IdentityState.BLOCKED
        ident.quarantined_at = ident.quarantined_at or now
        ident.reason = events.clean_detail(reason)[:200] or ident.reason
        ident.release_until = None
        ident.save()
        AgentCredential.objects.filter(agent=agent, revoked_at=None).update(
            revoked_at=now
        )
        pki.revoke(agent)
        _changed(agent.agent_id)
    events.record(
        SecurityEventKind.QUARANTINED,
        SecurityEventSeverity.HIGH,
        agent=agent,
        detail=f"blocked: {ident.reason}" if ident.reason else "blocked",
    )
    return ident


def request_rotation(agents, what: list[str]) -> dict:
    """Marks agents for rotation; "session" drops the E2E sessions now, the
    rest the agents do at their next heartbeat."""
    counts = {w: 0 for w in what}
    pending = [w for w in what if w != "session"]
    for agent in agents:
        if "session" in what:
            try:
                _forget(agent.agent_id)
            except Exception as e:
                logger.warning(f"envelope forget {agent.agent_id}: {type(e).__name__}")
            counts["session"] += 1
        if not pending:
            continue
        with transaction.atomic():
            ident = _locked(agent)
            if ident is None or ident.state != IdentityState.ACTIVE:
                continue
            ident.rotate_pending = list(dict.fromkeys(ident.rotate_pending + pending))
            ident.save(update_fields=["rotate_pending"])
        for w in pending:
            counts[w] += 1
    return counts


def done_rotation(ident, item: str) -> None:
    if item in ident.rotate_pending:
        ident.rotate_pending = [r for r in ident.rotate_pending if r != item]
        ident.save(update_fields=["rotate_pending"])

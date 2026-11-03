# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Agent REST tokens: HMAC digests only, a short-lived access token plus a
single-use refresh token per family, and the offline recovery."""

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import secrets
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone as djangotime

from remote.utils import decrypt_secret, encrypt_secret

from . import events
from .models import (
    AgentCredential,
    AgentIdentity,
    CredentialKind,
    IdentityState,
    SecurityEventKind,
    SecurityEventSeverity,
)

LEGACY_NATS_INFO = b"ulrmm legacy nats v1"
RETRY_INFO = b"ulrmm token retry v1"
MAX_PEPPERS = 3
# longer than the agent waits before it retries a lost answer (heartbeat 5 min)
RETRY_SECONDS = 900
# refresh digests of earlier generations kept to spot a clone that fell behind
HISTORY = 16
NONCE_SECONDS = 60
GRANT_MSG = b"ulrmm-grant-v1\0"
REFRESH_MSG = b"ulrmm-refresh-v1\0"
RECOVER_MSG = b"ulrmm-recover-v1\0"
UNKNOWN = (401, {"detail": "unknown token"})


def access_ttl() -> dt.timedelta:
    return getattr(settings, "AGENT_ACCESS_TTL", dt.timedelta(days=7))


def refresh_ttl() -> dt.timedelta:
    return getattr(settings, "AGENT_REFRESH_TTL", dt.timedelta(days=60))


def grace(agent) -> dt.timedelta:
    from .policy import effective

    return dt.timedelta(days=effective(agent)["offline_grace_days"])


def clock_window_ms() -> int:
    return int(getattr(settings, "E2E_CLOCK_WINDOW", 30)) * 1000


def now_ms() -> int:
    return int(djangotime.now().timestamp() * 1000)


def peppers() -> list[bytes]:
    """AGENT_TOKEN_PEPPERS decoded, the current one first, then the key
    derived from SECRET_KEY that digests made before any pepper use."""
    keys = []
    for value in (getattr(settings, "AGENT_TOKEN_PEPPERS", None) or [])[:MAX_PEPPERS]:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise ImproperlyConfigured("AGENT_TOKEN_PEPPERS holds a non-base64 key")
        if len(raw) != 32:
            raise ImproperlyConfigured("every AGENT_TOKEN_PEPPERS key needs 32 bytes")
        keys.append(raw)
    keys.append(
        hashlib.sha256(b"ulrmm token pepper\0" + settings.SECRET_KEY.encode()).digest()
    )
    return keys


def digest(token: str, pepper: bytes | None = None) -> str:
    key = pepper if pepper is not None else peppers()[0]
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def digests(token: str) -> list[str]:
    return [digest(token, key) for key in peppers()]


def create_legacy(agent) -> str:
    """The token of a new install: REST token and NATS password."""
    token = secrets.token_hex(20)
    AgentCredential.objects.create(
        agent=agent,
        kind=CredentialKind.LEGACY,
        access_digest=digest(token),
        legacy_nats=encrypt_secret(token, LEGACY_NATS_INFO),
    )
    return token


def lookup(token: str):
    """The credential whose access token this is, or None."""
    if not token:
        return None
    return (
        AgentCredential.objects.select_related("agent__user", "agent__identity")
        .filter(access_digest__in=digests(token))
        .first()
    )


def legacy_nats_password(cred) -> str:
    """Raises InvalidToken when the field keys no longer open it."""
    return decrypt_secret(cred.legacy_nats, LEGACY_NATS_INFO)


def issue_family(cred, *, now=None, generation: int = 1, ip=None) -> dict:
    """New access and refresh token on the credential (not saved yet)."""
    now = now or djangotime.now()
    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    if cred.family is None or generation == 1:
        cred.family = uuid.uuid4()
    cred.kind = CredentialKind.FAMILY
    cred.access_digest = digest(access)
    cred.access_expires = now + access_ttl()
    cred.access_used_at = None
    cred.refresh_digest = digest(refresh)
    cred.refresh_expires = now + refresh_ttl()
    cred.generation = generation
    cred.legacy_nats = ""
    cred.revoked_at = None
    cred.rotated_ip = ip
    return {
        "access": access,
        "access_expires": cred.access_expires.isoformat(),
        "refresh": refresh,
        "refresh_expires": cred.refresh_expires.isoformat(),
        "now_ms": now_ms(),
    }


# signed requests


def b64(value, size: int | None = None) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if size is None or len(raw) == size else None


def ts_of(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value < 2**63 else None


def clock_refused(ts: int):
    """The 400 answer for a timestamp outside the window, or None."""
    now = now_ms()
    if abs(ts - now) > clock_window_ms():
        return 400, {"detail": "clock", "now_ms": now}
    return None


def ed_ok(public_b64: str, sig: bytes, message: bytes) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        key.verify(sig, message)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def identity_of(agent):
    try:
        return agent.identity
    except AgentIdentity.DoesNotExist:
        return None


def _nonce_key(kind: str, agent_id: str, nonce: bytes) -> str:
    return f"tokch:{kind}:{agent_id}:{hashlib.sha256(nonce).hexdigest()}"


def challenge(kind: str, agent_id: str) -> dict:
    nonce = secrets.token_bytes(32)
    cache.set(_nonce_key(kind, agent_id, nonce), 1, NONCE_SECONDS)
    return {"nonce": base64.b64encode(nonce).decode(), "now_ms": now_ms()}


def _take_nonce(kind: str, agent_id: str, nonce: bytes) -> bool:
    return bool(cache.delete(_nonce_key(kind, agent_id, nonce)))


def _ts_bytes(ts: int) -> bytes:
    return ts.to_bytes(8, "big")


def signed_parts(data: dict):
    """((nonce, ts, sig), None) of a signed body, or (None, the answer)."""
    nonce, ts, sig = b64(data.get("nonce"), 32), ts_of(data.get("ts")), None
    sig = b64(data.get("sig"), 64)
    for name, value in (("nonce", nonce), ("ts", ts), ("sig", sig)):
        if value is None:
            return None, (400, {"detail": f"{name} invalid"})
    return (nonce, ts, sig), clock_refused(ts)


def grant_message(agent_id: str, nonce: bytes, ts: int) -> bytes:
    return GRANT_MSG + agent_id.encode() + b"\0" + nonce + _ts_bytes(ts)


def refresh_message(agent_id: str, token: str, ts: int) -> bytes:
    return (
        REFRESH_MSG
        + agent_id.encode()
        + b"\0"
        + hashlib.sha256(token.encode()).digest()
        + _ts_bytes(ts)
    )


def recover_message(agent_id: str, nonce: bytes, ts: int, csr: str) -> bytes:
    return (
        RECOVER_MSG
        + agent_id.encode()
        + b"\0"
        + nonce
        + _ts_bytes(ts)
        + hashlib.sha256(csr.encode()).digest()
    )


def grant(agent, data: dict, *, released: bool = False, ip=None):
    """Identity grant: a legacy token (or, inside the release window, the
    identity signature alone) is exchanged for a new token family."""
    from ulrmm.utils import reload_nats

    parsed, refused = signed_parts(data)
    if refused:
        return refused
    nonce, ts, sig = parsed
    if not _take_nonce("grant", agent.agent_id, nonce):
        return 400, {"detail": "nonce invalid"}
    with transaction.atomic():
        ident = AgentIdentity.objects.select_for_update().filter(agent=agent).first()
        if ident is None or ident.state != IdentityState.ACTIVE or not ident.ed25519:
            return 403, {"detail": "identity not active"}
        if released and not (
            ident.release_until and ident.release_until > djangotime.now()
        ):
            return 401, {"detail": "token required"}
        if not ed_ok(ident.ed25519, sig, grant_message(agent.agent_id, nonce, ts)):
            return 400, {"detail": "signature"}
        cred = AgentCredential.objects.select_for_update().filter(
            agent=agent
        ).first() or AgentCredential(agent=agent)
        # a family moves on only by refresh, where a copy shows up as reuse
        taken = not released and cred.kind == CredentialKind.FAMILY
        if not taken:
            body = issue_family(cred, generation=1, ip=ip)
            cred.prev_refresh_digest, cred.prev_rotated_at = "", None
            cred.refresh_history = []
            cred.save()
        if not taken:
            ident.rotate_pending = [r for r in ident.rotate_pending if r != "token"]
            # the release window opens one grant
            ident.release_until = None
            ident.save(update_fields=["rotate_pending", "release_until"])
            # the password user of this agent leaves nats-rmm.conf
            transaction.on_commit(reload_nats)
    if taken:
        events.record(
            SecurityEventKind.TOKEN_REUSE,
            SecurityEventSeverity.HIGH,
            agent=agent,
            ip=ip,
            detail=f"grant with a family token refused (generation {cred.generation})",
        )
        return 409, {"detail": "token family exists"}
    if released:
        events.record(
            SecurityEventKind.RELEASED,
            SecurityEventSeverity.WARNING,
            agent=agent,
            ip=ip,
            detail="new token family with the identity signature (release window)",
        )
    return 200, body


def _retry_key(agent_id: str, old: str) -> str:
    return f"tokrot:{agent_id}:{old}"


def refresh(agent, data: dict, *, ip=None):
    """Single-use refresh; a second use of a rotated token is a clone."""
    token = data.get("refresh")
    ts, sig = ts_of(data.get("ts")), b64(data.get("sig"), 64)
    if not isinstance(token, str) or not 0 < len(token) <= 200:
        return 400, {"detail": "refresh invalid"}
    if ts is None or sig is None:
        return 400, {"detail": "ts invalid" if ts is None else "sig invalid"}
    ident = identity_of(agent)
    # an old token alone (from a log, a backup) must not trigger a quarantine
    if ident is None or not ident.ed25519:
        return UNKNOWN
    if not ed_ok(ident.ed25519, sig, refresh_message(agent.agent_id, token, ts)):
        return UNKNOWN
    if ident.state != IdentityState.ACTIVE:
        return 403, {"detail": "quarantined"}
    candidates = digests(token)
    now = djangotime.now()
    # reuse is decided by the token; the clock only matters for one that
    # still gets a pair
    with transaction.atomic():
        cred = AgentCredential.objects.select_for_update().filter(agent=agent).first()
        if cred is None or cred.revoked_at is not None:
            return UNKNOWN
        if cred.refresh_digest in candidates:
            if refused := clock_refused(ts):
                return refused
            if cred.refresh_expires is None or cred.refresh_expires <= now:
                return 401, {"detail": "token expired"}
            old = cred.refresh_digest
            body = issue_family(cred, now=now, generation=cred.generation + 1, ip=ip)
            if cred.prev_refresh_digest:
                cred.refresh_history = (
                    cred.refresh_history + [cred.prev_refresh_digest]
                )[-HISTORY:]
            cred.prev_refresh_digest, cred.prev_rotated_at = old, now
            cred.save()
            if "token" in ident.rotate_pending:
                ident.rotate_pending = [r for r in ident.rotate_pending if r != "token"]
                ident.save(update_fields=["rotate_pending"])
            cache.set(
                _retry_key(agent.agent_id, old),
                encrypt_secret(json.dumps(body), RETRY_INFO),
                RETRY_SECONDS,
            )
            return 200, body
        if cred.prev_refresh_digest and cred.prev_refresh_digest in candidates:
            used = cred.generation - 1
            # the answer of the last rotation got lost: the same pair again,
            # but only while nobody has used its access token
            recent = (
                cred.access_used_at is None
                and cred.prev_rotated_at is not None
                and now - cred.prev_rotated_at <= dt.timedelta(seconds=RETRY_SECONDS)
            )
            cached = recent and cache.get(
                _retry_key(agent.agent_id, cred.prev_refresh_digest)
            )
            if cached:
                if refused := clock_refused(ts):
                    return refused
                try:
                    body = json.loads(decrypt_secret(cached, RETRY_INFO))
                except (InvalidToken, ValueError):
                    pass
                else:
                    return 200, {**body, "now_ms": now_ms()}
        else:
            history = cred.refresh_history or []
            hits = [i for i, d in enumerate(history) if d in candidates]
            if not hits:
                return UNKNOWN
            used = cred.generation - 1 - (len(history) - hits[-1])
        first_ip = cred.rotated_ip
    events.record(
        SecurityEventKind.TOKEN_REUSE,
        SecurityEventSeverity.CRITICAL,
        agent=agent,
        ip=ip,
        detail=f"refresh token of generation {used} used again "
        f"(rotated from {first_ip or 'unknown'}, reused from {ip or 'unknown'})",
    )
    from .identity import quarantine
    from .policy import effective

    if effective(agent)["auto_quarantine"]:
        quarantine(agent, "refresh token reused")
    return 403, {"detail": "token reuse"}


def recovery_due(agent, cred, now) -> bool:
    """The newest certificate expired unrevoked within the grace, or both
    tokens of the family expired within it."""
    limit = now - grace(agent)
    newest = agent.certificates.order_by("-not_after", "-pk").first()
    if newest is not None and newest.revoked_at is None:
        if limit < newest.not_after <= now:
            return True
    if (
        cred is None
        or cred.revoked_at is not None
        or cred.kind != CredentialKind.FAMILY
    ):
        return False
    return all(
        stamp is not None and limit < stamp <= now
        for stamp in (cred.access_expires, cred.refresh_expires)
    )


def _refuse_recovery(agent, ip, why: str):
    events.record(
        SecurityEventKind.GRACE_RECOVERY,
        SecurityEventSeverity.WARNING,
        agent=agent,
        ip=ip,
        detail=f"recovery refused: {why}",
    )
    return 403, {"detail": "recovery not allowed"}


def recover(agent, data: dict, *, ip=None):
    """Offline recovery inside OFFLINE_GRACE: a new certificate and a new
    family for the holder of the identity key."""
    from . import pki

    parsed, refused = signed_parts(data)
    if refused:
        return refused
    nonce, ts, sig = parsed
    csr = data.get("csr")
    if not isinstance(csr, str) or not 0 < len(csr) <= 8192:
        return 400, {"detail": "csr invalid"}
    if agent is None:
        return 403, {"detail": "recovery not allowed"}
    if not _take_nonce("recover", agent.agent_id, nonce):
        return 400, {"detail": "nonce invalid"}
    ident = identity_of(agent)
    if ident is None or not ident.ed25519:
        return _refuse_recovery(agent, ip, "no identity")
    if not ed_ok(ident.ed25519, sig, recover_message(agent.agent_id, nonce, ts, csr)):
        return 400, {"detail": "signature"}
    if ident.state != IdentityState.ACTIVE:
        return _refuse_recovery(agent, ip, f"identity {ident.state}")
    now = djangotime.now()
    with transaction.atomic():
        cred = AgentCredential.objects.select_for_update().filter(agent=agent).first()
        if not recovery_due(agent, cred, now):
            return _refuse_recovery(agent, ip, "outside the grace or revoked")
        try:
            issued = pki.issue(agent, csr)
        except pki.CertError as e:
            return 400, {"detail": f"csr invalid: {e}"}
        except pki.CAUnavailable:
            issued = {}
        cred = cred or AgentCredential(agent=agent)
        body = issue_family(cred, now=now, generation=cred.generation + 1, ip=ip)
        cred.prev_refresh_digest, cred.prev_rotated_at = "", None
        cred.refresh_history = []
        cred.save()
    events.record(
        SecurityEventKind.GRACE_RECOVERY,
        SecurityEventSeverity.WARNING,
        agent=agent,
        ip=ip,
        detail=f"recovered with identity {ident.kid}",
    )
    return 200, {**issued, **body}

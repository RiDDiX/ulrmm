# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Signed and encrypted commands for agents with an identity (sec2).

The server signs every command with its command key and encrypts it with a
session key both sides derived from an ephemeral X25519 exchange; the agent
signs its handshake answer and replies with its identity key. Session state is
shared by every server process through the cache (Redis).
"""

import asyncio
import base64
import functools
import hashlib
import logging
import os
import time

import msgpack
from asgiref.sync import sync_to_async
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.cache import cache
from nats.errors import NoRespondersError
from nats.errors import TimeoutError as NatsTimeoutError

logger = logging.getLogger("ulrmm")

LEGACY = "legacy"
SEC2 = "sec2"
REFUSED = "refused"
SESSION_INFO = b"ulrmm e2e session v1"
MODE_TTL = 60
PREV_TTL = 120
HS_LOCK_TTL = 15
HS_TIMEOUT = 10
EVENT_EVERY = 600
MAX_EPOCH = 64
ZERO16 = bytes(16)
TIMEOUT = "timeout"
REPLY_REFUSED = "error: reply refused"
SEC2_REQUIRED = "sec2 required"
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Refused(Exception):
    """Nothing was sent, or the answer did not verify; answer is what the
    caller returns in place of a reply."""

    def __init__(self, answer: str, reason: str = ""):
        super().__init__(reason or answer)
        self.answer = answer


def _conf(name: str, default: int) -> int:
    return getattr(settings, name, default)


def now_ms() -> int:
    return int(time.time() * 1000)


def _be(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info
    ).derive(ikm)


def x25519_public(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(*_RAW)


# wire layouts (T4.2, T4.4, T5.2, T5.3)


def cmd_header(agent_id, y, kid, s, e, q, t, n) -> bytes:
    return (
        b"ulrmm-cmd-v2\0"
        + agent_id.encode()
        + b"\0"
        + y.encode()
        + b"\0"
        + kid.encode()
        + (s or ZERO16)
        + _be(e, 4)
        + _be(q, 8)
        + _be(t, 8)
        + n
    )


def reply_header(agent_id, s, e, q, request_q) -> bytes:
    return (
        b"ulrmm-rsp-v2\0"
        + agent_id.encode()
        + b"\0"
        + s
        + _be(e, 4)
        + _be(q, 8)
        + _be(request_q, 8)
    )


def frame_header(subject, s, e, q) -> bytes:
    return b"ulrmm-frm-v2\0" + subject.encode() + b"\0" + s + _be(e, 4) + _be(q, 8)


def hs2_bytes(agent_id, sid, es, ea, cfp, pin_seq, ts) -> bytes:
    return (
        b"ulrmm-hs2-v1\0"
        + agent_id.encode()
        + b"\0"
        + sid
        + es
        + ea
        + cfp.encode()
        + _be(pin_seq, 8)
        + _be(ts, 8)
    )


def session_keys(shared, sid, agent_id, es, ea) -> tuple[bytes, bytes]:
    okm = hkdf(shared, sid, b"ulrmm e2e v1\0" + agent_id.encode() + es + ea, 64)
    return okm[:32], okm[32:]


@functools.lru_cache(maxsize=1024)
def epoch_key(base: bytes, e: int) -> bytes:
    """The key of epoch e, ratcheted forward from the session's first key."""
    key = base
    for step in range(1, e + 1):
        key = hkdf(key, b"", b"ulrmm e2e rekey v1" + _be(step, 4))
    return key


def aead_nonce(e: int, q: int) -> bytes:
    return _be(e, 4) + _be(q, 8)


def build(agent_id, y, kid, key, s, e, q, plain, k_s2a=None, t=None, n=None):
    """One envelope; plain goes out in clear for hs1 (k_s2a None)."""
    t = now_ms() if t is None else t
    n = os.urandom(16) if n is None else n
    head = cmd_header(agent_id, y, kid, s, e, q, t, n)
    c = plain
    if k_s2a is not None:
        c = ChaCha20Poly1305(k_s2a).encrypt(aead_nonce(e, q), plain, head)
    g = key.sign(head + hashlib.sha256(c).digest())
    return msgpack.dumps(
        {
            "v": 2,
            "y": y,
            "k": kid,
            "s": s,
            "e": e,
            "q": q,
            "t": t,
            "n": n,
            "c": c,
            "g": g,
        }
    )


def seal_body(agent_id, x_raw, path, body, kid, key, e_priv=None, t=None) -> dict:
    """Sealed REST answer (T5.8) to the agent's static X25519 key."""
    e_priv = e_priv or X25519PrivateKey.generate()
    t = now_ms() if t is None else t
    e = x25519_public(e_priv)
    shared = e_priv.exchange(X25519PublicKey.from_public_bytes(x_raw))
    sk = hkdf(shared, b"", b"ulrmm seal v1\0" + agent_id.encode() + path.encode())
    c = ChaCha20Poly1305(sk).encrypt(bytes(12), body, path.encode())
    g = key.sign(
        b"ulrmm-seal-v1\0"
        + agent_id.encode()
        + b"\0"
        + path.encode()
        + e
        + _be(t, 8)
        + hashlib.sha256(c).digest()
    )
    b64 = base64.b64encode
    return {
        "v": 2,
        "kid": kid,
        "e": b64(e).decode(),
        "c": b64(c).decode(),
        "t": t,
        "g": b64(g).decode(),
    }


# who gets envelopes


def _aid(agent) -> str:
    return getattr(agent, "agent_id", agent)


def _mode_key(agent_id: str) -> str:
    return f"e2e:mode:{agent_id}"


def target(agent) -> dict:
    """mode legacy, sec2 or refused, the identity's public keys; cached a minute."""
    agent_id = _aid(agent)
    hit = cache.get(_mode_key(agent_id))
    if hit is not None:
        return hit
    from .models import AgentIdentity
    from .pki import security_settings

    sec2 = security_settings().sec2_mode
    ident = (
        AgentIdentity.objects.filter(agent__agent_id=agent_id)
        .only(
            "state",
            "caps",
            "ed25519",
            "x25519",
            "prev_ed25519",
            "prev_until",
            "pin_seq",
        )
        .first()
    )
    required = sec2 == "required"
    tgt = {
        "mode": REFUSED if required else LEGACY,
        "active": False,
        "answer": SEC2_REQUIRED if required else TIMEOUT,
    }
    if ident is not None and ident.ed25519:
        active = ident.state == "active"
        tgt.update(
            active=active,
            ed=ident.ed25519,
            x=ident.x25519,
            prev=ident.prev_ed25519,
            prev_until=(
                int(ident.prev_until.timestamp() * 1000) if ident.prev_until else 0
            ),
        )
        if not active:
            tgt.update(mode=REFUSED, answer=TIMEOUT)
        elif "sec2" in (ident.caps or []) and (sec2 != "off" or _armed(ident.pin_seq)):
            tgt["mode"] = SEC2
    elif ident is not None:
        # a block without keys
        tgt.update(mode=REFUSED, answer=TIMEOUT)
    cache.set(_mode_key(agent_id), tgt, MODE_TTL)
    return tgt


def _armed(pin_seq: int) -> bool:
    """Whether the pin document the agent last reported still arms it: an
    armed agent refuses plaintext until it fetched one saying sec2 off."""
    from .models import PinSet

    if not pin_seq:
        return False
    sec2 = PinSet.objects.filter(seq=pin_seq).values_list("sec2", flat=True).first()
    return sec2 in ("optional", "required")


async def _atarget(agent_id: str) -> dict:
    hit = cache.get(_mode_key(agent_id))
    return hit if hit is not None else await sync_to_async(target)(agent_id)


async def amode(agent) -> str:
    return (await _atarget(_aid(agent)))["mode"]


def _identity_ok(tgt: dict, sig: bytes, data: bytes) -> bool:
    keys = [tgt.get("ed")]
    if tgt.get("prev") and tgt.get("prev_until", 0) > now_ms():
        keys.append(tgt["prev"])
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(sig, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            continue
    return False


def event(agent_id: str, detail: str) -> None:
    """e2e_refused, at most once per agent every 10 minutes."""
    if not cache.add(f"e2e:ev:{agent_id}", 1, EVENT_EVERY):
        return
    from agents.models import Agent

    from .events import record
    from .models import SecurityEventKind, SecurityEventSeverity

    record(
        SecurityEventKind.E2E_REFUSED,
        SecurityEventSeverity.WARNING,
        agent=Agent.objects.filter(agent_id=agent_id).first(),
        agent_id=agent_id,
        detail=detail,
    )


# sessions (T5.5)


def _skey(agent_id: str, prev: bool = False) -> str:
    return f"e2e:{agent_id}:prev" if prev else f"e2e:{agent_id}"


def _ttl(sess: dict) -> int:
    return sess["rekey"] + 300


def _store(agent_id: str, sess: dict, prev: bool = False) -> None:
    from remote.utils import encrypt_secret

    def wrap(key):
        return encrypt_secret(base64.b64encode(key).decode(), SESSION_INFO)

    cache.set(
        _skey(agent_id, prev),
        {
            "sid": base64.b64encode(sess["sid"]).decode(),
            "e": sess["e"],
            "k_s2a": wrap(sess["k_s2a"]),
            "k_a2s": wrap(sess["k_a2s"]),
            "created": sess["created"],
            "rekey": sess["rekey"],
            "rekey_b": sess["rekey_b"],
        },
        PREV_TTL if prev else _ttl(sess),
    )


def _load(agent_id: str, prev: bool = False) -> dict | None:
    from remote.utils import decrypt_secret

    rec = cache.get(_skey(agent_id, prev))
    if not isinstance(rec, dict):
        return None
    try:
        return {
            "sid": base64.b64decode(rec["sid"]),
            "e": rec["e"],
            "k_s2a": base64.b64decode(decrypt_secret(rec["k_s2a"], SESSION_INFO)),
            "k_a2s": base64.b64decode(decrypt_secret(rec["k_a2s"], SESSION_INFO)),
            "created": rec["created"],
            # records of an earlier version carry no limits
            "rekey": rec.get("rekey", _conf("E2E_REKEY_SECONDS", 3600)),
            "rekey_b": rec.get("rekey_b", _conf("E2E_REKEY_BYTES", 64 << 20)),
        }
    except Exception:
        # field keys rotated away or a broken record: handshake again
        return None


def _fresh(sess: dict) -> bool:
    return now_ms() - sess["created"] < sess["rekey"] * 1000


def forget(agent) -> None:
    """Drops the sessions and the cached mode (T5.6)."""
    agent_id = _aid(agent)
    cache.delete_many([_skey(agent_id), _skey(agent_id, True), _mode_key(agent_id)])


def _advance(agent_id: str, sess: dict, e: int) -> dict:
    """Moves the session to epoch e; every process derives the same keys."""
    if e > MAX_EPOCH:
        raise Refused(TIMEOUT, "epoch limit")
    cur = _load(agent_id)
    if cur is not None and cur["sid"] == sess["sid"] and cur["e"] < e:
        _store(agent_id, {**cur, "e": e})
    return {**sess, "e": max(e, sess["e"])}


def accept_hs2(agent_id, tgt, sid, es_priv, raw) -> dict:
    """The session from the agent's hs2 answer, or Refused (event recorded)."""
    from .models import AgentIdentity

    def refuse(reason):
        event(agent_id, f"handshake refused: {reason}")
        raise Refused(TIMEOUT, reason)

    try:
        ans = _loads(raw)
    except Exception:
        refuse("undecodable answer")
    if not isinstance(ans, dict):
        refuse("undecodable answer")
    if ans.get("y") != "hs2":
        err = ans.get("error")
        refuse(err[:120] if isinstance(err, str) else "no hs2")
    ea, cfp, pin_seq, ts, sig = (
        ans.get(k) for k in ("ea", "cfp", "pin_seq", "ts", "g")
    )
    try:
        ea, sig, got = _b(ea), _b(sig), _b(ans.get("sid"))
    except ValueError:
        refuse("malformed hs2")
    if (
        got != sid
        or len(ea) != 32
        or not isinstance(cfp, str)
        or len(cfp) > 64
        or not isinstance(pin_seq, int)
        or not 0 <= pin_seq < 2**31
        or not isinstance(ts, int)
        or len(sig) != 64
    ):
        refuse("malformed hs2")
    if abs(ts - now_ms()) > _conf("E2E_CLOCK_WINDOW", 30) * 1000:
        refuse("clock")
    es = x25519_public(es_priv)
    if not _identity_ok(tgt, sig, hs2_bytes(agent_id, sid, es, ea, cfp, pin_seq, ts)):
        refuse("signature")
    if not _cfp_ok(agent_id, cfp):
        refuse("client certificate does not match")
    try:
        shared = es_priv.exchange(X25519PublicKey.from_public_bytes(ea))
    except ValueError:
        refuse("low order key")
    k_s2a, k_a2s = session_keys(shared, sid, agent_id, es, ea)
    from .policy import effective

    pol = effective(agent_id)
    sess = {
        "sid": sid,
        "e": 0,
        "k_s2a": k_s2a,
        "k_a2s": k_a2s,
        "created": now_ms(),
        # the rotation policy at handshake time; a new session picks up a change
        "rekey": pol["rekey_minutes"] * 60,
        "rekey_b": pol["rekey_mb"] << 20,
    }
    old = _load(agent_id)
    if old is not None:
        _store(agent_id, old, prev=True)
    _store(agent_id, sess)
    from django.utils import timezone as djangotime

    AgentIdentity.objects.filter(agent__agent_id=agent_id).update(
        pin_seq=pin_seq, last_hs=djangotime.now()
    )
    # the reported pin document decides the mode while sec2 is off
    cache.delete(_mode_key(agent_id))
    return sess


def _cfp_ok(agent_id: str, cfp: str) -> bool:
    """B2 of draft 2.2: in mtls required the session names an active
    certificate of the same agent. Not compared with the certificate of the
    websocket admission: NATS connections outlive any cache entry, and the
    agent renews its certificate while connected."""
    from .pki import active_certs, mtls_mode

    if mtls_mode() != "required":
        return True
    return (
        bool(cfp)
        and active_certs()
        .filter(agent__agent_id=agent_id, fingerprint_sha1=cfp.lower())
        .exists()
    )


def _rotate_pending(agent_id: str) -> list:
    """What the dashboard asked the agent to rotate, read fresh each time."""
    from .models import AgentIdentity

    ident = (
        AgentIdentity.objects.filter(agent__agent_id=agent_id)
        .only("rotate_pending")
        .first()
    )
    return list(ident.rotate_pending) if ident else []


async def _handshake(nc, agent_id, tgt, timeout) -> dict:
    from .signing import command_signer

    kid, key = await sync_to_async(command_signer)()
    es_priv = X25519PrivateKey.generate()
    sid = os.urandom(16)
    rotate = await sync_to_async(_rotate_pending)(agent_id)
    body = msgpack.dumps(
        {"sid": sid, "es": x25519_public(es_priv), "ts": now_ms(), "rotate": rotate}
    )
    raw = build(agent_id, "hs1", kid, key, b"", 0, 0, body)
    try:
        msg = await nc.request(agent_id, raw, timeout=timeout)
    except (NatsTimeoutError, NoRespondersError):
        raise Refused(TIMEOUT, "no handshake answer")
    return await sync_to_async(accept_hs2)(agent_id, tgt, sid, es_priv, msg.data)


async def session(nc, agent_id, tgt, timeout=HS_TIMEOUT) -> dict:
    """The agent's current session; one process handshakes, the others wait."""
    sess = _load(agent_id)
    if sess is not None and _fresh(sess):
        return sess
    lock = f"e2e-hs:{agent_id}"
    deadline = time.monotonic() + HS_LOCK_TTL
    while not cache.add(lock, 1, HS_LOCK_TTL):
        await asyncio.sleep(0.05)
        sess = _load(agent_id)
        if sess is not None and _fresh(sess):
            return sess
        if time.monotonic() > deadline:
            raise Refused(TIMEOUT, "handshake busy")
    try:
        sess = _load(agent_id)
        if sess is not None and _fresh(sess):
            return sess
        return await _handshake(nc, agent_id, tgt, min(timeout, HS_TIMEOUT))
    finally:
        cache.delete(lock)


def _next_q(agent_id: str, sess: dict, size: int) -> tuple[dict, int]:
    """(session, q) with q unique per (sid, epoch) across processes; moves to
    the next epoch past the message or byte limit."""
    for _ in range(3):
        base = f"e2e:{agent_id}:{sess['sid'].hex()}:{sess['e']}"
        cache.add(base + ":q", 0, _ttl(sess))
        cache.add(base + ":b", 0, _ttl(sess))
        q = cache.incr(base + ":q")
        sent = cache.incr(base + ":b", size)
        if q <= _conf("E2E_REKEY_MESSAGES", 100_000) and sent <= sess["rekey_b"]:
            return sess, q
        sess = _advance(agent_id, sess, sess["e"] + 1)
    return sess, q


async def seal(nc, agent, plain: bytes, timeout=HS_TIMEOUT) -> tuple[bytes, dict]:
    """A signed, encrypted cmd envelope around plain (msgpack of a NatsMsg)."""
    from .signing import command_signer

    agent_id = _aid(agent)
    tgt = await _atarget(agent_id)
    if tgt["mode"] != SEC2:
        raise Refused(tgt["answer"], tgt["mode"])
    sess = await session(nc, agent_id, tgt, timeout)
    sess, q = _next_q(agent_id, sess, len(plain) + 16)
    kid, key = await sync_to_async(command_signer)()
    e = sess["e"]
    raw = build(
        agent_id, "cmd", kid, key, sess["sid"], e, q, plain, epoch_key(sess["k_s2a"], e)
    )
    return raw, {"agent_id": agent_id, "tgt": tgt, "sess": sess, "e": e, "q": q}


def _keys_for(ctx, agent_id, s, e) -> dict | None:
    cands = [ctx["sess"]] if ctx else []
    cands += [x for x in (_load(agent_id), _load(agent_id, True)) if x]
    for sess in cands:
        if sess["sid"] == s and 0 <= e <= MAX_EPOCH:
            return sess
    return None


def _decrypt(agent_id, sess, e, q, c, head) -> bytes:
    # only a frame that decrypts may move the stored epoch
    plain = ChaCha20Poly1305(epoch_key(sess["k_a2s"], e)).decrypt(
        aead_nonce(e, q), c, head
    )
    if e > sess["e"]:
        _advance(agent_id, sess, e)
    return plain


def open_reply(agent, ctx: dict, raw: bytes) -> bytes:
    """The msgpack plaintext of a sec2 reply, verified against the request."""
    agent_id = _aid(agent)
    try:
        r = _loads(raw)
        s, c, g = _b(r["s"]), _b(r["c"]), _b(r["g"])
        e, q = r["e"], r["q"]
        if r.get("v") != 2 or s != ctx["sess"]["sid"]:
            raise ValueError("session")
        head = reply_header(agent_id, s, e, q, ctx["q"])
        if not _identity_ok(ctx["tgt"], g, head + hashlib.sha256(c).digest()):
            raise ValueError("signature")
        sess = _keys_for(ctx, agent_id, s, e)
        return _decrypt(agent_id, sess, e, q, c, head)
    except Exception as exc:
        raise Refused(REPLY_REFUSED, f"reply refused: {exc!r}"[:200])


def open_frame(agent, subject: str, raw: bytes, ctx: dict | None = None) -> bytes:
    """The msgpack plaintext of a cmdoutput or terminal frame (T4.4)."""
    agent_id = _aid(agent)
    try:
        r = _loads(raw)
        s, c, e, q = _b(r["s"]), _b(r["c"]), r["e"], r["q"]
        if r.get("v") != 2:
            raise ValueError("not an envelope")
        sess = _keys_for(ctx, agent_id, s, e)
        return _decrypt(agent_id, sess, e, q, c, frame_header(subject, s, e, q))
    except Exception as exc:
        raise Refused(REPLY_REFUSED, f"frame refused: {exc!r}"[:200])


def _loads(raw: bytes):
    # the agent's encoder may write bytes as old-spec raw strings
    return msgpack.loads(raw, unicode_errors="surrogateescape")


def _b(value) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    if isinstance(value, bytes):
        return value
    raise ValueError("bytes expected")


def _agent_refusal(raw: bytes) -> str:
    """The reason of the agent's plaintext refusal answer, '' for anything else."""
    try:
        r = msgpack.loads(raw)
    except Exception:
        return ""
    err = r.get("error") if isinstance(r, dict) and "v" not in r else None
    return err if isinstance(err, str) and "refused" in err else ""


# what the call sites use


async def publish(nc, agent, plain: bytes):
    """nc.publish to the agent's subject; the ctx of a sec2 send, else None."""
    agent_id = _aid(agent)
    tgt = await _atarget(agent_id)
    if tgt["mode"] == LEGACY:
        await nc.publish(agent_id, plain)
        return None
    payload, ctx = await seal(nc, agent_id, plain)
    await nc.publish(agent_id, payload)
    return ctx


async def request(nc, agent, plain: bytes, timeout) -> bytes:
    """nc.request to the agent's subject; the reply's msgpack bytes. Raises
    what nc.request raises, and Refused."""
    agent_id = _aid(agent)
    tgt = await _atarget(agent_id)
    if tgt["mode"] == LEGACY:
        return (await nc.request(agent_id, plain, timeout=timeout)).data
    for attempt in range(2):
        payload, ctx = await seal(nc, agent_id, plain, timeout)
        msg = await nc.request(agent_id, payload, timeout=timeout)
        refusal = _agent_refusal(msg.data)
        if refusal.endswith("session") and attempt == 0:
            # the agent restarted and lost its sessions
            forget(agent_id)
            continue
        try:
            return open_reply(agent_id, ctx, msg.data)
        except Refused as e:
            await sync_to_async(event)(agent_id, refusal or str(e))
            raise
    raise Refused(REPLY_REFUSED)


def seal_response(agent, request, data, status: int = 200):
    """The REST answer, sealed to the agent's X25519 key when it asked for it
    and has an active identity (T5.8)."""
    from rest_framework.renderers import JSONRenderer
    from rest_framework.response import Response

    from .signing import command_signer

    if request.META.get("HTTP_X_ULRMM_SEAL") != "1":
        return Response(data, status=status)
    tgt = target(agent)
    if not tgt["active"]:
        return Response(data, status=status)
    kid, key = command_signer()
    body = seal_body(
        agent.agent_id,
        base64.b64decode(tgt["x"]),
        request.path,
        JSONRenderer().render(data),
        kid,
        key,
    )
    resp = Response(body, status=status)
    resp["X-ULRMM-Sealed"] = "1"
    return resp

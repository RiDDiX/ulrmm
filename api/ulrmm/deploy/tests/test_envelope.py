# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import base64
import binascii
import datetime as dt
import hashlib
import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import msgpack
from asgiref.sync import async_to_sync
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.core.management import call_command
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker
from nats.errors import NoRespondersError

from deploy import envelope, pki, signing
from deploy.models import AgentIdentity, CommandKey, PinSet, SecurityEvent
from deploy.tests.test_security_r1 import jws_parts
from remote.utils import decrypt_secret
from ulrmm.nats_utils import a_nats_cmd, abulk_nats_command
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

V = json.loads((Path(__file__).parent / "vectors_sec2.json").read_text())
X = bytes.fromhex
B64 = base64.b64encode


def _seed(info: bytes, master: bytes) -> bytes:
    return envelope.hkdf(master, b"", info)


def _nkey(pub: bytes) -> str:
    raw = bytes([0xA0]) + pub
    raw += binascii.crc_hqx(raw, 0).to_bytes(2, "little")
    return base64.b32encode(raw).decode().rstrip("=")


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(*envelope._RAW)


class TestVectors(SimpleTestCase):
    """The bytes the agent reproduces from agent/testdata/sec2_vectors.json."""

    aid = V["agent_id"]

    def test_identity_derivation_and_nkey(self):
        m = X(V["identity"]["master"])
        ed = Ed25519PrivateKey.from_private_bytes(
            _seed(b"ulrmm identity ed25519 v1", m)
        )
        xk = X25519PrivateKey.from_private_bytes(_seed(b"ulrmm identity x25519 v1", m))
        nk = Ed25519PrivateKey.from_private_bytes(_seed(b"ulrmm nats nkey v1", m))
        self.assertEqual(_raw_pub(ed).hex(), V["identity"]["ed25519"])
        self.assertEqual(envelope.x25519_public(xk).hex(), V["identity"]["x25519"])
        self.assertEqual(_nkey(_raw_pub(nk)), V["identity"]["nkey"])
        self.assertEqual(
            hashlib.sha256(_raw_pub(ed)).hexdigest()[:16], V["identity"]["kid"]
        )
        msg = X(V["identity"]["idreg_message"])
        Ed25519PublicKey.from_public_bytes(_raw_pub(nk)).verify(
            X(V["identity"]["nsig"]), msg
        )
        self.assertEqual(ed.sign(msg).hex(), V["identity"]["sig"])

    def _cmd_key(self):
        key = Ed25519PrivateKey.from_private_bytes(X(V["command_key"]["seed"]))
        kid = hashlib.sha256(_raw_pub(key)).hexdigest()[:16]
        self.assertEqual(kid, V["command_key"]["kid"])
        return kid, key

    def test_cmd_header_signature_and_aead(self):
        kid, key = self._cmd_key()
        sid, n, t = X(V["hs1"]["sid"]), X(V["cmd"]["nonce"]), V["t"]
        head = envelope.cmd_header(self.aid, "cmd", kid, sid, 0, 1, t, n)
        self.assertEqual(head.hex(), V["cmd"]["header"])
        raw = envelope.build(
            self.aid,
            "cmd",
            kid,
            key,
            sid,
            0,
            1,
            X(V["cmd"]["plaintext"]),
            X(V["keys"]["k_s2a"]),
            t=t,
            n=n,
        )
        env = msgpack.loads(raw)
        self.assertEqual(env["c"].hex(), V["cmd"]["c"])
        self.assertEqual(env["g"].hex(), V["cmd"]["sig"])
        self.assertEqual(raw.hex(), V["cmd"]["envelope_msgpack_py"])
        self.assertEqual(envelope.aead_nonce(0, 1).hex(), V["cmd"]["aead_nonce"])

    def test_hs1_hs2_and_session_keys(self):
        kid, key = self._cmd_key()
        es_priv = X25519PrivateKey.from_private_bytes(X(V["hs1"]["es_seed"]))
        ea_priv = X25519PrivateKey.from_private_bytes(X(V["hs2"]["ea_seed"]))
        es, ea = envelope.x25519_public(es_priv), envelope.x25519_public(ea_priv)
        sid, t = X(V["hs1"]["sid"]), V["t"]
        raw = envelope.build(
            self.aid,
            "hs1",
            kid,
            key,
            b"",
            0,
            0,
            X(V["hs1"]["body_msgpack"]),
            t=t,
            n=X(V["cmd"]["nonce"]),
        )
        self.assertEqual(raw.hex(), V["hs1"]["envelope_msgpack_py"])
        signed = envelope.hs2_bytes(self.aid, sid, es, ea, V["hs2"]["cfp"], 3, t)
        self.assertEqual(signed.hex(), V["hs2"]["signed"])
        shared = es_priv.exchange(X25519PublicKey.from_public_bytes(ea))
        k_s2a, k_a2s = envelope.session_keys(shared, sid, self.aid, es, ea)
        self.assertEqual((k_s2a + k_a2s).hex(), V["keys"]["okm"])
        self.assertEqual(envelope.epoch_key(k_s2a, 1).hex(), V["keys"]["k_s2a_e1"])
        self.assertEqual(envelope.epoch_key(k_a2s, 1).hex(), V["keys"]["k_a2s_e1"])
        head = envelope.cmd_header(
            self.aid, "cmd", kid, sid, 1, 1, t, X(V["cmd"]["nonce"])
        )
        self.assertEqual(head.hex(), V["cmd_e1"]["header"])
        c1 = ChaCha20Poly1305(envelope.epoch_key(k_s2a, 1)).encrypt(
            envelope.aead_nonce(1, 1), X(V["cmd_e1"]["plaintext"]), head
        )
        self.assertEqual(c1.hex(), V["cmd_e1"]["c"])

    def test_reply_and_frame_layouts(self):
        sid = X(V["hs1"]["sid"])
        head = envelope.reply_header(self.aid, sid, 0, 1, 1)
        self.assertEqual(head.hex(), V["reply"]["header"])
        c = ChaCha20Poly1305(X(V["keys"]["k_a2s"])).encrypt(
            envelope.aead_nonce(0, 1), X(V["reply"]["plaintext"]), head
        )
        self.assertEqual(c.hex(), V["reply"]["c"])
        fhead = envelope.frame_header(V["frame"]["subject"], sid, 0, 2)
        self.assertEqual(fhead.hex(), V["frame"]["header"])

    def test_sealed_body_vector(self):
        kid, key = self._cmd_key()
        body = envelope.seal_body(
            self.aid,
            X(V["identity"]["x25519"]),
            V["sealed"]["path"],
            X(V["sealed"]["plaintext"]),
            kid,
            key,
            X25519PrivateKey.from_private_bytes(X(V["sealed"]["e_seed"])),
            V["t"],
        )
        self.assertEqual(body, V["sealed"]["body"])


class FakeAgent:
    """The agent side of T4/T5, built from the same helpers the vectors pin."""

    def __init__(self, agent_id, cmd_keys, master=b"\x02" * 32):
        self.agent_id = agent_id
        self.cmd_keys = cmd_keys
        self.id_key = Ed25519PrivateKey.from_private_bytes(
            _seed(b"ulrmm identity ed25519 v1", master)
        )
        self.x_key = X25519PrivateKey.from_private_bytes(
            _seed(b"ulrmm identity x25519 v1", master)
        )
        nk = Ed25519PrivateKey.from_private_bytes(_seed(b"ulrmm nats nkey v1", master))
        self.nkey = _nkey(_raw_pub(nk))
        self.sessions = {}
        self.hs1 = 0
        self.seen = []
        self.q = 0
        self.cfp = ""
        self.pin_seq = 7
        self.ts_shift = 0
        self.wrong_hs2_key = False
        self.reply_hook = None
        self.answer = "pong"
        # ugorji's default handle writes []byte as old-spec raw strings
        self.bin = True

    def dumps(self, obj):
        return msgpack.dumps(obj, use_bin_type=self.bin)

    def identity(self, agent, **kw):
        ed = _raw_pub(self.id_key)
        return AgentIdentity.objects.create(
            agent=agent,
            ed25519=B64(ed).decode(),
            x25519=B64(envelope.x25519_public(self.x_key)).decode(),
            nkey=self.nkey,
            kid=hashlib.sha256(ed).hexdigest()[:16],
            caps=["sec2"],
            **kw,
        )

    def _verify(self, env):
        pub = Ed25519PublicKey.from_public_bytes(self.cmd_keys[env["k"]])
        s = env["s"] or bytes(16)
        head = envelope.cmd_header(
            self.agent_id, env["y"], env["k"], s, env["e"], env["q"], env["t"], env["n"]
        )
        pub.verify(env["g"], head + hashlib.sha256(env["c"]).digest())
        return head

    def handle(self, payload):
        env = msgpack.loads(payload)
        if "v" not in env:
            self.seen.append(("plain", env))
            return msgpack.dumps(self.answer)
        head = self._verify(env)
        if env["y"] == "hs1":
            self.hs1 += 1
            body = self.hs1_body = msgpack.loads(env["c"])
            ea_priv = X25519PrivateKey.generate()
            ea = envelope.x25519_public(ea_priv)
            shared = ea_priv.exchange(X25519PublicKey.from_public_bytes(body["es"]))
            self.sessions[body["sid"]] = envelope.session_keys(
                shared, body["sid"], self.agent_id, body["es"], ea
            )
            ts = envelope.now_ms() + self.ts_shift
            signer = Ed25519PrivateKey.generate() if self.wrong_hs2_key else self.id_key
            g = signer.sign(
                envelope.hs2_bytes(
                    self.agent_id,
                    body["sid"],
                    body["es"],
                    ea,
                    self.cfp,
                    self.pin_seq,
                    ts,
                )
            )
            return self.dumps(
                {
                    "v": 2,
                    "y": "hs2",
                    "sid": body["sid"],
                    "ea": ea,
                    "cfp": self.cfp,
                    "pin_seq": self.pin_seq,
                    "ver": "9.9.9",
                    "ts": ts,
                    "g": g,
                }
            )
        s, e, q = env["s"], env["e"], env["q"]
        if s not in self.sessions:
            return msgpack.dumps({"error": "envelope refused: session"})
        k_s2a, k_a2s = self.sessions[s]
        plain = ChaCha20Poly1305(envelope.epoch_key(k_s2a, e)).decrypt(
            envelope.aead_nonce(e, q), env["c"], head
        )
        self.seen.append((s, e, q, msgpack.loads(plain)))
        self.q += 1
        rhead = envelope.reply_header(self.agent_id, s, e, self.q, q)
        rc = ChaCha20Poly1305(envelope.epoch_key(k_a2s, e)).encrypt(
            envelope.aead_nonce(e, self.q), msgpack.dumps(self.answer), rhead
        )
        reply = {"v": 2, "s": s, "e": e, "q": self.q, "c": rc}
        reply["g"] = self.id_key.sign(rhead + hashlib.sha256(rc).digest())
        if self.reply_hook:
            self.reply_hook(reply)
        return self.dumps(reply)

    def frame(self, subject, sid, e, q, data):
        k_a2s = self.sessions[sid][1]
        head = envelope.frame_header(subject, sid, e, q)
        c = ChaCha20Poly1305(envelope.epoch_key(k_a2s, e)).encrypt(
            envelope.aead_nonce(e, q), msgpack.dumps(data), head
        )
        return self.dumps({"v": 2, "s": sid, "e": e, "q": q, "c": c})


class FakeNats:
    is_closed = False

    def __init__(self, *agents):
        self.agents = {a.agent_id: a for a in agents}
        self.sent = []
        self.subs = {}

    async def request(self, subject, payload, timeout=1):
        self.sent.append((subject, payload))
        if subject not in self.agents:
            raise NoRespondersError
        await asyncio.sleep(0)
        return SimpleNamespace(data=self.agents[subject].handle(payload))

    async def publish(self, subject, payload):
        self.sent.append((subject, payload))
        if subject in self.agents:
            self.agents[subject].handle(payload)

    async def subscribe(self, subject, cb):
        self.subs[subject] = cb
        return AsyncMock()

    async def flush(self):
        pass

    async def close(self):
        pass


def set_sec2(value):
    sec = pki.security_settings()
    sec.sec2_mode = value
    sec.save()


@override_settings(CACHES=LOCMEM_CACHE)
class EnvelopeBase(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent")
        self.fake = FakeAgent(self.agent.agent_id, self.cmd_keys())
        self.fake.identity(self.agent)
        self.nc = FakeNats(self.fake)

    def cmd_keys(self):
        return {c["kid"]: base64.b64decode(c["ed"]) for c in signing.command_claim()}

    def request(self, data=None, timeout=5):
        raw = async_to_sync(envelope.request)(
            self.nc,
            self.agent.agent_id,
            msgpack.dumps(data or {"func": "ping"}),
            timeout,
        )
        return msgpack.loads(raw)

    def events(self):
        return SecurityEvent.objects.filter(
            kind="e2e_refused", agent_uid=self.agent.agent_id
        )


class TestEnvelope(EnvelopeBase):
    def test_mode_legacy_without_identity(self):
        self.agent.identity.delete()
        envelope.forget(self.agent)
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.LEGACY)
        data = {"func": "ping"}
        self.assertEqual(self.request(data), "pong")
        # the bytes of today, nothing else on the wire
        self.assertEqual(self.nc.sent, [(self.agent.agent_id, msgpack.dumps(data))])

    def test_mode_off_and_without_cap_is_legacy(self):
        set_sec2("off")
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.LEGACY)
        set_sec2("optional")
        envelope.forget(self.agent)
        AgentIdentity.objects.filter(agent=self.agent).update(caps=[])
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.LEGACY)

    def test_quarantined_identity_gets_nothing(self):
        AgentIdentity.objects.filter(agent=self.agent).update(state="quarantined")
        envelope.forget(self.agent)
        with patch("agents.models.nats.connect", return_value=self.nc):
            ret = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, timeout=1)
        self.assertEqual(ret, "timeout")
        self.assertEqual(self.nc.sent, [])

    def test_required_refuses_legacy_send(self):
        self.agent.identity.delete()
        set_sec2("required")
        envelope.forget(self.agent)
        with patch("agents.models.nats.connect", return_value=self.nc):
            ret = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, timeout=1)
            none = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, wait=False)
        self.assertEqual(ret, envelope.SEC2_REQUIRED)
        self.assertIsNone(none)
        self.assertEqual(self.nc.sent, [])

    def test_handshake_roundtrip_stores_session(self):
        self.assertEqual(self.request({"func": "ping"}), "pong")
        self.assertEqual(self.fake.hs1, 1)
        sid, e, q, data = self.fake.seen[0]
        self.assertEqual((e, q, data), (0, 1, {"func": "ping"}))
        sess = envelope._load(self.agent.agent_id)
        self.assertEqual(sess["sid"], sid)
        ident = AgentIdentity.objects.get(agent=self.agent)
        self.assertEqual(ident.pin_seq, 7)
        self.assertIsNotNone(ident.last_hs)
        # the next command reuses the session
        self.request()
        self.assertEqual(self.fake.hs1, 1)
        self.assertEqual(self.fake.seen[1][2], 2)

    def test_hs1_carries_rotate_pending(self):
        AgentIdentity.objects.filter(agent=self.agent).update(
            rotate_pending=["cert", "token"]
        )
        self.request()
        self.assertEqual(self.fake.hs1_body["rotate"], ["cert", "token"])

    def test_session_keys_wrapped_in_redis(self):
        self.request()
        rec = cache.get(f"e2e:{self.agent.agent_id}")
        k_s2a, k_a2s = self.fake.sessions[base64.b64decode(rec["sid"])]
        blob = json.dumps(rec)
        for key in (k_s2a, k_a2s):
            self.assertNotIn(B64(key).decode(), blob)
            self.assertNotIn(key.hex(), blob)
        self.assertEqual(
            base64.b64decode(decrypt_secret(rec["k_s2a"], envelope.SESSION_INFO)),
            k_s2a,
        )

    def test_seal_header_layout_and_sig(self):
        self.request()
        raw = self.nc.sent[-1][1]
        env = msgpack.loads(raw)
        self.assertEqual(
            sorted(env), sorted(["v", "y", "k", "s", "e", "q", "t", "n", "c", "g"])
        )
        self.assertEqual((env["v"], env["y"], env["e"], env["q"]), (2, "cmd", 0, 1))
        kid, _ = signing.command_signer()
        self.assertEqual(env["k"], kid)
        self.assertEqual((len(env["s"]), len(env["n"]), len(env["g"])), (16, 16, 64))
        self.assertLess(abs(env["t"] - envelope.now_ms()), 5000)
        head = (
            b"ulrmm-cmd-v2\0"
            + self.agent.agent_id.encode()
            + b"\0cmd\0"
            + kid.encode()
            + env["s"]
            + (0).to_bytes(4, "big")
            + (1).to_bytes(8, "big")
            + env["t"].to_bytes(8, "big")
            + env["n"]
        )
        Ed25519PublicKey.from_public_bytes(self.cmd_keys()[kid]).verify(
            env["g"], head + hashlib.sha256(env["c"]).digest()
        )
        self.assertNotIn(b"ping", raw)

    def test_seal_seq_unique_across_processes(self):
        self.request()
        other = LocMemCache(LOCMEM_CACHE["default"]["LOCATION"], {})
        qs = []
        for i in range(10):
            with patch.object(envelope, "cache", other if i % 2 else cache):
                _, ctx = async_to_sync(envelope.seal)(
                    self.nc, self.agent.agent_id, msgpack.dumps({"func": "ping"})
                )
            qs.append(ctx["q"])
        self.assertEqual(qs, list(range(2, 12)))

    def test_handshake_lock_single(self):
        async def many():
            return await asyncio.gather(
                *(
                    envelope.request(self.nc, self.agent.agent_id, msgpack.dumps(i), 5)
                    for i in range(5)
                )
            )

        out = async_to_sync(many)()
        self.assertEqual(self.fake.hs1, 1)
        self.assertEqual(len(out), 5)
        self.assertEqual(sorted(s[2] for s in self.fake.seen), [1, 2, 3, 4, 5])

    def test_open_reply_rejects_bad_sig(self):
        self.fake.reply_hook = lambda r: r.update(g=bytes(64))
        with self.assertRaises(envelope.Refused) as cm:
            self.request()
        self.assertEqual(cm.exception.answer, envelope.REPLY_REFUSED)
        self.assertTrue(self.events().exists())

    def test_open_reply_rejects_wrong_request_q(self):
        def other_q(reply):
            # a valid answer to another question of the same session
            k_a2s = self.fake.sessions[reply["s"]][1]
            head = envelope.reply_header(
                self.agent.agent_id, reply["s"], 0, reply["q"], 99
            )
            reply["c"] = ChaCha20Poly1305(k_a2s).encrypt(
                envelope.aead_nonce(0, reply["q"]), msgpack.dumps("pong"), head
            )
            reply["g"] = self.fake.id_key.sign(
                head + hashlib.sha256(reply["c"]).digest()
            )

        self.fake.reply_hook = other_q
        with self.assertRaises(envelope.Refused):
            self.request()

    def test_open_reply_rejects_bit_flip(self):
        def flip(reply):
            reply["c"] = bytes([reply["c"][0] ^ 1]) + reply["c"][1:]

        self.fake.reply_hook = flip
        with self.assertRaises(envelope.Refused):
            self.request()

    def test_agent_old_spec_bytes_accepted(self):
        self.fake.bin = False
        self.assertEqual(self.request(), "pong")
        sess = envelope._load(self.agent.agent_id)
        subject = f"{self.agent.agent_id}.terminal.x"
        raw = self.fake.frame(subject, sess["sid"], 0, 1, {"output": "o"})
        self.assertEqual(
            msgpack.loads(envelope.open_frame(self.agent, subject, raw)),
            {"output": "o"},
        )

    def test_agent_lost_session_handshakes_again(self):
        self.request()
        self.fake.sessions.clear()
        self.assertEqual(self.request(), "pong")
        self.assertEqual(self.fake.hs1, 2)

    def test_handshake_refuses_bad_hs2_sig(self):
        self.fake.wrong_hs2_key = True
        with self.assertRaises(envelope.Refused) as cm:
            self.request()
        self.assertEqual(cm.exception.answer, envelope.TIMEOUT)
        self.assertIsNone(envelope._load(self.agent.agent_id))
        self.assertIn("signature", self.events().get().detail)

    def test_handshake_accepts_prev_key_while_valid(self):
        old = AgentIdentity.objects.get(agent=self.agent)
        AgentIdentity.objects.filter(pk=old.pk).update(
            prev_ed25519=old.ed25519,
            ed25519=B64(bytes(32)).decode(),
            prev_until=djangotime.now() + dt.timedelta(minutes=10),
        )
        envelope.forget(self.agent)
        self.assertEqual(self.request(), "pong")
        AgentIdentity.objects.filter(pk=old.pk).update(
            prev_until=djangotime.now() - dt.timedelta(seconds=1)
        )
        envelope.forget(self.agent)
        with self.assertRaises(envelope.Refused):
            self.request()

    def test_handshake_refuses_old_ts(self):
        self.fake.ts_shift = -31_000
        with self.assertRaises(envelope.Refused):
            self.request()
        self.assertIn("clock", self.events().get().detail)

    def test_handshake_cfp_required_own_active_cert(self):
        sec = pki.security_settings()
        sec.mtls_mode = "required"
        sec.save()

        def cert(agent, fp):
            return baker.make(
                "deploy.AgentCertificate",
                agent=agent,
                fingerprint_sha1=fp,
                not_before=djangotime.now() - dt.timedelta(days=1),
                not_after=djangotime.now() + dt.timedelta(days=1),
            )

        own = cert(self.agent, "ab" * 20)
        foreign = cert(baker.make_recipe("agents.online_agent"), "cd" * 20)
        for cfp in ("", foreign.fingerprint_sha1):
            self.fake.cfp = cfp
            with self.assertRaises(envelope.Refused):
                self.request()
        self.assertIn("certificate", self.events().get().detail)
        # long after the websocket was admitted, no admission record left
        self.assertIsNone(cache.get(f"natsadm:{self.agent.agent_id}"))
        self.fake.cfp = own.fingerprint_sha1.upper()
        self.assertEqual(self.request(), "pong")
        # renewed while connected: the session names the new certificate
        renewed = cert(self.agent, "ef" * 20)
        envelope.forget(self.agent)
        self.fake.cfp = renewed.fingerprint_sha1
        self.assertEqual(self.request(), "pong")

    def test_sec2_off_seals_until_agent_reports_off_pins(self):
        PinSet.objects.create(seq=7, sec2="optional")
        PinSet.objects.create(seq=8, sec2="off")
        self.assertEqual(self.request(), "pong")
        set_sec2("off")
        envelope.forget(self.agent)
        # still armed with pin document 7: plaintext would be refused
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.SEC2)
        self.assertEqual(self.request(), "pong")
        self.assertEqual(self.fake.hs1, 2)
        self.fake.pin_seq = 8
        envelope.forget(self.agent)
        self.assertEqual(self.request(), "pong")
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.LEGACY)
        AgentIdentity.objects.filter(agent=self.agent).update(pin_seq=99)
        envelope.forget(self.agent)
        self.assertEqual(envelope.target(self.agent)["mode"], envelope.LEGACY)

    @override_settings(E2E_REKEY_MESSAGES=3)
    def test_ratchet_messages(self):
        for _ in range(7):
            self.assertEqual(self.request(), "pong")
        self.assertEqual(
            [(e, q) for _, e, q, _ in self.fake.seen],
            [(0, 1), (0, 2), (0, 3), (1, 1), (1, 2), (1, 3), (2, 1)],
        )
        self.assertEqual(envelope._load(self.agent.agent_id)["e"], 2)
        self.assertEqual(self.fake.hs1, 1)

    def test_ratchet_bytes(self):
        sec = pki.security_settings()
        sec.rekey_mb = 1
        sec.save()
        self.request({"func": "x" * 600_000})
        self.request({"func": "x" * 600_000})
        self.assertEqual([e for _, e, _, _ in self.fake.seen], [0, 1])

    def test_rekey_limits_fixed_at_handshake(self):
        self.request()
        sess = envelope._load(self.agent.agent_id)
        self.assertEqual((sess["rekey"], sess["rekey_b"]), (3600, 64 << 20))
        sec = pki.security_settings()
        sec.rekey_minutes = 5
        sec.save()
        # the running session keeps its limits, the next handshake gets new ones
        self.request()
        self.assertEqual(self.fake.hs1, 1)
        envelope.forget(self.agent)
        self.request()
        self.assertEqual(envelope._load(self.agent.agent_id)["rekey"], 300)

    def test_time_rekey_new_sid_overlap(self):
        self.request()
        first = envelope._load(self.agent.agent_id)
        envelope._store(
            self.agent.agent_id, {**first, "created": first["created"] - 3_601_000}
        )
        self.request()
        self.assertEqual(self.fake.hs1, 2)
        cur = envelope._load(self.agent.agent_id)
        prev = envelope._load(self.agent.agent_id, prev=True)
        self.assertNotEqual(cur["sid"], first["sid"])
        self.assertEqual(prev["sid"], first["sid"])
        # a frame still in flight on the old session opens
        subject = f"{self.agent.agent_id}.terminal.x"
        raw = self.fake.frame(subject, first["sid"], 0, 1, {"output": "late"})
        self.assertEqual(
            msgpack.loads(envelope.open_frame(self.agent, subject, raw)),
            {"output": "late"},
        )

    def test_frame_aead(self):
        self.request()
        sess = envelope._load(self.agent.agent_id)
        subject = f"{self.agent.agent_id}.cmdoutput.c1"
        raw = self.fake.frame(subject, sess["sid"], 0, 1, {"line": "hi"})
        self.assertEqual(
            msgpack.loads(envelope.open_frame(self.agent, subject, raw)), {"line": "hi"}
        )
        # bound to the subject
        with self.assertRaises(envelope.Refused):
            envelope.open_frame(self.agent, subject + "x", raw)
        with self.assertRaises(envelope.Refused):
            envelope.open_frame(self.agent, subject, msgpack.dumps({"line": "plain"}))

    def test_only_a_frame_that_decrypts_moves_the_epoch(self):
        self.request()
        sess = envelope._load(self.agent.agent_id)
        subject = f"{self.agent.agent_id}.cmdoutput.c1"
        e = envelope.MAX_EPOCH
        bad = self.fake.dumps(
            {"v": 2, "s": sess["sid"], "e": e, "q": 1, "c": b"x" * 32}
        )
        with self.assertRaises(envelope.Refused):
            envelope.open_frame(self.agent, subject, bad)
        self.assertEqual(envelope._load(self.agent.agent_id)["e"], sess["e"])
        raw = self.fake.frame(subject, sess["sid"], sess["e"] + 1, 1, {"line": "hi"})
        envelope.open_frame(self.agent, subject, raw)
        self.assertEqual(envelope._load(self.agent.agent_id)["e"], sess["e"] + 1)

    def test_nats_cmd_sec2_roundtrip(self):
        with patch("agents.models.nats.connect", return_value=self.nc):
            ret = async_to_sync(self.agent.nats_cmd)(
                {"func": "runscriptfull", "env_vars": ["SECRET=marker123"]}, timeout=5
            )
            none = async_to_sync(self.agent.nats_cmd)({"func": "ping"}, wait=False)
        self.assertEqual(ret, "pong")
        self.assertIsNone(none)
        self.assertEqual(self.fake.seen[0][3]["env_vars"], ["SECRET=marker123"])
        self.assertEqual(self.fake.seen[1][3], {"func": "ping"})
        self.assertFalse(any(b"marker123" in p for _, p in self.nc.sent))

    def test_a_nats_cmd_sec2(self):
        out = async_to_sync(a_nats_cmd)(
            nc=self.nc, sub=self.agent.agent_id, data={"func": "ping"}, timeout=5
        )
        self.assertEqual(out, "pong")
        self.assertEqual(self.fake.hs1, 1)

    def test_bulk_seals_per_agent(self):
        second = baker.make_recipe("agents.online_agent")
        fake2 = FakeAgent(second.agent_id, self.cmd_keys(), master=b"\x09" * 32)
        fake2.identity(second)
        legacy = baker.make_recipe("agents.online_agent")
        nc = FakeNats(self.fake, fake2)
        items = [
            (self.agent.agent_id, {"func": "a"}),
            (second.agent_id, {"func": "b"}),
            (legacy.agent_id, {"func": "c"}),
        ]
        with patch("ulrmm.nats_utils.nats.connect", return_value=nc):
            async_to_sync(abulk_nats_command)(items=items)
        self.assertEqual(self.fake.seen[0][3], {"func": "a"})
        self.assertEqual(fake2.seen[0][3], {"func": "b"})
        self.assertIn((legacy.agent_id, msgpack.dumps({"func": "c"})), nc.sent)
        cmds = [msgpack.loads(p) for s, p in nc.sent if s != legacy.agent_id]
        self.assertEqual(len([c for c in cmds if c.get("y") == "cmd"]), 2)

    def test_stream_frames_opened(self):
        layer = SimpleNamespace(group_send=AsyncMock())
        subject = f"{self.agent.agent_id}.cmdoutput.c9"
        stop = asyncio.Event()

        async def run():
            task = asyncio.ensure_future(
                self.agent.nats_stream_cmd(
                    {"func": "rawcmd", "payload": {"cmd_id": "c9"}},
                    timeout=5,
                    stop_evt=stop,
                    output_subject=subject,
                    group="g",
                )
            )
            while subject not in self.nc.subs or not self.fake.seen:
                await asyncio.sleep(0.01)
            sid, e, _, _ = self.fake.seen[0]
            cb = self.nc.subs[subject]
            raw = self.fake.frame(subject, sid, e, 1, {"line": "out", "done": True})
            await cb(SimpleNamespace(subject=subject, data=raw))
            await cb(SimpleNamespace(subject=subject, data=msgpack.dumps("plain")))
            stop.set()
            await task

        with patch("agents.models.nats.connect", return_value=self.nc), patch(
            "agents.models.get_channel_layer", return_value=layer
        ):
            # the stream command is published; a handshake request comes first
            async_to_sync(run)()
        sent = [c.args[1] for c in layer.group_send.await_args_list]
        self.assertEqual(
            sent,
            [{"type": "stream_output", "cmd_id": "c9", "output": "out", "done": True}],
        )
        self.assertTrue(self.events().exists())

    def test_terminal_publish_sealed_and_frames_opened(self):
        from agents.consumers import TerminalStreamConsumer

        term = TerminalStreamConsumer()
        term.agent_id, term.session_id, term.group_name = self.agent.agent_id, "s1", "g"
        term.nc = self.nc
        term.channel_layer = SimpleNamespace(group_send=AsyncMock())
        subject = f"{self.agent.agent_id}.terminal.s1"

        async def run():
            term._sealed = await envelope.amode(term.agent_id) != envelope.LEGACY
            await term._nats_publish(
                {
                    "func": "terminal_input",
                    "payload": {"session_id": "s1", "data": "ls"},
                }
            )
            sid, e, _, _ = self.fake.seen[0]
            raw = self.fake.frame(subject, sid, e, 1, {"output": "hi"})
            await term._on_output(SimpleNamespace(subject=subject, data=raw))
            plain = msgpack.dumps({"output": "plain"})
            await term._on_output(SimpleNamespace(subject=subject, data=plain))

        async_to_sync(run)()
        self.assertEqual(self.fake.seen[0][3]["payload"]["data"], "ls")
        self.assertIsNotNone(term._e2e)
        sent = [c.args[1] for c in term.channel_layer.group_send.await_args_list]
        self.assertEqual([x["output"] for x in sent], ["hi"])
        self.assertTrue(term._frame_refused)

    def test_orphan_sweep_sealed(self):
        from autotasks.tasks import _remove_orphans
        from ulrmm.agent_ident import agent_task_prefix

        name = f"{agent_task_prefix()}orphan"
        self.fake.answer = [name]
        with patch("autotasks.tasks.nats.connect", return_value=self.nc):
            async_to_sync(_remove_orphans)({self.agent.agent_id: set()})
        funcs = [x[3]["func"] for x in self.fake.seen]
        self.assertEqual(funcs, ["listschedtasks", "delschedtask"])
        self.assertEqual(self.fake.seen[1][3]["schedtaskpayload"], {"name": name})


class TestSealResponse(EnvelopeBase):
    def _get(self, **headers):
        req = RequestFactory().get(
            f"/api/v4/{self.agent.agent_id}/pkgjob/1/", **headers
        )
        return envelope.seal_response(self.agent, req, {"plan": [1, 2]})

    def test_seal_response_and_agent_vector(self):
        r = self._get(HTTP_X_ULRMM_SEAL="1")
        self.assertEqual(r["X-ULRMM-Sealed"], "1")
        body = r.data
        kid = body["kid"]
        e, c, g = (base64.b64decode(body[k]) for k in ("e", "c", "g"))
        path = f"/api/v4/{self.agent.agent_id}/pkgjob/1/".encode()
        Ed25519PublicKey.from_public_bytes(self.cmd_keys()[kid]).verify(
            g,
            b"ulrmm-seal-v1\0"
            + self.agent.agent_id.encode()
            + b"\0"
            + path
            + e
            + body["t"].to_bytes(8, "big")
            + hashlib.sha256(c).digest(),
        )
        shared = self.fake.x_key.exchange(X25519PublicKey.from_public_bytes(e))
        key = envelope.hkdf(
            shared, b"", b"ulrmm seal v1\0" + self.agent.agent_id.encode() + path
        )
        plain = ChaCha20Poly1305(key).decrypt(bytes(12), c, path)
        self.assertEqual(json.loads(plain), {"plan": [1, 2]})

    def test_unsealed_without_header_or_identity(self):
        self.assertEqual(self._get().data, {"plan": [1, 2]})
        AgentIdentity.objects.filter(agent=self.agent).update(state="quarantined")
        envelope.forget(self.agent)
        r = self._get(HTTP_X_ULRMM_SEAL="1")
        self.assertEqual(r.data, {"plan": [1, 2]})
        self.assertFalse(r.has_header("X-ULRMM-Sealed"))

    def test_pkgjob_plan_sealed(self):
        from packages import jobs
        from packages.tests.test_jobs import package, queued
        from packages.utils import agent_lock

        self.setup_client()
        self.authenticate_agent(self.agent)
        install = queued(package(), self.agent)
        cache.add(agent_lock(self.agent.agent_id), install.pk, 60)
        jobs.start(install)
        url = f"/api/v4/{self.agent.agent_id}/pkgjob/{install.pk}/"
        plain = self.client.get(url)
        self.assertEqual(plain.status_code, 200, plain.data)
        self.assertIn("run", plain.data)
        sealed = self.client.get(url, HTTP_X_ULRMM_SEAL="1")
        self.assertEqual(sealed["X-ULRMM-Sealed"], "1")
        self.assertEqual(sorted(sealed.data), ["c", "e", "g", "kid", "t", "v"])


@override_settings(CACHES=LOCMEM_CACHE)
class TestCommandKeys(ULRMMTestCase):
    def setUp(self):
        cache.clear()

    def test_created_lazily_and_encrypted(self):
        self.assertFalse(CommandKey.objects.exists())
        kid, key = signing.command_signer()
        row = CommandKey.objects.get()
        self.assertEqual((row.kid, row.state), (kid, "current"))
        raw = key.private_bytes_raw()
        self.assertNotIn(B64(raw).decode(), row.seed)
        self.assertEqual(signing.command_signer()[0], kid)

    def test_command_key_rotation_promote_rules(self):
        cur = signing.current_command_key()
        agent = baker.make_recipe("agents.online_agent")
        FakeAgent(agent.agent_id, {}).identity(agent, pin_seq=1)
        signing.pin_document()
        nxt = signing.rotate_command_key()
        self.assertEqual(signing.rotate_command_key().pk, nxt.pk)
        listed = jws_parts(signing.pin_document())[1]
        self.assertEqual(
            [(c["kid"], c["state"]) for c in listed["cmd"]],
            [(cur.kid, "current"), (nxt.kid, "next")],
        )
        self.assertEqual(signing.promote_command_keys(), "waiting")
        # every sec2 agent has the document listing the next key
        AgentIdentity.objects.update(pin_seq=listed["seq"])
        self.assertEqual(signing.promote_command_keys(), f"promoted {nxt.kid}")
        cur.refresh_from_db()
        nxt.refresh_from_db()
        self.assertEqual((cur.state, nxt.state), ("retired", "current"))
        self.assertEqual(signing.command_signer()[0], nxt.kid)
        self.assertTrue(SecurityEvent.objects.filter(kind="command_key_rotated"))
        # 24 h after its creation a next key is promoted regardless
        third = signing.rotate_command_key()
        CommandKey.objects.filter(pk=third.pk).update(
            created=djangotime.now() - dt.timedelta(hours=25)
        )
        self.assertEqual(signing.promote_command_keys(), f"promoted {third.kid}")
        # retired keys stay listed for 7 days
        CommandKey.objects.filter(pk=cur.pk).update(
            retired_at=djangotime.now() - dt.timedelta(days=8)
        )
        kids = {c["kid"] for c in signing.command_claim()}
        self.assertEqual(kids, {nxt.kid, third.kid})
        self.assertEqual(signing.promote_command_keys(), "nothing to promote")

    def test_pin_doc_carries_cmd_and_sec2(self):
        claims = jws_parts(signing.pin_document())[1]
        kid, key = signing.command_signer()
        self.assertEqual(
            claims["cmd"],
            [{"kid": kid, "ed": B64(_raw_pub(key)).decode(), "state": "current"}],
        )
        self.assertEqual(
            (claims["sec2"], claims["v"], claims["seq"]), ("optional", 1, 1)
        )
        set_sec2("required")
        claims = jws_parts(signing.pin_document())[1]
        self.assertEqual((claims["sec2"], claims["seq"]), ("required", 2))
        self.assertEqual(PinSet.objects.get(seq=2).sec2, "required")

    def test_management_command(self):
        out = StringIO()
        call_command("command_key", "rotate", stdout=out)
        self.assertEqual(CommandKey.objects.filter(state="next").count(), 1)
        call_command("command_key", "promote", stdout=out)
        self.assertIn("waiting", out.getvalue())
        call_command("command_key", "list", stdout=out)
        self.assertEqual(out.getvalue().count(" current "), 3)

    def test_promote_task(self):
        from deploy.tasks import promote_command_keys

        self.assertEqual(promote_command_keys(), "nothing to promote")

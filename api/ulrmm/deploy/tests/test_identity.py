# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import binascii
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from accounts.models import User
from deploy import identity, pki, tokens
from deploy.models import (
    AgentCredential,
    AgentIdentity,
    IdentityState,
    SecurityEvent,
)
from deploy.tests.test_mtls import csr_pem, seen, set_mode, tls
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.utils import nats_config

RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
VECTORS = Path(__file__).with_name("vectors_sec2.json")


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(*RAW)


def nkey_string(pub: bytes, prefix: int = 0xA0) -> str:
    raw = bytes([prefix]) + pub
    return base64.b32encode(
        raw + binascii.crc_hqx(raw, 0).to_bytes(2, "little")
    ).decode()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def now_ms() -> int:
    return int(time.time() * 1000)


class Keys:
    """An agent's identity, sealing and nkey keys."""

    def __init__(self):
        self.ed = Ed25519PrivateKey.generate()
        self.x = X25519PrivateKey.generate()
        self.nk = Ed25519PrivateKey.generate()
        self.ed_raw, self.x_raw = raw_public(self.ed), raw_public(self.x)
        self.nkey = nkey_string(raw_public(self.nk))
        self.kid = identity.kid_of(self.ed_raw)

    def body(self, agent_id, *, ts=None, rotate_from=None, caps=("sec2",)) -> dict:
        ts = now_ms() if ts is None else ts
        message = identity.registration_message(
            agent_id, self.ed_raw, self.x_raw, self.nkey, ts
        )
        body = {
            "ed25519": b64(self.ed_raw),
            "x25519": b64(self.x_raw),
            "nkey": self.nkey,
            "caps": list(caps),
            "idreg": "",
            "ts": ts,
            "sig": b64(self.ed.sign(message)),
            "nsig": b64(self.nk.sign(message)),
        }
        if rotate_from is not None:
            rot = identity.rotation_message(
                agent_id, self.ed_raw, self.x_raw, self.nkey, ts
            )
            body["idreg"] = b64(rotate_from.ed.sign(rot))
        return body


def store_identity(agent, keys, **fields) -> AgentIdentity:
    return AgentIdentity.objects.create(
        agent=agent,
        ed25519=b64(keys.ed_raw),
        x25519=b64(keys.x_raw),
        nkey=keys.nkey,
        kid=keys.kid,
        caps=["sec2"],
        **fields,
    )


@override_settings(CACHES=LOCMEM_CACHE)
class AgentBase(ULRMMTestCase):
    """An agent with its user and a legacy credential, a CA for its certs."""

    def setUp(self):
        cache.clear()
        self.setup_client()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        override = override_settings(AGENT_CA_DIR=tmp.name)
        override.enable()
        self.addCleanup(override.disable)
        pki.ensure_ca()
        self.agent, self.token = self.new_agent()
        self.keys = Keys()
        reload = patch("ulrmm.utils.reload_nats")
        self.reload = reload.start()
        self.addCleanup(reload.stop)
        forget = patch("deploy.identity._forget")
        self.forget = forget.start()
        self.addCleanup(forget.stop)

    def new_agent(self):
        agent = baker.make_recipe("agents.online_agent")
        User.objects.create_user(
            username=agent.agent_id, agent=agent, password="x" * 40
        )
        return agent, tokens.create_legacy(agent)

    def as_agent(self, token=None):
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token or self.token}")

    def cert_for(self, agent=None):
        agent = agent or self.agent
        pki.issue(agent, csr_pem())
        return agent.certificates.get(revoked_at=None)

    def event(self, kind):
        return SecurityEvent.objects.filter(kind=kind).first()


class TestRegister(AgentBase):
    def setUp(self):
        super().setUp()
        self.as_agent()
        self.url = f"/api/v3/{self.agent.agent_id}/identity/"

    def post(self, body, **meta):
        return self.client.post(self.url, body, format="json", **meta)

    def test_register_new_201(self):
        r = self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual((r.data["kid"], r.data["state"]), (self.keys.kid, "active"))
        self.assertEqual(r.data["sec2"], "optional")
        self.assertEqual(r.data["rotate"], [])
        self.assertIn("now_ms", r.data)
        ident = AgentIdentity.objects.get(agent=self.agent)
        self.assertEqual((ident.nkey, ident.caps), (self.keys.nkey, ["sec2"]))
        self.assertEqual(ident.ed25519, b64(self.keys.ed_raw))
        self.assertIsNotNone(self.event("identity_registered"))

    def test_register_other_agents_url_404(self):
        other, _ = self.new_agent()
        r = self.client.post(
            f"/api/v3/{other.agent_id}/identity/",
            self.keys.body(other.agent_id),
            format="json",
        )
        self.assertEqual(r.status_code, 404)
        self.assertFalse(AgentIdentity.objects.exists())

    def test_register_idempotent_same_keys_200(self):
        self.assertEqual(
            self.post(self.keys.body(self.agent.agent_id)).status_code, 201
        )
        r = self.post(self.keys.body(self.agent.agent_id, caps=["sec2", "x"]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(AgentIdentity.objects.get().caps, ["sec2", "x"])

    def test_register_conflict_409_records_event(self):
        store_identity(self.agent, self.keys)
        other = Keys()
        r = self.post(other.body(self.agent.agent_id))
        self.assertEqual((r.status_code, r.data), (409, identity.CONFLICT))
        ident = AgentIdentity.objects.get()
        self.assertEqual(ident.kid, self.keys.kid)
        event = self.event("identity_conflict")
        self.assertEqual(event.severity, "high")
        self.assertEqual(
            event.detail, f"kid {self.keys.kid} registered, {other.kid} offered"
        )

    def test_register_rotation_with_idreg(self):
        store_identity(self.agent, self.keys, rotate_pending=["identity", "cert"])
        new = Keys()
        r = self.post(new.body(self.agent.agent_id, rotate_from=self.keys))
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["rotate"], ["cert"])
        ident = AgentIdentity.objects.get()
        self.assertEqual((ident.kid, ident.nkey), (new.kid, new.nkey))
        self.assertEqual(ident.prev_ed25519, b64(self.keys.ed_raw))
        self.assertGreater(ident.prev_until, djangotime.now())
        self.assertIsNotNone(ident.rotated_at)
        self.assertIsNotNone(self.event("identity_rotated"))

    def test_register_rotation_bad_idreg_409(self):
        store_identity(self.agent, self.keys)
        new = Keys()
        # signed by the new key instead of the stored one
        r = self.post(new.body(self.agent.agent_id, rotate_from=new))
        self.assertEqual(r.status_code, 409)
        self.assertEqual(AgentIdentity.objects.get().kid, self.keys.kid)
        self.assertIsNotNone(self.event("identity_conflict"))

    def test_register_after_release_window(self):
        later = djangotime.now() + identity.RELEASE_TIME
        store_identity(
            self.agent,
            self.keys,
            state=IdentityState.QUARANTINED,
            quarantined_at=djangotime.now(),
            reason="x",
            release_until=later,
        )
        new = Keys()
        r = self.post(new.body(self.agent.agent_id))
        self.assertEqual(r.status_code, 201, r.data)
        ident = AgentIdentity.objects.get()
        self.assertEqual((ident.kid, ident.state), (new.kid, "active"))
        self.assertEqual((ident.prev_ed25519, ident.reason), ("", ""))
        self.assertIsNone(ident.quarantined_at)

    def test_register_quarantine_without_window_403(self):
        store_identity(self.agent, self.keys, state=IdentityState.QUARANTINED)
        r = self.post(Keys().body(self.agent.agent_id))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data["detail"], "quarantined")

    def test_register_blocked_403(self):
        store_identity(self.agent, self.keys, state=IdentityState.BLOCKED)
        AgentCredential.objects.filter(agent=self.agent).update(revoked_at=None)
        with patch("ulrmm.auth.AgentTokenAuthentication._identity_check"):
            r = self.post(Keys().body(self.agent.agent_id))
        self.assertEqual((r.status_code, r.data["detail"]), (403, "blocked"))

    def test_register_quarantined_same_keys_403(self):
        store_identity(
            self.agent,
            self.keys,
            state=IdentityState.QUARANTINED,
            release_until=djangotime.now() + identity.RELEASE_TIME,
        )
        r = self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual((r.status_code, r.data["detail"]), (403, "quarantined"))

    def test_register_needs_presented_cert(self):
        cert = self.cert_for()
        seen(cert)
        r = self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            r.data["detail"], "identity needs the current client certificate"
        )
        self.assertIsNotNone(self.event("cert_refused"))
        r = self.post(self.keys.body(self.agent.agent_id), **tls(cert))
        self.assertEqual(r.status_code, 201)

    def test_register_cert_rule_off_mode(self):
        seen(self.cert_for())
        set_mode("off")
        cache.clear()
        self.assertEqual(
            self.post(self.keys.body(self.agent.agent_id)).status_code, 201
        )

    def test_register_clock_400_returns_now_ms(self):
        r = self.post(self.keys.body(self.agent.agent_id, ts=now_ms() - 31_000))
        self.assertEqual((r.status_code, r.data["detail"]), (400, "clock"))
        self.assertAlmostEqual(r.data["now_ms"], now_ms(), delta=5000)
        self.assertFalse(AgentIdentity.objects.exists())

    def test_register_bad_sig(self):
        body = self.keys.body(self.agent.agent_id)
        body["sig"] = b64(Keys().ed.sign(b"x"))
        r = self.post(body)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "signature"))

    def test_register_bad_nsig(self):
        body = self.keys.body(self.agent.agent_id)
        body["nsig"] = body["sig"]
        r = self.post(body)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "signature"))

    def test_register_bad_nkey_crc(self):
        body = self.keys.body(self.agent.agent_id)
        raw = bytearray(base64.b32decode(body["nkey"]))
        raw[-1] ^= 1
        body["nkey"] = base64.b32encode(bytes(raw)).decode()
        r = self.post(body)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "nkey invalid"))

    def test_register_nkey_wrong_prefix(self):
        body = self.keys.body(self.agent.agent_id)
        # an account key ("A...", prefix 0 << 3) with a valid checksum
        body["nkey"] = nkey_string(raw_public(self.keys.nk), prefix=0)
        r = self.post(body)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "nkey invalid"))

    def test_register_shapes(self):
        good = self.keys.body(self.agent.agent_id)
        cases = {
            "ed25519": b64(b"x" * 31),
            "x25519": b64(bytes(32)),
            "ts": True,
            "sig": "!!",
            "caps": ["x" * 17],
            "idreg": b64(b"x" * 10),
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                r = self.post({**good, field: value})
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.data["detail"], f"{field} invalid")

    def test_nkey_in_use_409(self):
        other, _ = self.new_agent()
        store_identity(other, self.keys)
        r = self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual((r.status_code, r.data["detail"]), (409, "nkey in use"))
        self.assertFalse(AgentIdentity.objects.filter(agent=self.agent).exists())
        self.assertIsNotNone(self.event("identity_conflict"))

    def test_register_clears_legacy_nats_and_reloads(self):
        self.assertTrue(AgentCredential.objects.get(agent=self.agent).legacy_nats)
        with self.captureOnCommitCallbacks(execute=True):
            r = self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(AgentCredential.objects.get(agent=self.agent).legacy_nats, "")
        self.reload.assert_called_once_with()
        self.forget.assert_called_once_with(self.agent.agent_id)
        # a retry with the same keys changes nothing
        self.reload.reset_mock()
        with self.captureOnCommitCallbacks(execute=True):
            self.post(self.keys.body(self.agent.agent_id))
        self.reload.assert_not_called()

    def test_register_throttled(self):
        for _ in range(20):
            self.post(self.keys.body(self.agent.agent_id))
        self.assertEqual(
            self.post(self.keys.body(self.agent.agent_id)).status_code, 429
        )


class TestNkey(ULRMMTestCase):
    def test_nkey_vectors(self):
        v = json.loads(VECTORS.read_text())
        ident, agent_id = v["identity"], v["agent_id"]
        nkey_raw = identity.nkey_public(ident["nkey"])
        self.assertEqual(nkey_raw.hex(), ident["nkey_public"])
        ed_raw = bytes.fromhex(ident["ed25519"])
        x_raw = bytes.fromhex(ident["x25519"])
        self.assertEqual(identity.kid_of(ed_raw), ident["kid"])
        message = identity.registration_message(
            agent_id, ed_raw, x_raw, ident["nkey"], ident["idreg_ts"]
        )
        self.assertEqual(message.hex(), ident["idreg_message"])
        Ed25519PublicKey.from_public_bytes(ed_raw).verify(
            bytes.fromhex(ident["sig"]), message
        )
        Ed25519PublicKey.from_public_bytes(nkey_raw).verify(
            bytes.fromhex(ident["nsig"]), message
        )
        seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ident["nkey_seed"]))
        self.assertEqual(nkey_string(raw_public(seed)), ident["nkey"])

    def test_nkey_rejects(self):
        good = nkey_string(bytes(range(32)))
        self.assertEqual(identity.nkey_public(good), bytes(range(32)))
        for bad in (good[:-1], "A" + good[1:], good.lower(), 56 * "U", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                identity.nkey_public(bad)


@override_settings(CACHES=LOCMEM_CACHE)
class TestNatsConfig(AgentBase):
    def users(self):
        return {
            u.get("user") or u.get("nkey"): u
            for u in nats_config()["authorization"]["users"]
        }

    def test_nats_config_nkey_user_websocket_only(self):
        store_identity(self.agent, self.keys)
        AgentCredential.objects.filter(agent=self.agent).update(legacy_nats="")
        users = self.users()
        self.assertNotIn(self.agent.agent_id, users)
        user = users[self.keys.nkey]
        self.assertEqual(user["allowed_connection_types"], ["WEBSOCKET"])
        self.assertNotIn("password", user)
        self.assertEqual(
            user["permissions"]["subscribe"], {"allow": [self.agent.agent_id]}
        )
        self.assertIn(
            f"{self.agent.agent_id}.checkin", user["permissions"]["publish"]["allow"]
        )

    @override_settings(USE_NATS_STANDARD=True)
    def test_nats_config_standard_allows_both(self):
        store_identity(self.agent, self.keys)
        user = self.users()[self.keys.nkey]
        self.assertEqual(user["allowed_connection_types"], ["STANDARD", "WEBSOCKET"])

    def test_nats_config_quarantined_left_out(self):
        for state in (IdentityState.QUARANTINED, IdentityState.BLOCKED):
            with self.subTest(state=state):
                AgentIdentity.objects.all().delete()
                store_identity(self.agent, self.keys, state=state)
                users = self.users()
                self.assertNotIn(self.keys.nkey, users)
                # the legacy password does not come back either
                self.assertNotIn(self.agent.agent_id, users)

    def test_nats_config_legacy_password_from_encrypted_copy(self):
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertNotIn(self.token, cred.legacy_nats)
        user = self.users()[self.agent.agent_id]
        self.assertEqual(user["password"], self.token)
        self.assertNotIn("allowed_connection_types", user)

    def test_nats_config_unreadable_password_skipped(self):
        AgentCredential.objects.filter(agent=self.agent).update(legacy_nats="garbage")
        self.assertNotIn(self.agent.agent_id, self.users())

    def test_nats_config_required_drops_password_users(self):
        other, _ = self.new_agent()
        store_identity(other, self.keys)
        sec = pki.security_settings()
        sec.sec2_mode = "required"
        sec.save()
        users = self.users()
        self.assertNotIn(self.agent.agent_id, users)
        self.assertIn(self.keys.nkey, users)

    def test_nats_config_drf_token_without_credential(self):
        from rest_framework.authtoken.models import Token

        AgentCredential.objects.filter(agent=self.agent).delete()
        key = Token.objects.create(user=self.agent.user).key
        self.assertEqual(self.users()[self.agent.agent_id]["password"], key)


@override_settings(CACHES=LOCMEM_CACHE)
class TestNatsAuth(AgentBase):
    url = "/api/v3/natsauth/"

    def setUp(self):
        super().setUp()
        self.client.credentials()
        self.cert = self.cert_for()

    def get(self, uri=None, cert=None):
        meta = tls(cert) if cert else {}
        if uri is not None:
            meta["ULRMM_NATS_URI"] = uri
        return self.client.get(self.url, **meta)

    def bound(self, agent=None):
        return f"/natsws/{(agent or self.agent).agent_id}"

    def test_natsauth_bound_path_foreign_cert_403(self):
        other, _ = self.new_agent()
        foreign = self.cert_for(other)
        r = self.get(self.bound(), foreign)
        self.assertEqual(r.status_code, 403)
        event = self.event("nats_refused")
        self.assertEqual(
            event.detail,
            f"certificate of {other.agent_id} used for {self.agent.agent_id}",
        )

    def test_natsauth_bound_path_own_cert(self):
        r = self.get(self.bound(), self.cert)
        self.assertEqual(r.status_code, 204)
        self.cert.refresh_from_db()
        self.assertIsNotNone(self.cert.last_seen)

    def test_natsauth_bound_path_modes(self):
        # optional without a certificate passes, required does not
        self.assertEqual(self.get(self.bound()).status_code, 204)
        set_mode("required")
        cache.clear()
        self.assertEqual(self.get(self.bound()).status_code, 403)
        self.assertEqual(self.event("nats_refused").detail, "no client certificate")
        set_mode("off")
        cache.clear()
        other, _ = self.new_agent()
        self.assertEqual(self.get(self.bound(), self.cert_for(other)).status_code, 204)

    def test_natsauth_bound_path_quarantined_403_every_mode(self):
        store_identity(self.agent, self.keys, state=IdentityState.QUARANTINED)
        for mode in ("off", "optional", "required"):
            with self.subTest(mode=mode):
                set_mode(mode)
                cache.clear()
                self.assertEqual(self.get(self.bound(), self.cert).status_code, 403)

    def test_natsauth_legacy_path_unchanged(self):
        other, _ = self.new_agent()
        foreign = self.cert_for(other)
        self.assertEqual(self.get("/natsws", foreign).status_code, 204)
        self.assertEqual(self.get("/natsws").status_code, 204)
        set_mode("required")
        cache.clear()
        # any agent's active certificate, as before
        self.assertEqual(self.get("/natsws", foreign).status_code, 204)
        self.assertEqual(self.get(None).status_code, 403)
        self.assertEqual(self.get("/natsws/../x").status_code, 403)

    def test_natsauth_bound_path_query_and_odd_paths(self):
        other, _ = self.new_agent()
        foreign = self.cert_for(other)
        # the query does not hide the bound path from the certificate rule
        self.assertEqual(self.get(self.bound() + "?x=1", foreign).status_code, 403)
        self.assertEqual(self.get(self.bound() + "?x=1", self.cert).status_code, 204)
        # anything else under /natsws/ never falls back to the legacy rule
        self.assertEqual(self.get("/natsws/%41bc", foreign).status_code, 403)
        self.assertEqual(self.get("/natsws/short", self.cert).status_code, 403)

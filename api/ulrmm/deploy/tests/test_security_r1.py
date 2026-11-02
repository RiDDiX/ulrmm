# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import json
from io import StringIO
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from django.core.cache import cache
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed

from accounts.models import User
from accounts.utils import grant_console_stepup
from deploy import events, pki, signing
from deploy.models import PinSet, SecurityEvent
from deploy.tasks import prune_security_events
from deploy.tests.conftest import TEST_PINS
from deploy.tests.test_mtls import CABase, csr_pem, set_mode, tls
from deploy.models import MtlsMode
from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

PIN_B = base64.b64encode(b"b" * 32).decode()
PIN_C = base64.b64encode(b"c" * 32).decode()
EVENTS = "/deploy/security/events/"


def jws_parts(token: str):
    """(header, claims) of a JWS this server signed; raises on a bad signature."""
    h, c, s = token.split(".")
    unb64 = lambda p: base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))  # noqa
    signing.signing_key().public_key().verify(unb64(s), f"{h}.{c}".encode())
    return json.loads(unb64(h)), json.loads(unb64(c))


def set_backup(pins):
    sec = pki.security_settings()
    sec.backup_pins = pins
    sec.save()


class TestPinDocument(ULRMMTestCase):
    def test_signed_document(self):
        header, claims = jws_parts(signing.pin_document())
        self.assertEqual(header["typ"], "ulrmm-pins")
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["kid"], signing.key_id())
        self.assertEqual(claims["typ"], "ulrmm-pins")
        self.assertEqual(claims["v"], 1)
        self.assertEqual(claims["iss"], signing.api_url())
        self.assertTrue(claims["iss"].startswith("https://"))
        self.assertEqual(claims["primary"], TEST_PINS)
        self.assertEqual(claims["backup"], [])
        self.assertEqual(claims["seq"], 1)
        self.assertIsInstance(claims["iat"], int)

    def test_tampered_document_fails(self):
        h, c, s = signing.pin_document().split(".")
        claims = json.loads(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
        claims["seq"] = 99
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        with self.assertRaises(InvalidSignature):
            jws_parts(f"{h}.{forged.decode()}.{s}")

    def test_seq_follows_changes(self):
        self.assertEqual(jws_parts(signing.pin_document())[1]["seq"], 1)
        self.assertEqual(jws_parts(signing.pin_document())[1]["seq"], 1)
        set_backup([PIN_B])
        claims = jws_parts(signing.pin_document())[1]
        self.assertEqual((claims["seq"], claims["backup"]), (2, [PIN_B]))
        with patch.object(signing, "spki_pins", return_value=[PIN_C]):
            claims = jws_parts(signing.pin_document())[1]
        self.assertEqual((claims["seq"], claims["primary"]), (3, [PIN_C]))
        # back to an earlier set is a new set, seq never goes back
        set_backup([])
        self.assertEqual(jws_parts(signing.pin_document())[1]["seq"], 4)
        self.assertEqual(PinSet.objects.count(), 4)

    def test_not_an_enrollment_token(self):
        for token in (
            signing.pin_document(),
            signing.sign_agent_update("A", "https://x", "1", "ab" * 32),
        ):
            with self.assertRaisesMessage(signing.EnrollmentError, "malformed"):
                signing.verify(token)

    def test_no_document_without_primary(self):
        with patch.object(signing, "spki_pins", return_value=[]):
            with self.assertRaisesMessage(signing.Unavailable, signing.NO_PINS):
                signing.pin_document()
        self.assertFalse(PinSet.objects.exists())

    def test_endpoint(self):
        self.setup_client()
        r = self.client.get("/api/v3/pins/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertEqual(jws_parts(r.data["jws"])[1]["primary"], TEST_PINS)
        # a token is not needed and not looked at
        self.client.credentials(HTTP_AUTHORIZATION="Token bogus")
        self.assertEqual(self.client.get("/api/v3/pins/").status_code, 200)

    def test_endpoint_without_chain(self):
        self.setup_client()
        with patch.object(signing, "spki_pins", return_value=[]):
            r = self.client.get("/api/v3/pins/")
        self.assertEqual(r.status_code, 503)
        self.assertNotIn("jws", r.data)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_document_cached_per_set(self):
        cache.clear()
        with patch.object(signing, "mint", wraps=signing.mint) as mint:
            first = signing.pin_document()
            self.assertEqual(signing.pin_document(), first)
            self.assertEqual(mint.call_count, 1)
            set_backup([PIN_B])
            claims = jws_parts(signing.pin_document())[1]
        self.assertEqual((claims["seq"], claims["backup"]), (2, [PIN_B]))
        self.assertEqual(mint.call_count, 2)
        self.assertEqual(signing.PIN_DOC_CACHE_TTL, 60)

    def test_bump_after_restore(self):
        signing.pin_document()
        set_backup([PIN_B])
        signing.pin_document()
        out = StringIO()
        call_command("pinset_bump", stdout=out)
        self.assertEqual(out.getvalue().strip(), "pin set 1002")
        bumped = PinSet.objects.get(seq=1002)
        self.assertEqual((bumped.primary, bumped.backup), (TEST_PINS, [PIN_B]))
        # the same set: the document now carries the bumped seq
        self.assertEqual(jws_parts(signing.pin_document())[1]["seq"], 1002)

    def test_bump_needs_chain(self):
        from django.core.management.base import CommandError

        with patch.object(signing, "spki_pins", return_value=[]):
            with self.assertRaisesMessage(CommandError, signing.NO_PINS):
                call_command("pinset_bump")
        self.assertFalse(PinSet.objects.exists())

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_endpoint_throttled_per_ip(self):
        from apiv3.views import PinsThrottle

        # agents behind one NAT address share the budget
        self.assertEqual(PinsThrottle.rate, "1200/hour")
        cache.clear()
        self.setup_client()
        with patch.object(PinsThrottle, "rate", "60/hour"):
            for _ in range(60):
                self.client.get("/api/v3/pins/", REMOTE_ADDR="198.51.100.7")
            r = self.client.get("/api/v3/pins/", REMOTE_ADDR="198.51.100.7")
            self.assertEqual(r.status_code, 429)
            r = self.client.get("/api/v3/pins/", REMOTE_ADDR="198.51.100.8")
            self.assertEqual(r.status_code, 200)


class TestUpdateManifest(ULRMMTestCase):
    def test_claims(self):
        sha = "ab" * 32
        header, claims = jws_parts(
            signing.sign_agent_update("AGENT1", "https://x/a.exe", "2.0", sha)
        )
        self.assertEqual(header["typ"], "ulrmm-update")
        self.assertEqual(
            {k: v for k, v in claims.items() if k != "iat"},
            {
                "v": 1,
                "typ": "ulrmm-update",
                "agent": "AGENT1",
                "url": "https://x/a.exe",
                "version": "2.0",
                "sha256": sha,
            },
        )

    def test_bad_sha_refused(self):
        for sha in ("", "AB" * 32, "ab" * 31, "zz" * 32):
            with self.assertRaises(ValueError):
                signing.sign_agent_update("A", "https://x", "1", sha)


class TestRecorder(ULRMMTestCase):
    def setUp(self):
        self.agent = baker.make_recipe("agents.agent")

    def test_new_and_counted(self):
        events.record("pin_mismatch", "high", agent=self.agent, ip="10.0.0.1")
        events.record("pin_mismatch", "high", agent=self.agent, ip="10.0.0.1")
        ev = SecurityEvent.objects.get()
        self.assertEqual(ev.count, 2)
        self.assertEqual(ev.agent_uid, self.agent.agent_id)
        self.assertEqual(ev.source_ip, "10.0.0.1")
        self.assertEqual(ev.severity, "high")
        self.assertGreaterEqual(ev.last_seen, ev.first_seen)
        # another detail, ip or agent is another event
        events.record("pin_mismatch", "high", agent=self.agent, detail="x")
        events.record("pin_mismatch", "high", agent_id="OTHER", ip="10.0.0.1")
        self.assertEqual(SecurityEvent.objects.count(), 3)

    def test_after_window_new_row(self):
        events.record("tls_failure", "warning", agent=self.agent)
        SecurityEvent.objects.update(
            last_seen=djangotime.now() - dt.timedelta(minutes=11)
        )
        events.record("tls_failure", "warning", agent=self.agent)
        self.assertEqual(
            sorted(SecurityEvent.objects.values_list("count", flat=True)), [1, 1]
        )

    def test_agent_deleted_keeps_id(self):
        events.record("update_refused", "high", agent=self.agent)
        agent_id = self.agent.agent_id
        self.agent.delete()
        ev = SecurityEvent.objects.get()
        self.assertIsNone(ev.agent)
        self.assertEqual(ev.agent_uid, agent_id)

    def test_never_raises(self):
        events.record("no_such_kind", "info")
        events.record("pin_mismatch", "loud")
        with patch.object(SecurityEvent.objects, "create", side_effect=RuntimeError):
            events.record("pin_mismatch", "high")
        self.assertFalse(SecurityEvent.objects.exists())

    def test_detail_cleaned(self):
        events.record("tls_failure", "warning", ip="not an ip", detail="a\nb\x00" * 300)
        ev = SecurityEvent.objects.get()
        self.assertIsNone(ev.source_ip)
        self.assertEqual(len(ev.detail), 500)
        self.assertNotIn("\n", ev.detail)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_one_write_per_ten_seconds(self):
        cache.clear()
        for _ in range(5):
            events.record("tls_failure", "warning", agent=self.agent)
        self.assertEqual(SecurityEvent.objects.get().count, 1)
        cache.clear()
        events.record("tls_failure", "warning", agent=self.agent)
        self.assertEqual(SecurityEvent.objects.get().count, 2)

    def test_prune(self):
        events.record("tls_failure", "warning", agent=self.agent)
        events.record("pin_rescue", "warning", agent=self.agent)
        SecurityEvent.objects.filter(kind="tls_failure").update(
            last_seen=djangotime.now() - dt.timedelta(days=91)
        )
        self.assertEqual(prune_security_events(), 1)
        self.assertEqual(SecurityEvent.objects.get().kind, "pin_rescue")

    def test_command(self):
        out = StringIO()
        call_command(
            "security_event",
            "backup_unencrypted",
            "warning",
            "--detail",
            "no age recipients",
            stdout=out,
        )
        ev = SecurityEvent.objects.get()
        self.assertEqual(
            (ev.kind, ev.severity, ev.detail, ev.agent_uid),
            ("backup_unencrypted", "warning", "no age recipients", ""),
        )


class TestAgentReport(CABase):
    def url(self, agent_id=None):
        return f"/api/v3/{agent_id or self.agent.agent_id}/security-event/"

    def test_report(self):
        self.as_agent()
        r = self.client.post(
            self.url(),
            {"kind": "pin_mismatch", "detail": "spki not pinned"},
            format="json",
            REMOTE_ADDR="192.0.2.5",
        )
        self.assertEqual(r.status_code, 200)
        ev = SecurityEvent.objects.get()
        self.assertEqual(
            (ev.kind, ev.severity, ev.agent, ev.source_ip, ev.detail),
            ("pin_mismatch", "high", self.agent, "192.0.2.5", "spki not pinned"),
        )

    def test_refused(self):
        self.as_agent()
        for body in (
            {"kind": "cert_refused"},
            {"kind": "backup_unencrypted"},
            {"kind": ["pin_mismatch"]},
            {},
            {"kind": "tls_failure", "detail": "x" * 501},
            {"kind": "tls_failure", "detail": 5},
        ):
            r = self.client.post(self.url(), body, format="json")
            self.assertEqual(r.status_code, 400, body)
        self.assertFalse(SecurityEvent.objects.exists())

    def test_own_agent_only(self):
        other = baker.make_recipe("agents.online_agent")
        self.as_agent()
        r = self.client.post(self.url(other.agent_id), {"kind": "tls_failure"})
        self.assertEqual(r.status_code, 404)
        self.client.credentials()
        r = self.client.post(self.url(), {"kind": "tls_failure"})
        self.assertEqual(r.status_code, 401)
        self.assertFalse(SecurityEvent.objects.exists())

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_throttled(self):
        cache.clear()
        self.as_agent()
        for i in range(30):
            body = {"kind": "tls_failure", "detail": str(i)}
            self.assertEqual(self.client.post(self.url(), body).status_code, 200)
        r = self.client.post(self.url(), {"kind": "tls_failure"})
        self.assertEqual(r.status_code, 429)


class TestServerSources(CABase):
    def test_cert_refused(self):
        other = baker.make_recipe("agents.online_agent")
        pki.issue(other, csr_pem())
        cert = other.certificates.get()
        self.setup_coresettings()
        self.as_agent()
        r = self.client.get(
            f"/api/v3/{self.agent.agent_id}/checkinterval/",
            REMOTE_ADDR="203.0.113.9",
            **tls(cert),
        )
        self.assertEqual(r.status_code, 401)
        ev = SecurityEvent.objects.get()
        self.assertEqual(
            (ev.kind, ev.severity, ev.agent, ev.source_ip),
            ("cert_refused", "warning", self.agent, "203.0.113.9"),
        )
        self.assertIn("does not belong", ev.detail)
        self.assertIn(cert.fingerprint_sha1, ev.detail)

    def test_nats_refused(self):
        set_mode(MtlsMode.REQUIRED)
        pki.issue(self.agent, csr_pem())
        cert = self.agent.certificates.get()
        pki.revoke(self.agent)
        r = self.client.get("/api/v3/natsauth/", REMOTE_ADDR="203.0.113.10")
        self.assertEqual(r.status_code, 403)
        r = self.client.get("/api/v3/natsauth/", **tls(cert))
        self.assertEqual(r.status_code, 403)
        anon, known = SecurityEvent.objects.order_by("pk")
        self.assertEqual(
            (anon.kind, anon.agent, anon.source_ip),
            ("nats_refused", None, "203.0.113.10"),
        )
        self.assertEqual(anon.detail, "no client certificate")
        self.assertEqual((known.kind, known.agent), ("nats_refused", self.agent))
        self.assertIn(cert.fingerprint_sha1, known.detail)


class TestEventsApi(ULRMMTestCase):
    def setUp(self):
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.user = self.create_user_with_roles(["can_view_core_settings"])
        self.client.force_authenticate(user=self.user)

    def make(self, n, **kw):
        now = djangotime.now()
        defaults = {"kind": "tls_failure", "severity": "warning"}
        return [
            SecurityEvent.objects.create(
                first_seen=now, last_seen=now, **{**defaults, **kw}
            )
            for _ in range(n)
        ]

    def test_list_and_filters(self):
        self.make(3, agent=self.agent, agent_uid=self.agent.agent_id, detail="d")
        self.make(2, kind="backup_unencrypted", severity="high")
        r = self.client.get(EVENTS)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data["results"]), 5)
        first = r.data["results"][-1]
        self.assertEqual(first["hostname"], self.agent.hostname)
        self.assertEqual(first["agent_id"], self.agent.agent_id)
        self.assertEqual(
            set(first),
            {
                "id",
                "kind",
                "severity",
                "agent_id",
                "hostname",
                "source_ip",
                "detail",
                "count",
                "first_seen",
                "last_seen",
            },
        )
        self.assertIn(
            {"value": "pin_mismatch", "label": "Server certificate pin mismatch"},
            r.data["kinds"],
        )
        ids = [e["id"] for e in r.data["results"]]
        self.assertEqual(ids, sorted(ids, reverse=True))
        r = self.client.get(EVENTS, {"severity": "high"})
        self.assertEqual(len(r.data["results"]), 2)
        r = self.client.get(EVENTS, {"kind": "tls_failure"})
        self.assertEqual(len(r.data["results"]), 3)
        r = self.client.get(EVENTS, {"agent_id": self.agent.agent_id})
        self.assertEqual(len(r.data["results"]), 3)
        r = self.client.get(EVENTS, {"limit": 2})
        self.assertEqual([e["id"] for e in r.data["results"]], ids[:2])
        r = self.client.get(EVENTS, {"limit": 2, "before": ids[1]})
        self.assertEqual([e["id"] for e in r.data["results"]], ids[2:4])

    def test_bad_params(self):
        for params in (
            {"severity": "loud"},
            {"kind": "nope"},
            {"limit": 201},
            {"limit": 0},
            {"limit": "x"},
            {"before": "x"},
        ):
            self.assertEqual(self.client.get(EVENTS, params).status_code, 400, params)

    def test_scope(self):
        other = baker.make_recipe("agents.agent")
        self.make(1, agent=self.agent, agent_uid=self.agent.agent_id)
        self.make(1, agent=other, agent_uid=other.agent_id)
        self.make(1)
        role = self.user.role
        role.can_view_clients.add(self.agent.client)
        r = self.client.get(EVENTS)
        self.assertEqual(
            sorted(e["agent_id"] for e in r.data["results"]),
            sorted(["", self.agent.agent_id]),
        )

    def test_needs_core_settings(self):
        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.assertEqual(self.client.get(EVENTS).status_code, 403)


@override_settings(CACHES=LOCMEM_CACHE)
class TestBackupPins(CABase):
    def setUp(self):
        cache.clear()
        super().setUp()
        self.user = self.create_user_with_roles(
            ["can_view_core_settings", "can_edit_core_settings"]
        )
        token, _ = AuthToken.objects.create(user=self.user)
        self.client.force_authenticate(user=self.user, token=token)

    def put(self, **data):
        return self.client.put("/deploy/security/", data, format="json")

    def test_get_shows_pins(self):
        r = self.client.get("/deploy/security/")
        self.assertEqual(r.data["backup_pins"], [])
        self.assertEqual(r.data["pins"]["seq"], 1)
        self.assertEqual(r.data["pins"]["primary"], TEST_PINS)
        self.assertEqual(r.data["pins"]["backup"], [])
        with patch.object(signing, "spki_pins", return_value=[]):
            self.assertIsNone(self.client.get("/deploy/security/").data["pins"])

    def test_change_needs_stepup_and_is_audited(self):
        self.assertEqual(self.client.get("/deploy/security/").data["pins"]["seq"], 1)
        r = self.put(backup_pins=[PIN_B])
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.assertEqual(pki.security_settings().backup_pins, [])
        grant_console_stepup(self.user)
        r = self.put(backup_pins=[PIN_B, PIN_B, PIN_C])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["backup_pins"], [PIN_B, PIN_C])
        self.assertEqual(r.data["pins"]["backup"], [PIN_B, PIN_C])
        self.assertEqual(r.data["pins"]["seq"], 2)
        audit = AuditLog.objects.filter(object_type="coresettings").latest("pk")
        self.assertEqual(audit.after_value["backup_pins"], [PIN_B, PIN_C])

    def test_unchanged_needs_no_stepup(self):
        self.assertEqual(self.put(cert_days=90, backup_pins=[]).status_code, 200)

    def test_invalid(self):
        grant_console_stepup(self.user)
        short = base64.b64encode(b"x" * 31).decode()
        for pins in (
            "abc",
            [short],
            ["!" * 44],
            [PIN_B + "x"],
            [base64.b64encode(bytes([i]) * 32).decode() for i in range(9)],
            [5],
        ):
            self.assertEqual(self.put(backup_pins=pins).status_code, 400, pins)
        self.assertEqual(pki.security_settings().backup_pins, [])


class TestTokenMaxLifetime(ULRMMTestCase):
    def setUp(self):
        self.setup_client()
        self.user = self.create_user_with_roles(["can_view_core_settings"])
        self.user.totp_key = "AB5RI6YPFTZAS52G"
        self.user.save(update_fields=["totp_key"])
        self.token_obj, key = AuthToken.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key}")

    def age(self, created, expiry):
        now = djangotime.now()
        AuthToken.objects.filter(pk=self.token_obj.pk).update(
            created=now - created, expiry=now + expiry
        )

    def test_past_max_refused_and_deleted(self):
        self.age(dt.timedelta(hours=12, minutes=1), dt.timedelta(hours=1))
        r = self.client.get(EVENTS)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.data["detail"], "session expired")
        self.assertFalse(AuthToken.objects.filter(pk=self.token_obj.pk).exists())
        ev = SecurityEvent.objects.get()
        self.assertEqual((ev.kind, ev.severity), ("token_expired_max", "info"))
        self.assertIn(self.user.username, ev.detail)

    def test_refresh_stops_at_max(self):
        self.age(dt.timedelta(hours=11), dt.timedelta(minutes=1))
        self.assertEqual(self.client.get(EVENTS).status_code, 200)
        token = AuthToken.objects.get(pk=self.token_obj.pk)
        self.assertEqual(token.expiry, token.created + dt.timedelta(hours=12))

    def test_refresh_as_before_below_max(self):
        self.age(dt.timedelta(hours=1), dt.timedelta(minutes=1))
        self.assertEqual(self.client.get(EVENTS).status_code, 200)
        token = AuthToken.objects.get(pk=self.token_obj.pk)
        self.assertGreater(token.expiry, djangotime.now() + dt.timedelta(hours=4))

    @override_settings(DASHBOARD_TOKEN_MAX_TTL=dt.timedelta(hours=2))
    def test_setting(self):
        self.age(dt.timedelta(hours=2, minutes=1), dt.timedelta(hours=1))
        self.assertEqual(self.client.get(EVENTS).status_code, 401)

    def test_websocket_path_refused(self):
        # ulrmm.utils.get_user authenticates websockets this way
        from ulrmm.auth import DashboardTokenAuthentication

        obj, key = AuthToken.objects.create(user=self.user)
        auth = DashboardTokenAuthentication()
        self.assertEqual(auth.authenticate_credentials(key.encode())[0], self.user)
        AuthToken.objects.update(created=djangotime.now() - dt.timedelta(hours=13))
        with self.assertRaisesMessage(AuthenticationFailed, "session expired"):
            auth.authenticate_credentials(key.encode())
        self.assertFalse(AuthToken.objects.filter(pk=obj.pk).exists())


class TestAgentApiToken(ULRMMTestCase):
    """The agent token is a DRF token: S7 does not apply to it."""

    def test_old_agent_token_still_works(self):
        self.setup_coresettings()
        self.setup_client()
        agent = baker.make_recipe("agents.online_agent")
        user = User.objects.create_user(
            username=agent.agent_id, agent=agent, password="x" * 40
        )
        key = Token.objects.create(user=user).key
        Token.objects.filter(key=key).update(
            created=djangotime.now() - dt.timedelta(days=400)
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key}")
        r = self.client.get(f"/api/v3/{agent.agent_id}/checkinterval/")
        self.assertEqual(r.status_code, 200)

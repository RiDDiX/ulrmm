# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import os
import stat
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from accounts.models import User
from accounts.utils import grant_console_stepup
from clients.models import InstallerToken
from deploy import mtls_views, pki
from deploy.models import AgentCertificate, AgentSecuritySettings, MtlsMode
from logs.models import AuditLog
from ulrmm.auth import AgentCertAuthentication, AgentTokenAuthentication
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

SECURITY = "/deploy/security/"


def csr_pem(key=None) -> str:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def bad_signature(pem: str) -> str:
    der = x509.load_pem_x509_csr(pem.encode()).public_bytes(serialization.Encoding.DER)
    # last byte of the ECDSA signature value
    der = der[:-1] + bytes([der[-1] ^ 1])
    csr = x509.load_der_x509_csr(der)
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def set_mode(mode: str) -> None:
    sec = pki.security_settings()
    sec.mtls_mode = mode
    sec.save()


def seen(cert) -> None:
    """The agent has presented it."""
    AgentCertificate.objects.filter(pk=cert.pk).update(last_seen=djangotime.now())


def tls(cert, verify="SUCCESS") -> dict:
    """The uwsgi params nginx passes for a client certificate."""
    return {
        "SSL_CLIENT_VERIFY": verify,
        "SSL_CLIENT_FINGERPRINT": cert.fingerprint_sha1,
    }


class CABase(ULRMMTestCase):
    def setUp(self):
        self.setup_client()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ca_dir = Path(tmp.name)
        override = override_settings(AGENT_CA_DIR=tmp.name)
        override.enable()
        self.addCleanup(override.disable)
        pki.ensure_ca()
        self.agent = baker.make_recipe("agents.online_agent")
        self.token = self.agent_token(self.agent)

    def agent_token(self, agent) -> str:
        user = User.objects.create_user(
            username=agent.agent_id, agent=agent, password="x" * 40
        )
        return Token.objects.create(user=user).key

    def as_agent(self, token=None) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token or self.token}")

    def cert_for(self, agent=None) -> AgentCertificate:
        agent = agent or self.agent
        pki.issue(agent, csr_pem())
        return agent.certificates.get(revoked_at=None)


class TestCA(CABase):
    def test_files_and_extensions(self):
        key_path, pem_path = self.ca_dir / "ca.key", self.ca_dir / "ca.pem"
        self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(pem_path).st_mode), 0o644)
        key, ca = pki.load_ca()
        self.assertIsInstance(key.curve, ec.SECP256R1)
        cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "UniversalLocal RMM Agent CA")
        self.assertEqual(ca.subject, ca.issuer)
        basic = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(basic.critical)
        self.assertEqual((basic.value.ca, basic.value.path_length), (True, 0))
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.key_cert_sign and usage.crl_sign)
        self.assertFalse(usage.digital_signature)
        self.assertGreaterEqual(
            (ca.not_valid_after_utc - ca.not_valid_before_utc).days, 3650
        )

    def test_existing_ca_is_kept(self):
        fingerprint = pki.ca_info()[0]
        self.assertEqual(pki.ensure_ca(), (False, fingerprint))

    def test_half_ca_is_not_replaced(self):
        (self.ca_dir / "ca.pem").unlink()
        with self.assertRaises(pki.CAUnavailable):
            pki.ensure_ca()
        self.assertTrue((self.ca_dir / "ca.key").exists())
        self.assertFalse((self.ca_dir / "ca.pem").exists())

    def test_foreign_key_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        (self.ca_dir / "ca.key").write_bytes(
            other.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        with self.assertRaisesMessage(pki.CAUnavailable, "does not belong"):
            pki.load_ca()


class TestIssue(CABase):
    def test_leaf(self):
        issued = pki.issue(self.agent, csr_pem())
        cert = x509.load_pem_x509_certificate(issued["cert"].encode())
        _, ca = pki.load_ca()
        cert.verify_directly_issued_by(ca)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, self.agent.agent_id)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(
            san.value.get_values_for_type(x509.UniformResourceIdentifier),
            [f"urn:ulrmm:agent:{self.agent.agent_id}"],
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertEqual(list(eku), [ExtendedKeyUsageOID.CLIENT_AUTH])
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        self.assertFalse(usage.key_cert_sign)
        self.assertFalse(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
        self.assertLess(cert.serial_number, 2**128)
        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertEqual(round(lifetime.total_seconds() / 60), 180 * 24 * 60 + 5)

        row = AgentCertificate.objects.get(agent=self.agent)
        der = cert.public_bytes(serialization.Encoding.DER)
        self.assertEqual(row.fingerprint_sha1, hashlib.sha1(der).hexdigest())
        self.assertEqual(row.fingerprint_sha256, hashlib.sha256(der).hexdigest())
        self.assertEqual(row.serial, format(cert.serial_number, "x"))
        self.assertEqual(row.not_after, cert.not_valid_after_utc)
        self.assertEqual(issued["not_after"], row.not_after.isoformat())
        self.assertEqual(
            issued["ca"], ca.public_bytes(serialization.Encoding.PEM).decode()
        )

    def test_cert_days(self):
        AgentSecuritySettings(cert_days=30).save()
        cert = self.cert_for()
        self.assertEqual((cert.not_after - cert.not_before).days, 30)

    def test_expired_cert_is_inactive(self):
        cert = self.cert_for()
        later = djangotime.now() + dt.timedelta(days=181)
        self.assertFalse(cert.is_active(later))
        self.assertFalse(pki.active_certs(later).exists())

    def test_new_cert_revokes_previous_after_grace(self):
        first = self.cert_for()
        second = self.cert_for()
        first.refresh_from_db()
        self.assertIsNotNone(first.revoked_at)
        self.assertTrue(second.is_active())
        # other agent processes still hold the previous one for a while
        self.assertTrue(first.is_active())
        later = djangotime.now() + pki.RENEW_GRACE + dt.timedelta(seconds=1)
        self.assertFalse(first.is_active(later))
        self.assertEqual(
            list(pki.active_certs(later).filter(agent=self.agent)), [second]
        )

    def test_reset_revokes_grace_certs_at_once(self):
        self.cert_for()
        self.cert_for()
        self.assertEqual(pki.revoke(self.agent), 2)
        self.assertFalse(pki.active_certs().filter(agent=self.agent).exists())

    def test_bad_csrs_refused(self):
        cases = (
            ("", "missing"),
            (None, "missing"),
            ("A" * 5000, "too large"),
            ("garbage", "not a PEM"),
            (csr_pem(ec.generate_private_key(ec.SECP384R1())), "P-256"),
            (csr_pem(rsa.generate_private_key(65537, 2048)), "P-256"),
            (bad_signature(csr_pem()), "signature"),
        )
        for pem, why in cases:
            with self.subTest(why=why), self.assertRaisesMessage(pki.CertError, why):
                pki.issue(self.agent, pem)
        self.assertFalse(AgentCertificate.objects.exists())

    def test_coverage(self):
        other = baker.make_recipe("agents.online_agent", hostname="aaa")
        cert = self.cert_for()
        self.assertEqual(
            {k: v for k, v in pki.coverage().items() if k != "missing"},
            {"agents": 2, "with_cert": 1, "seen_with_cert": 0},
        )
        pki.touch(cert)
        cov = pki.coverage()
        self.assertEqual((cov["with_cert"], cov["seen_with_cert"]), (1, 1))
        self.assertEqual([m["agent_id"] for m in cov["missing"]], [other.agent_id])
        self.assertEqual(
            set(cov["missing"][0]), {"agent_id", "hostname", "version", "last_seen"}
        )
        self.assertFalse(pki.full_coverage(cov))
        other.delete()
        self.assertTrue(pki.full_coverage(pki.coverage()))


class TestAgentTokenAuthentication(CABase):
    def setUp(self):
        super().setUp()
        self.cert = self.cert_for()
        self.other = baker.make_recipe("agents.online_agent")
        self.other_cert = self.cert_for(self.other)

    def auth(self, cls=AgentTokenAuthentication, **meta):
        request = APIRequestFactory().get(
            "/", HTTP_AUTHORIZATION=f"Token {self.token}", **meta
        )
        return cls().authenticate(request)

    def refused(self, why, cls=AgentTokenAuthentication, **meta):
        with self.assertRaisesMessage(AuthenticationFailed, why):
            self.auth(cls, **meta)

    def test_off_ignores_certificates(self):
        set_mode(MtlsMode.OFF)
        self.assertEqual(self.auth()[0].agent_id, self.agent.pk)
        self.assertIsNotNone(self.auth(**tls(self.other_cert)))

    def test_optional(self):
        self.assertIsNotNone(self.auth())
        self.assertIsNotNone(self.auth(**tls(self.cert)))
        self.cert.refresh_from_db()
        self.assertIsNotNone(self.cert.last_seen)
        # nginx lets a failed verification through only as "FAILED:..."
        self.assertIsNotNone(self.auth(**tls(self.other_cert, "FAILED:expired")))
        self.refused("does not belong", **tls(self.other_cert))
        unknown = {"SSL_CLIENT_VERIFY": "SUCCESS", "SSL_CLIENT_FINGERPRINT": "ab" * 20}
        self.refused("does not belong", **unknown)
        pki.revoke(self.agent)
        self.refused("does not belong", **tls(self.cert))

    def test_required(self):
        set_mode(MtlsMode.REQUIRED)
        self.refused("client certificate required")
        self.refused("client certificate required", **tls(self.cert, "NONE"))
        self.assertIsNotNone(self.auth(**tls(self.cert)))
        self.refused("does not belong", **tls(self.other_cert))

    def test_fingerprint_spelling(self):
        set_mode(MtlsMode.REQUIRED)
        fp = self.cert.fingerprint_sha1.upper()
        colons = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))
        meta = {"SSL_CLIENT_VERIFY": "SUCCESS", "SSL_CLIENT_FINGERPRINT": colons}
        self.assertIsNotNone(self.auth(**meta))

    def test_issuance_view(self):
        set_mode(MtlsMode.REQUIRED)
        self.assertIsNotNone(self.auth(AgentCertAuthentication))
        pki.revoke(self.agent)
        self.assertIsNotNone(self.auth(AgentCertAuthentication, **tls(self.cert)))
        self.refused("does not belong", AgentCertAuthentication, **tls(self.other_cert))

    def test_agent_api(self):
        self.setup_coresettings()
        set_mode(MtlsMode.REQUIRED)
        self.as_agent()
        url = f"/api/v3/{self.agent.agent_id}/checkinterval/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.data["detail"], "client certificate required")
        self.assertEqual(self.client.get(url, **tls(self.cert)).status_code, 200)
        r = self.client.get(url, **tls(self.other_cert))
        self.assertEqual(r.status_code, 401)


@override_settings(CACHES=LOCMEM_CACHE)
class TestCaches(CABase):
    def setUp(self):
        cache.clear()
        super().setUp()

    def test_last_seen_at_most_every_five_minutes(self):
        cert = self.cert_for()
        pki.touch(cert)
        first = AgentCertificate.objects.get(pk=cert.pk).last_seen
        self.assertIsNotNone(first)
        pki.touch(cert)
        self.assertEqual(AgentCertificate.objects.get(pk=cert.pk).last_seen, first)

    def test_mode_cached_until_saved(self):
        set_mode(MtlsMode.OPTIONAL)
        self.assertEqual(pki.mtls_mode(), "optional")
        # a queryset update skips save(), so the cached mode stays
        AgentSecuritySettings.objects.filter(pk=1).update(mtls_mode="off")
        self.assertEqual(pki.mtls_mode(), "optional")
        set_mode(MtlsMode.REQUIRED)
        self.assertEqual(pki.mtls_mode(), "required")


class TestCertView(CABase):
    def setUp(self):
        super().setUp()
        self.as_agent()
        self.url = f"/api/v3/{self.agent.agent_id}/cert/"

    def post(self, csr=None, **meta):
        return self.client.post(
            self.url, {"csr": csr or csr_pem()}, format="json", **meta
        )

    def test_first_issue_with_token(self):
        r = self.post()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.data), {"cert", "ca", "not_after", "renew_pct"})
        self.assertEqual(r.data["renew_pct"], 75)
        self.assertEqual(self.agent.certificates.count(), 1)

    def test_off(self):
        set_mode(MtlsMode.OFF)
        r = self.post()
        self.assertEqual((r.status_code, r.data), (409, {"detail": "mtls off"}))

    def test_renewal_needs_current_cert(self):
        current = self.cert_for()
        seen(current)
        self.assertEqual(self.post().status_code, 403)
        r = self.post(**tls(current))
        self.assertEqual(r.status_code, 200)
        current.refresh_from_db()
        self.assertIsNotNone(current.revoked_at)
        later = djangotime.now() + pki.RENEW_GRACE + dt.timedelta(seconds=1)
        self.assertEqual(pki.active_certs(later).filter(agent=self.agent).count(), 1)

    def test_lost_renewal_answer(self):
        old = self.cert_for()
        seen(old)
        self.assertEqual(self.post(**tls(old)).status_code, 200)
        # the answer got lost, the agent asks again within the grace
        self.assertEqual(self.post(**tls(old)).status_code, 200)
        # and after it, with the revoked one or with the token only
        self.agent.certificates.filter(pk=old.pk).update(
            revoked_at=djangotime.now() - dt.timedelta(seconds=1)
        )
        self.assertEqual(self.post(**tls(old)).status_code, 200)
        self.assertEqual(self.post().status_code, 200)

        # once a newer one is in use, the token or a revoked one is not enough
        newest = self.agent.certificates.order_by("-issued_at", "-pk").first()
        seen(newest)
        self.assertEqual(self.post().status_code, 403)
        self.assertEqual(self.post(**tls(old)).status_code, 403)
        self.assertEqual(self.post(**tls(newest)).status_code, 200)

    def test_any_active_cert_renews(self):
        old = self.cert_for()
        seen(old)
        newer = self.cert_for()
        seen(newer)
        # the previous one is still active during the grace
        self.assertEqual(self.post(**tls(newer)).status_code, 200)
        self.assertEqual(self.post(**tls(old)).status_code, 200)

    def test_bad_csr(self):
        r = self.post(bad_signature(csr_pem()))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.agent.certificates.exists())

    def test_after_reset(self):
        old = self.cert_for()
        pki.revoke(self.agent)
        self.assertEqual(self.post().status_code, 200)
        pki.revoke(self.agent)
        # the agent may still present the revoked one
        self.assertEqual(self.post(**tls(old)).status_code, 200)

    def test_required_mode_without_cert(self):
        set_mode(MtlsMode.REQUIRED)
        self.assertEqual(self.post().status_code, 200)

    def test_other_agents_url(self):
        other = baker.make_recipe("agents.online_agent")
        r = self.client.post(
            f"/api/v3/{other.agent_id}/cert/", {"csr": csr_pem()}, format="json"
        )
        self.assertEqual(r.status_code, 404)

    def test_ca_missing(self):
        (self.ca_dir / "ca.key").unlink()
        r = self.post()
        self.assertEqual((r.status_code, r.data), (409, {"detail": "agent CA missing"}))


@patch("apiv3.views.cache_agents_alert_template.delay")
@patch("apiv3.views.reload_nats")
class TestNewAgentCsr(CABase):
    def setUp(self):
        super().setUp()
        installer = User.objects.create_user(
            username="installer", is_installer_user=True
        )
        token, key = AuthToken.objects.create(user=installer)
        InstallerToken.objects.create(auth_token=token, site=self.agent.site)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key}")

    def newagent(self, **extra):
        data = {
            "agent_id": "n" * 40,
            "hostname": "host",
            "site": self.agent.site_id,
            "monitoring_type": "server",
            "mesh_node_id": "",
            "goarch": "amd64",
            "plat": "linux",
            **extra,
        }
        return self.client.post("/api/v3/newagent/", data, format="json")

    def test_cert_issued(self, *mocks):
        r = self.newagent(csr=csr_pem())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.data), {"pk", "token", "cert", "ca"})
        cert = x509.load_pem_x509_certificate(r.data["cert"].encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "n" * 40)
        self.assertTrue(AgentCertificate.objects.filter(agent_id=r.data["pk"]).exists())

    def test_bad_csr_registers_nothing(self, *mocks):
        r = self.newagent(csr="nonsense")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Invalid csr", r.data)
        self.assertFalse(User.objects.filter(username="n" * 40).exists())

    def test_without_csr_or_mode_off(self, *mocks):
        r = self.newagent()
        self.assertEqual(set(r.data), {"pk", "token"})
        set_mode(MtlsMode.OFF)
        r = self.newagent(agent_id="m" * 40, csr="ignored when off")
        self.assertEqual((r.status_code, set(r.data)), (200, {"pk", "token"}))
        self.assertFalse(AgentCertificate.objects.exists())

    def test_without_ca(self, *mocks):
        (self.ca_dir / "ca.pem").unlink()
        r = self.newagent(csr=csr_pem())
        self.assertEqual((r.status_code, set(r.data)), (200, {"pk", "token"}))


class TestNatsAuth(CABase):
    url = "/api/v3/natsauth/"

    def test_open_unless_required(self):
        for mode in (MtlsMode.OFF, MtlsMode.OPTIONAL):
            set_mode(mode)
            self.assertEqual(self.client.get(self.url).status_code, 204)

    def test_required(self):
        set_mode(MtlsMode.REQUIRED)
        cert = self.cert_for()
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(
            self.client.get(self.url, **tls(cert, "FAILED:x")).status_code, 403
        )
        self.assertEqual(self.client.get(self.url, **tls(cert)).status_code, 204)
        cert.refresh_from_db()
        self.assertIsNotNone(cert.last_seen)
        pki.revoke(self.agent)
        self.assertEqual(self.client.get(self.url, **tls(cert)).status_code, 403)


@override_settings(CACHES=LOCMEM_CACHE)
class TestSecurityApi(CABase):
    def setUp(self):
        cache.clear()
        super().setUp()
        self.login(
            self.create_user_with_roles(
                ["can_view_core_settings", "can_edit_core_settings"]
            )
        )

    def login(self, user, stepup=False):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)
        self.user = user

    def put(self, **data):
        return self.client.put(SECURITY, data, format="json")

    def test_get(self):
        self.login(self.create_user_with_roles(["can_view_core_settings"]))
        r = self.client.get(SECURITY)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["mtls_mode"], "optional")
        self.assertEqual(r.data["cert_days"], 180)
        self.assertEqual(r.data["ca_fingerprint_sha256"], pki.ca_info()[0])
        self.assertFalse(r.data["nats_standard"])
        self.assertEqual(r.data["coverage"]["agents"], 1)
        self.assertEqual(self.put(cert_days=90).status_code, 403)

    def test_no_ca(self):
        (self.ca_dir / "ca.pem").unlink()
        r = self.client.get(SECURITY)
        self.assertIsNone(r.data["ca_fingerprint_sha256"])
        self.assertIsNone(r.data["ca_not_after"])

    def test_cert_days(self):
        for days in (29, 826, "x"):
            r = self.put(cert_days=days)
            self.assertEqual(r.status_code, 400)
            self.assertIn("cert_days", r.data)
        self.assertEqual(self.put(mtls_mode="sometimes").status_code, 400)
        r = self.put(cert_days=365)
        self.assertEqual((r.status_code, r.data["cert_days"]), (200, 365))
        entry = AuditLog.objects.get(action="modify", object_type="coresettings")
        self.assertEqual(entry.before_value["cert_days"], 180)
        self.assertEqual(entry.after_value["cert_days"], 365)

    def test_required_needs_coverage_or_force(self):
        r = self.put(mtls_mode="required")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["coverage"]["missing"][0]["agent_id"], self.agent.agent_id
        )
        r = self.put(mtls_mode="required", force=True)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.data["stepup"])
        self.assertEqual(pki.security_settings().mtls_mode, "optional")
        self.login(self.user, stepup=True)
        r = self.put(mtls_mode="required", force=True)
        self.assertEqual((r.status_code, r.data["mtls_mode"]), (200, "required"))
        self.assertEqual(pki.mtls_mode(), "required")

    def test_required_with_full_coverage(self):
        pki.touch(self.cert_for())
        r = self.put(mtls_mode="required")
        self.assertEqual((r.status_code, r.data["mtls_mode"]), (200, "required"))

    @override_settings(USE_NATS_STANDARD=True)
    def test_required_refused_with_nats_standard(self):
        pki.touch(self.cert_for())
        self.login(self.user, stepup=True)
        r = self.put(mtls_mode="required", force=True)
        self.assertEqual(r.status_code, 400)
        self.assertIn("USE_NATS_STANDARD", r.data)
        self.assertTrue(self.client.get(SECURITY).data["nats_standard"])

    @override_settings(NATS_WS_BIND_HOST="0.0.0.0")
    def test_required_refused_with_open_nats_bind(self):
        seen(self.cert_for())
        self.login(self.user, stepup=True)
        r = self.put(mtls_mode="required", force=True)
        self.assertEqual(r.status_code, 400)
        self.assertIn("NATS_WS_BIND_HOST", r.data)
        self.assertTrue(self.client.get(SECURITY).data["nats_standard"])
        self.assertEqual(pki.security_settings().mtls_mode, "optional")

    def test_nats_bind_hosts(self):
        for std, ws, direct in (
            ("127.0.0.1", "127.0.0.1", False),
            ("localhost", "::1", False),
            ("0.0.0.0", "127.0.0.1", True),
            ("127.0.0.1", "192.168.1.5", True),
            ("", "127.0.0.1", True),
        ):
            with self.subTest(std=std, ws=ws), override_settings(
                NATS_STD_BIND_HOST=std, NATS_WS_BIND_HOST=ws
            ):
                self.assertEqual(mtls_views._nats_standard(), direct)

    def test_missing_list_follows_the_role(self):
        other = baker.make_recipe("agents.online_agent")
        user = self.create_user_with_roles(["can_view_core_settings"])
        user.role.can_view_clients.add(self.agent.client)
        self.login(user)
        cov = self.client.get(SECURITY).data["coverage"]
        # the counts stay global, required mode needs every agent
        self.assertEqual((cov["agents"], cov["seen_with_cert"]), (2, 0))
        self.assertEqual([m["agent_id"] for m in cov["missing"]], [self.agent.agent_id])
        user.role.can_view_clients.set([other.client])
        cov = self.client.get(SECURITY).data["coverage"]
        self.assertEqual([m["agent_id"] for m in cov["missing"]], [other.agent_id])

    def test_lowering_needs_stepup(self):
        r = self.put(mtls_mode="off")
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.login(self.user, stepup=True)
        self.assertEqual(self.put(mtls_mode="off").status_code, 200)
        self.assertEqual(pki.mtls_mode(), "off")
        # raising again needs none
        cache.clear()
        self.assertEqual(self.put(mtls_mode="optional").status_code, 200)


@override_settings(CACHES=LOCMEM_CACHE)
class TestAgentCertApi(CABase):
    def setUp(self):
        cache.clear()
        super().setUp()
        self.cert = self.cert_for()
        self.url = f"/deploy/agents/{self.agent.agent_id}/cert/"
        self.user = self.create_user_with_roles(["can_list_agents", "can_edit_agent"])
        self.login(stepup=False)

    def login(self, stepup):
        token, _ = AuthToken.objects.create(user=self.user)
        self.client.force_authenticate(user=self.user, token=token)
        if stepup:
            grant_console_stepup(self.user)

    def test_get(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["active"]["serial"], self.cert.serial)
        self.assertEqual(len(r.data["certs"]), 1)
        self.assertEqual(r.data["mtls_mode"], "optional")
        self.assertEqual(r.data["renew_pct"], 75)

    def test_reset(self):
        r = self.client.post(self.url + "reset/")
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.assertTrue(pki.active_certs().filter(agent=self.agent).exists())
        self.login(stepup=True)
        r = self.client.post(self.url + "reset/")
        self.assertEqual((r.status_code, r.data), (200, {"revoked": 1}))
        self.assertFalse(pki.active_certs().filter(agent=self.agent).exists())
        entry = AuditLog.objects.get(agent_id=self.agent.agent_id, action="modify")
        self.assertIn("reset the client certificate", entry.message)
        r = self.client.get(self.url)
        self.assertIsNone(r.data["active"])
        self.assertIsNotNone(r.data["certs"][0]["revoked_at"])

    def test_scope_and_flags(self):
        self.user.role.can_view_sites.add(baker.make("clients.Site"))
        self.login(stepup=True)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url + "reset/").status_code, 403)
        self.user = self.create_user_with_roles(["can_list_agents"])
        self.login(stepup=True)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(self.client.post(self.url + "reset/").status_code, 403)


class TestEnsureAgentCaCommand(CABase):
    def run_command(self, *args) -> str:
        out = StringIO()
        call_command("ensure_agent_ca", *args, stdout=out)
        return out.getvalue()

    def test_created_then_present(self):
        with tempfile.TemporaryDirectory() as fresh:
            with override_settings(AGENT_CA_DIR=fresh):
                created = self.run_command()
                fingerprint = pki.ca_info()[0]
                self.assertEqual(created, f"created {fingerprint}\n")
                self.assertEqual(self.run_command(), f"present {fingerprint}\n")

    def test_new_ca_revokes_and_sets_optional(self):
        self.cert_for()
        set_mode(MtlsMode.REQUIRED)
        self.run_command("--reset-certs-if-new")
        self.assertEqual(pki.active_certs().count(), 1)
        self.assertEqual(pki.mtls_mode(), "required")

        with tempfile.TemporaryDirectory() as fresh:
            with override_settings(AGENT_CA_DIR=fresh):
                out = self.run_command("--reset-certs-if-new")
        self.assertTrue(out.startswith("created "))
        self.assertIn("revoked 1 agent certificates", out)
        self.assertFalse(pki.active_certs().exists())
        self.assertEqual(pki.security_settings().mtls_mode, "optional")

    def test_missing_dir(self):
        with override_settings(AGENT_CA_DIR=str(self.ca_dir / "nope")):
            with self.assertRaises(CommandError):
                self.run_command()

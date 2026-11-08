# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import json
import tempfile
import warnings
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.cache import cache
from django.test.utils import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from deploy import signing
from logs.models import AuditLog
from ulrmm.constants import AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

OTHER_KEY = base64.b64encode(b"o" * 32).decode()


def _tamper(token: str, **changes) -> str:
    header, payload, sig = token.split(".")
    claims = json.loads(signing._unb64url(payload))
    claims.update(changes)
    return f"{header}.{signing._b64url(signing._json(claims))}.{sig}"


def _cert(subject, issuer_name, key, issuer_key, ca=False):
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .sign(issuer_key, hashes.SHA256())
    )


def _negative_serial(subject) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = dt.datetime.now(dt.timezone.utc)
    der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    # serial INTEGER 1 -> -127, same length; builders refuse non-positive serials
    i = der.index(bytes.fromhex("a003020102020101")) + 7
    der = der[:i] + b"\x81" + der[i + 1 :]
    body = base64.encodebytes(der)
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"-----END CERTIFICATE-----\n"


def _with_key_ids(cert, issuer_key, subject_key):
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(subject_key.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(*certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


class TestSigning(ULRMMTestCase):
    def setUp(self):
        self.site = baker.make("clients.Site")
        self.policy = baker.make("automation.Policy")
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site,
            mon_type="workstation",
            policy=self.policy,
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": True},
        )

    def _token(self):
        return signing.mint_for_deployment(
            self.deployment, api="https://api.example.com"
        )

    def test_roundtrip_and_claims(self):
        with override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent"):
            claims = signing.verify(self._token())
        self.assertEqual(claims["dep"], str(self.deployment.uid))
        self.assertEqual(claims["cli"], self.site.client_id)
        self.assertEqual(claims["site"], self.site.pk)
        self.assertEqual(claims["mon"], "workstation")
        self.assertEqual(claims["pol"], self.policy.pk)
        self.assertEqual(claims["flg"], {"power": True, "ping": False, "rdp": True})
        self.assertEqual(claims["iss"], "https://api.example.com")
        self.assertEqual(signing.check_deployment(claims), self.deployment)

    def test_deterministic(self):
        self.assertEqual(self._token(), self._token())

    def test_header_carries_key_id(self):
        header = json.loads(signing._unb64url(self._token().split(".")[0]))
        self.assertEqual(
            header, {"alg": "EdDSA", "kid": signing.key_id(), "typ": "JWT"}
        )
        self.assertEqual(len(signing.key_id()), 16)

    def test_tampered_payload_refused(self):
        token = _tamper(self._token(), site=self.site.pk + 1)
        with self.assertRaisesMessage(signing.EnrollmentError, "signature"):
            signing.verify(token)

    def test_tampered_header_refused(self):
        _, payload, sig = self._token().split(".")
        header = signing._b64url(
            signing._json({"alg": "none", "kid": signing.key_id(), "typ": "JWT"})
        )
        with self.assertRaisesMessage(signing.EnrollmentError, "not signed"):
            signing.verify(f"{header}.{payload}.{sig}")

    def test_other_key_refused(self):
        token = self._token()
        with override_settings(ENROLL_SIGNING_KEY=OTHER_KEY):
            with self.assertRaises(signing.EnrollmentError):
                signing.verify(token)

    def test_expired_refused(self):
        token = self._token()
        later = self.deployment.expiry.timestamp() + 120
        with self.assertRaisesMessage(signing.EnrollmentError, "expired"):
            signing.verify(token, now=later)

    def test_malformed_refused(self):
        for token in ("", "a.b", "a.b.c.d", "a$.b.c", "x" * 5000, None):
            with self.assertRaises(signing.EnrollmentError):
                signing.verify(token)

    def test_check_deployment_mismatch_and_gone(self):
        claims = signing.verify(self._token())
        with self.assertRaisesMessage(signing.EnrollmentError, "does not match"):
            signing.check_deployment({**claims, "mon": "server"})
        with self.assertRaisesMessage(signing.EnrollmentError, "does not match"):
            signing.check_deployment({**claims, "pol": None})
        with self.assertRaisesMessage(signing.EnrollmentError, "expired"):
            signing.check_deployment(claims, now=self.deployment.expiry.timestamp() + 1)
        self.deployment.delete()
        with self.assertRaisesMessage(signing.EnrollmentError, "not found"):
            signing.check_deployment(claims)

    def test_missing_key_is_a_config_error(self):
        from django.core.exceptions import ImproperlyConfigured

        with override_settings(ENROLL_SIGNING_KEY=""):
            with self.assertRaises(ImproperlyConfigured):
                signing.mint({"v": 1})

    def test_dist_pubkey_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(AGENTS_DIST_DIR=tmp):
                self.assertFalse(signing.dist_pubkey_ok())
                Path(tmp, signing.DIST_PUBKEY_FILE).write_text(
                    signing.public_key_b64() + "\n"
                )
                self.assertTrue(signing.dist_pubkey_ok())
                with override_settings(ENROLL_SIGNING_KEY=OTHER_KEY):
                    self.assertFalse(signing.dist_pubkey_ok())

    def test_public_key_forms(self):
        raw = base64.b64decode(signing.public_key_b64())
        self.assertEqual(len(raw), 32)
        self.assertIn("BEGIN PUBLIC KEY", signing.public_key_pem())


class TestDeploymentApi(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.policy = baker.make("automation.Policy")

    def _body(self, **extra):
        expires = djangotime.now() + dt.timedelta(days=3)
        return {
            "site": self.site.pk,
            "name": "Laptops",
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "agenttype": "workstation",
            "goarch": "amd64",
            "power": False,
            "ping": True,
            "rdp": False,
            **extra,
        }

    def test_create_returns_row_without_knox_token(self):
        r = self.client.post(
            "/clients/deployments/", self._body(policy=self.policy.pk), format="json"
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["name"], "Laptops")
        self.assertEqual(r.data["policy"], self.policy.pk)
        self.assertEqual(r.data["policy_name"], self.policy.name)
        self.assertTrue(r.data["url"].endswith(f"/clients/{r.data['uid']}/deploy/"))
        deployment = self.site.deploysites.get()
        self.assertIsNone(deployment.auth_token_id)
        self.assertEqual(deployment.token_key, "")

    def test_flags_and_expiry_input(self):
        url = "/clients/deployments/"
        for bad in ({"ping": 1}, {"rdp": "false"}, {"power": None}):
            r = self.client.post(url, self._body(**bad), format="json")
            self.assertEqual(r.status_code, 400, bad)
        later = djangotime.now() + dt.timedelta(days=3)
        for bad in (None, 24, "soon", later.replace(tzinfo=None).isoformat()):
            r = self.client.post(url, self._body(expires=bad), format="json")
            self.assertEqual(r.status_code, 400, bad)
        self.assertFalse(self.site.deploysites.exists())
        offset = later.astimezone(dt.timezone(dt.timedelta(hours=2)))
        r = self.client.post(url, self._body(expires=offset.isoformat()), format="json")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(
            self.site.deploysites.get().install_flags,
            {"power": False, "ping": True, "rdp": False},
        )

    def test_max_enrollments(self):
        for bad in (0, 100001, "5", True, 2.5):
            r = self.client.post(
                "/clients/deployments/", self._body(max_enrollments=bad), format="json"
            )
            self.assertEqual(r.status_code, 400, bad)
        self.assertFalse(self.site.deploysites.exists())
        r = self.client.post(
            "/clients/deployments/", self._body(max_enrollments=5), format="json"
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual((r.data["max_enrollments"], r.data["enrollments"]), (5, 0))
        deployment = self.site.deploysites.get()
        agents = baker.make_recipe("agents.agent", site=self.site, _quantity=2)
        for agent in agents:
            baker.make("deploy.Enrollment", agent=agent, deployment=deployment)
        r = self.client.post("/clients/deployments/", self._body(), format="json")
        self.assertIsNone(r.data["max_enrollments"])
        rows = {row["id"]: row for row in self.client.get("/clients/deployments/").data}
        self.assertEqual(rows[deployment.pk]["enrollments"], 2)
        self.assertEqual(rows[deployment.pk]["max_enrollments"], 5)
        self.assertEqual(rows[r.data["id"]]["enrollments"], 0)

    def test_legacy_token_masked(self):
        from knox.models import AuthToken

        token, key = AuthToken.objects.create(user=self.john)
        legacy = baker.make(
            "clients.Deployment",
            site=self.site,
            auth_token=token,
            token_key=key,
            expiry=djangotime.now() + dt.timedelta(days=2),
        )
        self.client.post("/clients/deployments/", self._body(), format="json")
        rows = self.client.get("/clients/deployments/").data
        self.assertNotIn(key, json.dumps(rows, default=str))
        by_pk = {row["id"]: row["legacy_token"] for row in rows}
        self.assertEqual(by_pk.pop(legacy.pk), "********")
        self.assertEqual(list(by_pk.values()), [None])

    def test_migration_blanks_token_keys(self):
        from importlib import import_module

        from django.apps import apps

        migration = import_module("clients.migrations.0004_deployment_max_enrollments")
        old = baker.make(
            "clients.Deployment",
            site=self.site,
            token_key="k" * 40,
            expiry=djangotime.now() - dt.timedelta(days=1),
        )
        live = baker.make(
            "clients.Deployment",
            site=self.site,
            token_key="l" * 40,
            expiry=djangotime.now() + dt.timedelta(days=1),
        )
        migration.blank_token_keys(apps, None)
        old.refresh_from_db()
        live.refresh_from_db()
        self.assertEqual((old.token_key, live.token_key), ("", ""))

    def test_bad_policy_and_name(self):
        r = self.client.post(
            "/clients/deployments/", self._body(policy=999999), format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            "/clients/deployments/", self._body(name="a\nb"), format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.site.deploysites.exists())

    def test_list_has_new_fields(self):
        self.client.post("/clients/deployments/", self._body(), format="json")
        r = self.client.get("/clients/deployments/")
        self.assertEqual(r.status_code, 200)
        row = r.data[0]
        for key in ("name", "policy", "policy_name", "url"):
            self.assertIn(key, row)
        self.assertIsNone(row["policy_name"])

    def test_delete_without_knox_token(self):
        self.client.post("/clients/deployments/", self._body(), format="json")
        deployment = self.site.deploysites.get()
        r = self.client.delete(f"/clients/deployments/{deployment.pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(self.site.deploysites.exists())
        entry = AuditLog.objects.get(action=AuditActionType.DELETE)
        self.assertEqual(
            entry.before_value,
            {
                "id": deployment.pk,
                "name": "Laptops",
                "client": self.site.client.name,
                "site": self.site.name,
                "expiry": deployment.expiry.isoformat(),
            },
        )
        self.assertIsNone(entry.after_value)


def _strict_loader():
    real = x509.load_der_x509_certificate

    def load(der):
        # what a future cryptography does with a non-positive serial
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return real(der)

    return load


class TestSpkiPins(ULRMMTestCase):
    real_pins = True

    def test_spki_pins_from_chain_and_root(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        mid_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        root = _cert("Root", "Root", root_key, root_key, ca=True)
        mid = _cert("Mid", "Root", mid_key, root_key, ca=True)
        leaf = _cert("api.example.com", "Mid", leaf_key, mid_key)
        with tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "fullchain.pem"
            chain.write_bytes(_pem(leaf, mid))
            roots = Path(tmp) / "roots.pem"
            roots.write_bytes(b"junk\n" + _pem(root))
            with override_settings(CERT_FILE=str(chain), KEY_FILE=str(chain)):
                original = signing.SYSTEM_ROOTS
                signing.SYSTEM_ROOTS = str(roots)
                try:
                    pins = signing._load_pins()
                finally:
                    signing.SYSTEM_ROOTS = original
        self.assertEqual(
            pins, [signing._spki_pin(c) for c in (leaf, mid, root)], "leaf, mid, root"
        )

    def _pins_with_roots(self, chain_pem: bytes, roots_pem: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "fullchain.pem"
            chain.write_bytes(chain_pem)
            roots = Path(tmp) / "roots.pem"
            roots.write_bytes(roots_pem)
            with override_settings(CERT_FILE=str(chain), KEY_FILE=str(chain)):
                with patch.object(signing, "SYSTEM_ROOTS", str(roots)):
                    return signing._load_pins()

    def test_spki_pins_skip_negative_serial_root(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        root = _cert("Root", "Root", root_key, root_key, ca=True)
        leaf = _cert("api.example.com", "Root", leaf_key, root_key)
        bundle = _negative_serial("Other") + _pem(root) + _negative_serial("Root")
        signing._skipped_certs.clear()
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            with patch.object(
                signing.x509,
                "load_der_x509_certificate",
                side_effect=_strict_loader(),
            ):
                with self.assertLogs("ulrmm", "WARNING") as logs:
                    pins = self._pins_with_roots(_pem(leaf), bundle)
                    again = self._pins_with_roots(_pem(leaf), bundle)
        self.assertEqual(pins, [signing._spki_pin(leaf), signing._spki_pin(root)])
        self.assertEqual(again, pins)
        # the unrelated bad root is never parsed, the bad candidate logged once
        self.assertEqual(len(logs.output), 1, logs.output)
        self.assertIn("skipped an unreadable certificate", logs.output[0])
        self.assertEqual([str(w.message) for w in seen], [])

    def test_spki_pins_bad_chain_cert_keeps_the_rest(self):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert("api.example.com", "api.example.com", key, key)
        signing._skipped_certs.clear()
        with self.assertLogs("ulrmm", "WARNING"):
            pins = self._pins_with_roots(
                _pem(leaf)
                + b"-----BEGIN CERTIFICATE-----\nMIIBAA==\n-----END CERTIFICATE-----\n",
                b"",
            )
        self.assertEqual(pins, [signing._spki_pin(leaf)])

    def test_spki_pins_root_chosen_by_key_id(self):
        old_key = ec.generate_private_key(ec.SECP256R1())
        new_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        old = _with_key_ids(
            _cert("Root", "Root", old_key, old_key, ca=True), old_key, old_key
        )
        new = _with_key_ids(
            _cert("Root", "Root", new_key, new_key, ca=True), new_key, new_key
        )
        leaf = _with_key_ids(
            _cert("api.example.com", "Root", leaf_key, new_key), new_key, leaf_key
        )
        pins = self._pins_with_roots(_pem(leaf), _pem(old, new))
        self.assertEqual(pins, [signing._spki_pin(leaf), signing._spki_pin(new)])

    def test_spki_pins_unreadable(self):
        with override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent"):
            self.assertEqual(signing.spki_pins(), [])

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_spki_pins_follow_the_file(self):
        cache.clear()
        key = ec.generate_private_key(ec.SECP256R1())
        first = _cert("api.example.com", "api.example.com", key, key)
        other_key = ec.generate_private_key(ec.SECP256R1())
        mid = _cert("Mid", "Mid", other_key, other_key, ca=True)
        second = _cert("api.example.com", "Mid", key, other_key)
        with tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "fullchain.pem"
            chain.write_bytes(_pem(first))
            with override_settings(CERT_FILE=str(chain), KEY_FILE=str(chain)):
                self.assertEqual(signing.spki_pins(), [signing._spki_pin(first)])
                # a renewed chain counts at once, not after the cache expired
                chain.write_bytes(_pem(second, mid))
                self.assertEqual(
                    signing.spki_pins(),
                    [signing._spki_pin(second), signing._spki_pin(mid)],
                )
                with patch.object(signing, "_load_pins") as load:
                    signing.spki_pins()
                load.assert_not_called()

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_spki_pins_empty_not_cached(self):
        cache.clear()
        with tempfile.NamedTemporaryFile() as chain:
            with override_settings(CERT_FILE=chain.name, KEY_FILE=chain.name):
                with patch.object(
                    signing, "_load_pins", side_effect=[[], OSError("busy"), ["p"]]
                ):
                    self.assertEqual(signing.spki_pins(), [])
                    self.assertEqual(signing.spki_pins(), [])
                    self.assertEqual(signing.spki_pins(), ["p"])
                    self.assertEqual(signing.spki_pins(), ["p"])

    def test_no_token_without_pins(self):
        site = baker.make("clients.Site")
        deployment = baker.make(
            "clients.Deployment",
            site=site,
            expiry=djangotime.now() + dt.timedelta(days=2),
        )
        with override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent"):
            with self.assertRaisesMessage(signing.Unavailable, signing.NO_PINS):
                signing.mint_for_deployment(deployment, api="https://api.example.com")

    def test_no_token_for_plain_http(self):
        site = baker.make("clients.Site")
        deployment = baker.make(
            "clients.Deployment",
            site=site,
            expiry=djangotime.now() + dt.timedelta(days=2),
        )
        with self.assertRaisesMessage(signing.Unavailable, "not https"):
            signing.claims_for(deployment, api="http://api.example.com", pins=["x"])
        with patch.object(signing, "spki_pins", return_value=["x"]):
            with override_settings(ULRMM_PROTO="http"):
                with self.assertRaisesMessage(signing.Unavailable, "not https"):
                    signing.pin_document()

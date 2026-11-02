# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Agent client certificates (mTLS): the agent CA, leaves, revocation.

nginx verifies a presented certificate against ca.pem and passes
SSL_CLIENT_VERIFY and SSL_CLIENT_FINGERPRINT (SHA-1 hex) to Django, which
matches the fingerprint against AgentCertificate.
"""

import datetime as dt
import hashlib
import os
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone as djangotime

from .models import MODE_CACHE_KEY, AgentCertificate, AgentSecuritySettings, MtlsMode

CA_NAME = "UniversalLocal RMM Agent CA"
CA_DAYS = 3652
CA_KEY = "ca.key"
CA_PEM = "ca.pem"
MAX_CSR = 4096
# X.509 upper bound for a common name; the SAN URI carries the full agent id
MAX_CN = 64
BACKDATE = dt.timedelta(minutes=5)
RENEW_GRACE = dt.timedelta(minutes=15)
MODE_CACHE_TTL = 60
SEEN_EVERY = 5 * 60
MISSING_LIMIT = 50
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
_KEY_USAGES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


class CertError(Exception):
    """The certificate request cannot be signed."""


class CAUnavailable(Exception):
    """The agent CA is missing, incomplete or unreadable."""


def security_settings() -> AgentSecuritySettings:
    return AgentSecuritySettings.objects.filter(pk=1).first() or AgentSecuritySettings(
        pk=1
    )


def mtls_mode() -> str:
    mode = cache.get(MODE_CACHE_KEY)
    if mode is None:
        mode = security_settings().mtls_mode
        cache.set(MODE_CACHE_KEY, mode, MODE_CACHE_TTL)
    return mode


def fingerprints(cert) -> tuple[str, str]:
    """(sha1, sha256) hex of the DER certificate."""
    der = cert.public_bytes(DER)
    return hashlib.sha1(der).hexdigest(), hashlib.sha256(der).hexdigest()


def _paths(directory=None) -> tuple[Path, Path]:
    base = Path(directory or settings.AGENT_CA_DIR)
    return base / CA_KEY, base / CA_PEM


def _serial() -> int:
    return secrets.randbelow(2**128 - 1) + 1


def _key_usage(**flags) -> x509.KeyUsage:
    return x509.KeyUsage(**{name: flags.get(name, False) for name in _KEY_USAGES})


def _write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_ca(directory=None):
    """(private key, certificate) of the agent CA."""
    key_path, pem_path = _paths(directory)
    try:
        cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise CAUnavailable(f"agent CA in {key_path.parent} is unusable: {e}")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.public_key().public_bytes(
        DER, SPKI
    ) != cert.public_key().public_bytes(DER, SPKI):
        raise CAUnavailable(f"{key_path} does not belong to {pem_path}")
    return key, cert


def ensure_ca(directory=None) -> tuple[bool, str]:
    """(created, sha256 fingerprint). Creates the CA when neither file
    exists; an existing CA must load, a half one is never overwritten."""
    key_path, pem_path = _paths(directory)
    if key_path.exists() or pem_path.exists():
        return False, fingerprints(load_ca(directory)[1])[1]

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    now = djangotime.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    private = key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    _write(key_path, private, 0o600)
    _write(pem_path, cert.public_bytes(PEM), 0o644)
    return True, fingerprints(cert)[1]


def ca_info() -> tuple:
    """(sha256 fingerprint, not_after) of ca.pem, (None, None) without one."""
    try:
        cert = x509.load_pem_x509_certificate(_paths()[1].read_bytes())
    except (OSError, ValueError):
        return None, None
    return fingerprints(cert)[1], cert.not_valid_after_utc


def load_csr(pem) -> x509.CertificateSigningRequest:
    if not isinstance(pem, str) or not pem.strip():
        raise CertError("csr is missing")
    if len(pem) > MAX_CSR:
        raise CertError("csr is too large")
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
        key = csr.public_key()
        signed = csr.is_signature_valid
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise CertError("csr is not a PEM certificate request")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise CertError("csr key must be ECDSA P-256")
    if not signed:
        raise CertError("csr signature does not match its key")
    return csr


def issue(agent, csr_pem) -> dict:
    """{"cert", "ca", "not_after"} for the CSR's key. Revokes the agent's
    previous certificates. CertError for the CSR, CAUnavailable for the CA."""
    from .policy import effective

    csr = load_csr(csr_pem)
    ca_key, ca_cert = load_ca()
    now = djangotime.now()
    pol = effective(agent)
    hours = pol["cert_ttl_hours"]
    lifetime = (
        dt.timedelta(hours=hours)
        if hours
        else dt.timedelta(days=security_settings().cert_days)
    )
    agent_id = agent.agent_id
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id[:MAX_CN])])
        )
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(_serial())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(min(now + lifetime, ca_cert.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:ulrmm:agent:{agent_id}")]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    sha1, sha256 = fingerprints(cert)
    with transaction.atomic():
        # agent processes started before the renewal keep the old one a while
        revoke(agent, now=now + RENEW_GRACE)
        AgentCertificate.objects.create(
            agent=agent,
            serial=format(cert.serial_number, "x"),
            fingerprint_sha1=sha1,
            fingerprint_sha256=sha256,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
        )
    return {
        "cert": cert.public_bytes(PEM).decode(),
        "ca": ca_cert.public_bytes(PEM).decode(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "renew_pct": pol["renew_pct"],
    }


def revoke(agent=None, *, now=None) -> int:
    """Revokes the certificates of the agent, or of every agent, that are not
    revoked yet, at ``now`` (default: at once)."""
    at = now or djangotime.now()
    certs = AgentCertificate.objects.filter(Q(revoked_at=None) | Q(revoked_at__gt=at))
    if agent is not None:
        certs = certs.filter(agent=agent)
    return certs.update(revoked_at=at)


def active_certs(now=None):
    now = now or djangotime.now()
    return AgentCertificate.objects.filter(
        Q(revoked_at=None) | Q(revoked_at__gt=now),
        not_before__lte=now,
        not_after__gt=now,
    )


def presented(request) -> str:
    """SHA-1 fingerprint of the client certificate nginx verified, or ""."""
    meta = request.META
    if meta.get("SSL_CLIENT_VERIFY") != "SUCCESS":
        return ""
    return str(meta.get("SSL_CLIENT_FINGERPRINT", "")).replace(":", "").lower()


def touch(cert) -> None:
    if cache.add(f"deploy_cert_seen_{cert.pk}", 1, SEEN_EVERY):
        AgentCertificate.objects.filter(pk=cert.pk).update(last_seen=djangotime.now())


def client_cert_error(request, user, *, issuance: bool = False) -> str:
    """Why the agent request's client certificate is refused, "" if it is
    fine. ``issuance`` is the certificate view, where a missing, unknown or
    no longer active own certificate is let through for a new one."""
    mode = mtls_mode()
    if mode == MtlsMode.OFF:
        return ""
    fingerprint = presented(request)
    if not fingerprint:
        if mode == MtlsMode.REQUIRED and not issuance:
            return "client certificate required"
        return ""
    cert = AgentCertificate.objects.filter(fingerprint_sha1=fingerprint).first()
    own = cert is not None and cert.agent_id == user.agent_id
    if own and cert.is_active():
        touch(cert)
        return ""
    if issuance and (cert is None or own):
        return ""
    return "client certificate does not belong to this agent"


def coverage(user=None, limit: int = MISSING_LIMIT) -> dict:
    """Agents with an active certificate, and those that presented it. The
    counts are global (required mode needs every agent), the missing list
    holds only agents the user may see."""
    from agents.models import Agent

    active = active_certs()
    seen = active.exclude(last_seen=None)
    agents = Agent.objects if user is None else Agent.objects.filter_by_role(user)
    missing = (
        agents.filter(~Exists(seen.filter(agent=OuterRef("pk"))))
        .order_by("hostname", "pk")
        .values("agent_id", "hostname", "version", "last_seen")
    )
    return {
        "agents": Agent.objects.count(),
        "with_cert": active.values("agent").distinct().count(),
        "seen_with_cert": seen.values("agent").distinct().count(),
        "missing": list(missing[:limit]),
    }


def full_coverage(cov: dict) -> bool:
    return cov["seen_with_cert"] >= cov["agents"]

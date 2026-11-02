# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Enrollment tokens: compact JWS (EdDSA) signed with ENROLL_SIGNING_KEY.

Agents verify them with the public key build_agents.sh bakes into brand.go,
the server verifies them again and checks them against the deployment row.
"""

import base64
import binascii
import datetime as dt
import hashlib
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction

from ulrmm.helpers import get_certs
from ulrmm.util_settings import get_backend_url

logger = logging.getLogger("ulrmm")

TOKEN_VERSION = 1
MAX_TOKEN = 4096
FLAGS = ("power", "ping", "rdp")
PINS_CACHE_KEY = "deploy_spki_pins"
PINS_CACHE_TTL = 60 * 60
PIN_DOC_CACHE_TTL = 60
SYSTEM_ROOTS = "/etc/ssl/certs/ca-certificates.crt"
DIST_PUBKEY_FILE = "enroll-pubkey.txt"

_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)
_CLAIM_TYPES = {
    "v": int,
    "iss": str,
    "dep": str,
    "cli": int,
    "site": int,
    "mon": str,
    "flg": dict,
    "pins": list,
    "iat": int,
    "exp": int,
    "jti": str,
}


class EnrollmentError(Exception):
    pass


class Unavailable(Exception):
    """The installer cannot be built right now (503)."""


NO_PINS = "server certificate chain unreadable"
PINS_TYP = "ulrmm-pins"
UPDATE_TYP = "ulrmm-update"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    if not _B64URL.fullmatch(text):
        raise EnrollmentError("enrollment token is malformed")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        # binascii.Error, e.g. a part whose length is 1 mod 4
        raise EnrollmentError("enrollment token is malformed")


def _json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def signing_key() -> Ed25519PrivateKey:
    seed = getattr(settings, "ENROLL_SIGNING_KEY", None)
    if not seed:
        raise ImproperlyConfigured("ENROLL_SIGNING_KEY is not set")
    try:
        raw = base64.b64decode(seed, validate=True)
    except (binascii.Error, ValueError):
        raise ImproperlyConfigured("ENROLL_SIGNING_KEY is not base64")
    if len(raw) != 32:
        raise ImproperlyConfigured("ENROLL_SIGNING_KEY must hold 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_raw() -> bytes:
    return (
        signing_key()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def public_key_b64() -> str:
    return base64.b64encode(_public_raw()).decode("ascii")


def public_key_pem() -> str:
    return (
        signing_key()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def key_id() -> str:
    return hashlib.sha256(_public_raw()).hexdigest()[:16]


def api_url() -> str:
    return get_backend_url(
        settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
    )


def mint(claims: dict, typ: str = "JWT") -> str:
    header = {"alg": "EdDSA", "kid": key_id(), "typ": typ}
    signing_input = f"{_b64url(_json(header))}.{_b64url(_json(claims))}"
    sig = signing_key().sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_b64url(sig)}"


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def verify(token, *, now=None, leeway: int = 60, typ: str = "JWT") -> dict:
    """The token's claims, or EnrollmentError."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN:
        raise EnrollmentError("enrollment token is malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise EnrollmentError("enrollment token is malformed")
    raw_header, raw_claims, sig = (_unb64url(p) for p in parts)
    try:
        header = json.loads(raw_header)
        claims = json.loads(raw_claims)
    except ValueError:
        raise EnrollmentError("enrollment token is malformed")
    if (
        not isinstance(header, dict)
        or header.get("alg") != "EdDSA"
        or header.get("kid") != key_id()
    ):
        raise EnrollmentError("enrollment token is not signed by this server")
    if header.get("typ") != typ:
        # a pin document or update manifest is signed with the same key
        raise EnrollmentError("enrollment token is malformed")
    try:
        signing_key().public_key().verify(sig, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except InvalidSignature:
        raise EnrollmentError("enrollment token signature does not match")

    if not isinstance(claims, dict):
        raise EnrollmentError("enrollment token is malformed")
    for key, kind in _CLAIM_TYPES.items():
        value = claims.get(key)
        if not (_int(value) if kind is int else isinstance(value, kind)):
            raise EnrollmentError(f"enrollment token claim {key} is invalid")
    if claims.get("pol") is not None and not _int(claims["pol"]):
        raise EnrollmentError("enrollment token claim pol is invalid")
    if claims["v"] != TOKEN_VERSION:
        raise EnrollmentError("enrollment token version is not supported")

    now = int(time.time()) if now is None else int(now)
    if claims["exp"] < now - leeway:
        raise EnrollmentError("enrollment token has expired")
    if claims["iat"] > now + 300:
        raise EnrollmentError("enrollment token is not valid yet")
    return claims


def claims_for(deployment, *, api=None, pins=None) -> dict:
    if deployment.expiry is None:
        raise EnrollmentError("deployment has no expiry")
    flags = deployment.install_flags or {}
    issued = deployment.created or deployment.expiry
    api = _https(api or api_url())
    pins = spki_pins() if pins is None else list(pins)
    if not pins:
        # agents would accept any certificate the OS trusts
        raise Unavailable(NO_PINS)
    return {
        "v": TOKEN_VERSION,
        "iss": api,
        "dep": str(deployment.uid),
        "cli": deployment.site.client_id,
        "site": deployment.site_id,
        "mon": deployment.mon_type,
        "pol": deployment.policy_id,
        "flg": {k: bool(flags.get(k)) for k in FLAGS},
        "pins": pins,
        "iat": int(issued.timestamp()),
        "exp": int(deployment.expiry.timestamp()),
        # stable per deployment, so the same deployment yields the same token
        "jti": hashlib.sha256(str(deployment.uid).encode()).hexdigest()[:32],
    }


def _https(api: str) -> str:
    if not api.startswith("https://"):
        raise Unavailable("the API URL is not https")
    return api


def mint_for_deployment(deployment, *, api=None) -> str:
    return mint(claims_for(deployment, api=api))


def check_deployment(claims: dict, *, now=None):
    """The deployment the claims were minted for, still valid and unchanged."""
    from clients.models import Deployment

    try:
        uid = uuid.UUID(claims["dep"])
    except (KeyError, TypeError, ValueError):
        raise EnrollmentError("enrollment token claim dep is invalid")
    deployment = (
        Deployment.objects.select_related("site", "policy").filter(uid=uid).first()
    )
    if deployment is None:
        raise EnrollmentError("deployment not found")
    moment = dt.datetime.fromtimestamp(
        time.time() if now is None else now, tz=dt.timezone.utc
    )
    if deployment.expiry is None or deployment.expiry <= moment:
        raise EnrollmentError("deployment has expired")
    expected = {
        "cli": deployment.site.client_id,
        "site": deployment.site_id,
        "mon": deployment.mon_type,
        "pol": deployment.policy_id,
    }
    if any(claims.get(k) != v for k, v in expected.items()):
        raise EnrollmentError("enrollment token does not match the deployment")
    return deployment


def _spki_pin(cert) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


_skipped_certs: set[str] = set()


def _ders(data: bytes) -> list[bytes]:
    ders = []
    for block in _PEM_CERT.findall(data):
        try:
            ders.append(
                base64.b64decode(b"".join(block[27:-25].split()), validate=True)
            )
        except ValueError:
            continue
    return ders


def _load_cert(der: bytes, source: str):
    try:
        return x509.load_der_x509_certificate(der)
    except Exception as e:
        # a future cryptography raises where 50.x only warns (negative serial)
        digest = hashlib.sha256(der).hexdigest()
        if digest not in _skipped_certs:
            _skipped_certs.add(digest)
            logger.warning(
                f"deploy: skipped an unreadable certificate in {source} "
                f"(sha256 {digest[:16]}): {e}"
            )
        return None


def _key_id(cert, ext_type):
    try:
        ext = cert.extensions.get_extension_for_class(ext_type).value
    except (x509.ExtensionNotFound, ValueError):
        return None
    if ext_type is x509.SubjectKeyIdentifier:
        return ext.digest
    return ext.key_identifier


def _issuing_roots(top, data: bytes) -> list:
    """Roots in data that issued top; only candidates holding top's issuer name
    or authority key id are parsed."""
    name = top.issuer.public_bytes()
    aki = _key_id(top, x509.AuthorityKeyIdentifier)
    roots = []
    for der in _ders(data):
        if name not in der and not (aki and aki in der):
            continue
        root = _load_cert(der, SYSTEM_ROOTS)
        if root is None:
            continue
        ski = _key_id(root, x509.SubjectKeyIdentifier)
        if (aki and ski == aki) or (root.subject == top.issuer and not (aki and ski)):
            roots.append(root)
    return roots


def _load_pins() -> list[str]:
    path = get_certs()[0]
    chain = [
        c for c in (_load_cert(d, path) for d in _ders(Path(path).read_bytes())) if c
    ]
    if not chain:
        return []
    pins = [_spki_pin(c) for c in chain]
    top = chain[-1]
    if top.subject != top.issuer:
        try:
            roots = _issuing_roots(top, Path(SYSTEM_ROOTS).read_bytes())
        except OSError:
            roots = []
        pins += [_spki_pin(r) for r in roots]
    return list(dict.fromkeys(pins))


def spki_pins() -> list[str]:
    """SPKI hashes of the server certificate chain, [] when unreadable. The
    cache follows the file, a new chain counts at once."""
    path = get_certs()[0]
    try:
        st = os.stat(path)
        key = "{}:{}:{}:{}:{}".format(
            PINS_CACHE_KEY,
            hashlib.sha256(path.encode()).hexdigest()[:16],
            st.st_mtime_ns,
            st.st_size,
            st.st_ino,
        )
        pins = cache.get(key)
        if not pins:
            pins = _load_pins()
            if pins:
                cache.set(key, pins, PINS_CACHE_TTL)
    except OSError as e:
        logger.warning(f"deploy: no certificate pins: {e}")
        return []
    return pins


def dist_pubkey_ok() -> bool:
    """The agent build in the dist dir carries the current public key."""
    dist = Path(getattr(settings, "AGENTS_DIST_DIR", "/opt/ulrmm-agents/dist"))
    try:
        return (dist / DIST_PUBKEY_FILE).read_text().strip() == public_key_b64()
    except (OSError, ImproperlyConfigured):
        return False


CMD_KEY_INFO = b"ulrmm command key v1"
CMD_KEY_TTL = 60
CMD_KID_CACHE = "deploy_cmd_kid"
CMD_RETIRED_DAYS = 7
CMD_PROMOTE_AFTER = dt.timedelta(hours=24)
_cmd_keys: dict = {}


def _ed_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def command_key_private(row) -> Ed25519PrivateKey:
    from remote.utils import decrypt_secret

    if (hit := _cmd_keys.get(row.kid)) is not None:
        return hit
    seed = base64.b64decode(decrypt_secret(row.seed, CMD_KEY_INFO))
    _cmd_keys[row.kid] = Ed25519PrivateKey.from_private_bytes(seed)
    return _cmd_keys[row.kid]


def _new_command_key(state: str):
    from remote.utils import encrypt_secret

    from .models import CommandKey

    seed = os.urandom(32)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return CommandKey.objects.create(
        kid=hashlib.sha256(_ed_raw(key)).hexdigest()[:16],
        seed=encrypt_secret(base64.b64encode(seed).decode(), CMD_KEY_INFO),
        state=state,
        switched_at=dt.datetime.now(dt.timezone.utc) if state == "current" else None,
    )


def current_command_key():
    """The CommandKey commands are signed with, created on first use."""
    from .models import CommandKey

    for _ in range(3):
        row = CommandKey.objects.filter(state="current").first()
        if row is not None:
            return row
        try:
            with transaction.atomic():
                return _new_command_key("current")
        except IntegrityError:
            continue
    raise Unavailable("command key is being changed")


def command_signer() -> tuple[str, Ed25519PrivateKey]:
    """(kid, key) of the current command key; the kid is cached for a minute."""
    kid = cache.get(CMD_KID_CACHE)
    if kid not in _cmd_keys:
        row = current_command_key()
        kid = row.kid
        command_key_private(row)
        cache.set(CMD_KID_CACHE, kid, CMD_KEY_TTL)
    return kid, _cmd_keys[kid]


def command_claim(now=None) -> list[dict]:
    """The cmd claim: next, current and recently retired keys, oldest first."""
    from .models import CommandKey

    current_command_key()
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=CMD_RETIRED_DAYS)
    rows = CommandKey.objects.exclude(state="retired", retired_at__lt=cutoff)
    return [
        {
            "kid": row.kid,
            "ed": base64.b64encode(_ed_raw(command_key_private(row))).decode(),
            "state": row.state,
        }
        for row in rows.order_by("created", "pk")
    ]


def rotate_command_key():
    """A next key (pin document seq+1); an existing next key is kept."""
    from .models import CommandKey

    current_command_key()
    with transaction.atomic():
        row = CommandKey.objects.select_for_update().filter(state="next").first()
        return row or _new_command_key("next")


def promote_command_keys(now=None) -> str:
    """next becomes current when it is 24 h old or every agent with an active
    sec2 identity reports the pin document that lists it."""
    from .models import AgentIdentity, CommandKey, PinSet

    now = now or dt.datetime.now(dt.timezone.utc)
    nxt = CommandKey.objects.filter(state="next").order_by("created").first()
    if nxt is None:
        return "nothing to promote"
    if nxt.created > now - CMD_PROMOTE_AFTER:
        listed = [
            p.seq
            for p in PinSet.objects.order_by("seq").only("seq", "cmd")
            if any(c.get("kid") == nxt.kid for c in p.cmd or [])
        ]
        idents = AgentIdentity.objects.filter(state="active", caps__contains=["sec2"])
        if not listed or idents.filter(pin_seq__lt=listed[0]).exists():
            return "waiting"
    with transaction.atomic():
        CommandKey.objects.filter(state="current").update(
            state="retired", retired_at=now
        )
        CommandKey.objects.filter(pk=nxt.pk).update(state="current", switched_at=now)
    cache.delete(CMD_KID_CACHE)
    from .events import record
    from .models import SecurityEventKind, SecurityEventSeverity

    record(
        SecurityEventKind.COMMAND_KEY_ROTATED,
        SecurityEventSeverity.INFO,
        detail=f"command key {nxt.kid} is current",
    )
    return f"promoted {nxt.kid}"


def current_pinset():
    """The PinSet of the running chain, the admin's backup pins, the command
    keys and the sec2 mode, a new one with the next seq when they changed."""
    from .models import PinSet
    from .pki import security_settings

    primary = spki_pins()
    if not primary:
        raise Unavailable(NO_PINS)
    sec = security_settings()
    backup = list(sec.backup_pins or [])
    cmd = command_claim()
    sec2 = sec.sec2_mode
    for _ in range(3):
        last = PinSet.objects.order_by("-seq").first()
        if last is not None and (last.primary, last.backup, last.cmd, last.sec2) == (
            primary,
            backup,
            cmd,
            sec2,
        ):
            return last
        try:
            with transaction.atomic():
                return PinSet.objects.create(
                    seq=last.seq + 1 if last else 1,
                    primary=primary,
                    backup=backup,
                    cmd=cmd,
                    sec2=sec2,
                )
        except IntegrityError:
            # a parallel request stored the same change
            continue
    raise Unavailable("pin set is being changed")


def pin_document() -> str:
    """Compact JWS of the current pin set; agents keep the highest seq."""
    pins = current_pinset()
    iss = _https(api_url())
    # a restored database can give a seq number to another set
    signed = _json(
        [pins.seq, pins.primary, pins.backup, pins.cmd, pins.sec2, iss, key_id()]
    )
    key = "deploy_pin_document:" + hashlib.sha256(signed).hexdigest()
    if jws := cache.get(key):
        return jws
    claims = {
        "v": 1,
        "typ": PINS_TYP,
        "iss": iss,
        "seq": pins.seq,
        "primary": list(pins.primary),
        "backup": list(pins.backup),
        "cmd": list(pins.cmd),
        "sec2": pins.sec2,
        "iat": int(time.time()),
    }
    jws = mint(claims, PINS_TYP)
    cache.set(key, jws, PIN_DOC_CACHE_TTL)
    return jws


def sign_agent_update(agent_id: str, url: str, version: str, sha256: str) -> str:
    """Compact JWS over an agentupdate payload for one agent."""
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    claims = {
        "v": 1,
        "typ": UPDATE_TYP,
        "agent": agent_id,
        "url": url,
        "version": version,
        "sha256": sha256,
        "iat": int(time.time()),
    }
    return mint(claims, UPDATE_TYP)

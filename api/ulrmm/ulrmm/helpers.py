# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import calendar
import hashlib
import hmac
import os
import random
import re
import secrets
import string
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone as djangotime
from packaging.version import InvalidVersion
from packaging.version import Version as PkgVersion
from rest_framework.response import Response

from ulrmm.constants import MONTHS, WEEKDAY_TO_BIT

if TYPE_CHECKING:
    from alerts.models import AlertTemplate


# X.DD.MM.YYYY, a leading "v" and 1- or 2-digit day/month tolerated
DATED_VER = re.compile(r"^v?(\d+)\.(\d{1,2})\.(\d{1,2})\.(\d{4})$")


def agent_ver(ver: Optional[str]) -> PkgVersion:
    """A sortable key for agent versions.

    Date-stamped versions (``X.DD.MM.YYYY``) are mapped to ``YYYY.MM.DD.X`` so
    they order by date then by the daily counter, and every one of them sorts
    above every legacy ``MAJOR.MINOR.PATCH`` build.
    """
    match = DATED_VER.match(ver or "")
    if match:
        counter, day, month, year = match.groups()
        return PkgVersion(f"{year}.{int(month)}.{int(day)}.{counter}")
    try:
        return PkgVersion(ver or "")
    except InvalidVersion:
        return PkgVersion("0")


def date_is_in_past(*, datetime_obj, agent_tz: str) -> bool:
    localized = datetime_obj.replace(tzinfo=ZoneInfo(agent_tz))
    return djangotime.now() > localized


def rand_range(min: int, max: int) -> float:
    # milliseconds in, seconds out; jitter only
    return round(random.uniform(min, max) / 1000, 2)


def make_random_password(*, len: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(len))


def get_certs() -> tuple[str, str]:
    host = settings.ALLOWED_HOSTS[0]
    # drop the first label: api.example.com -> example.com
    domain = host.split(".", 1)[1] if "." in host else host
    cert_file = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key_file = f"/etc/letsencrypt/live/{domain}/privkey.pem"

    configured_cert = getattr(settings, "CERT_FILE", None)
    configured_key = getattr(settings, "KEY_FILE", None)
    if configured_cert and configured_key:
        return configured_cert, configured_key
    return cert_file, key_file


def self_signed_cert_pem() -> str:
    """Certificate of a self-signed server (ULRMM_INSECURE) for the agent's
    -cert, "" otherwise or when it cannot be read."""
    if not getattr(settings, "ULRMM_INSECURE", False):
        return ""
    try:
        with open(get_certs()[0]) as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError):
        return ""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----",
        text,
    )
    return match.group(0) if match else ""


def days_until_cert_expires() -> int:
    from cryptography import x509

    with open(get_certs()[0], "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    return (cert.not_valid_after_utc - djangotime.now()).days


def is_weekday_in_bitmask(weekday: int, bitmask: int) -> int:
    return WEEKDAY_TO_BIT[weekday] & bitmask


def is_month_in_bitmask(month: int, bitmask: int) -> int:
    return MONTHS[calendar.month_name[month]] & bitmask


def has_webhook(alert_templ: "Optional[AlertTemplate]", instance: str) -> bool:
    if not alert_templ:
        return False
    # the flag first, the ids need no query
    return bool(
        getattr(alert_templ, f"{instance}_script_actions")
        and (alert_templ.action_rest_id or alert_templ.resolved_action_rest_id)
    )


def has_script_actions(alert_templ: "Optional[AlertTemplate]", instance: str) -> bool:
    if not alert_templ:
        return False
    return bool(
        getattr(alert_templ, f"{instance}_script_actions")
        and (alert_templ.action_id or alert_templ.resolved_action_id)
    )


def get_client_ip(meta) -> str:
    if getattr(settings, "ULRMM_TRUST_X_FORWARDED_FOR", False):
        from python_ipware import IpWare

        ip, _ = IpWare().get_client_ip(meta)
        return str(ip) if ip else ""
    return meta.get("REMOTE_ADDR", "") or ""


def get_issues_url() -> str:
    url = getattr(settings, "ISSUES_URL", "")
    if not url:
        git_url = getattr(settings, "ULRMM_GIT_URL", "")
        if not git_url:
            return ""
        base = git_url[:-1] if git_url.endswith("/") else git_url
        if base.endswith(".git"):
            base = base[:-4]
        url = f"{base}/issues"

    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return ""
        host = parts.hostname.lower()
        if ":" in host:
            # IPv6 literal, restore the brackets urlsplit stripped
            host = f"[{host}]"
        netloc = f"{host}:{parts.port}" if parts.port else host
        path = parts.path.rstrip("/")
        return urlunsplit((parts.scheme, netloc, path, "", ""))
    except ValueError:
        return ""


def get_nats_ports() -> tuple[int, int]:
    std = getattr(settings, "NATS_STANDARD_PORT", 4222)
    ws = getattr(settings, "NATS_WEBSOCKET_PORT", 9235)
    return std, ws


def get_nats_internal_protocol() -> str:
    return "tls" if getattr(settings, "USE_NATS_STANDARD", False) else "nats"


def _nats_host(env_name: str, default: str) -> str:
    if env_name in os.environ:
        return os.environ[env_name]
    return getattr(settings, env_name, default)


def get_nats_hosts() -> tuple[str, str, str]:
    # the websocket listener has no TLS and nginx proxies /natsws to loopback
    ws_bind = "127.0.0.1"
    if getattr(settings, "USE_NATS_STANDARD", False):
        std_bind, connect = "0.0.0.0", settings.ALLOWED_HOSTS[0]
    else:
        std_bind = connect = "127.0.0.1"

    std_bind = _nats_host("NATS_STD_BIND_HOST", std_bind)
    ws_bind = _nats_host("NATS_WS_BIND_HOST", ws_bind)
    connect = _nats_host("NATS_CONNECT_HOST", connect)
    return std_bind, ws_bind, connect


def get_nats_url() -> str:
    proto = get_nats_internal_protocol()
    connect = get_nats_hosts()[2]
    std_port = get_nats_ports()[0]
    return f"{proto}://{connect}:{std_port}"


def get_nats_server_password() -> str:
    configured = getattr(settings, "NATS_SERVER_PASSWORD", "")
    if configured:
        return configured
    # a deterministic fallback that is never the signing key itself
    return hmac.new(
        settings.SECRET_KEY.encode(), b"nats-server-user", hashlib.sha256
    ).hexdigest()


def setup_nats_options() -> dict:
    return {
        "servers": get_nats_url(),
        "user": "ulrmm",
        "name": "ulrmm-django",
        "password": get_nats_server_password(),
        "connect_timeout": 3,
        "max_reconnect_attempts": 2,
    }


def notify_error(msg) -> Response:
    return Response(msg, status=400)


def save_or_update_existing(serializer, model, **unique_key):
    """Saves a validated serializer. When a parallel writer inserted the
    unique key first, that row is updated instead of failing the request."""
    try:
        with transaction.atomic():
            return serializer.save()
    except IntegrityError:
        existing = None
        if serializer.instance is None:
            existing = model.objects.filter(**unique_key).first()
        if existing is None:
            raise
        serializer.instance = existing
        return serializer.save()

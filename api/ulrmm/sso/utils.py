# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import ipaddress
import logging
import re
import socket
from contextlib import suppress
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import HttpResponseRedirect

from core.utils import CoreSettingsNotFound, get_core_settings

logger = logging.getLogger("ulrmm")

PROVIDER = "openid_connect"

# a recorded IdP sign-in can be traded for a dashboard token this long (seconds)
EXCHANGE_MAX_AGE = 300

# first match wins, so the order matters
PROVIDER_ICONS = (
    ("google.com", "mdi-google"),
    ("microsoft", "mdi-microsoft"),
    ("discord.com", "fa-brands fa-discord"),
    ("github.com", "fa-brands fa-github"),
    ("slack.com", "fa-brands fa-slack"),
    ("facebook.com", "fa-brands fa-facebook"),
    ("linkedin.com", "fa-brands fa-linkedin"),
    ("apple.com", "fa-brands fa-apple"),
    ("amazon.com", "fa-brands fa-amazon"),
    ("auth0.com", "mdi-lock"),
    ("gitlab.com", "fa-brands fa-gitlab"),
    ("twitter.com", "fa-brands fa-twitter"),
    ("paypal.com", "fa-brands fa-paypal"),
    ("yahoo.com", "fa-brands fa-yahoo"),
)
DEFAULT_ICON = "mdi-key"


class IdPURLError(ValueError):
    pass


PRIVATE_ADDRESS = (
    "The URL points to a loopback, link-local, private or metadata address."
)


def sso_enabled() -> bool:
    try:
        return bool(get_core_settings().sso_enabled)
    except CoreSettingsNotFound:
        return False


def derive_provider_id(name: str) -> str:
    # whitespace becomes a hyphen, everything outside [a-z0-9_-] is dropped
    return re.sub(r"[^a-z0-9_-]", "", re.sub(r"\s", "-", name.lower()))


def provider_icon(server_url) -> str:
    url = str(server_url or "").lower()
    return next((icon for part, icon in PROVIDER_ICONS if part in url), DEFAULT_ICON)


# IPv6 ranges that carry an IPv4 address in their last 32 bits: the NAT64
# well-known prefix and the deprecated IPv4-compatible form
_EMBEDDED_IPV4 = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("::/96"),
)


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif any(ip in net for net in _EMBEDDED_IPV4):
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip.is_global and not ip.is_multicast


def public_addresses(host: str, port: int) -> list[str]:
    """The addresses host resolves to. Raises IdPURLError unless all are public.

    Resolver errors (OSError, UnicodeError) are left to the caller.
    """
    host = host.strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        raise IdPURLError(PRIVATE_ADDRESS)
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = [info[4][0] for info in infos]
    if not all(_is_public(a) for a in addresses):
        raise IdPURLError(PRIVATE_ADDRESS)
    return addresses


def check_idp_url(url: str, resolve: bool = True) -> None:
    """Raises IdPURLError unless url is https on a public address.

    Checked when a provider is saved and again before every request the server
    sends to an IdP, so a discovery document cannot point the token or userinfo
    call somewhere internal. A name that does not resolve passes here; the
    request to it fails on its own. The connection itself checks the address
    it connects to again (adapter.PinnedHTTPSConnection). resolve=False skips
    the DNS lookup and checks IP literals and localhost names only.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise IdPURLError("Enter a valid URL.")

    if parts.scheme != "https" or not parts.hostname:
        raise IdPURLError("The URL must be an https:// address.")
    if parts.username or parts.password:
        raise IdPURLError("The URL must not contain credentials.")

    if getattr(settings, "SSO_ALLOW_PRIVATE_ISSUER", False):
        return

    host = parts.hostname
    if not resolve and not (host == "localhost" or host.endswith(".localhost")):
        # other names are checked on save and when connecting
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return

    with suppress(OSError, UnicodeError):
        public_addresses(host, port or 443)


_reported_blocks = set()


def issuer_problem(app) -> str:
    """Why the provider's issuer URL fails the URL rule, "" if it passes.

    Providers saved before the rule existed keep their row but cannot sign in.
    Each one is logged once per process. Runs on the login page and the
    provider list, so it does not resolve names: the save check and the
    connection itself do that.
    """
    url = provider_settings(app).get("server_url")
    try:
        check_idp_url(str(url or ""), resolve=False)
    except IdPURLError as e:
        reason = str(e)
    else:
        return ""

    if (app.pk, url, reason) not in _reported_blocks:
        _reported_blocks.add((app.pk, url, reason))
        hint = ""
        if reason == PRIVATE_ADDRESS:
            hint = (
                " SSO_ALLOW_PRIVATE_ISSUER = True in local_settings.py allows an"
                " issuer on the internal network."
            )
        logger.warning(f"SSO provider {app.provider_id} is blocked: {reason}{hint}")
    return reason


def role_pk(value):
    """The role pk a provider setting or request holds, None for none or junk."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    with suppress(ValueError):
        return int(value) or None
    return None


def login_callback_url() -> str:
    # the dashboard page that finishes the sign-in, also the error target
    return settings.HEADLESS_FRONTEND_URLS["socialaccount_login_error"]


def login_error_redirect(code: str) -> HttpResponseRedirect:
    query = urlencode({"error": code, "error_process": "login"})
    return HttpResponseRedirect(f"{login_callback_url()}?{query}")


def provider_settings(app) -> dict:
    return app.settings if isinstance(app.settings, dict) else {}

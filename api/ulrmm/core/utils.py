# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import base64
import binascii
import contextvars
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, suppress
from urllib.parse import quote, urlencode, urlsplit

import psutil
import requests
import websockets
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse
from urllib3.util import connection as urllib3_connection

from ulrmm.constants import (
    CORE_BRANDING_CACHE_KEY,
    CORESETTINGS_CACHE_KEY,
    ULRMM_LATEST_VER_CACHE_KEY,
    ULRMM_WS_MAX_SIZE,
    AgentPlat,
    GoArch,
)
from ulrmm.logger import logger

from .meshtoken import get_auth_token

SERVER_SCRIPT_STEPUP = "A server script runs on this host as the service user."

MESH_INSTALLER_MAX_BYTES = 200 * 2**20
# a MeshCentral setting change alters the binary, so the hash is kept short
MESH_SHA_TTL = 15 * 60
MESH_SHA_FAIL_TTL = 5 * 60

_IMG_MAGIC = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/gif": b"GIF8",
    "image/webp": b"RIFF",
}
_DATA_URI_RE = re.compile(r"data:([^;]+);base64,(.*)", re.DOTALL)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


class CoreSettingsNotFound(Exception):
    pass


class MeshDeviceGroupNotFound(Exception):
    def __init__(self, device_group: str) -> None:
        self.device_group = device_group
        super().__init__(
            f"Device group '{device_group}' was not found in MeshCentral. Global "
            "Settings > MeshCentral must name an existing group."
        )


class MeshNoReply(MeshDeviceGroupNotFound):
    # a subclass so every caller that reports a missing group reports this too
    def __init__(self, device_group: str) -> None:
        self.device_group = device_group
        Exception.__init__(
            self, "MeshCentral did not answer the device group lookup in time."
        )


# settings / branding


def get_core_settings():
    from .models import CoreSettings

    cached = cache.get(CORESETTINGS_CACHE_KEY)
    if isinstance(cached, CoreSettings):
        return cached

    obj = CoreSettings.objects.first()
    if not obj:
        raise CoreSettingsNotFound("CoreSettings not found.")
    cache.set(CORESETTINGS_CACHE_KEY, obj, 600)
    return obj


def clear_entire_cache() -> None:
    # throttle_* stays: clearing it would reset the login brute-force counters
    for pattern in (
        "role_*",
        "agent_tbl_pendingactions_*",
        "agent_checks_data_*",
        "site_*",
        "agent_*",
    ):
        cache.delete_many_pattern(pattern)
    cache.delete(CORESETTINGS_CACHE_KEY)
    cache.delete(CORE_BRANDING_CACHE_KEY)
    cache.delete(ULRMM_LATEST_VER_CACHE_KEY)


def get_branding():
    from branding.models import Branding

    cached = cache.get(CORE_BRANDING_CACHE_KEY)
    if isinstance(cached, Branding):
        return cached

    obj = Branding.objects.first() or Branding()
    cache.set(CORE_BRANDING_CACHE_KEY, obj, 600)
    return obj


def validate_image_data_uri(value):
    if not value:
        return ""
    m = _DATA_URI_RE.fullmatch(value)
    if not m:
        raise ValueError("must be a base64 data URI")
    mime = m.group(1).lower()
    if mime not in _IMG_MAGIC:
        raise ValueError("unsupported image type")
    try:
        raw = base64.b64decode(m.group(2), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid base64")
    if len(raw) > 524288:
        raise ValueError("image too large (max 512 KB)")
    if not raw.startswith(_IMG_MAGIC[mime]):
        raise ValueError("content does not match declared type")
    return value


# MeshCentral


def _mesh_port() -> int:
    return getattr(settings, "MESH_PORT", None) or 4430


def get_mesh_ws_url() -> str:
    core = get_core_settings()
    token = get_auth_token(core.mesh_api_superuser, core.mesh_token)
    if getattr(settings, "USE_EXTERNAL_MESH", False):
        site = core.mesh_site or ""
        # the login token is in the query string, never over plain ws://
        if not site.startswith("https://"):
            raise ValueError("MESH_SITE must be an https:// URL with USE_EXTERNAL_MESH")
        return f"wss{site[len('https'):]}/control.ashx?auth={token}"
    return f"ws://{settings.MESH_HOST}:{_mesh_port()}/control.ashx?auth={token}"


async def get_mesh_device_id(uri: str, device_group: str) -> str:
    async with websockets.connect(uri, max_size=ULRMM_WS_MAX_SIZE) as ws:
        await ws.send(json.dumps({"action": "meshes", "responseid": "meshctrl"}))
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=120)
            except asyncio.TimeoutError:
                logger.warning("get_mesh_device_id: no reply from MeshCentral")
                raise MeshNoReply(device_group)
            data = json.loads(raw)
            if data.get("action") == "meshes":
                for mesh in data.get("meshes") or []:
                    if mesh.get("name") == device_group:
                        return str(mesh["_id"]).replace("mesh//", "")
                raise MeshDeviceGroupNotFound(device_group)


def get_meshagent_url(*, ident, plat, mesh_site, mesh_device_id) -> str:
    if getattr(settings, "USE_EXTERNAL_MESH", False):
        base = mesh_site
    else:
        base = f"http://{settings.MESH_HOST}:{_mesh_port()}"

    if plat == AgentPlat.WINDOWS:
        query = urlencode({"id": ident, "meshid": mesh_device_id, "installflags": 0})
    else:
        query = urlencode(
            {"id": mesh_device_id, "installflags": 2, "meshinstall": ident}
        )
    return f"{base}/meshagents?{query}"


def _mesh_download_verify():
    if getattr(settings, "USE_EXTERNAL_MESH", False):
        return not getattr(settings, "ULRMM_MESH_INSECURE", False)
    # loopback http has no certificate to check
    return True


def download_mesh_agent(dl_url: str) -> HttpResponse:
    content = bytearray()
    with requests.get(
        dl_url, stream=True, timeout=15, verify=_mesh_download_verify()
    ) as r:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=64 * 1024):
            content += chunk
            if len(content) > MESH_INSTALLER_MAX_BYTES:
                raise SuspiciousOperation("mesh installer too large")
    response = HttpResponse(bytes(content), content_type="application/octet-stream")
    response["Content-Disposition"] = 'attachment; filename="meshagent"'
    return response


def mesh_installer_sha256(*, ident, plat, mesh_device_id, mesh_site) -> str:
    """sha256 of the mesh agent an install script downloads from mesh_site,
    fetched once from the local MeshCentral; "" (logged) when that fails, and
    the script then installs it unchecked."""
    import hashlib

    key = (
        "mesh_installer_sha256:"
        + hashlib.sha256(
            "\0".join(
                (
                    str(mesh_device_id),
                    str(plat),
                    str(ident),
                    settings.MESH_VER,
                    mesh_site,
                )
            ).encode()
        ).hexdigest()[:32]
    )
    cached = cache.get(key)
    if cached is not None:
        return cached
    url = get_meshagent_url(
        ident=ident, plat=plat, mesh_site=mesh_site, mesh_device_id=mesh_device_id
    )
    # MeshCentral builds the agent's settings from the host it is asked for
    host = urlsplit(mesh_site or "").netloc
    digest = hashlib.sha256()
    size = 0
    try:
        with requests.get(
            url,
            stream=True,
            timeout=15,
            verify=_mesh_download_verify(),
            headers={"Host": host} if host else None,
        ) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=64 * 1024):
                size += len(chunk)
                if size > MESH_INSTALLER_MAX_BYTES:
                    raise SuspiciousOperation("mesh installer too large")
                digest.update(chunk)
        if not size:
            raise ValueError("empty answer")
    except Exception as e:
        logger.warning(
            f"mesh agent {plat} {ident}: no sha256, install scripts do not check "
            f"it for {MESH_SHA_FAIL_TTL // 60} minutes: {type(e).__name__}"
        )
        cache.set(key, "", MESH_SHA_FAIL_TTL)
        return ""
    value = digest.hexdigest()
    cache.set(key, value, MESH_SHA_TTL)
    return value


def get_mesh_installer(goarch: str, dl_url: str, plat: str) -> str:
    if plat not in AgentPlat.values or goarch not in GoArch.values:
        raise SuspiciousOperation("invalid args")

    import hashlib

    exe_dir = settings.EXE_DIR
    target = os.path.join(exe_dir, f"mesh-{plat}-{goarch}")

    with requests.get(
        dl_url, stream=True, timeout=15, verify=_mesh_download_verify()
    ) as r:
        r.raise_for_status()
        digest = hashlib.sha256()
        size = 0
        fd, tmp = tempfile.mkstemp(dir=exe_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MESH_INSTALLER_MAX_BYTES:
                        raise SuspiciousOperation("mesh installer too large")
                    digest.update(chunk)
                    fh.write(chunk)
            new_sha = digest.hexdigest()
            if os.path.isfile(target) and _file_sha256(target) == new_sha:
                os.remove(tmp)
                return target
            os.replace(tmp, target)
        except Exception:
            with suppress(OSError):
                os.remove(tmp)
            raise
    return target


def _file_sha256(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _b64_to_hex(h: str) -> str:
    raw = bytes.fromhex(h)
    return base64.b64encode(raw).decode().replace("/", "$").replace("+", "@")


async def _mesh_fire(uri: str, payload: dict) -> None:
    async with websockets.connect(uri, max_size=ULRMM_WS_MAX_SIZE) as ws:
        await ws.send(json.dumps(payload))


async def send_command_with_mesh(
    cmd: str, uri: str, mesh_node_id: str, shell: int, run_as_user
) -> None:
    await _mesh_fire(
        uri,
        {
            "action": "runcommands",
            "cmds": cmd,
            "nodeids": [f"node//{_b64_to_hex(mesh_node_id)}"],
            "runAsUser": run_as_user,
            "type": shell,
            "responseid": "ulrmm",
        },
    )


async def wake_on_lan(*, uri: str, mesh_node_ids) -> None:
    # takes the stored (hex) ids; MeshCentral looks devices up by their base64 db id
    nodeids = []
    for n in mesh_node_ids:
        with suppress(ValueError, TypeError):
            nodeids.append(f"node//{_b64_to_hex(n)}")
    if not nodeids:
        return
    await _mesh_fire(
        uri,
        {"action": "wakedevices", "nodeids": nodeids, "responseid": "ulrmm"},
    )


async def remove_mesh_agent(uri: str, mesh_node_id: str) -> None:
    await _mesh_fire(
        uri,
        {
            "action": "removedevices",
            "nodeids": [f"node//{mesh_node_id}"],
            "responseid": "ulrmm",
        },
    )


def sysd_svc_is_running(svc: str) -> bool:
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", svc], capture_output=True
        ).returncode
        == 0
    )


def make_alpha_numeric(s: str) -> str:
    return "".join(c for c in s if c.isalnum())


# URL actions


_VALUE_ESCAPES = {
    "url": lambda v: quote(v, safe=""),
    "json": lambda v: json.dumps(v, ensure_ascii=False)[1:-1],
}


def find_and_replace_db_values_str(*, text, instance, escape=None):
    """Fills {{model.field}} placeholders. With escape="url" or "json" the
    agent, client, site and alert values are encoded for that context; key
    store values are set by admins and go in as written."""
    if not instance:
        return text

    from ulrmm.utils import RE_DB_VALUE, get_db_value

    encode = _VALUE_ESCAPES[escape] if escape else None

    def repl(match):
        value = str(
            get_db_value(string=f"{match.group(2)}.{match.group(3)}", instance=instance)
        )
        if encode and match.group(2) != "global":
            value = encode(value)
        return value

    return RE_DB_VALUE.sub(repl, text)


def _sanitize_webhook(s: str) -> str:
    s = _CTRL_RE.sub(" ", s)
    # keep Windows paths valid inside JSON: double a lone backslash only
    return re.sub(r"\\(?![\\nrt])", r"\\\\", s)


# LAN and private ranges stay reachable on purpose (ticketing, chat, NAS)
_REFUSED_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "100::/64",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)


def _own_addresses() -> set:
    own = set()
    with suppress(Exception):
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family in (socket.AF_INET, socket.AF_INET6):
                    with suppress(ValueError):
                        own.add(ipaddress.ip_address(entry.address.split("%")[0]))
    return own


def _refused_address(addr: str, own: set) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or any(ip in net for net in _REFUSED_NETS)
        or ip in own
    )


def _is_internal_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return True
    if parts.scheme.lower() not in ("http", "https") or not host:
        return True
    try:
        infos = socket.getaddrinfo(host.split("%")[0], None)
    except (socket.gaierror, UnicodeError):
        # nothing to connect to; the connection guard refuses it again
        return False
    own = _own_addresses()
    return any(_refused_address(info[4][0], own) for info in infos)


_url_guard = contextvars.ContextVar("url_guard", default=False)
_plain_create_connection = urllib3_connection.create_connection


def _guarded_create_connection(address, *args, **kwargs):
    """urllib3 opens every socket through this. Inside url_guard() the host
    is resolved once, every address is checked and the socket goes to a
    checked address, so a second DNS answer cannot point it elsewhere. TLS
    still verifies the certificate against the host name."""
    if not _url_guard.get():
        return _plain_create_connection(address, *args, **kwargs)
    host, port = address
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = list(dict.fromkeys(info[4][0] for info in infos))
    own = _own_addresses()
    if not addrs or any(_refused_address(a, own) for a in addrs):
        raise OSError(f"{host} resolves to an address that may not be reached")
    error = None
    for addr in addrs:
        try:
            return _plain_create_connection((addr, port), *args, **kwargs)
        except OSError as e:
            error = e
    raise error


urllib3_connection.create_connection = _guarded_create_connection


@contextmanager
def url_guard():
    token = _url_guard.set(True)
    try:
        yield
    finally:
        _url_guard.reset(token)


def _run_url_rest_action(*, url, method, body, headers, instance=None):
    url = find_and_replace_db_values_str(text=url, instance=instance, escape="url")
    # the template is cleaned first, the substituted values are JSON escaped
    body = find_and_replace_db_values_str(
        text=_sanitize_webhook(body), instance=instance, escape="json"
    )
    headers = find_and_replace_db_values_str(
        text=headers, instance=instance, escape="json"
    )

    url = requests.utils.requote_uri(url)
    if _is_internal_url(url):
        raise ValueError("URL actions cannot target the server itself.")

    # blank is allowed: a GET webhook may have no body or headers
    try:
        if body:
            body = json.loads(body, strict=False)
    except Exception as e:
        logger.error("URL action body is not JSON: %s", type(e).__name__)
    try:
        if headers:
            headers = json.loads(headers, strict=False)
    except Exception as e:
        logger.error("URL action headers are not JSON: %s", type(e).__name__)

    method = method.lower()
    with url_guard():
        if method in ("get", "delete"):
            return getattr(requests, method)(
                url, headers=headers, timeout=8, allow_redirects=False
            )
        return getattr(requests, method)(
            url,
            data=json.dumps(body),
            headers=headers,
            timeout=8,
            allow_redirects=False,
        )


def run_url_rest_action(*, action_id, instance=None):
    from .models import URLAction

    try:
        action = URLAction.objects.get(pk=action_id)
        response = _run_url_rest_action(
            url=action.pattern,
            method=action.rest_method,
            body=action.rest_body,
            headers=action.rest_headers,
            instance=instance,
        )
        return (response.text, response.status_code)
    except Exception as e:
        # the message of a requests error holds the resolved URL
        logger.error("URL action failed: %s", type(e).__name__)
        return (f"URL action failed: {type(e).__name__}", 500)


def run_test_url_rest_action(*, url, method, body, headers, instance_type, instance_id):
    instance = None
    if instance_type in ("client", "site", "agent") and instance_id:
        from django.shortcuts import get_object_or_404

        from agents.models import Agent
        from clients.models import Client, Site

        if instance_type == "agent":
            instance = get_object_or_404(Agent, agent_id=instance_id)
        elif instance_type == "site":
            instance = get_object_or_404(Site, pk=instance_id)
        else:
            instance = get_object_or_404(Client, pk=instance_id)

    try:
        response = _run_url_rest_action(
            url=url, method=method, body=body, headers=headers, instance=instance
        )
    except requests.exceptions.ConnectionError as err:
        return (str(err), str(err.request.url), str(err.request.body))
    except Exception as e:
        return (str(e), str(e), str(e))

    return (response.text, response.request.url, response.request.body)


# server scripts


def stepup_denied(request, why):
    from rest_framework.response import Response
    from knox.models import AuthToken

    from accounts.utils import console_stepup_remaining

    if (
        isinstance(request.auth, AuthToken)
        and console_stepup_remaining(request.user) > 0
    ):
        return None
    return Response(
        {"detail": f"Confirm with a two-factor code first. {why}", "stepup": True},
        status=403,
    )


def run_server_script(*, body, args, env_vars, shell, timeout):
    from scripts.models import Script

    from .models import CoreSettings

    core = CoreSettings.objects.first()
    if not core or not core.server_scripts_enabled:
        return ("", "Error: this feature is disabled", 0.00, 1)

    body = Script.replace_with_snippets(body)
    parsed_args = Script.parse_script_args(None, shell, args)
    parsed_env = Script.parse_script_env_vars(None, shell=shell, env_vars=env_vars)

    # what a shell needs plus the script's variables, nothing else of the service
    env = {
        name: os.environ[name]
        for name in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
        if name in os.environ
    }
    env.setdefault("PATH", os.defpath)
    for pair in parsed_env:
        if isinstance(pair, str) and "=" in pair:
            name, _, value = pair.partition("=")
            env[name] = value

    body = body.replace("\r\n", "\n")

    start = time.monotonic()
    path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="ulrmm-") as fh:
            fh.write(body)
            path = fh.name
        os.chmod(path, 0o550)
        proc = subprocess.run(
            [path] + parsed_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        stdout, stderr, retcode = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, retcode = "", f"Error: Timed out after {timeout} seconds.", 98
    except Exception as e:
        stdout, stderr, retcode = "", f"Error: {e}", 99
    finally:
        if path:
            with suppress(OSError):
                os.remove(path)

    return (stdout, stderr, time.monotonic() - start, retcode)

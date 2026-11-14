# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import fcntl
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager, suppress
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo

from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async
from django.conf import settings
from django.core.cache import cache
from django.db.models import Model

from core.utils import get_core_settings
from ulrmm.constants import (
    MONTH_DAYS,
    MONTHS,
    REDIS_LOCK_EXPIRE,
    ULRMM_LATEST_VER_CACHE_KEY,
    WEEK_DAYS,
    WEEKS,
    DebugLogType,
    ScriptShell,
)
from ulrmm.helpers import (
    agent_ver,
    get_certs,
    get_nats_hosts,
    get_nats_internal_protocol,
    get_nats_ports,
    get_nats_server_password,
)
from ulrmm.logger import logger

# matches {{ client|site|agent|global|alert . path }}; group 1 the whole token,
# group 2 the model word, group 3 the path after the first dot
RE_DB_VALUE = re.compile(
    r"(\{\{\s*(client|site|agent|global|alert)\.([\w\s\-.]+?)\s*\}\})"
)

# NATS user name and subject of an agent: no ".", "*", ">" or whitespace
AGENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{21,150}")


def get_default_timezone() -> ZoneInfo:
    return ZoneInfo(get_core_settings().default_time_zone)


# --- bit string converters -------------------------------------------------


def get_bit_days(days: list) -> int:
    bit = 0
    for name in days:
        bit |= WEEK_DAYS.get(name, 0)
    return bit


def bitdays_to_string(day: int) -> str:
    if day == 127:
        return "Every day"
    return ", ".join(name for name, bit in WEEK_DAYS.items() if bit & day)


def bitmonths_to_string(day: int) -> str:
    if day == 4095:
        return "Every month"
    return ", ".join(name for name, bit in MONTHS.items() if bit & day)


def bitweeks_to_string(day: int) -> str:
    if day == 31:
        return "Every week"
    return ", ".join(name for name, bit in WEEKS.items() if bit & day)


def bitmonthdays_to_string(day: int) -> str:
    if day == 0x80000000:
        return "Last day"
    if day in (2147483647, 4294967295):
        return "Every day"
    return ", ".join(name for name, bit in MONTH_DAYS.items() if bit & day)


def convert_to_iso_duration(string: str) -> str:
    upper = string.upper()
    if "D" in upper:
        return "P" + upper.replace("D", "DT")
    return "PT" + upper


# --- git remote / version --------------------------------------------------


def url_host(url: str) -> str:
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.split("/", 1)[0].lower()


@contextmanager
def git_auth_env(url: str):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    token = getattr(settings, "ULRMM_GIT_TOKEN", "")
    host = url_host(url)
    askpass = None
    try:
        if token and host and host == url_host(getattr(settings, "ULRMM_GIT_URL", "")):
            user = getattr(settings, "ULRMM_GIT_USER", "") or "git"
            fd, askpass = tempfile.mkstemp()
            with os.fdopen(fd, "w") as fh:
                fh.write(
                    "#!/bin/sh\n"
                    'case "$1" in\n'
                    "*[Uu]sername*) printf '%s\\n' \"$ULRMM_GIT_USER\" ;;\n"
                    "*) printf '%s\\n' \"$ULRMM_GIT_TOKEN\" ;;\n"
                    "esac\n"
                )
            os.chmod(askpass, 0o700)
            env["GIT_ASKPASS"] = askpass
            env["ULRMM_GIT_USER"] = user
            env["ULRMM_GIT_TOKEN"] = token
        yield env
    finally:
        if askpass:
            with suppress(OSError):
                os.remove(askpass)


def get_remote_update_status() -> str:
    from logs.models import DebugLog

    url = getattr(settings, "ULRMM_GIT_URL", "")
    branch = getattr(settings, "ULRMM_GIT_BRANCH", "") or "main"
    repo_dir = getattr(settings, "ULRMM_REPO_DIR", "") or "/rmm"

    try:
        with git_auth_env(url) as env:
            remote = subprocess.run(
                [
                    "git",
                    "-c",
                    "credential.helper=",
                    "ls-remote",
                    url,
                    f"refs/heads/{branch}",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                env=env,
            )
        if remote.returncode != 0 or not remote.stdout.strip():
            return "error"
        remote_sha = remote.stdout.split()[0]

        local = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if local.returncode != 0:
            return "error"
        local_sha = local.stdout.strip()

        if local_sha == remote_sha:
            return settings.ULRMM_VERSION
        return f"{settings.ULRMM_VERSION}+{remote_sha[:8]}"
    except Exception as e:
        DebugLog.error(message=str(e))
        return "error"


def get_latest_version() -> str:
    from django.core.cache import cache

    if not getattr(settings, "ULRMM_GIT_URL", ""):
        return settings.ULRMM_VERSION

    cached = cache.get(ULRMM_LATEST_VER_CACHE_KEY)
    if cached:
        return cached

    # only one request at a time talks to the remote; the rest answer instantly
    if not cache.add("ulrmm_latest_ver_inflight", 1, 60):
        return settings.ULRMM_VERSION

    try:
        status = get_remote_update_status()
    finally:
        cache.delete("ulrmm_latest_ver_inflight")

    cache.set(ULRMM_LATEST_VER_CACHE_KEY, status, 60 if status == "error" else 1800)
    return status


# --- template / variable resolution ----------------------------------------


def is_credential_model(obj) -> bool:
    from ulrmm.constants import CREDENTIAL_MODEL_LABELS

    return isinstance(obj, Model) and obj._meta.label in CREDENTIAL_MODEL_LABELS


def _custom_field_value(custom_field, instance, model_part):
    from ulrmm.constants import CustomFieldType

    is_checkbox = custom_field.type == CustomFieldType.CHECKBOX
    try:
        if model_part != instance.__class__.__name__.lower():
            target = getattr(instance, model_part)
        else:
            target = instance
        row = getattr(custom_field, f"{model_part}_fields").get(**{model_part: target})
        value = row.value
        if is_checkbox:
            return bool(value)
        return value if value else custom_field.default_value
    except Exception:
        return (
            bool(custom_field.default_value)
            if is_checkbox
            else custom_field.default_value
        )


def get_db_value(*, string, instance=None, readable=None):
    from core.models import CustomField, GlobalKVStore
    from logs.models import DebugLog

    parts = string.strip().split(".")

    if parts[0] == "global" and len(parts) == 2:
        try:
            return GlobalKVStore.objects.get(name=parts[1]).value
        except GlobalKVStore.DoesNotExist:
            DebugLog.error(
                log_type=DebugLogType.SCRIPTING,
                message=(
                    f"Couldn't lookup value for: {string}. Make sure it exists "
                    "in CoreSettings > Key Store"
                ),
            )
            return None

    if instance is None:
        return None

    if len(parts) == 2:
        try:
            custom_field = CustomField.objects.get(model=parts[0], name=parts[1])
        except CustomField.DoesNotExist:
            custom_field = None
        if custom_field is not None:
            return _custom_field_value(custom_field, instance, parts[0])

    if parts and parts[0] == instance.__class__.__name__.lower():
        parts = parts[1:]

    current = instance
    for part in parts:
        if part.startswith("_"):
            return None
        if is_credential_model(current):
            return None
        if (
            readable is not None
            and isinstance(current, Model)
            and not readable(current, part)
        ):
            return None
        if not hasattr(current, part):
            # a mistyped placeholder resolves to nothing, not to the object
            return None
        value = getattr(current, part)
        if callable(value):
            return None
        current = value
        if current is None:
            return None

    return None if is_credential_model(current) else current


def format_shell_bool(value, shell) -> str:
    if shell == ScriptShell.POWERSHELL:
        return "$True" if value else "$False"
    return "1" if value else "0"


def format_shell_array(value: list) -> str:
    return ",".join(str(item) for item in value).strip(",")


def _quote_str(value: str, shell, quotes: bool) -> str:
    if shell == ScriptShell.CMD:
        # agent-controlled values must not inject cmd metacharacters
        if any(ch in value for ch in '&|<>^%"'):
            return ""
        return f"'{value}'" if quotes else value
    if shell == ScriptShell.POWERSHELL:
        escaped = value.replace("'", "''")
        return f"'{escaped}'" if quotes else escaped
    # posix shells / python: escape ' when embedding in single quotes
    if quotes:
        return "'" + value.replace("'", "'\\''") + "'"
    return value


def replace_arg_db_values(string, instance=None, shell=None, quotes=True):
    from logs.models import DebugLog

    def log_scripting_error(message: str) -> None:
        DebugLog.error(log_type=DebugLogType.SCRIPTING, message=message)

    value = get_db_value(string=string, instance=instance)
    if value is None:
        log_scripting_error(f"Couldn't lookup value for: {string}. Make sure it exists")
        return ""

    if isinstance(value, bool):
        return format_shell_bool(value, shell)
    if isinstance(value, list):
        value = format_shell_array(value)
    elif isinstance(value, dict):
        value = json.dumps(value)
    if isinstance(value, str):
        quoted = _quote_str(value, shell, quotes)
        if value and not quoted:
            log_scripting_error(
                f"Value for {string} holds cmd metacharacters and was "
                "replaced with an empty string"
            )
        return quoted
    try:
        return str(value)
    except Exception:
        return ""


def runcmd_placeholder_text() -> dict:
    return {
        "cmd": getattr(
            settings, "CMD_PLACEHOLDER_TEXT", r"rmdir /S /Q C:\Windows\System32"
        ),
        "powershell": getattr(
            settings,
            "POWERSHELL_PLACEHOLDER_TEXT",
            r"Remove-Item -Recurse -Force C:\Windows\System32",
        ),
        "shell": getattr(
            settings, "SHELL_PLACEHOLDER_TEXT", "rm -rf --no-preserve-root /"
        ),
    }


# --- infrastructure --------------------------------------------------------


def get_celery_queue_len() -> int:
    from ulrmm.celery import app

    conn = None
    try:
        conn = app.pool.acquire(block=True)
        redis_client = conn.default_channel.client
        return redis_client.llen("celery")
    except Exception as exc:
        raise RuntimeError(f"Error getting celery queue length: {exc}")
    finally:
        if conn is not None:
            conn.release()


def localhost_port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False


class BodyTooLarge(ValueError):
    pass


def capped_json(r, limit: int):
    """JSON of a response requested with stream=True, read up to limit bytes.
    None for an empty body, BodyTooLarge past the limit, ValueError for no JSON."""
    body = bytearray()
    try:
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > limit:
                raise BodyTooLarge(f"more than {limit} bytes")
    finally:
        r.close()
    return json.loads(body) if body else None


@contextmanager
def redis_lock(lock_id, oid, ttl=REDIS_LOCK_EXPIRE):
    from django.core.cache import cache

    acquired = cache.add(lock_id, oid, ttl)
    started = time.monotonic()
    try:
        yield acquired
    finally:
        if acquired and (time.monotonic() - started) < (ttl - 3):
            cache.delete(lock_id)


def _nats_http_port():
    if "NATS_HTTP_PORT" in os.environ:
        return int(os.environ["NATS_HTTP_PORT"])
    if hasattr(settings, "NATS_HTTP_PORT"):
        return settings.NATS_HTTP_PORT
    return None


def _write_conf_atomic(path, config) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(config, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        with suppress(OSError):
            os.remove(tmp)
        raise


def nats_publish_allow(agent_id: str, version: str) -> list[str]:
    allow = [f"{agent_id}.checkin", f"{agent_id}.cmdoutput.>", f"{agent_id}.terminal.>"]
    # older agents check in on their bare id, which is also their command subject
    if agent_ver(version) < agent_ver(settings.SEC_R1_MIN_AGENT):
        allow.insert(0, agent_id)
    return allow


def nats_config() -> dict:
    from agents.models import Agent
    from logs.models import DebugLog

    std_bind, ws_bind, _ = get_nats_hosts()
    std_port, ws_port = get_nats_ports()

    users = [
        {
            "user": "ulrmm",
            "password": get_nats_server_password(),
            "permissions": {"publish": ">", "subscribe": ">"},
            "allowed_connection_types": ["STANDARD"],
        }
    ]

    response_expiry = (
        getattr(settings, "NATS_ALLOW_RESPONSE_EXPIRATION", None) or "1435m"
    )

    def skipped(agent, message):
        # the config is rendered every few minutes; one entry a day is enough
        if cache.add(f"nats_config_skipped_{agent.pk}", 1, 24 * 60 * 60):
            DebugLog.critical(
                agent=agent, log_type=DebugLogType.AGENT_ISSUES, message=message
            )

    from cryptography.fernet import InvalidToken

    from deploy.models import IdentityState, MtlsMode
    from deploy.pki import security_settings
    from deploy.tokens import legacy_nats_password

    sec2_required = security_settings().sec2_mode == MtlsMode.REQUIRED
    nkey_conn = ["WEBSOCKET"]
    if getattr(settings, "USE_NATS_STANDARD", False):
        nkey_conn = ["STANDARD", "WEBSOCKET"]

    agents = (
        Agent.objects.select_related("identity", "credential")
        .prefetch_related("user__auth_token")
        .only(
            "pk",
            "agent_id",
            "version",
            "hostname",
            "identity__state",
            "identity__nkey",
            "credential__legacy_nats",
        )
        .order_by("pk")
    )
    for agent in agents:
        # an id with token separators or wildcards would widen its permissions
        if not AGENT_ID_RE.fullmatch(agent.agent_id or ""):
            skipped(
                agent,
                f"agent id {agent.agent_id!r} is not a valid NATS user name, "
                "the agent was left out of the NATS configuration",
            )
            continue
        perms = {
            "publish": {"allow": nats_publish_allow(agent.agent_id, agent.version)},
            "subscribe": {"allow": [agent.agent_id]},
            "allow_responses": {"expires": response_expiry},
        }
        ident = getattr(agent, "identity", None)
        if ident is not None:
            # quarantined or blocked: no user, the reload cuts the connection
            if ident.state == IdentityState.ACTIVE and ident.nkey:
                users.append(
                    {
                        "nkey": ident.nkey,
                        "permissions": perms,
                        "allowed_connection_types": nkey_conn,
                    }
                )
            continue
        if sec2_required:
            continue
        cred = getattr(agent, "credential", None)
        if cred is not None:
            if not cred.legacy_nats:
                skipped(agent, f"{agent.hostname} has no NATS credential")
                continue
            try:
                password = legacy_nats_password(cred)
            except (InvalidToken, ValueError):
                skipped(agent, f"{agent.hostname}: legacy NATS password unreadable")
                continue
        else:
            # DRF tokens of agents that have no credential row (fixtures)
            try:
                password = agent.user.auth_token.key
            except Exception:
                skipped(
                    agent,
                    f"{agent.hostname} does not have a user account, NATS will not work",
                )
                continue
        users.append(
            {"user": agent.agent_id, "password": password, "permissions": perms}
        )

    config = {
        "authorization": {"users": users},
        "max_payload": 67108864,
        "host": std_bind,
        "port": std_port,
        "websocket": {"host": ws_bind, "port": ws_port, "no_tls": True},
    }
    ws_compression = hasattr(settings, "NATS_WS_COMPRESSION") or (
        "NATS_WS_COMPRESSION" in os.environ
    )
    if ws_compression:
        config["websocket"]["compression"] = True
    if get_nats_internal_protocol() == "tls":
        config["tls"] = dict(
            zip(("cert_file", "key_file"), get_certs()), min_version="1.3"
        )
    http_port = _nats_http_port()
    if http_port is not None:
        config["http_port"] = http_port
    return config


def nats_signal_wanted(unit_state: str) -> bool:
    """Decides from ``systemctl show nats -p LoadState -p ActiveState`` whether
    a reload signal is needed. A nats unit that is stopped or (re)starting reads
    nats-rmm.conf when it starts, and nats-server -signal reload fails without
    a running server. An answer that cannot be read keeps the signal, so a
    failure is still logged."""
    props = dict(
        line.partition("=")[::2] for line in unit_state.splitlines() if "=" in line
    )
    if props.get("LoadState") != "loaded" or "ActiveState" not in props:
        return True
    return props["ActiveState"] in ("active", "reloading")


def _nats_signal_wanted() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "show", "nats", "-p", "LoadState", "-p", "ActiveState"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return True
    return nats_signal_wanted(result.stdout)


def reload_nats(*, only_if_changed: bool = False) -> bool:
    """Writes nats-rmm.conf and reloads nats-server. only_if_changed leaves
    both alone when the file already holds this config. True when written."""
    from logs.models import DebugLog

    path = os.path.join(settings.ULRMM_CONF_DIR or settings.BASE_DIR, "nats-rmm.conf")
    # two enrolments at once: the config read first must not be written last
    with open(f"{path}.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = nats_config()
        if only_if_changed:
            with suppress(OSError), open(path, "rb") as fh:
                if fh.read() == json.dumps(config).encode():
                    return False
        _write_conf_atomic(path, config)
    if not settings.ULRMM_NATS_RELOAD:
        # the compose nats service reloads itself (docker/nats/reload-watch.sh)
        return True
    if not _nats_signal_wanted():
        return True

    time.sleep(0.5)
    try:
        result = subprocess.run(
            ["/usr/local/bin/nats-server", "-signal", "reload"], capture_output=True
        )
        succeeded = not result.returncode
        detail = f"exit code {result.returncode}"
    except Exception as exc:
        succeeded = False
        detail = str(exc)

    if not succeeded:
        # a failed reload must be surfaced, but logging it must never break
        # the caller (the config file is already in place)
        with suppress(Exception):
            DebugLog.critical(
                log_type=DebugLogType.SYSTEM_ISSUES,
                message=f"nats-server config reload did not succeed: {detail}",
            )
    return True


# --- websocket authentication ----------------------------------------------


@database_sync_to_async
def get_user(query_string: bytes):
    from django.contrib.auth.models import AnonymousUser

    from ulrmm.auth import DashboardTokenAuthentication, needs_mfa_enrolment

    try:
        tokens = parse_qs(query_string.decode()).get("access_token")
        if not tokens:
            return AnonymousUser()
        user, _ = DashboardTokenAuthentication().authenticate_credentials(
            tokens[0].encode()
        )
        if needs_mfa_enrolment(user):
            return AnonymousUser()
        return user
    except Exception:
        logger.debug("websocket authentication failed", exc_info=True)
        return AnonymousUser()


class KnoxAuthMiddlewareInstance:
    """Resolves the dashboard token in ?access_token= before the consumer runs."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        user = await get_user(scope["query_string"])
        scope["user"] = user
        return await self.app(scope, receive, send)


def KnoxAuthMiddlewareStack(inner):
    return KnoxAuthMiddlewareInstance(AuthMiddlewareStack(inner))

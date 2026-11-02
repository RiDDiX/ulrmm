# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import binascii
import json
import re
import secrets
import string
from pathlib import Path
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from agents.utils import get_agent_display, get_agents_dist_url
from ulrmm.constants import AgentPlat, GoArch

from .models import RustDeskRelease, RustDeskSettings

# {v} = pinned client version, see pinned_client()
INSTALLERS = {
    (AgentPlat.WINDOWS, GoArch.AMD64): ("rustdesk-{v}-x86_64.msi",),
    (AgentPlat.LINUX, GoArch.AMD64): (
        "rustdesk-{v}-x86_64.deb",
        "rustdesk-{v}-0.x86_64.rpm",
    ),
    (AgentPlat.DARWIN, GoArch.AMD64): ("rustdesk-{v}-x86_64.dmg",),
    (AgentPlat.DARWIN, GoArch.ARM64): ("rustdesk-{v}-aarch64.dmg",),
}
CLIENT_NAMES = tuple(name for names in INSTALLERS.values() for name in names)

# for the machine you connect from, not the endpoint.
# these register rustdesk://. The portable Windows exe does not.
VIEWER_DOWNLOADS = (
    ("Windows", "rustdesk-{v}-x86_64.msi"),
    ("macOS (Apple silicon)", "rustdesk-{v}-aarch64.dmg"),
    ("macOS (Intel)", "rustdesk-{v}-x86_64.dmg"),
    ("Linux (.deb)", "rustdesk-{v}-x86_64.deb"),
    ("Linux (.rpm)", "rustdesk-{v}-0.x86_64.rpm"),
)

DEPLOY_SCRIPTS = {
    AgentPlat.WINDOWS: settings.BASE_DIR / "core" / "rustdesk_windows.ps1",
    AgentPlat.LINUX: settings.BASE_DIR / "core" / "rustdesk_linux.sh",
    AgentPlat.DARWIN: settings.BASE_DIR / "core" / "rustdesk_mac.sh",
}

# RUSTDESK_FAIL before pw step: keep old pw. update never sends pw, keeps stored.
PRE_PASSWORD_FAILURES = (
    "no password was handed to the script",
    "cannot read the installed RustDesk version",
    "RustDesk is not installed, use Install or reconfigure",
    "not downgrading: ",
    "the RustDesk config holds no ID or password",
    "busy: ",
    "no apt-get, dnf or yum on this system",
    "download failed: ",
    "checksum mismatch: ",
    "installing the RustDesk package failed",
    "the disk image does not mount",
    "copying RustDesk.app failed",
    "RustDesk.app could not be made root-owned",
    "RustDesk.app failed the signature check",
    "RustDesk.app is not com.carriez.rustdesk",
    "the RustDesk service does not start",
    "could not write ",
    "the RustDesk service did not take the password",
    # rustdesk_windows.ps1 puts this before any failure up to the password step
    "setup: ",
)

# below the 300 s uwsgi harakiri and nginx read timeout
DEPLOY_TIMEOUT = 240

# never change: stored passwords could no longer be decrypted
_HKDF_INFO = b"remote.RustDeskPeer.password"

_HOST_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])"
    r"(?::(\d{1,5}))?"
)
# hbbs writes base64 of the 32 byte ed25519 public key
_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=")
_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+-]{0,31}")
_URL_RE = re.compile(r"https?://[A-Za-z0-9.:\[\]/_~%-]+")
_PASSWORD_RE = re.compile(r"[A-Za-z0-9]{24}")
_ID_RE = re.compile(r"[A-Za-z0-9_]{6,16}")
# [version] in PowerShell and sort -V on the endpoints
_PLAIN_VERSION_RE = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CONFIG_RE = re.compile(r"[A-Za-z0-9_-]+")
_OK_RE = re.compile(r"RUSTDESK_OK ([A-Za-z0-9_]{6,16}) ([0-9][0-9A-Za-z.+-]{0,31})")
_FAIL_RE = re.compile(r"RUSTDESK_FAIL ([ -~]{1,1000})")


class DeployError(Exception):
    pass


class PasswordNotSent(DeployError):
    """The deploy failed before the endpoint took the new password."""


def _derive(secret: bytes, info: bytes) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        secret
    )
    return Fernet(base64.urlsafe_b64encode(key))


def field_keys() -> list[bytes]:
    """FIELD_ENCRYPTION_KEYS decoded, the current key first."""
    keys = []
    for value in getattr(settings, "FIELD_ENCRYPTION_KEYS", []) or []:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise ImproperlyConfigured("FIELD_ENCRYPTION_KEYS holds a non-base64 key")
        if len(raw) != 32:
            raise ImproperlyConfigured("every FIELD_ENCRYPTION_KEYS key needs 32 bytes")
        keys.append(raw)
    return keys


def _fernet(info: bytes) -> Fernet:
    """The key new tokens are encrypted with: the first FIELD_ENCRYPTION_KEYS
    key, SECRET_KEY on installs without one."""
    keys = field_keys()
    return _derive(keys[0] if keys else settings.SECRET_KEY.encode(), info)


def _multi(info: bytes) -> MultiFernet:
    # the SECRET_KEY derived key opens tokens from before FIELD_ENCRYPTION_KEYS
    keys = field_keys() + [settings.SECRET_KEY.encode()]
    return MultiFernet([_derive(key, info) for key in keys])


# other models pass their own info, so one key never opens another's secrets
def encrypt_secret(value: str, info: bytes = _HKDF_INFO) -> str:
    return _fernet(info).encrypt(value.encode()).decode()


def decrypt_secret(token: str, info: bytes = _HKDF_INFO) -> str:
    """Raises cryptography.fernet.InvalidToken when no configured key opens it."""
    return _multi(info).decrypt(token.encode()).decode()


def rotate_secret(token: str, info: bytes = _HKDF_INFO) -> str:
    """The token encrypted again with the current key; InvalidToken as above."""
    return _fernet(info).encrypt(_multi(info).decrypt(token.encode())).decode()


def new_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(24))


def is_valid_host(value: str) -> bool:
    m = _HOST_RE.fullmatch(value)
    return bool(m) and (m.group(1) is None or 0 < int(m.group(1)) < 65536)


def config_string(host: str, relay: str, key: str) -> str:
    """`--config` / "Import server config" string: compact JSON, base64url
    without padding, reversed. Same as get_custom_server_from_config_string
    in src/custom_server.rs and ServerConfig.decode in flutter/lib/common.dart.
    Empty fields are omitted.
    """
    data = {k: v for k, v in (("host", host), ("relay", relay), ("key", key)) if v}
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")[::-1]


def get_rustdesk_settings() -> RustDeskSettings:
    return RustDeskSettings.objects.filter(pk=1).first() or RustDeskSettings(pk=1)


def pinned_client() -> tuple[str, dict[str, str]]:
    """(version, {name: sha256}) of the mirrored client.
    Endpoints check downloads against these sums."""
    version = get_rustdesk_settings().pinned_client_version
    release = (
        RustDeskRelease.objects.filter(component="client", version=version)
        .exclude(mirrored_at=None)
        .first()
    )
    return version, (release.files if release else {})


def _key_file() -> Path:
    return Path(getattr(settings, "RUSTDESK_KEY_FILE", "/opt/rustdesk/id_ed25519.pub"))


def read_public_key() -> str:
    try:
        key = _key_file().read_text().strip()
    except OSError:
        return ""
    return key if _KEY_RE.fullmatch(key) else ""


def server_version() -> str:
    # written next to the key by install-rustdesk-server.sh
    try:
        ver = (_key_file().parent / "version").read_text().strip()
    except OSError:
        return ""
    return ver if _VERSION_RE.fullmatch(ver) else ""


def settings_payload(rd: RustDeskSettings) -> dict:
    key = read_public_key()
    return {
        "enabled": rd.enabled,
        "id_server": rd.id_server,
        "relay_server": rd.relay_server,
        "public_key": key,
        "key_present": bool(key),
        "config_string": (
            config_string(rd.id_server, rd.relay_server, key)
            if rd.id_server and key
            else ""
        ),
        "server_version": server_version(),
        "auto_update_server": rd.auto_update_server,
        "auto_update_clients": rd.auto_update_clients,
    }


def viewer_downloads() -> list[dict]:
    base = f"{get_agents_dist_url()}/rustdesk/"
    version = get_rustdesk_settings().pinned_client_version
    names = ((label, name.format(v=version)) for label, name in VIEWER_DOWNLOADS)
    return [{"label": label, "file": name, "url": base + name} for label, name in names]


def connect_uri(rustdesk_id: str, host: str, key: str, password: str) -> str:
    """rustdesk://connection/new/<id>@<host>?key=&password=.
    LoginConfigHandler::initialize in src/client.rs splits on @ and reads
    key from the query; only the per-peer key is stored. The client
    decodes the query, so + and = in the key are percent-encoded.
    """
    query = urlencode({"key": key, "password": password}, quote_via=quote)
    return f"rustdesk://connection/new/{quote(rustdesk_id, safe='')}@{host}?{query}"


def version_key(value: str) -> tuple[int, ...] | None:
    m = re.match(r"[0-9]+(?:\.[0-9]+)*", value)
    return tuple(int(n) for n in m.group().split(".")) if m else None


def update_available(peer, pinned: str = "") -> bool:
    """Only a known version older than the mirrored one counts."""
    have = version_key(peer.client_version)
    pinned = pinned or get_rustdesk_settings().pinned_client_version
    return bool(peer.rustdesk_id and have) and have < version_key(pinned)


def unsupported_reason(agent, probe: bool) -> str:
    """Empty string if a deploy can run here, else the reason.
    probe=False uses the cached linux display state."""
    if (agent.plat, agent.goarch) not in INSTALLERS:
        return f"There is no RustDesk client for {agent.plat}/{agent.goarch}."
    if (
        agent.plat == AgentPlat.LINUX
        and get_agent_display(agent, probe=probe) == "absent"
    ):
        return (
            f"{agent.hostname} has no graphical session, so RustDesk has no "
            "screen to share. Use the MeshCentral terminal instead."
        )
    return ""


def render_deploy(
    agent,
    *,
    host: str,
    config: str,
    password: str = "",
    mode: str = "deploy",
    expect_id: str = "",
) -> dict:
    """runscriptfull payload that installs and configures RustDesk.
    The password stays in env_vars. The script is written to disk on the
    endpoint and lands in the PowerShell script-block log.
    mode "update" upgrades the installed client instead. It sends no
    password, and the endpoint has to keep the ID expect_id."""
    version, files = pinned_client()
    if not _PLAIN_VERSION_RE.fullmatch(version):
        raise DeployError("Refusing to render the script with these values.")
    values = {
        "rdHost": host,
        "rdConfig": config,
        "rdMode": mode,
        "rdVersion": version,
        "rdExpectId": expect_id,
    }
    base = f"{get_agents_dist_url()}/rustdesk/"
    for name in INSTALLERS[(agent.plat, agent.goarch)]:
        name = name.format(v=version)
        if not _SHA256_RE.fullmatch(files.get(name, "")):
            raise DeployError(f"RustDesk {version} is not mirrored on this server.")
        kind = name.rsplit(".", 1)[1].capitalize()
        values[f"rd{kind}Url"] = base + name
        values[f"rd{kind}Sha256"] = files[name]
        if not _URL_RE.fullmatch(values[f"rd{kind}Url"]):
            raise DeployError(f"The agent download URL {base} is not usable here.")
    if mode == "deploy":
        ok = _PASSWORD_RE.fullmatch(password) and not expect_id
    else:
        ok = mode == "update" and not password and _ID_RE.fullmatch(expect_id)
    # the rest is single-quoted in the script; password is an env var
    if not (ok and is_valid_host(host) and _CONFIG_RE.fullmatch(config)):
        raise DeployError("Refusing to render the script with these values.")

    # one pass, so a value is never searched for the next placeholder
    names = re.compile("|".join(sorted(values, key=len, reverse=True)))
    template = DEPLOY_SCRIPTS[agent.plat].read_text()
    data = {
        "func": "runscriptfull",
        "timeout": DEPLOY_TIMEOUT,
        "payload": {
            "code": names.sub(lambda m: values[m.group(0)], template),
            "shell": "powershell" if agent.plat == AgentPlat.WINDOWS else "shell",
        },
        "run_as_user": False,
    }
    if mode == "deploy":
        data["env_vars"] = [f"RD_PASSWORD={password}"]
    return data


def _hide(text: str, password: str) -> str:
    return text.replace(password, "********") if password else text


def parse_deploy_output(out, password: str = "") -> tuple[str, str]:
    """(rustdesk_id, client_version) from the script's one stdout line.
    DeployError otherwise. PasswordNotSent if the endpoint kept its password."""
    if out == "timeout":
        raise DeployError(f"The agent gave no answer within {DEPLOY_TIMEOUT} seconds.")
    if out == "natsdown":
        raise PasswordNotSent("NATS is not reachable from this server.")

    stdout = out.get("stdout") if isinstance(out, dict) else None
    lines = stdout.strip().splitlines() if isinstance(stdout, str) else []
    if len(lines) == 1:
        line = lines[0].strip()
        if m := _OK_RE.fullmatch(line):
            return m.group(1), m.group(2)
        if m := _FAIL_RE.fullmatch(line):
            reason = m.group(1)
            error = (
                PasswordNotSent
                if reason.startswith(PRE_PASSWORD_FAILURES)
                else DeployError
            )
            raise error(_hide(reason, password)[:300])

    why = "The agent did not report a result"
    if isinstance(out, dict):
        why += f" (exit code {out.get('retcode')})"
        if stderr := str(out.get("stderr") or "").strip():
            why += ": " + _hide(stderr.splitlines()[-1], password)[:200]
    raise DeployError(f"{why}, see rustdesk-deploy.log on the endpoint.")

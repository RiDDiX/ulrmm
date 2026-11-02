# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
from dataclasses import dataclass, field

from django.conf import settings
from django.db import transaction
from django.utils import timezone as djangotime

from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.constants import AgentPlat

from .models import EncryptionState, KeyKind, KeyStatus, RecoveryKey

SCRIPTS = settings.BASE_DIR / "encryption" / "scripts"
COLLECTORS = {
    AgentPlat.WINDOWS: "collect_windows.ps1",
    AgentPlat.DARWIN: "status_mac.sh",
    AgentPlat.LINUX: "status_linux.sh",
}
COLLECT_TIMEOUT = 60
ROTATE_TIMEOUT = 120
# far above any real disk layout; an endpoint cannot flood the database
MAX_MARKERS = 256

# never change: stored keys could no longer be decrypted
_KEY_INFO = b"encryption.RecoveryKey.key"

# 8 groups of 6 digits, each a 16 bit value times 11
_BL_PASSWORD = r"\d{6}(?:-\d{6}){7}"
_FV_KEY = r"[A-Z0-9]{4}(?:-[A-Z0-9]{4}){5}"
_SECRET_RE = re.compile(_BL_PASSWORD + "|" + _FV_KEY)
_GUID = r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}"
# printable ascii without "|"
_BL_RE = re.compile(
    r"ULRMM-BL ([!-{}~][ -{}~]{0,63})\|(" + _GUID + r")?\|(" + _BL_PASSWORD + r")?"
    r"\|(On|Off|Unknown)\|(\d{1,3})"
)
_FVS_RE = re.compile(
    r"ULRMM-FVS (on|off|unknown)\|(\d{1,3}(?:\.\d+)?)?\|(true|false|unknown)"
)
_LUKS_RE = re.compile(r"ULRMM-LUKS (/dev/[!-{}~]{1,58})\|([!-{}~]{0,200})")
_FAIL_RE = re.compile(r"ULRMM-FAIL (.+)")
_LOST_RE = re.compile(r"ULRMM-LOST (.+)")
_ROTATED_RE = re.compile(r"ULRMM-FV (" + _FV_KEY + ")")


@dataclass
class Report:
    # volume -> {"volume", "kind", "protection", "percent", ...}
    volumes: dict = field(default_factory=dict)
    # (volume, protector id) -> recovery password
    keys: dict = field(default_factory=dict)
    complete: bool = False
    error: str = ""


class RotateError(Exception):
    def __init__(self, message: str, *, replaced: bool):
        super().__init__(message)
        # the Mac may have a new key the server does not know
        self.replaced = replaced


def seal(key: str) -> str:
    return encrypt_secret(key, _KEY_INFO)


def unseal(token: str) -> str:
    """Raises cryptography.fernet.InvalidToken, e.g. after a SECRET_KEY change."""
    return decrypt_secret(token, _KEY_INFO)


def clean(text, limit: int = 300) -> str:
    """Endpoint text for the database and the UI: printable, keys masked."""
    text = "".join(c if c.isprintable() else " " for c in str(text))
    return _SECRET_RE.sub("***", text).strip()[:limit]


def _script(name: str, timeout: int) -> dict:
    return {
        "func": "runscriptfull",
        "timeout": timeout,
        "payload": {
            "code": (SCRIPTS / name).read_text(),
            "shell": "powershell" if name.endswith(".ps1") else "shell",
        },
        "run_as_user": False,
    }


def collect_payload(plat: str) -> dict:
    return _script(COLLECTORS[plat], COLLECT_TIMEOUT)


def rotate_payload(username: str, password: str) -> dict:
    data = _script("rotate_mac.sh", ROTATE_TIMEOUT)
    # env only: the script lands on disk and argv shows in the process list
    data["env_vars"] = [f"FV_USER={username}", f"FV_PASSWORD={password}"]
    return data


def _valid_password(value: str) -> bool:
    return all(int(g) % 11 == 0 and int(g) < 720896 for g in value.split("-"))


def _bitlocker(line: str, rep: Report) -> bool:
    m = _BL_RE.fullmatch(line)
    if not m or bool(m[2]) != bool(m[3]) or (m[3] and not _valid_password(m[3])):
        return False
    volume = m[1]
    rep.volumes[volume] = {
        "volume": volume,
        "kind": "bitlocker",
        "protection": m[4].lower(),
        "percent": min(int(m[5]), 100),
    }
    if m[2]:
        rep.keys[(volume, m[2].upper())] = m[3]
    return True


def _filevault(line: str, rep: Report) -> bool:
    if not (m := _FVS_RE.fullmatch(line)):
        return False
    percent = float(m[2]) if m[2] else {"on": 100, "off": 0}.get(m[1])
    rep.volumes["/"] = {
        "volume": "/",
        "kind": "filevault",
        "protection": m[1],
        "percent": None if percent is None else min(int(percent), 100),
        # the Mac has one; whether the server has it is has_key
        "personal_key": {"true": True, "false": False}.get(m[3]),
    }
    return True


def _luks(line: str, rep: Report) -> bool:
    if not (m := _LUKS_RE.fullmatch(line)):
        return False
    rep.volumes[m[1]] = {
        "volume": m[1],
        "kind": "luks",
        "protection": "on",
        "percent": None,
        "mount": m[2],
    }
    return True


_LINE_PARSERS = {
    AgentPlat.WINDOWS: _bitlocker,
    AgentPlat.DARWIN: _filevault,
    AgentPlat.LINUX: _luks,
}


def _no_reply(out, timeout: int) -> str:
    if out == "timeout":
        return f"The agent gave no answer within {timeout + 10} seconds."
    if out == "natsdown":
        return "NATS is not reachable from this server."
    if not isinstance(out, dict):
        return "The agent sent an unreadable reply."
    return ""


def _markers(out: dict) -> list[str]:
    lines = (s.strip() for s in str(out.get("stdout") or "").splitlines())
    return [s for s in lines if s.startswith("ULRMM-")]


def _incomplete(out: dict) -> str:
    why = f"The script output was incomplete (exit code {out.get('retcode')})"
    if lines := str(out.get("stderr") or "").strip().splitlines():
        why += ": " + clean(lines[-1], 200)
    return why


def parse_collect(plat: str, out) -> Report:
    """Volumes and keys parsed from a collector reply.

    Complete when ULRMM-END is the last marker, no marker was malformed and
    the exit code is 0. Key lines that parse are kept either way.
    """
    rep = Report(error=_no_reply(out, COLLECT_TIMEOUT))
    if rep.error:
        return rep
    parse_line = _LINE_PARSERS[plat]
    lines = _markers(out)
    if len(lines) > MAX_MARKERS:
        rep.error = f"The script printed more than {MAX_MARKERS} result lines."
        return rep
    end = bad = False
    for line in lines:
        if line == "ULRMM-END":
            end = True
        elif m := _FAIL_RE.fullmatch(line):
            rep.error = clean(m[1])
            return rep
        elif end or not parse_line(line, rep):
            bad = True
    if end and not bad and out.get("retcode") == 0:
        rep.complete = True
    else:
        rep.error = _incomplete(out)
    return rep


def parse_rotate(out) -> str:
    """The new FileVault key, else RotateError."""
    if error := _no_reply(out, ROTATE_TIMEOUT):
        raise RotateError(error, replaced=out != "natsdown")
    lines = _markers(out)
    if len(lines) == 1 and out.get("retcode") == 0:
        if m := _ROTATED_RE.fullmatch(lines[0]):
            return m[1]
    for line in lines:
        if m := _FAIL_RE.fullmatch(line):
            raise RotateError(clean(m[1]), replaced=False)
    lost = next((m[1] for s in lines if (m := _LOST_RE.fullmatch(s))), "")
    raise RotateError(clean(lost) if lost else _incomplete(out), replaced=True)


@transaction.atomic
def store(agent, rep: Report) -> None:
    now = djangotime.now()
    seen = [
        RecoveryKey.objects.update_or_create(
            agent=agent,
            kind=KeyKind.BITLOCKER,
            volume=volume,
            protector_id=protector_id,
            defaults={
                "key": seal(key),
                "collected_at": now,
                "status": KeyStatus.ACTIVE,
            },
        )[0].pk
        for (volume, protector_id), key in rep.keys.items()
    ]
    state, _ = EncryptionState.objects.get_or_create(agent=agent)
    if rep.complete:
        if agent.plat == AgentPlat.WINDOWS:
            RecoveryKey.objects.filter(
                agent=agent, kind=KeyKind.BITLOCKER, status=KeyStatus.ACTIVE
            ).exclude(pk__in=seen).update(status=KeyStatus.STALE)
        state.volumes = list(rep.volumes.values())
        state.collected_at = now
    state.error = rep.error
    state.save()


def store_rotated(agent, key: str) -> None:
    RecoveryKey.objects.update_or_create(
        agent=agent,
        kind=KeyKind.FILEVAULT,
        volume="/",
        protector_id="",
        defaults={
            "key": seal(key),
            "collected_at": djangotime.now(),
            "status": KeyStatus.ACTIVE,
        },
    )


def agent_payload(agent) -> dict:
    state = EncryptionState.objects.filter(agent=agent).first() or EncryptionState()
    keys = list(
        RecoveryKey.objects.filter(agent=agent)
        .order_by("kind", "volume", "status", "-collected_at")
        .values("id", "kind", "volume", "protector_id", "collected_at", "status")
    )
    active = {(k["kind"], k["volume"]) for k in keys if k["status"] == KeyStatus.ACTIVE}
    return {
        "volumes": [
            {
                **v,
                "has_key": (v["kind"], v["volume"]) in active,
                "collected_at": state.collected_at,
            }
            for v in state.volumes
        ],
        "keys": keys,
        "error": state.error,
    }


def fleet_summary(agents) -> dict:
    """agents is a role-filtered Agent queryset.

    Encrypted means at least one volume in the last complete collection is protected.
    """
    known = EncryptionState.objects.filter(agent__in=agents, collected_at__isnull=False)
    total = agents.count()
    n_known = known.count()
    encrypted = known.filter(volumes__contains=[{"protection": "on"}]).count()
    return {
        "agents": total,
        "encrypted": encrypted,
        "not_encrypted": n_known - encrypted,
        "unknown": total - n_known,
        "keys_escrowed": RecoveryKey.objects.filter(
            agent__in=agents, status=KeyStatus.ACTIVE
        ).count(),
    }

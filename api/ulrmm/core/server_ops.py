# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Server updates and backups started from the dashboard.

The web processes never run update.sh or backup.sh: update.sh stops and
restarts them. They drop a one-word request in MAINT_DIR; ulrmm-maint.path
starts riddix/scripts/maint_runner.sh, which writes <action>.log and
<action>.state.json there. Backups are read from BACKUP_DIR directly, the
service user owns both directories.
"""

import fcntl
import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.core.cache import cache

from .about import parse_changelog

ACTIONS = ("update", "backup", "schedule")
# a run that never wrote its final state (machine rebooted mid-update)
STALE_AFTER = 4 * 3600
LOG_CHUNK = 256 * 1024
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[c()][0-9A-B]?")

# folder below BACKUP_DIR per backup type ("" is the top level)
BACKUP_TYPES = {
    "manual": "",
    "pre-update": "pre-update",
    "daily": "daily",
    "weekly": "weekly",
    "monthly": "monthly",
}
BACKUP_NAME = re.compile(
    r"rmm-backup-\d{4}_\d{2}_\d{2}__\d{2}_\d{2}_\d{2}\.tar(\.age)?"
)

# backup.conf keys, their defaults and limits; backup.sh reads the same keys
CONF_INT = {
    "daily_keep_days": ("DAILY_KEEP_DAYS", 14, 1, 3650),
    "weekly_keep_days": ("WEEKLY_KEEP_DAYS", 60, 1, 3650),
    "monthly_keep_days": ("MONTHLY_KEEP_DAYS", 380, 1, 3650),
    "pre_update_keep": ("PRE_UPDATE_KEEP", 5, 0, 100),
}
SCHEDULE_TIME = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


class MaintError(Exception):
    pass


def maint_dir() -> Path:
    return Path(getattr(settings, "ULRMM_MAINT_DIR", "/var/lib/ulrmm-maint"))


def backup_dir() -> Path:
    return Path(getattr(settings, "ULRMM_BACKUP_DIR", "/rmmbackups"))


def runner_installed() -> bool:
    return maint_dir().is_dir()


# --- runner state ------------------------------------------------------------


def _runner_alive() -> bool:
    # the runner holds MAINT_DIR/lock for the whole run; a free lock means
    # nothing is running, whatever the state file says (reboot mid-update)
    try:
        fd = os.open(maint_dir() / "lock", os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def read_state(action: str) -> dict:
    empty = {"action": action, "state": "idle", "exit_code": None}
    try:
        data = json.loads((maint_dir() / f"{action}.state.json").read_text())
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    state = {
        "action": action,
        "state": (
            data.get("state")
            if data.get("state") in ("running", "done", "failed")
            else "idle"
        ),
        "exit_code": data.get("exit_code"),
        "started": data.get("started"),
        "finished": data.get("finished"),
    }
    started = state["started"]
    if state["state"] == "running" and (
        not _runner_alive()
        or (isinstance(started, (int, float)) and time.time() - started > STALE_AFTER)
    ):
        state["state"] = "interrupted"
    return state


def busy_with() -> str | None:
    """The action that is queued or running, None when the runner is free."""
    if (maint_dir() / "request").exists():
        return "queued"
    for action in ACTIONS:
        if read_state(action)["state"] == "running":
            return action
    return None


def request_action(action: str) -> None:
    if action not in ACTIONS:
        raise MaintError("Unknown action.")
    if not runner_installed():
        raise MaintError(
            "The maintenance runner is not installed on this server yet. "
            "Run update.sh once on the server; it installs the runner."
        )
    current = busy_with()
    if current:
        raise MaintError(
            "Another maintenance task is queued."
            if current == "queued"
            else f"A {current} is already running."
        )
    tmp = maint_dir() / ".request"
    tmp.write_text(action + "\n")
    os.chmod(tmp, 0o600)
    # the previous run's done/failed state would end the new run in the UI
    (maint_dir() / f"{action}.state.json").unlink(missing_ok=True)
    os.replace(tmp, maint_dir() / "request")


def write_release_request(version: str | None) -> None:
    """release.json: update.sh runs in release mode when it exists."""
    tmp = maint_dir() / ".release.json"
    tmp.write_text(
        json.dumps({"version": version, "requested_at": _iso(time.time())}) + "\n"
    )
    os.chmod(tmp, 0o600)
    os.replace(tmp, maint_dir() / "release.json")


def drop_release_request() -> None:
    (maint_dir() / "release.json").unlink(missing_ok=True)


def read_progress() -> dict:
    try:
        data = json.loads((maint_dir() / "update.progress.json").read_text())
    except (OSError, ValueError):
        data = None
    return data if isinstance(data, dict) else {"phase": None}


def read_log(action: str, offset: int = 0) -> dict:
    """Log text from byte offset on, ANSI codes removed; next offset included."""
    if action not in ACTIONS:
        raise MaintError("Unknown action.")
    path = maint_dir() / f"{action}.log"
    try:
        size = path.stat().st_size
    except OSError:
        return {"text": "", "offset": 0, "size": 0}
    # the runner truncates the log at the start of a run
    if offset < 0 or offset > size:
        offset = 0
    with path.open("rb") as f:
        f.seek(offset)
        chunk = f.read(LOG_CHUNK)
    text = ANSI.sub("", chunk.decode("utf-8", errors="replace")).replace("\r", "")
    return {"text": text, "offset": offset + len(chunk), "size": size}


# --- backups -----------------------------------------------------------------


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def list_backups() -> list[dict]:
    root = backup_dir()
    out = []
    for kind, sub in BACKUP_TYPES.items():
        folder = root / sub if sub else root
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            if not BACKUP_NAME.fullmatch(entry.name):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            out.append(
                {
                    "type": kind,
                    "name": entry.name,
                    "size": st.st_size,
                    "created": _iso(st.st_mtime),
                }
            )
    out.sort(key=lambda b: b["created"], reverse=True)
    return out


def backup_path(kind: str, name: str) -> Path:
    """Path of an existing backup file; MaintError for anything else."""
    if kind not in BACKUP_TYPES or not BACKUP_NAME.fullmatch(name or ""):
        raise MaintError("Unknown backup.")
    sub = BACKUP_TYPES[kind]
    folder = backup_dir() / sub if sub else backup_dir()
    path = folder / name
    try:
        st = path.lstat()
    except OSError:
        raise MaintError("Unknown backup.")
    if not stat.S_ISREG(st.st_mode):
        raise MaintError("Unknown backup.")
    return path


def delete_backup(kind: str, name: str) -> None:
    backup_path(kind, name).unlink()


def disk_usage() -> dict:
    try:
        st = os.statvfs(backup_dir())
    except OSError:
        return {}
    return {"free": st.f_bavail * st.f_frsize, "total": st.f_blocks * st.f_frsize}


# --- backup settings (backup.conf) -------------------------------------------


def _conf_path() -> Path:
    return backup_dir() / "backup.conf"


def read_backup_conf() -> dict:
    conf = {k: v[1] for k, v in CONF_INT.items()}
    conf["schedule_enabled"] = True
    conf["schedule_time"] = "00:00"
    try:
        lines = _conf_path().read_text().splitlines()
    except OSError:
        return conf
    raw = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep:
            raw[key.strip()] = value.strip()
    for field, (key, _default, low, high) in CONF_INT.items():
        if raw.get(key, "").isdigit() and low <= int(raw[key]) <= high:
            conf[field] = int(raw[key])
    if raw.get("SCHEDULE_ENABLED") in ("0", "1"):
        conf["schedule_enabled"] = raw["SCHEDULE_ENABLED"] == "1"
    if SCHEDULE_TIME.fullmatch(raw.get("SCHEDULE_TIME", "")):
        conf["schedule_time"] = raw["SCHEDULE_TIME"]
    return conf


def validate_backup_conf(data) -> dict:
    """Full settings from request data, or MaintError with a short message."""
    if not isinstance(data, dict):
        raise MaintError("The request was invalid.")
    conf = read_backup_conf()
    for field, (_key, _default, low, high) in CONF_INT.items():
        if field in data:
            value = data[field]
            if isinstance(value, bool) or not isinstance(value, int):
                raise MaintError(f"{field} must be a whole number.")
            if not low <= value <= high:
                raise MaintError(f"{field} must be between {low} and {high}.")
            conf[field] = value
    if "schedule_enabled" in data:
        if not isinstance(data["schedule_enabled"], bool):
            raise MaintError("schedule_enabled must be true or false.")
        conf["schedule_enabled"] = data["schedule_enabled"]
    if "schedule_time" in data:
        value = data["schedule_time"]
        if not isinstance(value, str) or not SCHEDULE_TIME.fullmatch(value):
            raise MaintError("schedule_time must be HH:MM (24 h).")
        conf["schedule_time"] = value
    return conf


def write_backup_conf(conf: dict) -> None:
    lines = [f"{key}={conf[field]}" for field, (key, *_rest) in CONF_INT.items()]
    lines.append(f"SCHEDULE_ENABLED={1 if conf['schedule_enabled'] else 0}")
    lines.append(f"SCHEDULE_TIME={conf['schedule_time']}")
    # keys the dashboard does not edit (BACKUP_AGE_RECIPIENTS) stay as they are
    managed = {key for key, *_rest in CONF_INT.values()}
    managed |= {"SCHEDULE_ENABLED", "SCHEDULE_TIME"}
    try:
        old = _conf_path().read_text().splitlines()
    except OSError:
        old = []
    for line in old:
        key, sep, _value = line.partition("=")
        if sep and key.strip() and key.strip() not in managed:
            lines.append(line)
    tmp = backup_dir() / ".backup.conf"
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, _conf_path())


# --- pending changes for the update dialog ------------------------------------

PENDING_CACHE_KEY = "ulrmm_pending_changes"
PENDING_REF = "refs/ulrmm/pending"
# "check again" fetches at most once a minute
REFRESH_AFTER = 60
# the same defaults update.sh falls back to
DEFAULT_GIT_URL = "https://github.com/RiDDiX/ulrmm.git"
DEFAULT_WEB_GIT_URL = "https://github.com/RiDDiX/ulrmm-web.git"


def _git(repo: str, *args: str, env=None, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", repo, "-c", "credential.helper=", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _component_changes(repo: str, url: str, branch: str, current: str) -> dict:
    from ulrmm.utils import git_auth_env

    if not url:
        return {"error": "no git remote configured"}
    if not Path(repo, ".git").exists():
        return {"error": f"{repo} is not a git checkout"}
    with git_auth_env(url) as env:
        fetched = _git(
            repo,
            "fetch",
            "--quiet",
            "--no-tags",
            url,
            f"+refs/heads/{branch}:{PENDING_REF}",
            env=env,
            timeout=120,
        )
    if fetched is None:
        return {"error": "could not reach the git server"}
    text = _git(repo, "show", f"{PENDING_REF}:CHANGELOG.md") or ""
    releases = []
    for release in parse_changelog(text):
        if release["version"] == current:
            break
        releases.append(release)
    return {
        "current": current,
        "next": releases[0]["version"] if releases else current,
        "releases": releases[:20],
    }


def _installed_web_version(repo: str) -> str:
    text = _git(repo, "show", "HEAD:CHANGELOG.md") or ""
    found = parse_changelog(text)
    return found[0]["version"] if found else ""


def pending_changes(refresh: bool = False) -> dict:
    """Changelog entries on the remote branches that this server lacks."""
    cached = cache.get(PENDING_CACHE_KEY)
    if cached and (
        not refresh or time.time() - cached.get("checked", 0) < REFRESH_AFTER
    ):
        return cached
    repo = getattr(settings, "ULRMM_REPO_DIR", "") or "/rmm"
    web_repo = getattr(settings, "ULRMM_WEB_SRC_DIR", "") or "/opt/ulrmm-web/src"
    result = {
        "server": _component_changes(
            repo,
            getattr(settings, "ULRMM_GIT_URL", "") or DEFAULT_GIT_URL,
            getattr(settings, "ULRMM_GIT_BRANCH", "") or "main",
            settings.ULRMM_VERSION,
        ),
        "web": _component_changes(
            web_repo,
            getattr(settings, "ULRMM_WEB_GIT_URL", "") or DEFAULT_WEB_GIT_URL,
            getattr(settings, "ULRMM_WEB_GIT_BRANCH", "") or "main",
            _installed_web_version(web_repo),
        ),
    }
    result["checked"] = time.time()
    cache.set(PENDING_CACHE_KEY, result, 600)
    return result

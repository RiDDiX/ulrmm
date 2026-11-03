# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import time
from contextlib import suppress

from django.conf import settings
from django.core.cache import cache
from django.core.files.uploadhandler import FileUploadHandler, SkipFile
from django.utils import timezone as djangotime

from ulrmm.constants import AgentPlat
from ulrmm.util_settings import get_backend_url

from .models import (
    ARCHIVE_TYPES,
    EXTENSIONS,
    OPEN_STATES,
    InstallState,
    PackageInstall,
    PackageKind,
    RunAs,
)

SCRIPTS = {
    AgentPlat.WINDOWS: settings.BASE_DIR
    / "packages"
    / "scripts"
    / "install_windows.ps1",
    AgentPlat.LINUX: settings.BASE_DIR / "packages" / "scripts" / "install_linux.sh",
    AgentPlat.DARWIN: settings.BASE_DIR / "packages" / "scripts" / "install_mac.sh",
}
REMOVE_DRIVER_SCRIPT = (
    settings.BASE_DIR / "packages" / "scripts" / "remove_driver_windows.ps1"
)
REMOVE_DRIVER_TIMEOUT = 150

# the first ar member of a deb is always debian-binary.
# bytes or a tuple of them, see bytes.startswith
MAGIC = {
    PackageKind.EXE: b"MZ",
    PackageKind.MSI: bytes.fromhex("d0cf11e0a1b11ae1"),
    PackageKind.MSIX: b"PK\x03\x04",
    PackageKind.APPX: b"PK\x03\x04",
    PackageKind.PKG: b"xar!",
    PackageKind.DEB: b"!<arch>\ndebian-binary",
    PackageKind.RPM: b"\xed\xab\xee\xdb",
    # zip or cab, the script picks the extractor by these bytes
    PackageKind.DRIVER: (b"PK\x03\x04", b"MSCF"),
}
# per archive type, it has to match the file name
ARCHIVE_MAGIC = {
    "zip": b"PK\x03\x04",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "tar.gz": b"\x1f\x8b",
}
HEAD_SIZE = 64
MAX_FILENAME = 120
OUTPUT_MAX = 8000
MARKER = "ULRMM-PKG "
RESULTS = {
    "ok": InstallState.SUCCEEDED,
    "reboot": InstallState.REBOOT_REQUIRED,
    "fail": InstallState.FAILED,
    "refused": InstallState.REFUSED,
}
# open rows of a batch stay up while this key does. start_installs sets it
# for the queue pickup, the batch task refreshes it until it is done.
BATCH_QUEUED_TTL = 30 * 60
BATCH_ALIVE_TTL = 5 * 60
# rows younger than this are not expired, cache or not
STALE_GRACE = dt.timedelta(minutes=5)
# an agent job without a plan fetch or a progress report for this long is
# gone; unpacking and installing get the package timeout on top (jobs.py)
JOB_IDLE = 15 * 60

# chunked uploads, staged in PACKAGES_DIR/.uploads
CHUNK_SIZE = 32 << 20
UPLOAD_HEADROOM = 1 << 30
UPLOAD_TTL = 24 * 60 * 60
UPLOAD_ID_RE = re.compile(r"[0-9a-f]{32}")

SHA256_RE = re.compile(r"[0-9a-f]{64}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._()+ -]+")
_URL_TOKEN_RE = re.compile(r"(/packages/download/)[^/\s\"'<>]+")


def clean_filename(raw: str) -> tuple[str, str]:
    """(file name, kind) from the upload name. ValueError on a bad extension."""
    base = raw.replace("\\", "/").rsplit("/", 1)[-1].strip()
    ext = next((e for e in EXTENSIONS if base.lower().endswith(e)), "")
    if not ext:
        raise ValueError(f"Only {', '.join(EXTENSIONS)} files can be uploaded.")
    # no leading dash or dot, the name ends up on installer command lines
    stem = _UNSAFE_RE.sub("_", base[: -len(ext)]).lstrip("-. ")
    return (stem[: MAX_FILENAME - len(ext)] or "package") + ext, EXTENSIONS[ext]


def archive_type(filename: str) -> str:
    """zip, 7z or tar.gz, "" for a name that is no archive."""
    name = filename.lower()
    return next((t for e, t in ARCHIVE_TYPES.items() if name.endswith(e)), "")


def magic_ok(kind: str, head: bytes, filename: str = "") -> bool:
    if kind == PackageKind.ARCHIVE:
        wanted = ARCHIVE_MAGIC.get(archive_type(filename))
        return bool(wanted) and head.startswith(wanted)
    return head.startswith(MAGIC[kind])


def packages_dir() -> str:
    path = settings.PACKAGES_DIR
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        # nginx (www-data) reads the files through X-Accel
        os.chmod(path, 0o755)
    return path


class IncomingUpload(FileUploadHandler):
    """Writes the "file" part into PACKAGES_DIR and hashes it there.
    Nothing goes to /tmp. Caller deletes self.path unless it moved the file."""

    def __init__(self, request=None):
        super().__init__(request)
        self.path = ""
        self.fh = None
        self.original = ""
        self.sha = hashlib.sha256()
        self.head = b""
        self.size = 0
        self.done = False

    def new_file(self, field_name, file_name, *args, **kwargs):
        super().new_file(field_name, file_name, *args, **kwargs)
        if field_name != "file" or self.path:
            raise SkipFile()
        # same filesystem as the final name, so os.replace is atomic
        fd, self.path = tempfile.mkstemp(prefix=".incoming-", dir=packages_dir())
        os.fchmod(fd, 0o644)
        self.fh = os.fdopen(fd, "wb")
        self.original = file_name

    def receive_data_chunk(self, raw_data, start):
        if len(self.head) < HEAD_SIZE:
            self.head += raw_data[: HEAD_SIZE - len(self.head)]
        self.sha.update(raw_data)
        self.fh.write(raw_data)
        self.size += len(raw_data)

    def file_complete(self, file_size):
        self.fh.close()
        self.done = True

    def cleanup(self) -> None:
        if self.fh:
            self.fh.close()
        if self.path:
            with suppress(FileNotFoundError):
                os.unlink(self.path)


def download_key(token: str) -> str:
    return f"pkgdl:{hashlib.sha256(token.encode()).hexdigest()}"


def download_url(token: str) -> str:
    # the api host, same base as agents.utils.get_agents_dist_url
    base = get_backend_url(
        settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
    )
    return f"{base}/packages/download/{token}/"


def hide(text: str, token: str = "") -> str:
    if token:
        text = text.replace(token, "***")
    return _URL_TOKEN_RE.sub(r"\1***", text)


def install_env(package, run_as: str) -> dict:
    """PKG_* values of the install script, without the download link."""
    env = {
        "PKG_SHA256": package.sha256,
        "PKG_NAME": package.filename,
        "PKG_KIND": package.kind,
        "PKG_ALLOW_UNSIGNED": "1" if package.allow_unsigned else "0",
        "PKG_MODE": run_as,
    }
    if package.plat == AgentPlat.WINDOWS:
        env["PKG_ARGS"] = package.default_args
        # the script stops the installer before the agent kills the script
        env["PKG_TIMEOUT"] = str(max(15, package.timeout - 45))
    return env


def install_payload(package, run_as: str, token: str) -> dict:
    """runscriptfull payload. The script file is static; values go in env_vars."""
    env = {"PKG_URL": download_url(token), **install_env(package, run_as)}
    return {
        "func": "runscriptfull",
        "timeout": package.timeout,
        "payload": {
            "code": SCRIPTS[package.plat].read_text(),
            "shell": "powershell" if package.plat == AgentPlat.WINDOWS else "shell",
        },
        "run_as_user": run_as == RunAs.USER,
        "env_vars": [f"{k}={v}" for k, v in env.items()],
    }


def remove_driver_payload(inf: str) -> dict:
    return {
        "func": "runscriptfull",
        "timeout": REMOVE_DRIVER_TIMEOUT,
        "payload": {"code": REMOVE_DRIVER_SCRIPT.read_text(), "shell": "powershell"},
        "run_as_user": False,
        "env_vars": [f"DRV_INF={inf}"],
    }


def _text(value, limit: int, token: str) -> str:
    return hide(value, token)[:limit] if isinstance(value, str) else ""


def parse_result(out, timeout: int, token: str = "") -> tuple[str, dict]:
    """(state, PackageInstall fields) from a runscriptfull reply.
    Last stdout line that starts with ULRMM-PKG is the result."""
    if out == "timeout":
        return InstallState.FAILED, {
            "detail": f"the agent gave no answer within {timeout + 30} seconds"
        }
    if out == "natsdown":
        return InstallState.FAILED, {"detail": "NATS is not reachable from this server"}
    if not isinstance(out, dict):
        return InstallState.FAILED, {"detail": "the agent sent an unreadable reply"}

    stdout = str(out.get("stdout") or "")
    stderr = str(out.get("stderr") or "")
    output = hide("\n".join(s for s in (stdout, stderr) if s), token)[-OUTPUT_MAX:]
    line = next((s for s in reversed(stdout.splitlines()) if s.startswith(MARKER)), "")
    try:
        res = json.loads(line[len(MARKER) :])
    except (ValueError, RecursionError):
        res = None
    if not isinstance(res, dict) or res.get("result") not in RESULTS:
        detail = (
            f"the install script reported no result (exit code {out.get('retcode')})"
        )
        if lines := stderr.strip().splitlines():
            detail += ": " + lines[-1].strip()[:200]
        return InstallState.FAILED, {"detail": hide(detail, token), "output": output}

    code = res.get("exit")
    if (
        isinstance(code, bool)
        or not isinstance(code, int)
        or not -(2**31) <= code < 2**31
    ):
        code = None
    return RESULTS[res["result"]], {
        "exit_code": code,
        "signature": _text(res.get("sig"), 32, token),
        "signer": _text(res.get("signer"), 255, token),
        "detail": _text(res.get("msg"), 500, token),
        "output": output,
    }


def batch_key(batch) -> str:
    return f"pkg_batch_{batch}"


def job_key(pk: int) -> str:
    return f"pkgjob_{pk}"


def agent_lock(agent_id: str) -> str:
    # one install per agent: package runs, agent jobs, driver removal
    return f"pkg_install_{agent_id}"


def release_job(install: PackageInstall) -> None:
    cache.delete(job_key(install.pk))
    lock = agent_lock(install.agent.agent_id)
    if cache.get(lock) == install.pk:
        cache.delete(lock)


def expire_stale() -> None:
    """Fails open rows whose batch task is gone, and agent jobs that went
    quiet (they outlive their batch task, see jobs.py)."""
    now = djangotime.now()
    rows = PackageInstall.objects.filter(
        state__in=OPEN_STATES, created__lt=now - STALE_GRACE
    )
    jobs = {
        pk: agent_id
        for pk, agent_id in rows.filter(
            state=InstallState.RUNNING, total_bytes__isnull=False
        ).values_list("pk", "agent__agent_id")
    }
    if jobs:
        alive = cache.get_many([job_key(pk) for pk in jobs])
        quiet = [pk for pk in jobs if job_key(pk) not in alive]
        PackageInstall.objects.filter(pk__in=quiet, state=InstallState.RUNNING).update(
            state=InstallState.FAILED,
            detail="the agent sent nothing about this job within its time limit",
            finished=now,
        )
        for pk in quiet:
            if cache.get(agent_lock(jobs[pk])) == pk:
                cache.delete(agent_lock(jobs[pk]))
        rows = rows.exclude(pk__in=list(jobs))
    batches = set(rows.values_list("batch", flat=True))
    if not batches:
        return
    alive = cache.get_many([batch_key(b) for b in batches])
    dead = [b for b in batches if batch_key(b) not in alive]
    if dead:
        rows.filter(batch__in=dead).update(
            state=InstallState.FAILED,
            detail="no result, the server lost this install",
            finished=now,
        )


def uploads_dir() -> str:
    path = os.path.join(packages_dir(), ".uploads")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def upload_paths(uid: str, root: str = "") -> tuple[str, str]:
    """(bytes so far, metadata) of a chunked upload staged in root,
    PACKAGES_DIR/.uploads by default."""
    base = os.path.join(root or uploads_dir(), uid)
    return f"{base}.part", f"{base}.json"


def load_upload(uid: str, root: str = "") -> dict | None:
    """The upload with its received byte count, None for an unknown id."""
    if not UPLOAD_ID_RE.fullmatch(uid):
        return None
    part, meta = upload_paths(uid, root)
    try:
        with open(meta, encoding="utf-8") as fh:
            info = json.load(fh)
        received = os.path.getsize(part)
    except (OSError, ValueError):
        return None
    return {**info, "id": uid, "received": received} if isinstance(info, dict) else None


def remove_upload(uid: str, root: str = "") -> None:
    for path in upload_paths(uid, root):
        with suppress(FileNotFoundError):
            os.unlink(path)


def remove_stale_uploads(path: str = "") -> int:
    """Staged uploads untouched for a day are deleted."""
    path = path or os.path.join(settings.PACKAGES_DIR, ".uploads")
    cut = time.time() - UPLOAD_TTL
    removed = 0
    with suppress(FileNotFoundError):
        for entry in os.scandir(path):
            with suppress(FileNotFoundError):
                if entry.is_file(follow_symlinks=False) and entry.stat().st_mtime < cut:
                    os.unlink(entry.path)
                    removed += 1
    return removed

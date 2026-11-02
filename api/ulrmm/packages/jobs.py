# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Agent jobs (pkgjob): the agent downloads with resume, unpacks and runs the
package itself, fetches its plan and reports progress over the agent API.
Archives always take this path, other kinds from JOB_SIZE on."""

import asyncio
import secrets
import shlex

from django.core.cache import cache
from django.utils import timezone as djangotime

from ulrmm.constants import AgentPlat
from ulrmm.helpers import agent_ver

from .models import InstallState, PackageKind, RunAs
from .utils import (
    JOB_IDLE,
    MARKER,
    OUTPUT_MAX,
    SCRIPTS,
    agent_lock,
    archive_type,
    download_key,
    download_url,
    hide,
    install_env,
    job_key,
    parse_result,
    release_job,
)

PKGJOB_MIN_AGENT = "1.25.10.2026"
JOB_SIZE = 256 << 20
STEPS = ("downloading", "extracting", "installing")
QUIET_STEPS = ("extracting", "installing")
RESULTS = ("done", "failed")
# bare names the agent finds on PATH, anything else is a path in the archive
COMMANDS = {
    AgentPlat.WINDOWS: ("msiexec.exe", "powershell.exe", "pwsh.exe"),
    AgentPlat.LINUX: ("sh", "bash"),
    AgentPlat.DARWIN: ("sh", "bash"),
}


def supports_job(agent) -> bool:
    return agent_ver(agent.version) >= agent_ver(PKGJOB_MIN_AGENT)


def uses_job(package, agent, run_as: str) -> bool:
    if package.kind == PackageKind.ARCHIVE:
        return True
    return package.size > JOB_SIZE and run_as == RunAs.SYSTEM and supports_job(agent)


def keep_alive(install, step: str = "") -> None:
    """A plan fetch or a progress report: the job and the agent lock stay.
    The agent reports nothing while it unpacks or runs the installer, so
    those steps get the package timeout on top."""
    idle = JOB_IDLE
    if step in QUIET_STEPS:
        idle += install.package.timeout
    cache.set(job_key(install.pk), 1, idle)
    lock = agent_lock(install.agent.agent_id)
    if cache.get(lock) == install.pk:
        cache.touch(lock, idle + 60)


def start(install) -> None:
    install.state = InstallState.RUNNING
    install.started = djangotime.now()
    install.done_bytes, install.total_bytes = 0, install.package.size
    install.detail = ""
    install.save(
        update_fields=["state", "started", "done_bytes", "total_bytes", "detail"]
    )
    keep_alive(install)


def plan(install) -> dict:
    """What the agent runs. Every fetch gets its own download link."""
    package = install.package
    token = secrets.token_urlsafe(32)
    cache.set(download_key(token), install.pk, package.timeout + 300)
    keep_alive(install)
    data = {
        "job": install.pk,
        "url": download_url(token),
        "sha256": package.sha256,
        "size": package.size,
        "filename": package.filename,
        "extract": "none",
        "success_codes": package.success_codes,
        "reboot_codes": package.reboot_codes,
    }
    windows = package.plat == AgentPlat.WINDOWS
    if package.kind == PackageKind.ARCHIVE:
        data["extract"] = archive_type(package.filename)
        data["run"] = {
            "type": "command",
            "exe": package.command,
            # windows builds the command line from args, unix runs argv
            "args": package.default_args,
            "argv": [] if windows else shlex.split(package.default_args),
            "timeout": package.timeout,
        }
    else:
        # the script finds the file in PKG_FILE and skips its download
        data["run"] = {
            "type": "script",
            "shell": "powershell" if windows else "shell",
            "body": SCRIPTS[package.plat].read_text(),
            "env": install_env(package, RunAs.SYSTEM),
            "timeout": package.timeout,
        }
    return data


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**53


def outcome(install, data: dict) -> tuple[str, dict]:
    """(state, PackageInstall fields) of the agent's final report. Scripts
    end with their ULRMM-PKG line, commands are judged by the exit codes."""
    package = install.package
    output = hide(str(data.get("output") or ""))[-OUTPUT_MAX:]
    detail = hide(str(data.get("detail") or "")).strip()[:500]
    code = data.get("exit_code")
    if isinstance(code, bool) or not isinstance(code, int):
        code = None
    elif not -(2**31) <= code < 2**32:
        code = None

    if package.kind != PackageKind.ARCHIVE:
        state, fields = parse_result(
            {"stdout": output, "stderr": "", "retcode": code}, package.timeout
        )
        # no result line: the agent failed before or around the script
        if MARKER not in output and detail:
            fields["detail"] = detail
        return state, fields

    fields = {"exit_code": code, "output": output}
    if data.get("state") == "failed" or code is None:
        fields["detail"] = detail or "the agent reported a failure without details"
        return InstallState.FAILED, fields
    if code in package.success_codes:
        state = InstallState.SUCCEEDED
    elif code in package.reboot_codes:
        state = InstallState.REBOOT_REQUIRED
    else:
        state = InstallState.FAILED
    fields["detail"] = detail or f"{package.command} exited with {code}"
    return state, fields


def report(install, data: dict) -> str:
    """Progress or the final result from the agent. Returns an error text."""
    from .tasks import after_install, finish

    state = data.get("state")
    if state in STEPS:
        install.detail = state
        fields = ["detail"]
        done, total = data.get("done"), data.get("total")
        if _count(done) and _count(total) and done <= total:
            install.done_bytes, install.total_bytes = done, total
            fields += ["done_bytes", "total_bytes"]
        install.save(update_fields=fields)
        keep_alive(install, state)
        return ""
    if state not in RESULTS:
        return "unknown state"
    result, fields = outcome(install, data)
    finish(install, result, **fields)
    release_job(install)
    asyncio.run(after_install(install, result))
    return ""

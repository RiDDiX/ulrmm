# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Chocolatey and winget installs through a pending action: the agent acks,
installs and reports to apiv4 chocoresult/wingetresult."""

import asyncio
import re

from django.conf import settings

from logs.models import AuditLog, PendingAction
from ulrmm.constants import PAAction
from ulrmm.helpers import agent_ver

from . import winget

# what the agent accepts as a chocolatey package id
CHOCO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")


class InstallError(Exception):
    pass


def _send(agent, action: PendingAction, nats_data: dict) -> PendingAction:
    if asyncio.run(agent.nats_cmd(nats_data, timeout=2)) != "ok":
        action.delete()
        raise InstallError("Unable to contact the agent")
    return action


def start_choco(agent, name: str, username: str, debug_info=None) -> PendingAction:
    # installs as SYSTEM, so it goes into the audit log like a command
    command = f"choco install {name}"
    AuditLog.audit_raw_command(
        username=username,
        agent=agent,
        cmd=command,
        shell="choco",
        debug_info=debug_info,
    )
    details = {"name": name, "output": None, "installed": False}
    action = PendingAction.objects.create(
        agent=agent, action_type=PAAction.CHOCO_INSTALL, details=details
    )
    return _send(
        agent,
        action,
        {
            "func": "installwithchoco",
            "choco_prog_name": name,
            "pending_action_pk": action.pk,
        },
    )


def start_winget(agent, name: str, username: str, debug_info=None) -> PendingAction:
    row = winget.find(name)
    if row is None:
        raise InstallError(f"{name} is not in the winget catalog")
    if agent_ver(agent.version) < agent_ver(settings.WINGET_MIN_AGENT):
        raise InstallError(
            f"Installing from winget needs agent {settings.WINGET_MIN_AGENT} "
            "or newer, update the agent first."
        )
    package_id, title = row[0], row[1]

    AuditLog.audit_raw_command(
        username=username,
        agent=agent,
        cmd=f"winget install --id {package_id} --exact --source winget "
        "--scope machine",
        shell="winget",
        debug_info=debug_info,
    )
    action = PendingAction.objects.create(
        agent=agent,
        action_type=PAAction.WINGET_INSTALL,
        details={
            "name": title,
            "id": package_id,
            "source": "winget",
            "output": None,
            "installed": False,
            "exit_code": None,
            "reboot": False,
        },
    )
    nats_data = {
        "func": "installwithwinget",
        "winget_id": package_id,
        "pending_action_pk": action.pk,
    }
    return _send(agent, action, nats_data)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import re

from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import EvtLogPerms
from logs.models import AuditLog
from services.permissions import WinSvcsPerms
from ulrmm.agent_ident import agent_ident, nix_rc_name
from ulrmm.constants import AgentPlat
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info

# agent rule: no leading dash, so the name is not parsed as an option
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:+\-]{0,199}")
ACTIONS = {"start", "stop", "restart", "enable", "disable"}
UPDATE_MSG = "Agent update required"
CONTACT_MSG = "Unable to contact the agent"


def _posix_agent(agent_id: str):
    agent = get_object_or_404(Agent, agent_id=agent_id)
    if not agent.is_posix:
        return agent, notify_error(
            "This is only available for Linux, macOS and FreeBSD agents."
        )
    # an offline agent times out, and a timeout is what an old agent looks like
    if not agent.is_online:
        return agent, notify_error(CONTACT_MSG)
    return agent, None


def _own_service(name: str) -> bool:
    unit = settings.AGENT_NIX_SVC
    return name in (
        unit,
        unit.removesuffix(".service"),
        settings.AGENT_MAC_PLIST_LABEL,
        nix_rc_name(agent_ident()),
    )


def _int_param(request, key, default, lo, hi):
    raw = request.query_params.get(key)
    if raw in (None, ""):
        return default, None
    try:
        val = int(raw)
    except ValueError:
        return None, f"{key} must be a number."
    if not lo <= val <= hi:
        return None, f"{key} must be between {lo} and {hi}."
    return val, None


# FreeBSD has neither a journal nor a unified log
_DEFAULT_SOURCES = {
    AgentPlat.LINUX: "journal",
    AgentPlat.DARWIN: "unified",
    AgentPlat.FREEBSD: "file",
}

_DONE = {
    "start": "started successfully",
    "stop": "stopped successfully",
    "restart": "restarted successfully",
    "enable": "enabled successfully",
    "disable": "disabled successfully",
}


class PosixServices(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    def get(self, request, agent_id):
        agent, err = _posix_agent(agent_id)
        if err:
            return err
        r = asyncio.run(agent.nats_cmd(data={"func": "posixservices"}, timeout=30))
        if r == "natsdown":
            return notify_error(CONTACT_MSG)
        if r == "timeout":
            return notify_error(UPDATE_MSG)
        if isinstance(r, str):
            return notify_error(r)
        if not isinstance(r, list):
            return notify_error(UPDATE_MSG)
        return Response(r)


class PosixServiceAction(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    def post(self, request, agent_id, name):
        agent, err = _posix_agent(agent_id)
        if err:
            return err
        if not NAME_RE.fullmatch(name):
            return notify_error("Invalid service name.")
        action = request.data.get("action")
        if action not in ACTIONS:
            return notify_error("Invalid action.")

        data = {"func": "posixsvcaction", "payload": {"name": name, "action": action}}
        r = asyncio.run(agent.nats_cmd(data, timeout=65))
        if r == "natsdown":
            return notify_error(CONTACT_MSG)
        # stopping or restarting its own service ends the agent before it answers
        if r == "timeout" and action in ("stop", "restart") and _own_service(name):
            AuditLog.audit_service_action(
                request.user.username, agent, name, action, debug_info=get_debug_info()
            )
            if action == "stop":
                return Response(
                    "The agent stopped its own service and stays offline until "
                    "the service is started again."
                )
            return Response(
                "The agent is restarting its own service and reconnects in a moment."
            )
        if r == "timeout":
            return notify_error(UPDATE_MSG)
        if not isinstance(r, str):
            return notify_error(UPDATE_MSG)
        if r != "ok":
            return notify_error(r)

        AuditLog.audit_service_action(
            request.user.username, agent, name, action, debug_info=get_debug_info()
        )
        return Response(f"The service {name} was {_DONE[action]}")


class PosixLogs(APIView):
    permission_classes = [IsAuthenticated, EvtLogPerms]

    def get(self, request, agent_id):
        agent, err = _posix_agent(agent_id)
        if err:
            return err
        q = request.query_params
        source = q.get("source") or _DEFAULT_SOURCES[agent.plat]
        if source not in ("journal", "file", "unified"):
            return notify_error("Invalid source.")

        lines, e1 = _int_param(request, "lines", 200, 50, 2000)
        priority, e2 = _int_param(request, "priority", None, 0, 7)
        since, e3 = _int_param(request, "since", None, 1, 525600)
        if e1 or e2 or e3:
            return notify_error(e1 or e2 or e3)

        payload = {"source": source, "lines": str(lines)}
        if priority is not None:
            payload["priority"] = str(priority)
        if since is not None:
            payload["since"] = str(since)

        unit = q.get("unit")
        if unit:
            if not NAME_RE.fullmatch(unit):
                return notify_error("Invalid unit.")
            payload["unit"] = unit

        path = q.get("path")
        if source == "file" and not path and agent.plat == AgentPlat.FREEBSD:
            path = "/var/log/messages"
        if source == "file":
            if (
                not path
                or len(path) > 300
                or not path.startswith("/var/log/")
                or ".." in path
                or "\x00" in path
            ):
                return notify_error("The log path must be below /var/log/.")
            payload["path"] = path

        r = asyncio.run(
            agent.nats_cmd(data={"func": "posixlogs", "payload": payload}, timeout=65)
        )
        if r == "natsdown":
            return notify_error(CONTACT_MSG)
        if r == "timeout":
            return notify_error(UPDATE_MSG)
        if isinstance(r, str):
            return notify_error(r)
        if not isinstance(r, dict) or not isinstance(r.get("lines"), list):
            return notify_error(UPDATE_MSG)
        return Response(r)

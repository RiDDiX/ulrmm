# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from typing import Any

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from logs.models import AuditLog
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info

from .permissions import WinSvcsPerms

UNREACHABLE = "Unable to contact the agent"
FALLBACK = "Something went wrong"
POSIX_REFUSED = "Please use 'Recover Connection' instead."
NO_REPLY = ("timeout", "natsdown")
ACTIONS = ("start", "stop", "restart")
START_TYPES = ("auto", "autodelay", "manual", "disabled")


def process_nats_response(data: Any) -> tuple[bool, bool, str]:
    """(success, natserror, errormsg) of a winsvcaction/editwinsvc reply."""
    if not isinstance(data, dict):
        return False, isinstance(data, str), "timeout"
    errormsg = data.get("errormsg")
    return (
        data.get("success") is True,
        False,
        errormsg if isinstance(errormsg, str) else "timeout",
    )


def _body(request, key: str):
    return request.data.get(key) if hasattr(request.data, "get") else None


def _valid_name(name: str) -> bool:
    return 0 < len(name) <= 256 and not any(
        ord(char) < 32 or ord(char) == 127 for char in name
    )


def _reply_error(reply) -> "Response | None":
    """None when the agent did it, else the 400 to answer with."""
    success, natserror, errormsg = process_nats_response(reply)
    if natserror or errormsg == "timeout":
        return notify_error(UNREACHABLE)
    if success:
        return None
    return notify_error(errormsg or FALLBACK)


class GetServices(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    def get(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        listing = asyncio.run(agent.nats_cmd(data={"func": "winservices"}, timeout=10))
        # "timeout" / "natsdown" and any other non-list reply mean no answer
        if not isinstance(listing, list):
            return notify_error(UNREACHABLE)
        # Linux, macOS and FreeBSD agents answer [], their services live elsewhere
        if not agent.is_posix:
            agent.services = listing
            agent.save(update_fields=["services"])
        return Response(listing)


class GetEditActionService(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    def _agent(self, agent_id: str, svcname: str):
        found = get_object_or_404(Agent, agent_id=agent_id)
        bad = None if _valid_name(svcname) else notify_error("Invalid service name.")
        return found, bad

    def _send(self, agent, data: dict, timeout: int):
        return asyncio.run(agent.nats_cmd(data, timeout=timeout))

    def _audit(self, request, agent, svcname: str, action: str) -> None:
        AuditLog.audit_service_action(
            request.user.username,
            agent,
            svcname,
            action,
            debug_info=get_debug_info(),
        )

    def get(self, request, agent_id, svcname):
        agent, error = self._agent(agent_id, svcname)
        if error:
            return error
        r = self._send(
            agent, {"func": "winsvcdetail", "payload": {"name": svcname}}, 10
        )
        if r in NO_REPLY:
            return notify_error(UNREACHABLE)
        return Response(r)

    def post(self, request, agent_id, svcname):
        agent, error = self._agent(agent_id, svcname)
        if error:
            return error
        if agent.is_posix:
            return notify_error(POSIX_REFUSED)

        action = _body(request, "sv_action")
        if action not in ACTIONS:
            return notify_error("Invalid action.")

        def control(step: str):
            payload = {"name": svcname, "action": step}
            return self._send(agent, {"func": "winsvcaction", "payload": payload}, 32)

        if action == "restart":
            reply = control("stop")
            error = _reply_error(reply)
            # a stopped service is restarted by starting it
            if error is not None and not _already_stopped(reply):
                return error
            error = _reply_error(control("start"))
            if error is not None:
                return error
            self._audit(request, agent, svcname, action)
            return Response("The service was restarted successfully")

        error = _reply_error(control(action))
        if error is not None:
            return error
        self._audit(request, agent, svcname, action)
        done = "started" if action == "start" else "stopped"
        return Response(f"The service was {done} successfully")

    def put(self, request, agent_id, svcname):
        agent, error = self._agent(agent_id, svcname)
        if error:
            return error
        if agent.is_posix:
            return notify_error(POSIX_REFUSED)

        start_type = _body(request, "startType")
        if start_type not in START_TYPES:
            return notify_error("Unknown startup type provided")

        data = {
            "func": "editwinsvc",
            "payload": {"name": svcname, "startType": start_type},
        }
        error = _reply_error(self._send(agent, data, 10))
        if error is not None:
            return error
        self._audit(request, agent, svcname, f"set start type {start_type}")
        return Response("The service start type was updated successfully")


def _already_stopped(reply) -> bool:
    # ERROR_SERVICE_NOT_ACTIVE, the agent reports the English system text
    success, natserror, errormsg = process_nats_response(reply)
    return not natserror and "has not been started" in errormsg.lower()

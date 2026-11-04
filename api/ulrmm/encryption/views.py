# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from cryptography.fernet import InvalidToken
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from core.utils import stepup_denied
from logs.models import AuditLog
from ulrmm.constants import (
    AGENT_DEFER,
    AgentPlat,
    AuditActionType,
    AuditObjType,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm_on_agent
from ulrmm.throttles import VaultRevealThrottle

from .models import KeyKind, KeyStatus, RecoveryKey
from .permissions import RecoveryKeyPerms
from .utils import (
    COLLECT_TIMEOUT,
    COLLECTORS,
    ROTATE_TIMEOUT,
    RotateError,
    agent_payload,
    collect_payload,
    fleet_summary,
    parse_collect,
    parse_rotate,
    rotate_payload,
    store,
    store_rotated,
    unseal,
)

STEPUP = "Recovery keys need the same 60 minute step-up as terminal and files."


def _agent(agent_id: str) -> Agent:
    return get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)


def _audit(request, agent: Agent, action: str, message: str) -> None:
    by = request.user.username
    AuditLog.objects.create(
        username=by,
        agent=agent.hostname,
        agent_id=agent.agent_id,
        message=message,
        object_type=AuditObjType.AGENT,
        action=action,
        debug_info=get_debug_info(),
    )


def _text(value, limit: int) -> str:
    # goes into a plist on the Mac; xml has no control characters
    if isinstance(value, str) and 0 < len(value) <= limit and value.isprintable():
        return value
    return ""


class AgentEncryption(APIView):
    permission_classes = [IsAuthenticated, RecoveryKeyPerms]

    def get(self, request, agent_id):
        return Response(agent_payload(_agent(agent_id)))


class CollectEncryption(APIView):
    permission_classes = [IsAuthenticated, RecoveryKeyPerms]

    def post(self, request, agent_id):
        agent = _agent(agent_id)
        if agent.plat not in COLLECTORS:
            return notify_error(f"{agent.hostname} runs an unsupported platform.")
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline.")

        out = asyncio.run(
            agent.nats_cmd(collect_payload(agent.plat), timeout=COLLECT_TIMEOUT + 10)
        )
        rep = parse_collect(agent.plat, out)
        store(agent, rep)
        message = (
            f"{request.user.username} read the disk encryption of {agent.hostname}"
        )
        if rep.error:
            message += f": {rep.error}"
        _audit(request, agent, AuditActionType.EXEC_SCRIPT, message)
        if rep.error:
            return notify_error(f"Reading the disk encryption failed: {rep.error}")
        return Response(agent_payload(agent))


class RotateFileVaultKey(APIView):
    permission_classes = [IsAuthenticated, RecoveryKeyPerms]

    def post(self, request, agent_id):
        if denied := stepup_denied(request, STEPUP):
            return denied
        agent = _agent(agent_id)
        if agent.plat != AgentPlat.DARWIN:
            return notify_error("Only FileVault keys on macOS can be rotated.")
        username = _text(request.data.get("username"), 255)
        password = _text(request.data.get("password"), 1024)
        if not (username and password):
            return notify_error(
                "Enter the user name and password of an account that can unlock "
                "the disk (printable characters only)."
            )
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline.")

        # a second rotation would leave the Mac and the database with different keys
        lock = f"filevault_rotate_{agent.agent_id}"
        if not cache.add(lock, 1, ROTATE_TIMEOUT + 30):
            return notify_error(
                f"The FileVault key of {agent.hostname} is already being rotated."
            )
        try:
            data = rotate_payload(username, password)
            out = asyncio.run(agent.nats_cmd(data, timeout=ROTATE_TIMEOUT + 10))
            store_rotated(agent, parse_rotate(out))
        except RotateError as e:
            error = f"Rotating the FileVault key of {agent.hostname} failed: {e}"
            if e.replaced:
                RecoveryKey.objects.filter(
                    agent=agent, kind=KeyKind.FILEVAULT, status=KeyStatus.ACTIVE
                ).update(status=KeyStatus.STALE)
                error += (
                    ". The Mac may have a new key already, so the stored one is "
                    "marked stale. Rotate again."
                )
            _audit(
                request,
                agent,
                AuditActionType.EXEC_SCRIPT,
                f"{request.user.username}: {error} (account {username})",
            )
            return notify_error(error)
        finally:
            cache.delete(lock)

        _audit(
            request,
            agent,
            AuditActionType.EXEC_SCRIPT,
            f"{request.user.username} rotated the FileVault recovery key of "
            f"{agent.hostname} (account {username})",
        )
        return Response(agent_payload(agent))


class RevealRecoveryKey(APIView):
    permission_classes = [IsAuthenticated, RecoveryKeyPerms]
    # one budget with credential reveals, per user
    throttle_classes = [VaultRevealThrottle]

    def post(self, request, pk):
        row = get_object_or_404(RecoveryKey.objects.select_related("agent"), pk=pk)
        if not _has_perm_on_agent(request.user, row.agent.agent_id):
            return Response({"detail": "You cannot view this key."}, status=403)
        if denied := stepup_denied(request, STEPUP):
            return denied
        try:
            key = unseal(row.key)
        except InvalidToken:
            return notify_error(
                "The stored key cannot be decrypted (SECRET_KEY changed?). "
                "Collect or rotate it again."
            )

        what = f"{row.get_kind_display()} recovery key of {row.agent.hostname}"
        what += f" ({row.volume}"
        what += f", protector {row.protector_id})" if row.protector_id else ")"
        _audit(
            request,
            row.agent,
            AuditActionType.VIEW,
            f"{request.user.username} revealed the {what}",
        )
        r = Response({"key": key})
        r["Cache-Control"] = "no-store"
        return r


class EncryptionSummary(APIView):
    permission_classes = [IsAuthenticated, RecoveryKeyPerms]

    def get(self, request):
        return Response(fleet_summary(Agent.objects.filter_by_role(request.user)))

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from cryptography.fernet import InvalidToken
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import MeshPerms
from core.permissions import CoreSettingsPerms
from core.utils import stepup_denied
from logs.models import AuditLog
from ulrmm.constants import (
    AGENT_DEFER,
    AuditActionType,
    AuditObjType,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.throttles import VaultRevealThrottle

from .models import RustDeskPeer
from .serializers import RustDeskSettingsSerializer, VersionSerializer
from .tasks import (
    MAX_PEERS,
    UpdateError,
    audit,
    outdated_peers,
    releases_payload,
    rustdesk_check_releases_task,
    rustdesk_pin_client_task,
    rustdesk_update_clients_task,
    rustdesk_update_server_task,
    update_peer,
)
from .utils import (
    DEPLOY_TIMEOUT,
    DeployError,
    PasswordNotSent,
    config_string,
    connect_uri,
    decrypt_secret,
    encrypt_secret,
    get_rustdesk_settings,
    new_password,
    parse_deploy_output,
    read_public_key,
    render_deploy,
    settings_payload,
    unsupported_reason,
    update_available,
    viewer_downloads,
)


def _agent(agent_id: str) -> Agent:
    return get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)


def _audit(request, agent: Agent, action: str, message: str) -> None:
    audit(request.user.username, message, agent, action)


class RustDeskSettingsView(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(settings_payload(get_rustdesk_settings()))

    def put(self, request):
        rd = get_rustdesk_settings()
        fields = RustDeskSettingsSerializer.Meta.fields
        before = {f: getattr(rd, f) for f in fields}
        serializer = RustDeskSettingsSerializer(
            instance=rd, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        rd = serializer.save()
        after = {f: getattr(rd, f) for f in fields}
        if before != after:
            AuditLog.audit_object_changed(
                request.user.username,
                AuditObjType.CORE,
                before,
                after,
                "RustDesk",
                debug_info=get_debug_info(),
            )
        return Response(settings_payload(rd))


class AgentRustDesk(APIView):
    permission_classes = [IsAuthenticated, MeshPerms]

    def get(self, request, agent_id):
        agent = _agent(agent_id)
        rd = get_rustdesk_settings()
        peer = RustDeskPeer.objects.filter(agent=agent).first() or RustDeskPeer()
        available = bool(rd.enabled and rd.id_server and read_public_key())
        return Response(
            {
                "available": available,
                "supported": not unsupported_reason(agent, probe=False),
                "installed": bool(peer.rustdesk_id),
                "rustdesk_id": peer.rustdesk_id,
                "password_set": bool(peer.password),
                "client_version": peer.client_version,
                "latest_version": rd.pinned_client_version,
                "update_available": update_available(peer, rd.pinned_client_version),
                "deployed_at": peer.deployed_at,
                "last_error": peer.last_error,
                "downloads": viewer_downloads() if available else [],
            }
        )


class DeployRustDesk(APIView):
    permission_classes = [IsAuthenticated, MeshPerms]

    def post(self, request, agent_id):
        agent = _agent(agent_id)
        rd = get_rustdesk_settings()
        key = read_public_key()
        if not (rd.enabled and rd.id_server):
            return notify_error(
                "RustDesk is off or has no ID server, see Global Settings > RustDesk."
            )
        if not key:
            return notify_error(
                "The RustDesk server key is missing on this server "
                "(riddix/rustdesk/install-rustdesk-server.sh)."
            )
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline.")
        if reason := unsupported_reason(agent, probe=True):
            return notify_error(reason)

        # a second click would leave the endpoint with one password and the
        # database with the other. Updates take the same lock.
        lock = f"rustdesk_deploy_{agent.agent_id}"
        if not cache.add(lock, 1, DEPLOY_TIMEOUT + 30):
            return notify_error(
                f"RustDesk is already being deployed or updated on {agent.hostname}."
            )
        try:
            config = config_string(rd.id_server, rd.relay_server, key)
            return self._deploy(request, agent, host=rd.id_server, config=config)
        finally:
            cache.delete(lock)

    def _deploy(self, request, agent: Agent, *, host: str, config: str):
        password = new_password()
        peer, _ = RustDeskPeer.objects.get_or_create(agent=agent)
        previous = peer.password
        try:
            data = render_deploy(agent, password=password, host=host, config=config)
            # saved before the call: a lost reply can mean the endpoint
            # already has this password
            peer.password = encrypt_secret(password)
            peer.save(update_fields=["password"])
            out = asyncio.run(agent.nats_cmd(data, timeout=DEPLOY_TIMEOUT + 10))
            rustdesk_id, version = parse_deploy_output(out, password)
        except DeployError as e:
            if isinstance(e, PasswordNotSent):
                peer.password = previous
            peer.last_error = f"RustDesk deploy on {agent.hostname} failed: {e}"
            peer.save(update_fields=["password", "last_error"])
            _audit(
                request,
                agent,
                AuditActionType.EXEC_COMMAND,
                f"{request.user.username}: {peer.last_error}",
            )
            return notify_error(peer.last_error)

        peer.rustdesk_id = rustdesk_id
        peer.client_version = version
        peer.deployed_at = djangotime.now()
        peer.last_error = ""
        peer.save()
        _audit(
            request,
            agent,
            AuditActionType.EXEC_COMMAND,
            f"{request.user.username} deployed RustDesk {version} on "
            f"{agent.hostname}, ID {rustdesk_id}",
        )
        return Response({"rustdesk_id": rustdesk_id, "client_version": version})


class UpdateRustDesk(DeployRustDesk):
    """upgrade to the pinned version. no pw sent, stored one untouched."""

    def _deploy(self, request, agent: Agent, *, host: str, config: str):
        peer = RustDeskPeer.objects.filter(agent=agent).exclude(rustdesk_id="").first()
        if not peer:
            return notify_error(
                f"RustDesk is not installed on {agent.hostname}. "
                "Use Install or reconfigure."
            )
        try:
            rustdesk_id, version = update_peer(
                agent, peer, request.user.username, host=host, config=config
            )
        except DeployError as e:
            return notify_error(str(e))
        return Response({"rustdesk_id": rustdesk_id, "client_version": version})


class RevealRustDeskPassword(APIView):
    permission_classes = [IsAuthenticated, MeshPerms]
    throttle_classes = [VaultRevealThrottle]

    def post(self, request, agent_id):
        agent = _agent(agent_id)
        if denied := stepup_denied(
            request,
            "Showing a RustDesk password needs the same 60 minute step-up as "
            "terminal and files.",
        ):
            return denied
        peer = RustDeskPeer.objects.filter(agent=agent).exclude(password="").first()
        if not peer:
            return notify_error(f"No RustDesk password is stored for {agent.hostname}.")
        try:
            password = decrypt_secret(peer.password)
        except InvalidToken:
            return notify_error(
                "The stored RustDesk password cannot be decrypted (SECRET_KEY "
                "changed?). Deploy RustDesk again."
            )

        _audit(
            request,
            agent,
            AuditActionType.VIEW,
            f"{request.user.username} revealed the RustDesk password of "
            f"{agent.hostname}",
        )
        rd = get_rustdesk_settings()
        key = read_public_key()
        uri = ""
        if rd.enabled and rd.id_server and key and peer.rustdesk_id:
            uri = connect_uri(peer.rustdesk_id, rd.id_server, key, password)
        r = Response({"password": password, "uri": uri})
        r["Cache-Control"] = "no-store"
        return r


class RustDeskReleases(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(releases_payload())


class CheckRustDeskReleases(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        if errors := rustdesk_check_releases_task():
            return notify_error(" ".join(errors))
        return Response(releases_payload())


class UpdateRustDeskServer(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        if denied := stepup_denied(
            request, "The server update runs the install script as root on this host."
        ):
            return denied
        serializer = VersionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            # download and install stay below the uwsgi harakiri
            rustdesk_update_server_task(
                serializer.validated_data["version"],
                request.user.username,
                timeout=DEPLOY_TIMEOUT,
            )
        except UpdateError as e:
            return notify_error(f"The RustDesk server update failed: {e}")
        return Response(releases_payload())


class PinRustDeskClient(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        serializer = VersionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            # five downloads, below the uwsgi harakiri together
            rustdesk_pin_client_task(
                serializer.validated_data["version"],
                request.user.username,
                timeout=DEPLOY_TIMEOUT,
            )
        except UpdateError as e:
            return notify_error(f"Pinning the RustDesk client failed: {e}")
        return Response(releases_payload())


class UpdateRustDeskClients(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        rd = get_rustdesk_settings()
        # off or no ID server: the task skips every device
        if not (rd.enabled and rd.id_server):
            return notify_error(
                "RustDesk is off or has no ID server, see Global Settings > RustDesk."
            )
        if not read_public_key():
            return notify_error(
                "The RustDesk server key is missing on this server "
                "(riddix/rustdesk/install-rustdesk-server.sh)."
            )
        online = [
            p for p in outdated_peers(rd.pinned_client_version) if p.agent.is_online
        ]
        if online:
            rustdesk_update_clients_task.delay(request.user.username)
        return Response({"queued": min(len(online), MAX_PEERS)})

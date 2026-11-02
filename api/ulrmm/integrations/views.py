# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db.models import Q
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm
from ulrmm.utils import redis_lock

from .models import NetworkClient, OpnsenseFirewall, UniFiController
from .serializers import NetworkClientSerializer, OpnsenseSerializer, UniFiSerializer
from .tasks import SYNC_LOCK, sync

KINDS = {
    "unifi": (UniFiController, UniFiSerializer),
    "opnsense": (OpnsenseFirewall, OpnsenseSerializer),
}
MAX_CLIENTS = 5000


class IntegrationPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_manage_integrations")


class ListPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_list_agents")


def _settings() -> dict:
    return {key: s(model.get()).data for key, (model, s) in KINDS.items()}


def _restricted(user) -> bool:
    role = user.role
    if user.is_superuser or (role and role.is_superuser):
        return False
    return bool(role) and (
        role.can_view_clients.exists() or role.can_view_sites.exists()
    )


class Settings(APIView):
    """{"unifi": {...}, "opnsense": {...}}. Secrets are write-only."""

    permission_classes = [IsAuthenticated, IntegrationPerms]

    def get(self, request):
        return Response(_settings())

    def put(self, request):
        valid = []
        for key, (model, serializer) in KINDS.items():
            if key not in request.data:
                continue
            s = serializer(model.get(), data=request.data[key], partial=True)
            if not s.is_valid():
                raise ValidationError({key: s.errors})
            valid.append(s)
        for s in valid:
            s.save()
        return Response(_settings())


class Sync(APIView):
    permission_classes = [IsAuthenticated, IntegrationPerms]

    def post(self, request):
        with redis_lock(SYNC_LOCK, "manual") as acquired:
            if not acquired:
                return notify_error("A sync is already running.")
            results = sync()
        if not results:
            return notify_error("Turn UniFi or OPNsense on and enter its address.")
        return Response({"results": results, **_settings()})


class Clients(APIView):
    """?vlan=<id>&search=<mac, ip or name>. A role limited to clients or
    sites only gets the clients that are its devices."""

    permission_classes = [IsAuthenticated, ListPerms]

    def get(self, request):
        agents = {}
        rows = (
            Agent.objects.filter_by_role(request.user)  # type: ignore
            .exclude(network_info={})
            .values_list("agent_id", "display_name", "hostname", "network_info__mac")
        )
        for agent_id, display_name, hostname, mac in rows:
            agents[mac] = {"agent_id": agent_id, "name": display_name or hostname}

        clients = NetworkClient.objects.order_by("vlan_id", "ip", "mac")
        if _restricted(request.user):
            clients = clients.filter(mac__in=list(agents))
        if vlan := request.query_params.get("vlan"):
            if not vlan.isdigit():
                return notify_error("A VLAN id.")
            clients = clients.filter(vlan_id=int(vlan))
        if search := request.query_params.get("search", "").strip()[:64]:
            clients = clients.filter(
                Q(mac__icontains=search)
                | Q(ip__icontains=search)
                | Q(hostname__icontains=search)
            )
        return Response(
            NetworkClientSerializer(
                clients[:MAX_CLIENTS], many=True, context={"agents": agents}
            ).data
        )


class Vlans(APIView):
    permission_classes = [IsAuthenticated, ListPerms]

    def get(self, request):
        seen, ret = set(), []
        for source, (model, _) in KINDS.items():
            for vlan in model.get().vlans:
                key = (vlan.get("vlan_id"), vlan.get("subnet"))
                if key not in seen:
                    seen.add(key)
                    ret.append({**vlan, "source": source})
        return Response(sorted(ret, key=lambda v: (v["vlan_id"] or 0, v["name"])))

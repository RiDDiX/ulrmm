# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from ipaddress import IPv4Address, IPv4Network

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.utils import server_networks
from logs.models import AuditLog
from netmon.models import MAX_DEVICES, NetworkDevice, probe_scope
from netmon.probe import clean
from netmon.serializers import NetworkDeviceSerializer
from ulrmm.constants import AGENT_DEFER, AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm, _has_perm_on_site

from .models import DeviceState, DiscoveredDevice, Scan, ScanStatus
from .serializers import (
    DEFAULT_PORTS,
    MAX_ADDRESSES,
    MAX_PORTS,
    DiscoveredDeviceSerializer,
    ScanSerializer,
)
from .tasks import (
    agent_matches,
    expire_stale,
    matched_state,
    netmon_matches,
    scan_network_task,
)

ACTIVE = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def devices():
    # the matched agent's names. skip its inventory columns
    return DiscoveredDevice.objects.select_related("agent").defer(
        *(f"agent__{f}" for f in AGENT_DEFER)
    )


def visible_agents(request) -> dict:
    # a match on another client is returned as state "agent", with no names
    pks = Agent.objects.filter_by_role(request.user).values_list("pk", flat=True)
    return {"agents": set(pks)}


class DiscoveryPerms(BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_run_network_discovery")


def audit(request, action, message, before=None, after=None) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.DISCOVERY,
        action=action,
        message=message,
        before_value=before,
        after_value=after,
        debug_info=get_debug_info(),
    )


class GetAddScans(APIView):
    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def get(self, request):
        expire_stale()
        scans = Scan.objects.order_by("-pk")[:50]
        return Response(ScanSerializer(scans, many=True).data)

    def post(self, request):
        serializer = ScanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        expire_stale()
        if Scan.objects.filter(status__in=ACTIVE).exists():
            return notify_error("A scan is queued or running already.")

        scan = serializer.save(started_by=request.user.username)
        audit(
            request,
            AuditActionType.CHECK_RUN,
            f"{request.user.username} started a network scan of"
            f" {', '.join(scan.networks)}",
            after={
                "scan": scan.pk,
                "networks": scan.networks,
                "ports": scan.ports,
                "snmp": scan.snmp,
            },
        )
        scan_network_task.delay(scan.pk)
        return Response(ScanSerializer(scan).data)


class GetScan(APIView):
    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def get(self, request, pk):
        expire_stale()
        return Response(ScanSerializer(get_object_or_404(Scan, pk=pk)).data)


class GetDevices(APIView):
    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def get(self, request):
        rows = devices().order_by("ip")
        if state := request.query_params.get("state"):
            if state not in DeviceState.values:
                return notify_error("Unknown state.")
            rows = rows.filter(state=state)
        if network := request.query_params.get("network"):
            try:
                net = IPv4Network(network, strict=False)
            except ValueError:
                return notify_error("An IPv4 network, e.g. 192.168.1.0/24.")
            rows = [d for d in rows if IPv4Address(d.ip) in net]
        return Response(
            DiscoveredDeviceSerializer(
                rows, many=True, context=visible_agents(request)
            ).data
        )


class IgnoreDevice(APIView):
    """Toggles ignored. Optional {"note"}."""

    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def post(self, request, pk):
        device = get_object_or_404(DiscoveredDevice, pk=pk)
        before = {"state": device.state, "note": device.note}
        if device.state == DeviceState.IGNORED:
            agents, netmon = agent_matches(), netmon_matches()
            device.state = matched_state(device.ip, agents, netmon)
            device.agent_id = agents.get(device.ip)
            device.netmon_device_id = netmon.get(device.ip)
            verb = "stopped ignoring"
        else:
            device.state = DeviceState.IGNORED
            verb = "ignored"
        if "note" in request.data:
            device.note = clean(request.data["note"] or "", 255)
        device.save(update_fields=["state", "note", "agent", "netmon_device"])
        audit(
            request,
            AuditActionType.MODIFY,
            f"{request.user.username} {verb} discovered device {device.ip}",
            before=before,
            after={"state": device.state, "note": device.note},
        )
        return Response(
            DiscoveredDeviceSerializer(
                devices().get(pk=pk), context=visible_agents(request)
            ).data
        )


class AddToNetmon(APIView):
    """{"site", "name"} and the other network device fields.

    netmon's serializer checks them. host is the discovered address.
    """

    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def post(self, request, pk):
        if not _has_perm(request, "can_manage_network_devices"):
            raise PermissionDenied()
        device = get_object_or_404(DiscoveredDevice, pk=pk)
        if not isinstance(request.data, dict):
            return notify_error("Send an object with site and name.")
        data = {"ping": True, "tcp_ports": device.open_ports[:8], **request.data}
        data["host"] = device.ip
        serializer = NetworkDeviceSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        if not _has_perm_on_site(request.user, serializer.validated_data["site"].pk):
            raise PermissionDenied()
        if NetworkDevice.objects.count() >= MAX_DEVICES:
            return notify_error(f"The server monitors at most {MAX_DEVICES} devices.")

        # audited as an added network device
        netdev = serializer.save()
        DiscoveredDevice.objects.filter(pk=pk).update(
            state=DeviceState.NETMON, netmon_device=netdev
        )
        return Response({"id": netdev.pk, "name": netdev.name})


class GetNetworks(APIView):
    """Networks this server may scan.

    MAC addresses show up for hosts on an attached network.
    """

    permission_classes = [IsAuthenticated, DiscoveryPerms]

    def get(self, request):
        allowed, _ = probe_scope()
        attached = server_networks()
        return Response(
            {
                "networks": [
                    {
                        "network": str(n),
                        "attached": n in attached,
                        "addresses": n.num_addresses,
                    }
                    for n in sorted(allowed)
                ],
                "max_addresses": MAX_ADDRESSES,
                "max_ports": MAX_PORTS,
                "default_ports": DEFAULT_PORTS,
                "mac_note": "MAC addresses are only known for hosts on an attached network.",
            }
        )

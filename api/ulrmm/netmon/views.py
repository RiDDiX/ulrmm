# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio

from django.core.cache import cache
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm_on_site
from ulrmm.throttles import NetmonTestThrottle

from .models import MAX_DEVICES, NetworkDevice, probe_scope
from .permissions import NetworkDevicePerms
from .probe import probe
from .serializers import NetworkDeviceSerializer


class GetAddNetworkDevices(APIView):
    permission_classes = [IsAuthenticated, NetworkDevicePerms]

    def get(self, request):
        devices = (
            NetworkDevice.objects.filter_by_role(request.user)  # type: ignore
            .select_related("site__client")
            .order_by("site__client__name", "site__name", "name")
        )
        return Response(NetworkDeviceSerializer(devices, many=True).data)

    def post(self, request):
        serializer = NetworkDeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not _has_perm_on_site(request.user, serializer.validated_data["site"].pk):
            raise PermissionDenied()
        if NetworkDevice.objects.count() >= MAX_DEVICES:
            return notify_error(f"The server monitors at most {MAX_DEVICES} devices.")

        device = serializer.save()
        return Response(f"{device.name} was added")


class GetEditDeleteNetworkDevice(APIView):
    permission_classes = [IsAuthenticated, NetworkDevicePerms]

    def get(self, request, pk):
        device = get_object_or_404(NetworkDevice, pk=pk)
        return Response(NetworkDeviceSerializer(device).data)

    def put(self, request, pk):
        device = get_object_or_404(NetworkDevice, pk=pk)
        serializer = NetworkDeviceSerializer(
            instance=device, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        # the permission class checked the current site, this is the new one
        site = serializer.validated_data.get("site", device.site)
        if not _has_perm_on_site(request.user, site.pk):
            raise PermissionDenied()

        serializer.save()
        return Response(f"{device.name} was edited")

    def delete(self, request, pk):
        device = get_object_or_404(NetworkDevice, pk=pk)
        device.delete()
        return Response(f"{device.name} was deleted")


class TestNetworkDevice(APIView):
    permission_classes = [IsAuthenticated, NetworkDevicePerms]
    throttle_classes = [NetmonTestThrottle]

    def post(self, request, pk):
        device = get_object_or_404(NetworkDevice, pk=pk)
        try:
            target = device.probe_target(*probe_scope())
        except ValueError as e:
            return notify_error(str(e))

        lock = f"netmon_test_{device.pk}"
        if not cache.add(lock, request.user.pk, 30):
            return notify_error("This device is being tested already.")
        try:
            AuditLog.objects.create(
                username=request.user.username,
                object_type=AuditObjType.NETWORK_DEVICE,
                action=AuditActionType.CHECK_RUN,
                message=f"{request.user.username} tested {device}",
                debug_info=get_debug_info(),
            )
            result = asyncio.run(probe(target))
        finally:
            cache.delete(lock)

        return Response(result)

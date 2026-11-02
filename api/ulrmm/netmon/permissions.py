# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_site


class NetworkDevicePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            perm = "can_list_network_devices"
        else:
            perm = "can_manage_network_devices"
        if not _has_perm(r, perm):
            return False

        if "pk" in view.kwargs:
            from .models import NetworkDevice

            device = get_object_or_404(NetworkDevice, pk=view.kwargs["pk"])
            return _has_perm_on_site(r.user, device.site_id)
        return True

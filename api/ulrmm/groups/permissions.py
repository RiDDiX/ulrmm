# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm


class GroupPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_list_agents" if r.method == "GET" else "can_manage_device_groups"
        )


class PreviewGroupPerms(permissions.BasePermission):
    # preview is a read of the caller's own agents
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_list_agents")

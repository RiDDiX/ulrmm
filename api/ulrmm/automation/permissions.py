# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import RoleFlagPermission, _has_perm


class AutomationPolicyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r,
            (
                "can_list_automation_policies"
                if r.method == "GET"
                else "can_manage_automation_policies"
            ),
        )


class PatchPolicyPerms(RoleFlagPermission):
    flag = "can_manage_patch_policies"

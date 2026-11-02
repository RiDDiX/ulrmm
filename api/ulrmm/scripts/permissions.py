# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm


class ScriptsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_list_scripts" if r.method == "GET" else "can_manage_scripts"
        )


class TestScriptPerms(permissions.BasePermission):
    # arbitrary code as root or SYSTEM. needs can_manage_scripts or can_send_cmd
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_manage_scripts") or _has_perm(r, "can_send_cmd")

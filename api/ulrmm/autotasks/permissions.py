# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import RoleFlagPermission, _has_perm, _has_perm_on_agent


class AutoTaskPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method != "GET":
            return _has_perm(r, "can_manage_autotasks")
        if not _has_perm(r, "can_list_autotasks"):
            return False
        if "agent_id" in view.kwargs:
            return _has_perm_on_agent(r.user, view.kwargs["agent_id"])
        return True


class RunAutoTaskPerms(RoleFlagPermission):
    flag = "can_run_autotasks"

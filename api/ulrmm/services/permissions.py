# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_agent


class WinSvcsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if not _has_perm(r, "can_manage_winsvcs"):
            return False
        agent_id = view.kwargs.get("agent_id")
        return agent_id is None or _has_perm_on_agent(r.user, agent_id)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_agent


class RecoveryKeyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if "agent_id" in view.kwargs:
            return _has_perm(r, "can_view_recovery_keys") and _has_perm_on_agent(
                r.user, view.kwargs["agent_id"]
            )
        return _has_perm(r, "can_view_recovery_keys")

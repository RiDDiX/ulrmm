# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_agent_or_hidden


def _installer(request) -> bool:
    return getattr(request.user, "is_installer_user", False)


class AuditLogPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return not _installer(r) and _has_perm(r, "can_view_auditlogs")


class DebugLogPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return not _installer(r) and _has_perm(r, "can_view_debuglogs")


class PendingActionPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if _installer(r):
            return False
        if r.method not in permissions.SAFE_METHODS:
            return _has_perm(r, "can_manage_pendingactions")
        if not _has_perm(r, "can_list_pendingactions"):
            return False
        agent_id = view.kwargs.get("agent_id")
        return agent_id is None or _has_perm_on_agent_or_hidden(r.user, agent_id)

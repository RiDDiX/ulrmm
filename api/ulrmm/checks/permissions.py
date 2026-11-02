# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
)


class ChecksPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method not in ("GET", "PATCH"):
            return _has_perm(r, "can_manage_checks")
        if not _has_perm(r, "can_list_checks"):
            return False
        if "agent_id" in view.kwargs:
            return _has_perm_on_agent(r.user, view.kwargs["agent_id"])
        return True


class RunChecksPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        agent_id = view.kwargs["agent_id"]
        return _has_perm(r, "can_run_checks") and _has_perm_on_agent(r.user, agent_id)


class BulkRunChecksPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if not _has_perm(r, "can_run_checks"):
            return False
        target, pk = view.kwargs["target"], view.kwargs["pk"]
        if target == "client":
            return _has_perm_on_client(r.user, pk)
        if target == "site":
            return _has_perm_on_site(r.user, pk)
        return False

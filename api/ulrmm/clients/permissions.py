# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_client, _has_perm_on_site


class ClientsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        pk = view.kwargs.get("pk")
        if r.method == "GET":
            allowed = _has_perm(r, "can_list_clients")
            return allowed and (pk is None or _has_perm_on_client(r.user, pk))
        allowed = _has_perm(r, "can_manage_clients")
        if allowed and pk is not None and r.method in ("PUT", "PATCH", "DELETE"):
            return _has_perm_on_client(r.user, pk, manage=True)
        return allowed


class SitesPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        pk = view.kwargs.get("pk")
        if r.method == "GET":
            allowed = _has_perm(r, "can_list_sites")
            return allowed and (pk is None or _has_perm_on_site(r.user, pk))
        allowed = _has_perm(r, "can_manage_sites")
        if allowed and pk is not None and r.method in ("PUT", "PATCH", "DELETE"):
            return _has_perm_on_site(r.user, pk)
        return allowed


class DeploymentPerms(permissions.BasePermission):
    # the site scope of a deployment is checked by the view
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_list_deployments" if r.method == "GET" else "can_manage_deployments"
        )

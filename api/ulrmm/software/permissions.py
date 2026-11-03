# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import _has_perm, _has_perm_on_agent, _is_restricted


class SoftwarePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        agent_id = view.kwargs.get("agent_id")
        flag = "can_list_software" if r.method == "GET" else "can_manage_software"
        if not _has_perm(r, flag):
            return False
        return agent_id is None or _has_perm_on_agent(r.user, agent_id)


class UninstallSoftwarePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        flags = ("can_manage_software", "can_send_cmd")
        if not all(_has_perm(r, flag) for flag in flags):
            return False
        return _has_perm_on_agent(r.user, view.kwargs["agent_id"])


class DriverPerms(permissions.BasePermission):
    """Installed drivers are inventory, like the software list."""

    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_list_software") and _has_perm_on_agent(
            r.user, view.kwargs["agent_id"]
        )


class CatalogInstallPerms(permissions.BasePermission):
    """Installing a catalog driver is a package install on that agent."""

    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_install_packages") and _has_perm_on_agent(
            r.user, view.kwargs["agent_id"]
        )


class SdioApprovalPerms(permissions.BasePermission):
    """An approval installs on every agent, so it needs an unrestricted role."""

    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_list_software")
        return _has_perm(r, "can_install_packages") and not _is_restricted(r.user)


class BaselinePerms(permissions.BasePermission):
    """Baselines install software on every agent they reach, like packages."""

    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_manage_packages") or _has_perm(
                r, "can_install_packages"
            )
        return _has_perm(r, "can_install_packages")


class AgentBaselinePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        flag = "can_list_software" if r.method == "GET" else "can_install_packages"
        return _has_perm(r, flag) and _has_perm_on_agent(
            r.user, view.kwargs["agent_id"]
        )


class DeploymentBaselinePerms(permissions.BasePermission):
    """What a deployment installs; the site scope is checked in the view."""

    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_list_deployments")
        return _has_perm(r, "can_manage_deployments") and _has_perm(
            r, "can_install_packages"
        )

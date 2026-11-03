# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import (
    RoleFlagPermission,
    _has_install_perm,
    _has_perm,
    _has_perm_on_agent,
)


def _agent_id(view):
    return getattr(view, "kwargs", {}).get("agent_id")


def _flag_and_scope(r, view, flag: str) -> bool:
    """Role flag, plus the agent scope when the URL names an agent."""
    if not _has_perm(r, flag):
        return False
    agent_id = _agent_id(view)
    return agent_id is None or _has_perm_on_agent(r.user, agent_id)


def _flag_on_agent(r, view, flag: str) -> bool:
    """Role flag on a route that must name an agent."""
    agent_id = _agent_id(view)
    if agent_id is None:
        return False
    return _has_perm(r, flag) and _has_perm_on_agent(r.user, agent_id)


class AgentPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _flag_and_scope(r, view, "can_list_agents")
        if r.method == "DELETE":
            return _flag_on_agent(r, view, "can_uninstall_agents")
        # writes without an agent in the URL are refused, not guessed
        return _flag_on_agent(r, view, "can_edit_agent")


class AgentMaintenancePerms(permissions.BasePermission):
    # bulk maintenance toggle: the view limits the agents to the user's scope
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_edit_agent")


class RecoverAgentPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_and_scope(r, view, "can_recover_agents")


class MeshPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_use_mesh")


class UpdateAgentPerms(permissions.BasePermission):
    # the views only touch agents in the user's scope
    def has_permission(self, r, view) -> bool:
        return _has_perm(r, "can_update_agents")


class ManageProcPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_manage_procs")


class EvtLogPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_view_eventlogs")


class SendCMDPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_send_cmd")


class RebootAgentPerms(permissions.BasePermission):
    # reboot, shutdown, suspend and keep awake
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_reboot_agents")


class InstallAgentPerms(RoleFlagPermission):
    flag = "can_install_agents"


class AgentInstallerPerms(permissions.BasePermission):
    message = "Invalid installer token. Please generate a new installer from the RMM"

    def has_permission(self, r, view) -> bool:
        return _has_install_perm(r)


class RunScriptPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_on_agent(r, view, "can_run_scripts")


class AgentNotesPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _flag_and_scope(r, view, "can_list_notes")
        # the views check the scope of the note's agent
        return _has_perm(r, "can_manage_notes")


class RunBulkPerms(RoleFlagPermission):
    flag = "can_run_bulk"


class AgentHistoryPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_and_scope(r, view, "can_list_agent_history")


class AgentWOLPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_and_scope(r, view, "can_send_wol")


class AgentRegistryPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_and_scope(r, view, "can_use_registry")


class AgentTerminalPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _flag_and_scope(r, view, "can_use_terminal")

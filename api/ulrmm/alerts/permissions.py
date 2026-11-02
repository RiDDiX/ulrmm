# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework import permissions

from ulrmm.constants import AlertTemplateActionType
from ulrmm.permissions import _has_perm, _has_perm_on_agent, _has_perm_on_site


def _has_perm_on_alert(user, pk: int) -> bool:
    from alerts.models import Alert

    role = user.get_and_set_role_cache()
    if user.is_superuser or (role and role.is_superuser):
        return True
    if not role:
        return False

    alert = get_object_or_404(
        Alert.objects.select_related("agent", "network_device"), pk=pk
    )
    if alert.network_device and not _has_perm_on_site(
        user, alert.network_device.site_id
    ):
        return False
    # custom alerts carry no agent and are open to every holder of the flag
    if alert.agent is None:
        return True
    return _has_perm_on_agent(user, alert.agent.agent_id)


class AlertPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method in ("GET", "PATCH"):
            allowed = _has_perm(r, "can_list_alerts")
        else:
            allowed = _has_perm(r, "can_manage_alerts")

        if allowed and "pk" in view.kwargs:
            return _has_perm_on_alert(r.user, view.kwargs["pk"])
        return allowed


class AlertTemplatePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_list_alerttemplates")

        if r.method in ("POST", "PUT", "PATCH") and isinstance(r.data, dict):
            kinds = (r.data.get("action_type"), r.data.get("resolved_action_type"))
            if AlertTemplateActionType.SERVER in kinds:
                return _has_perm(r, "can_run_server_scripts") and _has_perm(
                    r, "can_manage_alerttemplates"
                )

        return _has_perm(r, "can_manage_alerttemplates")

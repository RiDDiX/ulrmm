# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import RoleFlagPermission, _has_perm


class CoreSettingsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r,
            "can_view_core_settings" if r.method == "GET" else "can_edit_core_settings",
        )


class GlobalKeyStorePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r,
            (
                "can_view_global_keystore"
                if r.method == "GET"
                else "can_edit_global_keystore"
            ),
        )


class URLActionPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method in ("GET", "PATCH"):
            return _has_perm(r, "can_run_urlactions")
        # the "test" endpoint runs an action a technician is drafting
        if r.method == "POST" and r.path == "/core/urlaction/run/test/":
            return _has_perm(r, "can_run_urlactions")
        # authoring url actions needs the core settings edit right
        return _has_perm(r, "can_edit_core_settings")


class ServerMaintPerms(RoleFlagPermission):
    flag = "can_do_server_maint"


class CustomFieldPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        # PATCH on GetAddCustomFields is a filtered read
        if r.method == "GET" or (
            r.method == "PATCH" and type(view).__name__ == "GetAddCustomFields"
        ):
            return _has_perm(r, "can_view_customfields")
        return _has_perm(r, "can_manage_customfields")


class SchedulePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_view_schedules" if r.method == "GET" else "can_manage_schedules"
        )


class RunServerScriptPerms(RoleFlagPermission):
    flag = "can_run_server_scripts"


class WebTerminalPerms(RoleFlagPermission):
    flag = "can_use_webterm"

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from core.utils import get_core_settings
from ulrmm.permissions import _has_perm


def _names_caller(r) -> bool:
    data = r.data if isinstance(r.data, dict) else {}
    try:
        named = int(data.get("id"))
    except (TypeError, ValueError):
        return False
    return named == r.user.pk


class AccountsPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        reading = r.method == "GET"
        # resetting your own login is open to everyone (the view adds step-up)
        if not reading and getattr(view, "allows_self_service", False):
            if _names_caller(r):
                return True
        return _has_perm(r, "can_list_accounts" if reading else "can_manage_accounts")


class RolesPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_list_roles" if r.method == "GET" else "can_manage_roles"
        )


class APIKeyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return _has_perm(
            r, "can_list_api_keys" if r.method == "GET" else "can_manage_api_keys"
        )


class LocalUserPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return not get_core_settings().block_local_user_logon


class SelfResetSSOPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return not r.user.is_sso_user

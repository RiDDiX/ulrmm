# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import permissions

from ulrmm.permissions import RoleFlagPermission, _has_perm


class PackagePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_manage_packages") or _has_perm(
                r, "can_install_packages"
            )
        return _has_perm(r, "can_manage_packages")


class InstallPackagePerms(RoleFlagPermission):
    flag = "can_install_packages"

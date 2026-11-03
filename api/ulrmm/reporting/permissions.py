# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from types import SimpleNamespace

from rest_framework import permissions

from ulrmm.permissions import _has_perm


def can_manage_reports(user) -> bool:
    return bool(_has_perm(SimpleNamespace(user=user), "can_manage_reports"))


def can_view_reports(user) -> bool:
    return can_manage_reports(user) or bool(
        _has_perm(SimpleNamespace(user=user), "can_view_reports")
    )


class ReportingPerms(permissions.BasePermission):
    """Reading needs view or manage, everything else needs manage."""

    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return can_view_reports(r.user)
        return can_manage_reports(r.user)


class GenerateReportPerms(permissions.BasePermission):
    """Running, exporting and emailing reports needs view or manage."""

    def has_permission(self, r, view) -> bool:
        return can_view_reports(r.user)

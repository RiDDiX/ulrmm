# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework.exceptions import PermissionDenied


class GenericPermsViewMixin:
    """Runs the normal DRF ``initial`` (auth, permissions, throttles) and then
    refuses installer users on the views that mix it in.
    """

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return
        if getattr(user, "is_installer_user", False):
            raise PermissionDenied()

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import threading

from django.conf import settings

from ulrmm.helpers import get_client_ip

# per-thread audit context, stamped onto model saves and audit-log rows
request_local = threading.local()

_admin_url = getattr(settings, "ADMIN_URL", "")

# paths whose traffic never populates the audit context (agent APIs, the audit
# listing itself, logout, installer, schema, SSO token/redirect endpoints)
EXCLUDE_PATHS = (
    *(f"/api/{part}" for part in ("v3", "v4", "schema")),
    *(f"/_allauth/browser/v1/{part}" for part in ("config", "auth/provider/redirect")),
    "/accounts/ssoproviders/token",
    "/agents/installer",
    "/logout",
    "/logs/audit",
    *((f"/{_admin_url}",) if _admin_url else ()),
)


def get_username():
    return getattr(request_local, "username", None)


def get_debug_info():
    return getattr(request_local, "debug_info", None) or {}


def _clear_request_local() -> None:
    # worker threads are reused; never carry a previous request's context over
    for attr in list(vars(request_local)):
        delattr(request_local, attr)


class AuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _clear_request_local()
        try:
            return self.get_response(request)
        finally:
            # also clear on the way out: an ASGI worker thread may next run
            # consumer DB code that would otherwise inherit this context
            _clear_request_local()

    def process_view(self, request, view_func, view_args, view_kwargs):
        if any(request.path.startswith(prefix) for prefix in EXCLUDE_PATHS):
            return None

        # imported lazily: pulling DRF views in at module import time forces the
        # auth classes to resolve before accounts.models finishes loading
        from rest_framework.exceptions import AuthenticationFailed
        from rest_framework.views import APIView

        cls = getattr(view_func, "cls", None)
        try:
            view = cls()
            view.action_map = {}
            drf_request = view.initialize_request(request)
        except (AttributeError, TypeError):
            drf_request = APIView().initialize_request(request)

        try:
            user = drf_request.user
        except AuthenticationFailed:
            return None
        if not (user and user.is_authenticated):
            return None

        # class based views expose the class, plain function views only themselves
        view_name = getattr(view_func, "view_class", view_func).__name__
        request_local.username = user.username
        request_local.debug_info = {
            "url": request.path,
            "method": request.method,
            "view_class": cls.__name__ if cls else None,
            "view_func": view_name,
            "view_args": view_args,
            "view_kwargs": view_kwargs,
            "ip": getattr(request, "_client_ip", None),
        }
        return None

    @staticmethod
    def _forget():
        request_local.debug_info = request_local.username = None

    def process_exception(self, request, exception):
        self._forget()

    def process_template_response(self, request, response):
        self._forget()
        return response


class LogIPMiddleware:
    """Stores the resolved client address as request._client_ip for later layers."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = get_client_ip(request.META)
        request._client_ip = client_ip
        return self.get_response(request)

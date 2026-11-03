# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import secrets
from functools import wraps

from django.conf import settings
from django.http import HttpResponse


def _text(message: str, status: int) -> HttpResponse:
    return HttpResponse(message, status=status, content_type="text/plain")


def monitoring_view(view_func):
    """Token auth for the deprecated v1 monitoring endpoint (POST, token in body)."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method != "POST":
            return _text("Invalid request type\n", 400)

        try:
            data = json.loads(request.body)
        except (ValueError, TypeError):
            return _text("Invalid json\n", 400)

        if not isinstance(data, dict) or "auth" not in data:
            return _text("Invalid payload\n", 400)

        token = getattr(settings, "MON_TOKEN", "") or ""
        if not token:
            return _text("Missing token\n", 401)

        auth = data["auth"]
        if not isinstance(auth, str) or not secrets.compare_digest(
            auth.encode("utf-8"), token.encode("utf-8")
        ):
            return _text("Not authenticated\n", 401)

        return view_func(request, *args, **kwargs)

    return wrapper


def monitoring_view_v2(view_func):
    """Token auth for the v2 monitoring endpoint (GET, token in X-Mon-Token)."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method != "GET":
            return _text("Invalid request type\n", 400)

        header = request.META.get("HTTP_X_MON_TOKEN")
        if not header:
            return _text("Missing X-Mon-Token header\n", 401)

        token = getattr(settings, "MON_TOKEN", "") or ""
        if not token:
            return _text("Missing mon token\n", 401)

        try:
            ok = secrets.compare_digest(header.encode("utf-8"), token.encode("utf-8"))
        except (UnicodeError, AttributeError):
            ok = False
        if not ok:
            return _text("Not authenticated\n", 401)

        return view_func(request, *args, **kwargs)

    return wrapper

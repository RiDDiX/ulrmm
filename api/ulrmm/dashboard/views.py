# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid

from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from groups.models import DeviceGroup
from ulrmm.helpers import notify_error

from .widgets import WIDGETS, allowed, clean_settings, query_settings

MAX_WIDGETS = 24
SIZES = ("s", "m", "l")
KEYS = {"id", "type", "size", "settings"}

DEFAULT = (
    ("be765a48-3e3a-4b24-afd3-dffc5f030fd4", "fleet", "m"),
    ("c12ffc27-6cc1-4c74-8f3e-d12f85c2c67b", "alerts", "m"),
    ("eb25ec6b-57a5-4660-b5ea-fe0eddc1afb2", "offline", "m"),
    ("a28b2adb-909c-497e-b084-47ab89c4f2cc", "patches", "s"),
    ("d6a7fec9-6c59-4817-ba8e-ad62b901286e", "activity", "l"),
)


def _uuid4(value) -> bool:
    try:
        u = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return u.version == 4 and str(u) == value


def _widget(w, seen: set) -> dict:
    if not isinstance(w, dict):
        raise ValidationError("must be an object")
    if unknown := sorted(set(w) - KEYS):
        raise ValidationError(f"unknown keys: {', '.join(unknown)}")
    if missing := sorted(KEYS - {"settings"} - set(w)):
        raise ValidationError(f"missing: {', '.join(missing)}")
    if not _uuid4(w["id"]):
        raise ValidationError("id must be a UUID4 string")
    if w["id"] in seen:
        raise ValidationError("duplicate id")
    if not isinstance(w["type"], str) or w["type"] not in WIDGETS:
        raise ValidationError(f"type must be one of {', '.join(WIDGETS)}")
    if w["size"] not in SIZES:
        raise ValidationError(f"size must be one of {', '.join(SIZES)}")
    settings = clean_settings(w["type"], w.get("settings", {}))
    seen.add(w["id"])
    return {"id": w["id"], "type": w["type"], "size": w["size"], "settings": settings}


def clean_layout(data) -> dict:
    if not isinstance(data, dict) or set(data) != {"widgets"}:
        raise ValidationError('The layout is {"widgets": [...]}.')
    widgets = data["widgets"]
    if not isinstance(widgets, list):
        raise ValidationError("widgets must be a list")
    if len(widgets) > MAX_WIDGETS:
        raise ValidationError(f"At most {MAX_WIDGETS} widgets.")

    out, seen = [], set()
    for n, w in enumerate(widgets, 1):
        try:
            out.append(_widget(w, seen))
        except ValidationError as e:
            raise ValidationError(f"Widget {n}: {e.detail[0]}")

    wanted = {pk for w in out for pk in w["settings"].get("group_ids", ())}
    if wanted:
        known = set(
            DeviceGroup.objects.filter(pk__in=wanted).values_list("pk", flat=True)
        )
        if missing := sorted(wanted - known):
            raise ValidationError(
                f"Unknown device groups: {', '.join(map(str, missing))}"
            )
    return {"widgets": out}


def default_layout(request) -> dict:
    return {
        "widgets": [
            {"id": i, "type": t, "size": s, "settings": clean_settings(t, {})}
            for i, t, s in DEFAULT
            if allowed(request, t)
        ]
    }


class Layout(APIView):
    """Overview layout stored on the signed-in user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_installer_user:
            raise PermissionDenied()
        stored = request.user.dashboard_layout
        if isinstance(stored, dict) and "widgets" in stored:
            return Response(stored)
        return Response(default_layout(request))

    def put(self, request):
        if request.user.is_installer_user:
            raise PermissionDenied()
        try:
            layout = clean_layout(request.data)
        except ValidationError as e:
            return notify_error(e.detail[0])
        # personal preference, stored with the UI settings. no audit row
        User.objects.filter(pk=request.user.pk).update(dashboard_layout=layout)
        request.user.dashboard_layout = layout
        return Response(layout)

    def delete(self, request):
        # drop the saved layout and return the role default the web renders
        if request.user.is_installer_user:
            raise PermissionDenied()
        User.objects.filter(pk=request.user.pk).update(dashboard_layout={})
        request.user.dashboard_layout = {}
        return Response(default_layout(request))


class WidgetData(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, kind):
        if kind not in WIDGETS:
            raise NotFound()
        if not allowed(request, kind):
            raise PermissionDenied()
        try:
            settings = clean_settings(kind, query_settings(kind, request.query_params))
        except ValidationError as e:
            return notify_error(e.detail[0])
        data = WIDGETS[kind][2](request, settings)
        return data if isinstance(data, Response) else Response(data)

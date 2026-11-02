# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework import generics, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ulrmm.permissions import _has_perm

from . import dispatch, senders
from .models import Channel, Notification, Route
from .serializers import ChannelSerializer, NotificationSerializer, RouteSerializer

HISTORY = 200


class NotifyPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET" and _has_perm(r, "can_view_core_settings"):
            return True
        return _has_perm(r, "can_manage_notifications")


class Channels(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated, NotifyPerms]
    queryset = Channel.objects.order_by("name", "pk")
    serializer_class = ChannelSerializer


class ChannelDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, NotifyPerms]
    queryset = Channel.objects.all()
    serializer_class = ChannelSerializer


class TestChannel(APIView):
    permission_classes = [IsAuthenticated, NotifyPerms]

    def post(self, request, pk):
        channel = get_object_or_404(Channel, pk=pk)
        now = djangotime.now()
        n = {
            "source": "test",
            "severity": "info",
            "title": "Test notification",
            "body": f"Sent by {request.user.username} from the notification settings.",
            "alert": None,
            "agent_id": None,
            "escalation_level": 0,
        }
        try:
            dispatch.send(channel, n)
        except Exception as e:
            error = str(e) if isinstance(e, senders.SendError) else type(e).__name__
            Channel.objects.filter(pk=pk).update(last_error=error[:500])
            return Response({"ok": False, "error": error})
        Channel.objects.filter(pk=pk).update(last_sent=now, last_error="")
        return Response({"ok": True, "error": ""})


class Routes(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated, NotifyPerms]
    queryset = Route.objects.prefetch_related("channels", "escalate_to").order_by(
        "name", "pk"
    )
    serializer_class = RouteSerializer


class RouteDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, NotifyPerms]
    queryset = Route.objects.all()
    serializer_class = RouteSerializer


class Notifications(APIView):
    permission_classes = [IsAuthenticated, NotifyPerms]

    def get(self, request):
        rows = Notification.objects.select_related("channel", "route")
        if source := request.query_params.get("source"):
            rows = rows.filter(source=source)
        if (alert := request.query_params.get("alert", "")).isdigit():
            rows = rows.filter(alert_id=int(alert))
        return Response(
            NotificationSerializer(rows.order_by("-pk")[:HISTORY], many=True).data
        )

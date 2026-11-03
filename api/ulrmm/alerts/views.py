# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from collections.abc import Mapping
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.utils import SERVER_SCRIPT_STEPUP, stepup_denied
from ulrmm.constants import AlertTemplateActionType
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm, _has_perm_on_agent

from .models import Alert, AlertTemplate
from .permissions import AlertPerms, AlertTemplatePerms
from .serializers import (
    AlertSerializer,
    AlertTemplateRelationSerializer,
    AlertTemplateSerializer,
)
from .tasks import cache_agents_alert_template

INVALID = "The request was invalid"
OPEN_ALERT_EXISTS = "There is already an open alert for this check or task"
TOP_MAX = 500
SNOOZE_DAYS_MAX = 3650
BULK_MAX = 5000
# without a time window the list stops at the newest rows
LIST_CAP = 5000
FILTER_KEYS = tuple(
    f"{name}Filter"
    for name in ("time", "client", "severity", "resolved", "snoozed", "agent")
)


def _recache_templates():
    # every template write refreshes the per-agent template cache
    cache_agents_alert_template.delay()
    return Response("ok")


def _store_template(serializer):
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return _recache_templates()


class _AlertListQuery(serializers.Serializer):
    top = serializers.IntegerField(required=False)
    timeFilter = serializers.IntegerField(required=False, min_value=0)
    clientFilter = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    severityFilter = serializers.ListField(
        child=serializers.CharField(max_length=30), required=False
    )
    resolvedFilter = serializers.BooleanField(required=False)
    snoozedFilter = serializers.BooleanField(required=False)
    agentFilter = serializers.CharField(max_length=200, required=False)


class _BulkAlertAction(serializers.Serializer):
    bulk_action = serializers.ChoiceField(choices=("resolve", "snooze"))
    alerts = serializers.ListField(
        child=serializers.IntegerField(), max_length=BULK_MAX
    )
    snooze_days = serializers.IntegerField(
        required=False, min_value=1, max_value=SNOOZE_DAYS_MAX
    )


def _snooze_days(value):
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    return days if 1 <= days <= SNOOZE_DAYS_MAX else None


def _template_context(request) -> dict:
    return {"reveal_env_vars": _has_perm(request, "can_manage_alerttemplates")}


def _server_action_stepup(request):
    # the server script rule: a dashboard session confirms with two-factor,
    # an API key is refused. Every real credential sets request.auth; only
    # in-process callers without one (force_authenticate) pass.
    if request.auth is None:
        return None
    return stepup_denied(request, SERVER_SCRIPT_STEPUP)


class GetAddAlerts(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    def patch(self, request):
        if not isinstance(request.data, Mapping):
            return notify_error(INVALID)
        query = _AlertListQuery(data=request.data)
        if not query.is_valid():
            return notify_error(INVALID)
        given = {k: v for k, v in query.validated_data.items() if k in request.data}

        alerts = Alert.objects.filter_by_role(request.user).filter(hidden=False)

        if "top" in given:
            top = min(max(given["top"], 1), TOP_MAX)
            active = alerts.filter(resolved=False, snoozed=False)
            return Response(
                {
                    "alerts_count": active.count(),
                    "alerts": AlertSerializer(
                        active.order_by("alert_time", "pk")[:top], many=True
                    ).data,
                }
            )

        if any(key in given for key in FILTER_KEYS):
            # a true flag means "include them", a false one filters them out
            if "snoozedFilter" in given and not given["snoozedFilter"]:
                alerts = alerts.filter(snoozed=False)
            if "resolvedFilter" in given and not given["resolvedFilter"]:
                alerts = alerts.filter(resolved=False)
            if "clientFilter" in given:
                clients = given["clientFilter"]
                alerts = alerts.filter(
                    Q(agent__site__client_id__in=clients)
                    | Q(network_device__site__client_id__in=clients)
                )
            if "severityFilter" in given:
                alerts = alerts.filter(severity__in=given["severityFilter"])
            if "agentFilter" in given:
                alerts = alerts.filter(agent__agent_id=given["agentFilter"])

        alerts = alerts.order_by("-alert_time", "-pk")
        days = given.get("timeFilter")
        if days:
            now = djangotime.now()
            alerts = alerts.filter(
                alert_time__lte=now, alert_time__gt=now - timedelta(days=days)
            )
        else:
            alerts = alerts[:LIST_CAP]

        return Response(AlertSerializer(alerts, many=True).data)

    def post(self, request):
        new_alert = AlertSerializer(data=request.data, partial=True)
        new_alert.is_valid(raise_exception=True)

        target = new_alert.validated_data.get("agent")
        if target is not None and not _has_perm_on_agent(request.user, target.agent_id):
            raise PermissionDenied()

        new_alert.save()
        return Response("ok")


class GetUpdateDeleteAlert(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    def get(self, request, pk):
        return Response(AlertSerializer(get_object_or_404(Alert, pk=pk)).data)

    def put(self, request, pk):
        data, alert = request.data, get_object_or_404(Alert, pk=pk)
        if not isinstance(data, Mapping):
            return notify_error(INVALID)

        if "type" not in data:
            edit = AlertSerializer(alert, data=data, partial=True)
            edit.is_valid(raise_exception=True)
            try:
                with transaction.atomic():
                    edit.save()
            except IntegrityError:
                return notify_error(OPEN_ALERT_EXISTS)
            return Response("ok")

        now = djangotime.now()
        if data["type"] == "resolve":
            alert.resolved = True
            alert.resolved_on = now
            alert.snoozed = False
            alert.snooze_until = None
        elif data["type"] == "snooze":
            if "snooze_days" not in data:
                return notify_error(
                    "Missing 'snoozed_days' when trying to snooze alert"
                )
            days = _snooze_days(data["snooze_days"])
            if days is None:
                return notify_error(
                    f"snooze_days must be a whole number from 1 to {SNOOZE_DAYS_MAX}"
                )
            alert.snoozed = True
            alert.snooze_until = now + timedelta(days=days)
        elif data["type"] == "unsnooze":
            alert.snoozed = False
            alert.snooze_until = None
        else:
            return notify_error("There was an error in the request data")

        alert.save(update_fields=["resolved", "resolved_on", "snoozed", "snooze_until"])
        return Response("ok")

    def delete(self, request, pk):
        get_object_or_404(Alert, pk=pk).delete()
        return Response("ok")


class BulkAlerts(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    def post(self, request):
        serializer = _BulkAlertAction(data=request.data)
        if not serializer.is_valid():
            return notify_error(INVALID)
        data = serializer.validated_data

        alerts = Alert.objects.filter_by_role(request.user).filter(
            id__in=data["alerts"]
        )
        now = djangotime.now()
        if data["bulk_action"] == "resolve":
            alerts.update(
                resolved=True, resolved_on=now, snoozed=False, snooze_until=None
            )
        elif "snooze_days" in data:
            alerts.update(
                snoozed=True, snooze_until=now + timedelta(days=data["snooze_days"])
            )
        else:
            return notify_error(INVALID)

        return Response("ok")


class GetAddAlertTemplates(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    def get(self, request):
        templates = AlertTemplate.objects.select_related(
            "action", "action_rest", "resolved_action", "resolved_action_rest"
        )
        return Response(
            AlertTemplateSerializer(
                templates, many=True, context=_template_context(request)
            ).data
        )

    def post(self, request):
        data = request.data
        if isinstance(data, Mapping) and AlertTemplateActionType.SERVER in (
            data.get("action_type"),
            data.get("resolved_action_type"),
        ):
            if denied := _server_action_stepup(request):
                return denied

        return _store_template(
            AlertTemplateSerializer(data=data, context=_template_context(request))
        )


class GetUpdateDeleteAlertTemplate(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    def get(self, request, pk):
        found = get_object_or_404(AlertTemplate, pk=pk)
        return Response(
            AlertTemplateSerializer(found, context=_template_context(request)).data
        )

    def put(self, request, pk):
        template = get_object_or_404(AlertTemplate, pk=pk)
        data = request.data
        if not isinstance(data, Mapping):
            return notify_error(INVALID)

        # the stored kind counts when the body leaves it out
        kinds = (
            data.get("action_type", template.action_type),
            data.get("resolved_action_type", template.resolved_action_type),
        )
        if AlertTemplateActionType.SERVER in kinds:
            if not _has_perm(request, "can_run_server_scripts"):
                raise PermissionDenied()
            if denied := _server_action_stepup(request):
                return denied

        return _store_template(
            AlertTemplateSerializer(
                template, data=data, partial=True, context=_template_context(request)
            )
        )

    def delete(self, request, pk):
        get_object_or_404(AlertTemplate, pk=pk).delete()
        return _recache_templates()


class RelatedAlertTemplate(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    def get(self, request, pk):
        relations = AlertTemplateRelationSerializer(
            get_object_or_404(AlertTemplate, pk=pk), context=_template_context(request)
        )
        return Response(relations.data)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Import from another RMM. Superusers only: an import writes clients,
sites, scripts, keystore entries, policies, roles and users for everyone."""

import json

from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import DELETE_NEEDS_TOTP, has_superuser_rights, verify_fresh_totp
from accounts.views import _body
from ulrmm.helpers import notify_error

from . import engine, link, removal
from .models import ImportedDevice, ImportSource, MigrateState, SourceKind
from .sources import source_class
from .tasks import fetch_task, migrate_task

URL_RE = r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$"
MAX_DEVICES = 20000


class ImportPerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        return has_superuser_rights(r.user)


def _secrets(source) -> dict:
    try:
        return json.loads(source.secret) if source.secret else {}
    except ValueError:
        return {}


class SourceSerializer(serializers.ModelSerializer):
    url = serializers.RegexField(
        URL_RE,
        max_length=255,
        error_messages={"invalid": "https://host[:port][/path]"},
    )
    name = serializers.CharField(max_length=100)
    options = serializers.DictField(
        child=serializers.CharField(max_length=255, allow_blank=True),
        required=False,
    )
    # write-only: a missing or blank key keeps the stored one, null deletes it
    secrets = serializers.DictField(
        child=serializers.CharField(
            max_length=4096, allow_blank=True, allow_null=True, trim_whitespace=False
        ),
        write_only=True,
        required=False,
    )

    class Meta:
        model = ImportSource
        fields = (
            "id",
            "kind",
            "name",
            "url",
            "verify_tls",
            "options",
            "secrets",
            "last_fetch",
            "last_import",
            "last_error",
        )
        read_only_fields = ("last_fetch", "last_import", "last_error")

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        cls = source_class(instance.kind)
        stored = _secrets(instance)
        ret["secrets_set"] = [k for k in cls.SECRETS if stored.get(k)]
        ret["secret_names"] = list(cls.SECRETS)
        ret["push_plats"] = list(cls.PUSH_PLATS)
        ret["parts"] = list(cls.PARTS)
        ret["removes_agent"] = cls.REMOVES
        return ret

    def validate_kind(self, value):
        if self.instance and value != self.instance.kind:
            raise ValidationError("The kind of a source cannot change.")
        return value

    def validate(self, attrs):
        inst = self.instance
        kind = attrs.get("kind") or (inst and inst.kind)
        if kind not in SourceKind.values:
            raise ValidationError({"kind": "Choose a source."})
        names = source_class(kind).SECRETS
        stored = _secrets(inst) if inst else {}
        given = attrs.pop("secrets", {})
        unknown = set(given) - set(names)
        if unknown:
            raise ValidationError({"secrets": f"unknown: {', '.join(sorted(unknown))}"})
        if inst and "url" in attrs and attrs["url"].rstrip("/") != inst.url.rstrip("/"):
            # stored secrets never follow the address to another host
            kept = [k for k in names if stored.get(k) and not given.get(k)]
            if kept:
                raise ValidationError(
                    {"secrets": f"The address changed, enter {', '.join(kept)} again."}
                )
        for k, v in given.items():
            if v is None:
                stored.pop(k, None)
            elif v:
                stored[k] = v
        attrs["secret"] = json.dumps(stored) if stored else ""
        return attrs


class Sources(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def get(self, request):
        return Response(
            SourceSerializer(ImportSource.objects.order_by("pk"), many=True).data
        )

    def post(self, request):
        s = SourceSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(SourceSerializer(s.save()).data, status=201)


class SourceDetail(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def get(self, request, pk):
        return Response(SourceSerializer(get_object_or_404(ImportSource, pk=pk)).data)

    def put(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        s = SourceSerializer(source, data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        return Response(SourceSerializer(s.save()).data)

    def delete(self, request, pk):
        get_object_or_404(ImportSource, pk=pk).delete()
        return Response("The source was deleted")


class Fetch(APIView):
    """Reads the source in the background; poll the source for last_fetch."""

    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        fetch_task.delay(source.pk)
        return Response({"queued": True}, status=202)


class Plan(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def get(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        if not source.last_fetch:
            return notify_error("Read the source first.")
        return Response(engine.plan(source))


class Import(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        parts = _body(request).get("parts")
        if (
            not isinstance(parts, list)
            or not parts
            or any(p not in engine.PARTS for p in parts)
        ):
            return notify_error(f"parts: a list of {', '.join(engine.PARTS)}")
        if not source.last_fetch:
            return notify_error("Read the source first.")
        return Response(engine.run(source, parts, request.user.username))


class Devices(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def get(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        rows = source.devices.select_related("site__client", "agent").order_by(
            "site__client__name", "site__name", "hostname"
        )[:MAX_DEVICES]
        return Response(
            [
                {
                    "id": d.pk,
                    "hostname": d.hostname,
                    "plat": d.plat,
                    "os_name": d.os_name,
                    "monitoring_type": d.monitoring_type,
                    "client": d.site.client.name if d.site else "",
                    "site": d.site.name if d.site else "",
                    "agent_id": d.agent.agent_id if d.agent else None,
                    "migrate_state": d.migrate_state,
                    "migrate_error": d.migrate_error,
                    "sent_at": d.sent_at,
                    "remove_requested_at": d.remove_requested_at,
                    "remove_state": d.remove_state,
                    "remove_at": d.remove_at,
                    "remove_reason": d.remove_reason,
                    "recovery": d.recovery,
                    # device-level objects the link step could not take
                    "link_skipped": (d.data or {}).get("link_skipped", []),
                }
                for d in rows
            ]
        )


class Link(APIView):
    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        return Response({"linked": link.link_source(source)})


def _ids(request):
    ids = _body(request).get("devices")
    if (
        not isinstance(ids, list)
        or not ids
        or len(ids) > MAX_DEVICES
        or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids)
    ):
        return None
    return ids


def _can_remove(source):
    if not source_class(source.kind).REMOVES:
        return notify_error(
            f"{source.get_kind_display()} cannot remove its agent from a device."
        )
    return None


def _source_ids(source, ids) -> list[int]:
    return list(
        ImportedDevice.objects.filter(source=source, pk__in=ids).values_list(
            "pk", flat=True
        )
    )


class Migrate(APIView):
    """Sends the installer to the given devices in the background. With
    remove_old the old agent is removed later, see removal.py."""

    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        ids = _ids(request)
        if ids is None:
            return notify_error("devices: a list of device ids")
        remove_old = _body(request).get("remove_old", False)
        if not isinstance(remove_old, bool):
            return notify_error("remove_old: true or false")
        if remove_old and (refused := _can_remove(source)):
            return refused
        cls = source_class(source.kind)
        if not cls.PUSH_PLATS:
            return notify_error(
                f"{source.get_kind_display()} cannot run commands on its devices. "
                "Install the agent with a deployment; it links on enrollment."
            )
        # single use, so checked after every other refusal
        if remove_old and not verify_fresh_totp(
            request.user, _body(request).get("totp_code")
        ):
            return notify_error(DELETE_NEEDS_TOTP)
        ids = _source_ids(source, ids)
        # queued: the state comes back once the device was handled
        ImportedDevice.objects.filter(pk__in=ids, agent=None).update(
            migrate_state=MigrateState.NONE, migrate_error=""
        )
        requested = (
            removal.request(source, ids, request.user.username) if remove_old else 0
        )
        migrate_task.delay(source.pk, ids)
        return Response({"queued": len(ids), "remove_requested": requested}, status=202)


class Remove(APIView):
    """Asks for the removal of the old agent without sending an installer,
    for devices whose agent was installed another way."""

    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        ids = _ids(request)
        if ids is None:
            return notify_error("devices: a list of device ids")
        if refused := _can_remove(source):
            return refused
        if not verify_fresh_totp(request.user, _body(request).get("totp_code")):
            return notify_error(DELETE_NEEDS_TOTP)
        ids = _source_ids(source, ids)
        return Response(
            {"remove_requested": removal.request(source, ids, request.user.username)}
        )


class Withdraw(APIView):
    """Withdraws the removal of the old agent where it was not sent yet."""

    permission_classes = [IsAuthenticated, ImportPerms]

    def post(self, request, pk):
        source = get_object_or_404(ImportSource, pk=pk)
        ids = _ids(request)
        if ids is None:
            return notify_error("devices: a list of device ids")
        return Response(
            {"withdrawn": removal.withdraw(source, ids, request.user.username)}
        )

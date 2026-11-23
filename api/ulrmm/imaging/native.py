# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import secrets
from datetime import timedelta

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from apiv3.views import AgentTokenView, _token_agent
from .models import (
    LINUX_FILES_METHOD,
    LINUX_OFFLINE_METHOD,
    METHODS,
    MODE_CHANGED,
    VOLUME_KINDS,
    NativeInventory,
    Image,
    ImageStatus,
    Profile,
    Transfer,
)
from .service import agent_allowed, audit, origin, set_status
from .storage import NO_SPACE, OTHER_STORE
from .views import RENEW_LIMIT, _grant_response, _token_digest

FAILURES = {
    "network": "Waiting for the permitted imaging network.",
    "capture": "Native capture failed preflight or could not complete. Check the local agent imaging log.",
    "upload": "Upload paused. Check backup storage and network availability.",
}


class VolumeSerializer(serializers.Serializer):
    id = serializers.CharField(max_length=300, allow_blank=True)
    mount = serializers.CharField(
        max_length=255, allow_blank=True, trim_whitespace=False
    )
    fs = serializers.CharField(max_length=32, allow_blank=True)
    kind = serializers.ChoiceField(choices=VOLUME_KINDS)
    disk = serializers.CharField(max_length=255, allow_blank=True)
    size = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    used = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    consistency = serializers.ChoiceField(
        choices=("", "live", "lvm-snapshot", "btrfs-snapshot")
    )
    reason = serializers.CharField(max_length=255, allow_blank=True)


class CapabilitySerializer(serializers.Serializer):
    method = serializers.CharField(max_length=64, allow_blank=True)
    ready = serializers.BooleanField()
    scope = serializers.CharField(max_length=2048, allow_blank=True)
    recovery = serializers.CharField(max_length=2048, allow_blank=True)
    reason = serializers.CharField(max_length=2048, allow_blank=True)
    encryption = serializers.CharField(max_length=512, allow_blank=True)
    source_id = serializers.CharField(max_length=255, allow_blank=True)
    device_uuid = serializers.CharField(max_length=36, allow_blank=True)
    boot_mode = serializers.CharField(max_length=32, allow_blank=True)
    size = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    sector_size = serializers.IntegerField(min_value=0, max_value=65536)
    volumes = VolumeSerializer(many=True, required=False, default=list, max_length=64)
    min_target_size = serializers.IntegerField(
        min_value=0, max_value=2**63 - 1, required=False, default=0
    )

    def validate(self, data):
        if data["device_uuid"]:
            uuid = serializers.UUIDField().run_validation(data["device_uuid"])
            if uuid.int in (0, 2**128 - 1):
                raise serializers.ValidationError("The device UUID is a placeholder.")
            data["device_uuid"] = str(uuid)
        ids = [
            v["id"]
            for v in data["volumes"]
            if v["id"] and v["kind"] in ("system", "extra", "unmounted")
        ]
        if len(ids) != len(set(ids)):
            raise serializers.ValidationError("Volume IDs must be unique.")
        if data["ready"] and (
            not all(
                data[k]
                for k in (
                    "method",
                    "source_id",
                    "device_uuid",
                    "size",
                    "sector_size",
                    "scope",
                    "recovery",
                )
            )
            or (
                data["method"] == LINUX_FILES_METHOD
                and not (
                    any(v["kind"] == "system" for v in data["volumes"])
                    and 0 < data["min_target_size"] <= data["size"]
                )
            )
        ):
            raise serializers.ValidationError(
                "A ready provider must identify its source and recovery procedure."
            )
        return data


def _fail(agent, image, reason):
    # A point that can never be claimed would block every later scheduled run.
    image.parts.all().delete()
    set_status(image, ImageStatus.FAILED, reason)
    audit(agent, "imaging", f"Image {image.id} failed: {reason}")
    return Response(status=204)


class NativePoll(AgentTokenView):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not request.is_secure():
            raise PermissionDenied(
                "Native imaging requires an authenticated HTTPS control channel."
            )

    def get(self, request, agentid):
        agent = _token_agent(request, agentid)
        point = serializers.UUIDField().run_validation(
            request.query_params.get("point")
        )
        image = (
            Image.objects.filter(pk=point, agent=agent, native__isnull=False)
            .values("status")
            .first()
        )
        return Response(image, status=200 if image else 404)

    @transaction.atomic
    def post(self, request, agentid):
        agent = _token_agent(request, agentid)
        if not isinstance(request.data, dict):
            raise serializers.ValidationError("Expected an imaging capability report.")
        serializer = CapabilitySerializer(data=request.data.get("capability"))
        serializer.is_valid(raise_exception=True)
        cap = serializer.validated_data
        if cap["method"] and cap["method"] not in METHODS.get(agent.plat, ()):
            raise serializers.ValidationError(
                "The capture method belongs to a different platform."
            )
        NativeInventory.objects.update_or_create(
            agent=agent, defaults={"capability": cap}
        )
        image = (
            Image.objects.select_for_update()
            .filter(
                agent=agent,
                native__isnull=False,
                status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING),
            )
            .first()
        )
        if not image:
            return Response(status=204)
        allowed = image.operator_id and agent_allowed(
            image.operator, agent, "can_manage_images"
        )
        # An offline Linux point is claimed by its rescue pairing, not the operator.
        if not allowed and image.native.get("method") != LINUX_OFFLINE_METHOD:
            return _fail(
                agent,
                image,
                "The backup operator no longer has imaging access. Save the imaging configuration again.",
            )
        profile = Profile.objects.filter(agent=agent).first()
        if not profile or profile.network_mode != image.network_mode:
            return _fail(agent, image, MODE_CHANGED)
        failure = request.data.get("failure")
        if failure:
            if (
                request.data.get("image_id") == str(image.id)
                and isinstance(failure, str)
                and failure in FAILURES
                and Transfer.objects.filter(
                    image=image,
                    direction="capture",
                    id=serializers.UUIDField().run_validation(
                        request.data.get("claim")
                    ),
                    expires_at__gt=timezone.now(),
                ).update(expires_at=timezone.now())
            ):
                if image.reason not in (NO_SPACE, OTHER_STORE):
                    reason = FAILURES[failure]
                    if failure == "upload" and image.network_mode == "internal":
                        reason = "Upload paused. Waiting for the permitted internal network and storage."
                    set_status(image, image.status, reason)
            return Response(status=204)
        if not cap["ready"] or not origin(image.network_mode):
            reason = cap["reason"] or "Waiting for the configured HTTPS imaging origin."
            if image.reason != reason[:255]:
                set_status(image, image.status, reason[:255])
            return Response(status=204)
        if any(
            image.native.get(k) != cap[k]
            for k in (
                "method",
                "device_uuid",
                "source_id",
                "size",
                "sector_size",
                "boot_mode",
                "encryption",
                "scope",
            )
        ):
            return _fail(
                agent,
                image,
                "The backup source changed. Review the capability and request a new capture.",
            )
        current = {v["id"]: v for v in cap["volumes"]}
        queued = {v["id"]: v for v in image.native.get("volumes", [])}
        for vid in image.native.get("include", []):
            mount = queued.get(vid, {}).get("mount", vid)
            v = current.get(vid)
            if not v or v["kind"] not in ("system", "extra") or v["mount"] != mount:
                return _fail(
                    agent, image, f"Selected volume {mount} is not mounted."[:255]
                )
        now = timezone.now()
        active = Transfer.objects.filter(
            image=image, direction="capture", expires_at__gt=now
        )
        # Native snapshots can take a long time before the first byte. After
        # upload begins, each committed block renews the claim's activity.
        idle_limit = (
            timedelta(minutes=5)
            if image.status == ImageStatus.UPLOADING
            else timedelta(hours=1)
        )
        if not allowed or (active.exists() and image.updated_at > now - idle_limit):
            return Response(status=204)
        active.update(expires_at=now)
        set_status(image, image.status, "Native agent is preparing the backup source.")
        secret = secrets.token_urlsafe(32)
        grant = Transfer.objects.create(
            image=image,
            target=agent,
            user=image.operator,
            direction="capture",
            device_uuid=cap["device_uuid"],
            disk_id=cap["source_id"],
            token_digest=_token_digest(secret),
            expires_at=now + timedelta(hours=24),
            renew_until=now + RENEW_LIMIT,
        )
        audit(agent, image.operator.username, f"Native agent claimed image {image.id}.")
        return _grant_response(grant, secret, status=200, image_id=str(image.id))

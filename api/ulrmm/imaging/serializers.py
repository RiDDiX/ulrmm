# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import posixpath
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from rest_framework import serializers

from .models import Image, Profile
from .storage import DESTINATION


class ProfileSerializer(serializers.ModelSerializer):
    destination = serializers.RegexField(DESTINATION)
    compression = serializers.ChoiceField(choices=("none", "gzip"))
    compression_level = serializers.IntegerField(min_value=0, max_value=9)
    network_mode = serializers.ChoiceField(choices=("internal", "internet"))
    schedule_time = serializers.TimeField(
        format="%H:%M", input_formats=["%H:%M"], allow_null=True
    )
    keep_last = serializers.IntegerField(min_value=0, max_value=365, default=0)
    volumes = serializers.ListField(
        child=serializers.CharField(max_length=255, trim_whitespace=False),
        max_length=32,
        default=list,
    )

    class Meta:
        model = Profile
        fields = (
            "destination",
            "compression",
            "compression_level",
            "network_mode",
            "schedule_time",
            "timezone",
            "next_run",
            "keep_last",
            "volumes",
        )
        read_only_fields = ("next_run",)

    def validate_volumes(self, value):
        if len(set(value)) != len(value) or not all(
            re.fullmatch(r"[A-Z]:", s)
            or (
                s.startswith("/")
                and s != "/"
                and posixpath.normpath(s) == s
                and not re.search(r"[\x00-\x1f\x7f-\x9f]", s)
            )
            for s in value
        ):
            raise serializers.ValidationError(
                "Use absolute mount paths such as /media/data or drive letters such as D:."
            )
        return value

    def validate_timezone(self, value):
        try:
            ZoneInfo(value)
        except (ValueError, ZoneInfoNotFoundError) as error:
            raise serializers.ValidationError("Use an IANA time zone.") from error
        return value

    def validate(self, data):
        if data["compression"] == "none":
            data["compression_level"] = 0
        return data


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = (
            "id",
            "status",
            "native",
            "new_bytes",
            "reason",
            "destination",
            "network_mode",
            "created_at",
            "verified_at",
            "size",
            "raw_size",
            "sha256",
            "raw_sha256",
            "offset",
            "compression",
            "compression_level",
            "sector_size",
            "disk_id",
            "architecture",
            "boot_mode",
        )


DISK_ID = r"\A(?:ata|nvme|scsi|usb|virtio|wwn)-[A-Za-z0-9_.:+-]+\Z"


class CaptureGrantSerializer(serializers.Serializer):
    device_uuid = serializers.UUIDField()
    disk_id = serializers.RegexField(DISK_ID, max_length=255)

    def validate_device_uuid(self, value):
        if value.int in (0, (1 << 128) - 1):
            raise serializers.ValidationError("Use a non-placeholder system UUID.")
        return value


class RestoreGrantSerializer(CaptureGrantSerializer):
    confirmed = serializers.BooleanField()
    target_agent_id = serializers.CharField(max_length=200)

    def validate_confirmed(self, value):
        if not value:
            raise serializers.ValidationError(
                "Confirm the image, device and target disk."
            )
        return value


class ManifestSerializer(serializers.Serializer):
    raw_size = serializers.IntegerField(min_value=512)
    sector_size = serializers.ChoiceField(choices=(512, 4096))
    disk_id = serializers.RegexField(DISK_ID, max_length=255)
    architecture = serializers.ChoiceField(choices=("x86_64",))
    boot_mode = serializers.ChoiceField(choices=("uefi", "bios"))

    def validate(self, data):
        size = data["raw_size"]
        if size > settings.ULRMM_IMAGING_MAX_BYTES or size % data["sector_size"]:
            raise serializers.ValidationError(
                "Unsupported image size or sector alignment."
            )
        return data


class CompleteRestoreSerializer(serializers.Serializer):
    raw_sha256 = serializers.RegexField(r"\A[0-9a-f]{64}\Z")


class CompleteCaptureSerializer(CompleteRestoreSerializer):
    size = serializers.IntegerField(min_value=1)
    sha256 = serializers.RegexField(r"\A[0-9a-f]{64}\Z")


class NativeRestoreSerializer(RestoreGrantSerializer):
    disk_id = serializers.RegexField(r"\A[A-Za-z0-9][A-Za-z0-9_.:+{}-]{0,254}\Z")
    # Target geometry from the recovery preflight, checked where the server
    # cannot see the disk that Windows Recovery writes.
    raw_size = serializers.IntegerField(min_value=512, required=False)
    sector_size = serializers.ChoiceField(choices=(512, 4096), required=False)

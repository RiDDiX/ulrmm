# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import posixpath
import re
from datetime import date
from functools import cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from celery.schedules import crontab, crontab_parser
from django.conf import settings
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from scripts.models import ENV_DENIED, ENV_NAME, Script

from .models import Image, Profile, StorageTarget
from .storage import DESTINATION

HHMM = r"\A([01][0-9]|2[0-3]):[0-5][0-9]\Z"
DATE = r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z"
ENFORCEABLE = ("target", "hooks", "auto_setup")
GFS_TIERS = ("hourly", "daily", "weekly", "monthly", "yearly")
PHASES = ("pre-backup", "pre-snapshot", "post-snapshot", "post-backup")


class ProfileSerializer(serializers.ModelSerializer):
    destination = serializers.RegexField(DESTINATION)
    compression = serializers.ChoiceField(choices=("none", "gzip"))
    compression_level = serializers.IntegerField(min_value=0, max_value=9)
    network_mode = serializers.ChoiceField(choices=("internal", "internet"))
    schedule_time = serializers.TimeField(
        format="%H:%M", input_formats=["%H:%M"], allow_null=True
    )
    keep_last = serializers.IntegerField(min_value=0, max_value=365)
    volumes = serializers.ListField(
        child=serializers.CharField(max_length=255, trim_whitespace=False),
        max_length=32,
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
            "target",
        )


def _volumes(value):
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


@cache
def _zones():
    return available_timezones()


def _zone(value):
    # only names of the server's zone data, so every resolve can load them
    if value not in _zones():
        raise serializers.ValidationError("Use an IANA time zone.")
    try:
        ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError) as error:
        raise serializers.ValidationError("Use an IANA time zone.") from error
    return value


class RangeSerializer(serializers.Serializer):
    days = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=7),
        min_length=1,
        max_length=7,
    )
    start = serializers.RegexField(HHMM)
    end = serializers.RegexField(HHMM)


class ThrottleRuleSerializer(RangeSerializer):
    kbps = serializers.IntegerField(min_value=0, max_value=10_000_000)


class ThrottleSerializer(serializers.Serializer):
    default_kbps = serializers.IntegerField(min_value=0, max_value=10_000_000)
    rules = ThrottleRuleSerializer(many=True, max_length=16)


class EnvField(serializers.Field):
    """`NAME=value`, or `{"name": NAME}` to keep the stored value of that name."""

    def to_internal_value(self, data):
        if isinstance(data, str) and len(data) <= 1024:
            return data
        if (
            isinstance(data, dict)
            and set(data) == {"name"}
            and isinstance(data["name"], str)
            and len(data["name"]) <= 1024
        ):
            return {"name": data["name"]}
        raise serializers.ValidationError("Send NAME=value or the name to keep.")

    def to_representation(self, value):
        return value


class HookSerializer(serializers.Serializer):
    key = serializers.RegexField(r"\A[0-9a-f]{8}\Z", required=False)
    script_id = serializers.IntegerField(min_value=1)
    phase = serializers.ChoiceField(choices=PHASES)
    args = serializers.ListField(
        child=serializers.CharField(max_length=1024, trim_whitespace=False),
        max_length=16,
        default=list,
    )
    env_vars = serializers.ListField(child=EnvField(), max_length=16, default=list)
    timeout = serializers.IntegerField(min_value=1, max_value=3600)
    on_fail = serializers.ChoiceField(choices=("abort", "warn"))

    def validate_script_id(self, value):
        if not Script.objects.filter(pk=value).exists():
            raise serializers.ValidationError("The script does not exist.")
        return value

    def validate_env_vars(self, value):
        seen = set()
        for env_var in value:
            if isinstance(env_var, dict):
                name, sep = env_var["name"], "="
            else:
                name, sep, _ = env_var.partition("=")
            if not sep or not ENV_NAME.fullmatch(name) or ENV_DENIED.fullmatch(name):
                raise serializers.ValidationError(
                    f"{name} cannot be set as an environment variable."
                )
            if name in seen:
                raise serializers.ValidationError(f"{name} is set more than once.")
            seen.add(name)
        return value


class HookConfirmSerializer(serializers.Serializer):
    script_id = serializers.IntegerField(min_value=1, max_value=2**31 - 1)
    sha256 = serializers.RegexField(r"\A[0-9a-f]{64}\Z")


def _schedule(value):
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise serializers.ValidationError("Choose a schedule kind.")
    kind = value["kind"]
    shapes = {
        "none": {},
        "daily": {"time": serializers.RegexField(HHMM)},
        "interval": {"hours": serializers.IntegerField(min_value=1, max_value=720)},
        "cron": {"expr": serializers.CharField(max_length=200)},
        "calendar": {
            "frequency": serializers.ChoiceField(
                choices=("once", "daily", "weekly", "monthly")
            ),
            "run_time": serializers.RegexField(HHMM),
            "weekdays": serializers.ListField(
                child=serializers.IntegerField(min_value=0, max_value=6),
                max_length=7,
                default=list,
            ),
            "month_day": serializers.IntegerField(
                min_value=1, max_value=31, allow_null=True, default=None
            ),
            "month_week": serializers.ChoiceField(
                choices=(1, 2, 3, 4, -1), allow_null=True, default=None
            ),
            "month_weekday": serializers.IntegerField(
                min_value=0, max_value=6, allow_null=True, default=None
            ),
            "dates": serializers.ListField(
                child=serializers.RegexField(DATE), max_length=32, default=list
            ),
            "excluded_dates": serializers.ListField(
                child=serializers.RegexField(DATE), max_length=366, default=list
            ),
            "start_date": serializers.RegexField(DATE, allow_null=True, default=None),
            "end_date": serializers.RegexField(DATE, allow_null=True, default=None),
        },
    }
    if kind not in shapes:
        raise serializers.ValidationError("Choose a schedule kind.")
    fields = shapes[kind]
    extra = set(value) - set(fields) - {"kind"}
    if extra:
        raise serializers.ValidationError(f"Unknown schedule key {sorted(extra)[0]}.")
    out = {"kind": kind}
    for key, field in fields.items():
        out[key] = field.run_validation(value.get(key, serializers.empty))
    if kind == "cron":
        parts = out["expr"].split()
        try:
            if len(parts) != 5:
                raise ValueError
            crontab(
                minute=parts[0],
                hour=parts[1],
                day_of_month=parts[2],
                month_of_year=parts[3],
                day_of_week=parts[4],
            )
        except (ValueError, TypeError, crontab_parser.ParseException):
            raise serializers.ValidationError("Enter five cron fields.") from None
    if kind == "calendar":
        days = [
            *out["dates"],
            *out["excluded_dates"],
            out["start_date"],
            out["end_date"],
        ]
        for day in filter(None, days):
            try:
                date.fromisoformat(day)
            except ValueError:
                raise serializers.ValidationError(f"{day} is not a date.") from None
        if out["frequency"] == "weekly" and not out["weekdays"]:
            raise serializers.ValidationError("Choose at least one weekday.")
        if out["frequency"] == "monthly" and not (
            out["month_day"]
            or (out["month_week"] is not None and out["month_weekday"] is not None)
        ):
            raise serializers.ValidationError("Choose a day of the month.")
        if out["frequency"] == "once" and not out["dates"]:
            raise serializers.ValidationError("Choose at least one date.")
    return out


class ConfigSerializer(serializers.Serializer):
    """A sparse backup config: every setting optional, unknown keys refused."""

    target = serializers.IntegerField(min_value=1)
    network_mode = serializers.ChoiceField(choices=("internal", "internet"))
    compression = serializers.ChoiceField(choices=("none", "gzip"))
    compression_level = serializers.IntegerField(min_value=0, max_value=9)
    schedule = serializers.JSONField()
    schedule_events = serializers.ListField(
        child=serializers.ChoiceField(choices=("agent_start", "ac_connected")),
        max_length=2,
    )
    min_spacing_minutes = serializers.IntegerField(min_value=0, max_value=10080)
    catch_up = serializers.ChoiceField(choices=("run_asap", "skip"))
    catch_up_delay_minutes = serializers.IntegerField(min_value=0, max_value=1440)
    windows_allowed = RangeSerializer(many=True, max_length=28)
    windows_blackout = RangeSerializer(many=True, max_length=28)
    stop_at_window_end = serializers.BooleanField()
    timezone = serializers.CharField(max_length=64, allow_blank=True)
    keep_last = serializers.IntegerField(min_value=0, max_value=365)
    gfs = serializers.JSONField()
    quota_bytes = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    volumes = serializers.ListField(
        child=serializers.CharField(max_length=255, trim_whitespace=False),
        max_length=32,
    )
    auto_setup = serializers.ChoiceField(choices=("safe", "all", "off"))
    hooks = HookSerializer(many=True, max_length=8)
    throttle = ThrottleSerializer()
    on_battery = serializers.ChoiceField(choices=("defer", "run"))
    pause_on_battery = serializers.BooleanField()
    pause_max_minutes = serializers.IntegerField(min_value=0, max_value=240)
    keep_awake = serializers.BooleanField()
    priority = serializers.ChoiceField(choices=("background", "normal"))
    smart = serializers.ChoiceField(choices=("warn", "abort", "off"))
    rpo_hours = serializers.IntegerField(min_value=0, max_value=8760)
    alert_failures = serializers.IntegerField(min_value=1, max_value=100)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.required = False

    def to_internal_value(self, data):
        if isinstance(data, dict):
            unknown = sorted(set(data) - set(self.fields))
            if unknown:
                raise serializers.ValidationError(
                    {key: ["Unknown setting."] for key in unknown}
                )
        return super().to_internal_value(data)

    def validate_target(self, value):
        if not StorageTarget.objects.filter(pk=value, kind="server").exists():
            raise serializers.ValidationError("Choose an existing backup target.")
        return value

    def validate_network_mode(self, value):
        from .service import NO_INTERNAL, internal_available

        if value == "internal" and not internal_available():
            raise serializers.ValidationError(NO_INTERNAL)
        return value

    def validate_schedule(self, value):
        return _schedule(value)

    def validate_schedule_events(self, value):
        if len(set(value)) != len(value):
            raise serializers.ValidationError("List each event once.")
        return value

    def validate_timezone(self, value):
        return _zone(value) if value else value

    def validate_gfs(self, value):
        if (
            not isinstance(value, dict)
            or set(value) != set(GFS_TIERS)
            or not all(type(v) is int and 0 <= v <= 1000 for v in value.values())
        ):
            raise serializers.ValidationError(
                "Give hourly, daily, weekly, monthly and yearly counts of 0-1000."
            )
        return value

    def validate_volumes(self, value):
        return _volumes(value)


class TargetSerializer(serializers.ModelSerializer):
    name = serializers.RegexField(
        DESTINATION,
        max_length=64,
        validators=[UniqueValidator(StorageTarget.objects.all())],
    )
    max_runs = serializers.IntegerField(min_value=1, max_value=100, default=5)
    quota_bytes = serializers.IntegerField(min_value=0, max_value=2**63 - 1, default=0)

    class Meta:
        model = StorageTarget
        fields = (
            "name",
            "scope",
            "client",
            "site",
            "quota_bytes",
            "max_runs",
            "is_default",
        )

    def validate(self, data):
        # a PUT is partial: check the values the row will hold
        def merged(key, default):
            return data[key] if key in data else getattr(self.instance, key, default)

        scope = merged("scope", "global")
        client, site = merged("client", None), merged("site", None)
        if merged("is_default", False) and scope != "global":
            raise serializers.ValidationError(
                {"is_default": ["The default target must be global."]}
            )
        if (
            (scope == "global" and (client or site))
            or (scope == "client" and (not client or site))
            or (scope == "site" and (not site or client))
        ):
            raise serializers.ValidationError(
                {"scope": ["Choose exactly the client or site of this scope."]}
            )
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
            "trigger",
            "protected",
            "snapshot_at",
            "target",
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

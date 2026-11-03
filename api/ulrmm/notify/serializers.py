# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

from django.core.validators import EmailValidator
from rest_framework import serializers

from logs.models import hmac_marker
from remote.utils import encrypt_secret
from ulrmm.constants import AlertSeverity

from .models import HKDF_INFO, SOURCES, Channel, ChannelKind, Notification, Route

HTTPS = re.compile(r"^https://[^\s<>\"'/?#]+(/[^\s<>\"']*)?$")
AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")

# config keys per kind: (pattern or "emails", required, help)
CONFIG = {
    ChannelKind.MATRIX: {
        "homeserver": (HTTPS, True, "https:// address of the homeserver"),
        "room_id": (
            re.compile(r"^[!#][^\s:]{1,200}:[A-Za-z0-9.\-]{1,200}(:\d{1,5})?$"),
            True,
            "room id like !abc:example.org",
        ),
    },
    ChannelKind.TELEGRAM: {
        "chat_id": (
            re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$"),
            True,
            "numeric chat id or @channelname",
        ),
    },
    ChannelKind.NTFY: {
        "server": (HTTPS, False, "https:// address of the ntfy server"),
        "topic": (re.compile(r"^[A-Za-z0-9_-]{1,64}$"), True, "topic name"),
    },
    ChannelKind.SLACK: {},
    ChannelKind.TEAMS: {},
    ChannelKind.WEBHOOK: {"url": (HTTPS, True, "https:// address")},
    ChannelKind.EMAIL: {"recipients": ("emails", False, "list of addresses")},
}
# config key of the host a stored token is sent to
DESTINATION = {ChannelKind.MATRIX: "homeserver", ChannelKind.NTFY: "server"}
SECRET_RULES = {
    ChannelKind.MATRIX: (re.compile(r"^\S{8,1024}$"), True, "the access token"),
    ChannelKind.TELEGRAM: (
        re.compile(r"^\d{3,20}:[A-Za-z0-9_-]{20,100}$"),
        True,
        "the bot token from @BotFather",
    ),
    ChannelKind.NTFY: (re.compile(r"^\S{1,512}$"), False, "an access token"),
    ChannelKind.SLACK: (HTTPS, True, "the incoming webhook https:// address"),
    ChannelKind.TEAMS: (HTTPS, True, "the incoming webhook https:// address"),
    ChannelKind.WEBHOOK: (re.compile(r"^\S{8,512}$"), False, "a signing key"),
    ChannelKind.EMAIL: (None, False, ""),
}


def _check_config(kind: str, config) -> dict:
    if not isinstance(config, dict):
        raise serializers.ValidationError({"config": "An object."})
    rules = CONFIG[kind]
    # keys of other kinds are dropped
    out = {}
    for key, (pattern, required, help_text) in rules.items():
        value = config.get(key)
        if value in (None, "", []):
            if required:
                raise serializers.ValidationError({"config": f"{key}: {help_text}."})
            continue
        if pattern == "emails":
            if not isinstance(value, list) or len(value) > 20:
                raise serializers.ValidationError(
                    {"config": f"{key}: at most 20 addresses."}
                )
            for email in value:
                try:
                    EmailValidator()(email)
                except Exception:
                    raise serializers.ValidationError(
                        {"config": f"{key}: {email!r} is not an address."}
                    )
        elif not isinstance(value, str) or not pattern.fullmatch(value):
            raise serializers.ValidationError({"config": f"{key}: {help_text}."})
        out[key] = value
    return out


class ChannelSerializer(serializers.ModelSerializer):
    # write-only. blank keeps the stored one, secret_clear removes it
    secret = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=1024
    )
    secret_clear = serializers.BooleanField(write_only=True, required=False)
    secret_set = serializers.SerializerMethodField()

    class Meta:
        model = Channel
        fields = (
            "id",
            "name",
            "kind",
            "config",
            "secret",
            "secret_clear",
            "secret_set",
            "enabled",
            "quiet_start",
            "quiet_end",
            "min_severity",
            "last_sent",
            "last_error",
            *AUDIT_FIELDS,
        )
        read_only_fields = ("last_sent", "last_error", *AUDIT_FIELDS)

    def get_secret_set(self, obj) -> bool:
        return bool(obj.secret)

    def validate(self, attrs):
        inst = self.instance
        kind = attrs.get("kind", inst.kind if inst else None)
        if inst and kind != inst.kind:
            raise serializers.ValidationError(
                {"kind": "The kind of a channel cannot be changed."}
            )
        if "config" in attrs or not inst:
            attrs["config"] = _check_config(kind, attrs.get("config", {}))

        start = attrs.get("quiet_start", inst.quiet_start if inst else None)
        end = attrs.get("quiet_end", inst.quiet_end if inst else None)
        if bool(start) != bool(end):
            raise serializers.ValidationError(
                {"quiet_end": "Set both ends of the quiet hours or none."}
            )

        pattern, required, help_text = SECRET_RULES[kind]
        clear = attrs.pop("secret_clear", False)
        secret = attrs.pop("secret", "").strip()
        if secret:
            if not pattern or not pattern.fullmatch(secret):
                raise serializers.ValidationError({"secret": f"Expected {help_text}."})
            attrs["secret"] = encrypt_secret(secret, HKDF_INFO)
        elif clear:
            attrs["secret"] = ""
        elif inst and inst.secret and (key := DESTINATION.get(kind)):
            # the stored token never follows the address to another host
            if attrs.get("config", inst.config).get(key) != inst.config.get(key):
                raise serializers.ValidationError(
                    {"secret": f"The address changed, enter {help_text} again."}
                )
        stored = attrs.get("secret", inst.secret if inst else "")
        if required and not stored:
            raise serializers.ValidationError({"secret": f"Enter {help_text}."})
        return attrs


class ChannelAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Channel
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["secret"] = hmac_marker(instance.secret)
        return ret


class RouteSerializer(serializers.ModelSerializer):
    severities = serializers.ListField(
        child=serializers.ChoiceField(choices=AlertSeverity.values),
        required=False,
        max_length=3,
    )
    sources = serializers.ListField(
        child=serializers.ChoiceField(choices=SOURCES), required=False, max_length=20
    )
    escalate_after_minutes = serializers.IntegerField(
        required=False, min_value=0, max_value=10080
    )

    class Meta:
        model = Route
        fields = (
            "id",
            "name",
            "severities",
            "sources",
            "channels",
            "escalate_after_minutes",
            "escalate_to",
            "mute_in_maintenance",
            *AUDIT_FIELDS,
        )
        read_only_fields = AUDIT_FIELDS

    def validate(self, attrs):
        for key in ("severities", "sources"):
            if key in attrs:
                attrs[key] = list(dict.fromkeys(attrs[key]))
        inst = self.instance
        minutes = attrs.get(
            "escalate_after_minutes", inst.escalate_after_minutes if inst else 0
        )
        targets = (
            attrs["escalate_to"]
            if "escalate_to" in attrs
            else (list(inst.escalate_to.all()) if inst else [])
        )
        if minutes and not targets:
            raise serializers.ValidationError(
                {"escalate_to": "Pick the channels to escalate to."}
            )
        return attrs


class NotificationSerializer(serializers.ModelSerializer):
    channel_name = serializers.ReadOnlyField(source="channel.name", default=None)
    channel_kind = serializers.ReadOnlyField(source="channel.kind", default=None)
    route_name = serializers.ReadOnlyField(source="route.name", default=None)

    class Meta:
        model = Notification
        fields = (
            "id",
            "route",
            "route_name",
            "channel",
            "channel_name",
            "channel_kind",
            "alert",
            "source",
            "severity",
            "title",
            "body",
            "state",
            "escalation_level",
            "created",
            "sent_at",
            "error",
        )

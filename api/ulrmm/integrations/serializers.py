# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from remote.utils import encrypt_secret

from .models import (
    OPNSENSE_INFO,
    UNIFI_INFO,
    NetworkClient,
    OpnsenseFirewall,
    UniFiController,
)

URL_RE = r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$"
STATUS = ("last_sync", "last_error")


def _secret():
    # write-only: missing or blank keeps the stored one, null deletes it
    return serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        allow_null=True,
        max_length=512,
        trim_whitespace=False,
    )


class IntegrationSerializer(serializers.ModelSerializer):
    url = serializers.RegexField(
        URL_RE,
        required=False,
        allow_blank=True,
        error_messages={"invalid": "https://host or https://host:port, no path."},
    )

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        for k in self.Meta.model.SECRETS:
            ret[f"{k}_set"] = bool(getattr(instance, k))
        return ret

    def validate(self, attrs):
        inst = self.instance
        if inst and "url" in attrs and attrs["url"].rstrip("/") != inst.url.rstrip("/"):
            # stored secrets never follow the address to another host
            kept = [
                k
                for k in self.Meta.model.SECRETS
                if getattr(inst, k) and attrs.get(k, "") == ""
            ]
            if kept:
                raise serializers.ValidationError(
                    {k: "The address changed, enter it again." for k in kept}
                )
        for k in self.Meta.model.SECRETS:
            if k not in attrs:
                continue
            value = attrs.pop(k)
            if value is None:
                attrs[k] = ""
            elif value:
                attrs[k] = encrypt_secret(value, self.INFO)

        def get(k):
            return attrs[k] if k in attrs else getattr(self.instance, k, "")

        if get("enabled") and not get("url"):
            raise serializers.ValidationError({"url": "Required when it is on."})
        if get("enabled") and not self.credentials_set(get):
            raise serializers.ValidationError(self.MISSING)
        return attrs


class UniFiSerializer(IntegrationSerializer):
    INFO = UNIFI_INFO
    MISSING = "Enter an API key, or a user name and password."
    site = serializers.RegexField(
        r"^[A-Za-z0-9_-]{1,64}$",
        required=False,
        error_messages={"invalid": "The site id, e.g. default."},
    )
    username = serializers.RegexField(
        r"^[ -~]{0,128}$",
        required=False,
        allow_blank=True,
        error_messages={"invalid": "Printable ASCII."},
    )
    password = _secret()
    api_key = _secret()

    class Meta:
        model = UniFiController
        fields = (
            "url",
            "site",
            "username",
            "password",
            "api_key",
            "verify_tls",
            "enabled",
            *STATUS,
        )
        read_only_fields = STATUS

    def credentials_set(self, get) -> bool:
        return bool(get("api_key") or (get("username") and get("password")))


class OpnsenseSerializer(IntegrationSerializer):
    INFO = OPNSENSE_INFO
    MISSING = "Enter the API key and secret."
    api_key = _secret()
    api_secret = _secret()

    class Meta:
        model = OpnsenseFirewall
        fields = ("url", "api_key", "api_secret", "verify_tls", "enabled", *STATUS)
        read_only_fields = STATUS

    def credentials_set(self, get) -> bool:
        return bool(get("api_key") and get("api_secret"))


class NetworkClientSerializer(serializers.ModelSerializer):
    agent = serializers.SerializerMethodField()

    class Meta:
        model = NetworkClient
        exclude = ("id",)

    def get_agent(self, obj):
        # context "agents": mac -> {agent_id, name} of the agents the user may see
        return self.context["agents"].get(obj.mac)

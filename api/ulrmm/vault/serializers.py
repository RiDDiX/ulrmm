# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from agents.models import Agent
from logs.models import hmac_marker
from remote.utils import encrypt_secret
from ulrmm.constants import AGENT_DEFER

from .models import HKDF_INFO, MAX_BODY_BYTES, SCOPES, Credential, Document

AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")
URL_RE = r"^https?://[^\s<>\"']+$"


class ScopedSerializer(serializers.ModelSerializer):
    agent = serializers.SlugRelatedField(
        slug_field="agent_id",
        queryset=Agent.objects.defer(*AGENT_DEFER),
        required=False,
        allow_null=True,
    )
    # set when the item belongs to a parent of the listed scope
    inherited = serializers.SerializerMethodField()

    def get_inherited(self, obj):
        scope = self.context.get("scope")
        return obj.scope if scope and obj.scope != scope else None

    def validate(self, attrs):
        if self.instance:
            if any(
                s in attrs and attrs[s] != getattr(self.instance, s) for s in SCOPES
            ):
                raise serializers.ValidationError(
                    "The client, site or device of an item cannot be changed."
                )
        elif sum(attrs.get(s) is not None for s in SCOPES) != 1:
            raise serializers.ValidationError(
                "Set exactly one of client, site or agent."
            )
        return attrs


class DocumentSerializer(ScopedSerializer):
    body = serializers.CharField(
        required=False, allow_blank=True, trim_whitespace=False
    )

    class Meta:
        model = Document
        fields = ("id", *SCOPES, "title", "body", "pinned", "inherited", *AUDIT_FIELDS)
        read_only_fields = AUDIT_FIELDS

    def validate_body(self, value):
        if len(value.encode()) > MAX_BODY_BYTES:
            raise serializers.ValidationError("A document holds at most 100 KB.")
        return value


class CredentialSerializer(ScopedSerializer):
    # write-only. a blank value leaves the stored secret in place
    secret = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        max_length=4096,
        trim_whitespace=False,
    )
    secret_clear = serializers.BooleanField(write_only=True, required=False)
    secret_set = serializers.SerializerMethodField()
    url = serializers.RegexField(
        URL_RE,
        max_length=500,
        required=False,
        allow_blank=True,
        error_messages={"invalid": "An http:// or https:// address."},
    )

    class Meta:
        model = Credential
        fields = (
            "id",
            *SCOPES,
            "name",
            "username",
            "secret",
            "secret_clear",
            "secret_set",
            "url",
            "notes",
            "inherited",
            *AUDIT_FIELDS,
        )
        read_only_fields = AUDIT_FIELDS

    def get_secret_set(self, obj) -> bool:
        return bool(obj.secret)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        clear = attrs.pop("secret_clear", False)
        if secret := attrs.pop("secret", ""):
            attrs["secret"] = encrypt_secret(secret, HKDF_INFO)
        elif clear:
            attrs["secret"] = ""
        return attrs


class CredentialAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Credential
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["secret"] = hmac_marker(instance.secret)
        return ret


class DocumentAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # the text stays in the vault. the log gets an hmac of it
        ret["body"] = hmac_marker(instance.body)
        return ret

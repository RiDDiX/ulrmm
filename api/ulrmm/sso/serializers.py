# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from allauth.socialaccount.models import SocialApp
from django.conf import settings
from rest_framework import serializers

from accounts.models import Role
from ulrmm.util_settings import get_backend_url

from .utils import (
    IdPURLError,
    check_idp_url,
    issuer_problem,
    provider_settings,
    role_pk,
)


class SSOProviderSerializer(serializers.ModelSerializer):
    # the secret itself never leaves the server
    secret_set = serializers.SerializerMethodField()
    server_url = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    callback_url = serializers.SerializerMethodField()
    javascript_origin_url = serializers.SerializerMethodField()
    # why the issuer fails the URL rule, so the provider cannot sign in
    blocked_reason = serializers.SerializerMethodField()

    def get_secret_set(self, obj) -> bool:
        return bool(obj.secret)

    def get_server_url(self, obj):
        return provider_settings(obj).get("server_url")

    def get_role(self, obj):
        return provider_settings(obj).get("role")

    def get_callback_url(self, obj) -> str:
        backend = get_backend_url(
            settings.ALLOWED_HOSTS[0],
            settings.ULRMM_PROTO,
            settings.ULRMM_BACKEND_PORT,
        )
        return f"{backend}/accounts/oidc/{obj.provider_id}/login/callback/"

    def get_javascript_origin_url(self, obj) -> str:
        return settings.CORS_ORIGIN_WHITELIST[0]

    def get_blocked_reason(self, obj):
        return issuer_problem(obj) or None

    class Meta:
        model = SocialApp
        fields = [
            "id",
            "name",
            "provider",
            "provider_id",
            "client_id",
            "secret_set",
            "server_url",
            "settings",
            "role",
            "callback_url",
            "javascript_origin_url",
            "blocked_reason",
        ]


class SSOProviderInputSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=40)
    client_id = serializers.CharField(max_length=191)
    secret = serializers.CharField(
        max_length=191, required=False, allow_blank=True, trim_whitespace=False
    )
    secret_clear = serializers.BooleanField(required=False)
    server_url = serializers.CharField(max_length=255)
    # a pk, or null / 0 / "" for no role; unknown values are stored as sent and
    # give users no role at sign-in, so providers with a deleted role stay editable
    role = serializers.JSONField(required=False, allow_null=True)

    def validate_server_url(self, value):
        try:
            check_idp_url(value)
        except IdPURLError as e:
            raise serializers.ValidationError(str(e))
        return value

    def validate_role(self, value):
        if value in (None, "", "0", 0):
            return None
        pk = role_pk(value)
        if pk and Role.objects.filter(pk=pk).exists():
            return pk
        return value


class SSOSettingsSerializer(serializers.Serializer):
    sso_enabled = serializers.BooleanField()
    block_local_user_logon = serializers.BooleanField()


class DisconnectAccountSerializer(serializers.Serializer):
    provider = serializers.CharField()
    account = serializers.CharField()

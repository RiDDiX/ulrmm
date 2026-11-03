# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

import pyotp
from django.conf import settings
from rest_framework import serializers

from ulrmm.util_settings import get_webdomain

from .models import APIKey, Role, User

AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")

# the names Quasar has text- and bg- classes for; anything else leaves the
# dashboard counters without a color
_HUES = """
    red pink purple deep-purple indigo blue light-blue cyan teal green
    light-green lime yellow amber orange deep-orange brown grey blue-grey
    """.split()
_DASH_COLOR = re.compile(
    "primary|secondary|accent|positive|negative|info|warning|dark|black|white"
    f"|({'|'.join(_HUES)})(-([1-9]|1[0-4]))?"
)


_DASH_COLOR_FIELDS = tuple(
    f"dash_{name}_color" for name in ("info", "positive", "negative", "warning")
)


class UserUISerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = tuple("""
            dark_mode show_community_scripts agent_dblclick_action url_action
            default_agent_tbl_tab client_tree_sort client_tree_splitter
            loading_bar_color dash_info_color dash_positive_color
            dash_negative_color dash_warning_color clear_search_when_switching
            date_format
            """.split())

    def validate(self, attrs):
        # the form sends every color; a value stored before this check stays
        # saveable until the user picks another one
        errors = {
            field: "Not a color the dashboard can show."
            for field in _DASH_COLOR_FIELDS
            if field in attrs
            and attrs[field] != getattr(self.instance, field, None)
            and not _DASH_COLOR.fullmatch(attrs[field])
        }
        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = tuple("""
            id username first_name last_name email is_active last_login
            last_login_ip role block_dashboard_login date_format is_superuser
            """.split())
        # set by the login flow only
        read_only_fields = ("last_login", "last_login_ip", "is_superuser")


class TOTPSetupSerializer(serializers.ModelSerializer):
    # the pending key from the view, never the stored column
    totp_key = serializers.SerializerMethodField()
    qr_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("username", "totp_key", "qr_url")

    def get_totp_key(self, obj):
        return self.context["totp_key"]

    def get_qr_url(self, obj):
        issuer = get_webdomain(settings.CORS_ORIGIN_WHITELIST[0])
        return pyotp.totp.TOTP(self.context["totp_key"]).provisioning_uri(
            obj.username, issuer_name=issuer
        )


class RoleSerializer(serializers.ModelSerializer):
    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = "__all__"
        read_only_fields = AUDIT_FIELDS

    def get_user_count(self, obj) -> int:
        return obj.users.count()


class RoleAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"


class APIKeySerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source="user.username")

    class Meta:
        model = APIKey
        exclude = ("key", "key_hash")
        read_only_fields = AUDIT_FIELDS


class APIKeyAuditSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source="user.username")

    class Meta:
        model = APIKey
        fields = ("name", "username", "expiration")

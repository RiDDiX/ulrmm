# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from .models import LapsPolicy, LapsState

# what the three library scripts all take: Linux wants lower case,
# macOS no leading underscore, Windows at most 20 characters
ACCOUNT_RE = r"^[a-z][a-z0-9_-]{0,19}$"


class LapsPolicySerializer(serializers.ModelSerializer):
    account = serializers.RegexField(
        ACCOUNT_RE,
        required=False,
        error_messages={
            "invalid": "1 to 20 lower case letters, digits, dash or underscore,"
            " starting with a letter."
        },
    )
    rotate_days = serializers.IntegerField(min_value=1, max_value=365, required=False)
    length = serializers.IntegerField(min_value=14, max_value=64, required=False)
    rotate_after_reveal_hours = serializers.IntegerField(
        min_value=0, max_value=168, required=False
    )
    site_name = serializers.ReadOnlyField(source="site.name")
    client_name = serializers.ReadOnlyField(source="site.client.name")

    class Meta:
        model = LapsPolicy
        fields = (
            "id",
            "site",
            "site_name",
            "client_name",
            "enabled",
            "account",
            "create_if_missing",
            "rotate_days",
            "length",
            "rotate_after_reveal_hours",
            "modified_by",
            "modified_time",
        )
        read_only_fields = ("modified_by", "modified_time")


class LapsStateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LapsState
        fields = (
            "account",
            "last_rotation",
            "next_rotation",
            "last_error",
            "credential",
        )

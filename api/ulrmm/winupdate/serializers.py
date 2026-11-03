# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from .models import WinUpdate, WinUpdatePolicy


class WinUpdateSerializer(serializers.ModelSerializer):
    date_installed = serializers.SerializerMethodField()
    installing = serializers.SerializerMethodField()

    class Meta:
        model = WinUpdate
        fields = "__all__"

    def get_date_installed(self, obj):
        if not obj.date_installed:
            return None
        tz = self.context["default_tz"]
        return obj.date_installed.astimezone(tz).strftime("%m %d %Y %H:%M")

    def get_installing(self, obj) -> bool:
        return obj.guid in self.context.get("installing_guids", set())


class WinUpdatePolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = WinUpdatePolicy
        fields = "__all__"
        # the views attach the owner, the audit columns belong to the server
        read_only_fields = (
            "agent",
            "policy",
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )

    def validate_run_time_days(self, value):
        if value is None:
            return value
        if len(set(value)) != len(value) or any(not 0 <= day <= 6 for day in value):
            raise serializers.ValidationError("run_time_days must contain weekdays 0-6")
        return value

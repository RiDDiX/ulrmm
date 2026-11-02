# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from .models import RustDeskSettings
from .utils import is_valid_host


class RustDeskSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RustDeskSettings
        fields = (
            "enabled",
            "id_server",
            "relay_server",
            "auto_update_server",
            "auto_update_clients",
        )

    def _host(self, value: str) -> str:
        if value and not is_valid_host(value):
            raise serializers.ValidationError(
                "Expected a host name or IP address, optionally with :port."
            )
        return value

    validate_id_server = _host
    validate_relay_server = _host

    def validate(self, attrs):
        enabled = attrs.get("enabled", self.instance.enabled)
        if enabled and not attrs.get("id_server", self.instance.id_server):
            raise serializers.ValidationError(
                {"id_server": "Required while RustDesk is enabled."}
            )
        return attrs


class VersionSerializer(serializers.Serializer):
    version = serializers.CharField(max_length=32)

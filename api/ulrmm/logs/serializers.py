# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from clients.serializers import SiteMinimumSerializer

from .models import AuditLog, DebugLog, PendingAction


class DebugLogSerializer(serializers.ModelSerializer):
    class Meta:
        fields = "__all__"
        model = DebugLog

    agent = serializers.ReadOnlyField(source="agent.hostname")
    entry_time = serializers.ReadOnlyField()


class PendingActionSerializer(serializers.ModelSerializer):
    class Meta:
        fields = "__all__"
        model = PendingAction

    hostname = serializers.ReadOnlyField(source="agent.hostname")
    client = serializers.ReadOnlyField(source="agent.client.name")
    site = serializers.ReadOnlyField(source="agent.site.name")
    due = serializers.ReadOnlyField()
    description = serializers.ReadOnlyField()


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        fields = "__all__"
        model = AuditLog

    entry_time = serializers.ReadOnlyField()
    ip_address = serializers.ReadOnlyField(source="debug_info.ip")
    site = serializers.SerializerMethodField()

    def get_site(self, obj):
        # the view loads the sites of one page at once: {agent_id: Site}
        if not obj.agent_id:
            return None
        site = self.context.get("sites", {}).get(obj.agent_id)
        return None if site is None else SiteMinimumSerializer(site).data

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework.serializers import (
    ModelSerializer,
    ReadOnlyField,
    SerializerMethodField,
)

from agents.serializers import AgentHostnameSerializer
from autotasks.models import TaskResult
from checks.models import CheckResult
from clients.models import Client, Site
from clients.serializers import ClientMinimumSerializer, SiteMinimumSerializer
from winupdate.serializers import WinUpdatePolicySerializer

from .models import Policy

AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")
EXCLUSIONS = ("excluded_sites", "excluded_clients", "excluded_agents")


class _ScopedExclusions:
    """A scoped role only sees the exclusions inside its scope. The view puts
    the visible pk sets into the context as `visible`."""

    def to_representation(self, instance):
        data = super().to_representation(instance)
        visible = self.context.get("visible")
        if visible:
            for field in EXCLUSIONS:
                if field in data:
                    data[field] = [pk for pk in data[field] if pk in visible[field]]
        return data


class PolicySerializer(_ScopedExclusions, ModelSerializer):
    class Meta:
        model = Policy
        fields = "__all__"
        read_only_fields = AUDIT_FIELDS


class PolicyTableSerializer(_ScopedExclusions, ModelSerializer):
    default_server_policy = ReadOnlyField(source="is_default_server_policy")
    default_workstation_policy = ReadOnlyField(source="is_default_workstation_policy")
    agents_count = SerializerMethodField()
    winupdatepolicy = WinUpdatePolicySerializer(many=True, read_only=True)
    alert_template = ReadOnlyField(source="alert_template_id")

    class Meta:
        model = Policy
        fields = "__all__"

    def get_agents_count(self, policy: Policy) -> int:
        counts = self.context.get("agents_count")
        if counts is not None:
            return counts[policy.pk]
        agents = policy.related_agents()
        scope = self.context.get("scope")
        return (agents.filter(scope) if scope is not None else agents).count()


class PolicyRelatedSerializer(ModelSerializer):
    workstation_clients = SerializerMethodField()
    workstation_sites = SerializerMethodField()
    server_clients = SerializerMethodField()
    server_sites = SerializerMethodField()
    agents = SerializerMethodField()
    is_default_server_policy = ReadOnlyField()
    is_default_workstation_policy = ReadOnlyField()
    # the names the web relations dialog reads
    default_server_policy = ReadOnlyField(source="is_default_server_policy")
    default_workstation_policy = ReadOnlyField(source="is_default_workstation_policy")

    class Meta:
        model = Policy
        fields = tuple("""
            pk name workstation_clients workstation_sites server_clients
            server_sites agents is_default_server_policy
            is_default_workstation_policy default_server_policy
            default_workstation_policy
            """.split())

    def _mine(self, related):
        return related.filter_by_role(self.context["user"])

    def get_workstation_clients(self, policy):
        clients = self._mine(policy.workstation_clients)
        return ClientMinimumSerializer(clients, many=True).data

    def get_server_clients(self, policy):
        clients = self._mine(policy.server_clients)
        return ClientMinimumSerializer(clients, many=True).data

    def get_workstation_sites(self, policy):
        sites = self._mine(policy.workstation_sites).select_related("client")
        return SiteMinimumSerializer(sites, many=True).data

    def get_server_sites(self, policy):
        sites = self._mine(policy.server_sites).select_related("client")
        return SiteMinimumSerializer(sites, many=True).data

    def get_agents(self, policy):
        agents = self._mine(policy.agents).select_related("site__client")
        return AgentHostnameSerializer(agents, many=True).data


class PolicyOverviewSiteSerializer(ModelSerializer):
    workstation_policy = PolicySerializer(read_only=True)
    server_policy = PolicySerializer(read_only=True)

    class Meta:
        model = Site
        fields = ("pk", "name", "workstation_policy", "server_policy")


class PolicyOverviewSerializer(ModelSerializer):
    sites = PolicyOverviewSiteSerializer(
        source="filtered_sites", many=True, read_only=True
    )
    workstation_policy = PolicySerializer(read_only=True)
    server_policy = PolicySerializer(read_only=True)

    class Meta:
        model = Client
        fields = ("pk", "name", "sites", "workstation_policy", "server_policy")


class PolicyCheckStatusSerializer(ModelSerializer):
    hostname = ReadOnlyField(source="agent.hostname")
    # read per row by the policy status dialog
    check_type = ReadOnlyField(source="assigned_check.check_type")
    readable_desc = ReadOnlyField(source="assigned_check.readable_desc")
    history_info = ReadOnlyField()

    class Meta:
        model = CheckResult
        fields = "__all__"


class PolicyTaskStatusSerializer(ModelSerializer):
    hostname = ReadOnlyField(source="agent.hostname")

    class Meta:
        model = TaskResult
        fields = "__all__"


class PolicyAuditSerializer(ModelSerializer):
    class Meta:
        model = Policy
        fields = "__all__"

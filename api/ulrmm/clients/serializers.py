# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from deploy.signing import api_url

from .models import Client, ClientCustomField, Deployment, Site, SiteCustomField

MASK = "********"

_VALUE_COLUMNS = {
    "string_value": {"write_only": True},
    "bool_value": {"write_only": True},
    "multiple_value": {"write_only": True},
}


class SiteCustomFieldSerializer(serializers.ModelSerializer):
    value = serializers.ReadOnlyField()

    class Meta:
        model = SiteCustomField
        fields = tuple("""
            id field site value string_value bool_value multiple_value
            """.split())
        extra_kwargs = _VALUE_COLUMNS


class ClientCustomFieldSerializer(serializers.ModelSerializer):
    value = serializers.ReadOnlyField()

    class Meta:
        model = ClientCustomField
        fields = tuple("""
            id field client value string_value bool_value multiple_value
            """.split())
        extra_kwargs = _VALUE_COLUMNS


def _refuse_pipe(attrs, what: str) -> None:
    if "|" in attrs.get("name", ""):
        raise serializers.ValidationError(f"{what} name cannot contain the | character")


class SiteSerializer(serializers.ModelSerializer):
    client_name = serializers.ReadOnlyField(source="client.name")
    custom_fields = SiteCustomFieldSerializer(many=True, read_only=True)
    # present only on querysets annotated with them, skipped otherwise
    agent_count = serializers.ReadOnlyField()
    maintenance_mode = serializers.ReadOnlyField()

    class Meta:
        model = Site
        fields = tuple("""
            id name server_policy workstation_policy alert_template client_name
            client custom_fields agent_count block_policy_inheritance
            maintenance_mode failing_checks
            """.split())
        # rewritten by core.tasks every few minutes
        read_only_fields = ("failing_checks",)

    def validate(self, attrs):
        _refuse_pipe(attrs, "Site")
        return attrs


class SiteMinimumSerializer(serializers.ModelSerializer):
    client_name = serializers.ReadOnlyField(source="client.name")

    class Meta:
        model = Site
        fields = "__all__"


class ClientMinimumSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = "__all__"


class ClientSerializer(serializers.ModelSerializer):
    sites = serializers.SerializerMethodField()
    custom_fields = ClientCustomFieldSerializer(many=True, read_only=True)
    agent_count = serializers.ReadOnlyField()
    maintenance_mode = serializers.ReadOnlyField()

    class Meta:
        model = Client
        fields = tuple("""
            id name server_policy workstation_policy alert_template
            block_policy_inheritance sites custom_fields agent_count
            maintenance_mode failing_checks
            """.split())
        read_only_fields = ("failing_checks",)

    def get_sites(self, obj):
        # the views prefetch the role-filtered sites into filtered_sites
        return SiteSerializer(obj.filtered_sites, many=True).data

    def validate(self, attrs):
        _refuse_pipe(attrs, "Client")
        return attrs


class DeploymentSerializer(serializers.ModelSerializer):
    client_id = serializers.ReadOnlyField(source="client.id")
    site_id = serializers.ReadOnlyField(source="site.id")
    client_name = serializers.ReadOnlyField(source="client.name")
    site_name = serializers.ReadOnlyField(source="site.name")
    policy_name = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()
    enrollments = serializers.SerializerMethodField()
    legacy_token = serializers.SerializerMethodField()

    class Meta:
        model = Deployment
        fields = tuple("""
            id uid name client_id site_id client_name site_name mon_type goarch
            policy policy_name expiry install_flags created url max_enrollments
            enrollments legacy_token
            """.split())

    def get_policy_name(self, obj):
        return obj.policy.name if obj.policy_id else None

    def get_url(self, obj):
        return f"{api_url()}/clients/{obj.uid}/deploy/"

    def get_enrollments(self, obj) -> int:
        count = getattr(obj, "enrollment_count", None)
        return obj.enrollments.count() if count is None else count

    def get_legacy_token(self, obj):
        # the knox token of a deployment made before signed links; never shown
        return MASK if obj.auth_token_id else None


class SiteAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = "__all__"


class ClientAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = "__all__"

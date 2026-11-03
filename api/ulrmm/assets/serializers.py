# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers

from agents.models import Agent
from logs.models import hmac_marker
from remote.utils import encrypt_secret
from ulrmm.constants import AGENT_DEFER

from .models import HKDF_INFO, License

AUDIT_FIELDS = ("created_by", "created_time", "modified_by", "modified_time")


class LicenseSerializer(serializers.ModelSerializer):
    # write-only. blank keeps the stored key, key_clear removes it
    key = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=4096
    )
    key_clear = serializers.BooleanField(write_only=True, required=False)
    key_set = serializers.SerializerMethodField()
    # agent_id list on write, [{agent_id, name}] of the visible ones on read
    agents = serializers.SlugRelatedField(
        slug_field="agent_id",
        queryset=Agent.objects.defer(*AGENT_DEFER),
        many=True,
        required=False,
    )
    assigned = serializers.SerializerMethodField()
    over_seats = serializers.SerializerMethodField()
    # devices whose installed Microsoft key matches, from activation.matches;
    # null without a product key in the license
    activation = serializers.SerializerMethodField()

    class Meta:
        model = License
        fields = (
            "id",
            "name",
            "vendor",
            "key",
            "key_clear",
            "key_set",
            "seats",
            "expires",
            "notes",
            "agents",
            "assigned",
            "over_seats",
            "activation",
            "site",
            *AUDIT_FIELDS,
        )
        read_only_fields = AUDIT_FIELDS

    def get_key_set(self, obj) -> bool:
        return bool(obj.key)

    def get_assigned(self, obj) -> int:
        return len(obj.agents.all())

    def get_over_seats(self, obj) -> bool:
        return obj.seats is not None and len(obj.agents.all()) > obj.seats

    def get_activation(self, obj) -> list | None:
        return self.context.get("activation", {}).get(obj.pk)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        visible = self.context.get("visible")
        ret["agents"] = [
            {"agent_id": a.agent_id, "name": a.effective_name}
            for a in instance.agents.all()
            if visible is None or a.pk in visible
        ]
        return ret

    def validate(self, attrs):
        clear = attrs.pop("key_clear", False)
        if key := attrs.pop("key", "").strip():
            attrs["key"] = encrypt_secret(key, HKDF_INFO)
        elif clear:
            attrs["key"] = ""
        inst = self.instance
        visible = self.context.get("visible")
        if "agents" in attrs and visible is not None:
            if any(a.pk not in visible for a in attrs["agents"]):
                raise serializers.ValidationError({"agents": "Unknown device."})
            # devices outside the user's clients stay assigned
            if inst:
                attrs["agents"] += [a for a in inst.agents.all() if a.pk not in visible]
        agents = attrs.get("agents", inst.agents.all() if inst else [])
        site = attrs.get("site", inst.site if inst else None)
        if site and any(a.site_id != site.pk for a in agents):
            raise serializers.ValidationError(
                {"agents": "A license of a site covers devices of that site only."}
            )
        return attrs


class LicenseAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = License
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["key"] = hmac_marker(instance.key)
        return ret

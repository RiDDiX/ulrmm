# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

from rest_framework import serializers

from agents.models import Agent
from logs.models import AuditLog
from ulrmm.constants import AuditObjType
from ulrmm.middleware import get_debug_info

from .models import DeviceGroup, GroupKind, Tag
from .rules import clean_rules

HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _unique_name(model, value: str, instance) -> str:
    value = value.strip()
    if not value:
        raise serializers.ValidationError("Enter a name.")
    others = model.objects.filter(name__iexact=value)
    if instance:
        others = others.exclude(pk=instance.pk)
    if others.exists():
        raise serializers.ValidationError("This name is taken.")
    return value


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ("id", "name", "color")

    def validate_name(self, value):
        return _unique_name(Tag, value, self.instance)

    def validate_color(self, value):
        if not HEX_COLOR.match(value):
            raise serializers.ValidationError("Use a color like #1a2b3c.")
        return value.lower()


class AgentTagsSerializer(serializers.Serializer):
    tags = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Tag.objects.all(), allow_empty=True
    )


class DeviceGroupSerializer(serializers.ModelSerializer):
    # agent ids the requesting user can see. those are accepted and listed
    members = serializers.SlugRelatedField(
        slug_field="agent_id",
        many=True,
        required=False,
        write_only=True,
        queryset=Agent.objects.none(),
    )

    class Meta:
        model = DeviceGroup
        fields = ("id", "name", "description", "kind", "rules", "members")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        user = self.context["request"].user
        agents = Agent.objects.filter_by_role(user)  # type: ignore
        self.fields["members"].child_relation.queryset = agents

    def validate_name(self, value):
        return _unique_name(DeviceGroup, value, self.instance)

    def validate(self, data):
        kind = data.get("kind", getattr(self.instance, "kind", GroupKind.DYNAMIC))
        if kind == GroupKind.STATIC:
            data["rules"] = {}
        elif "rules" in data or not self.instance or "kind" in data:
            data["rules"] = clean_rules(data.get("rules"))
        return data

    def save(self, **kwargs):
        members = self.validated_data.pop("members", None)
        before = self._member_names(self.instance) if self.instance else []
        group = super().save(**kwargs)
        if group.kind == GroupKind.DYNAMIC:
            group.members.clear()
        elif members is not None:
            # keep members the user cannot see. they were not in the request
            visible = self.fields["members"].child_relation.queryset
            hidden = list(group.members.exclude(pk__in=visible.values("pk")))
            group.members.set(members + hidden)

        # the model audit covers the fields, membership is audited here
        after = self._member_names(group)
        if before != after:
            AuditLog.audit_object_changed(
                self.context["request"].user.username,
                AuditObjType.DEVICE_GROUP,
                {"members": before},
                {"members": after},
                group.name,
                debug_info=get_debug_info(),
            )
        return group

    @staticmethod
    def _member_names(group) -> list:
        return sorted(group.members.values_list("hostname", flat=True))

    def to_representation(self, group):
        data = super().to_representation(group)
        visible = Agent.objects.filter_by_role(  # type: ignore
            self.context["request"].user
        ).filter(pk__in=group.agents().values("pk"))
        data["count"] = visible.count()
        data["members"] = (
            list(visible.order_by("hostname").values_list("agent_id", flat=True))
            if group.kind == GroupKind.STATIC
            else []
        )
        return data


class DeviceGroupAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceGroup
        fields = ("id", "name", "description", "kind", "rules")

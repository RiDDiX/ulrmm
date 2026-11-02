# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

from rest_framework import serializers

from automation.models import Policy
from clients.models import Deployment
from ulrmm.constants import AgentPlat

from . import detect, winget
from .installs import CHOCO_NAME
from .models import Baseline, BaselineItem, BaselineSource, InstalledSoftware

# a distribution package name, never an option
LINUX_PKG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
SOURCE_PLATS = {
    BaselineSource.WINGET: (AgentPlat.WINDOWS,),
    BaselineSource.CHOCO: (AgentPlat.WINDOWS,),
    BaselineSource.LINUX_PKG: (AgentPlat.LINUX,),
    BaselineSource.PACKAGE: (AgentPlat.WINDOWS, AgentPlat.LINUX, AgentPlat.DARWIN),
}
MAX_ITEMS = 100


class InstalledSoftwareSerializer(serializers.ModelSerializer):
    class Meta:
        model = InstalledSoftware
        fields = "__all__"


def _item(data: dict, plat: str, order: int) -> dict:
    """One validated item; the name defaults to the catalog or package name."""
    from packages.models import SoftwarePackage

    if "source" not in data or "ref" not in data:
        # a partial edit skips missing fields, an item needs both
        raise serializers.ValidationError({"ref": "Every item needs source and ref."})
    source, ref = data["source"], data["ref"]
    name = data.get("name") or ""
    if plat not in SOURCE_PLATS[source]:
        raise serializers.ValidationError(
            {"source": f"{source} items do not install on {plat}."}
        )
    if source == BaselineSource.WINGET:
        if not winget.ID_RE.fullmatch(ref):
            raise serializers.ValidationError({"ref": "Not a winget package id."})
        if not name and (row := winget.find(ref)):
            name = row[1]
    elif source == BaselineSource.CHOCO and not CHOCO_NAME.fullmatch(ref):
        raise serializers.ValidationError({"ref": "Not a chocolatey package id."})
    elif source == BaselineSource.LINUX_PKG and not LINUX_PKG_RE.fullmatch(ref):
        raise serializers.ValidationError({"ref": "Not a package name."})
    elif source == BaselineSource.PACKAGE:
        package = (
            SoftwarePackage.objects.filter(pk=int(ref)).first()
            if ref.isdecimal()
            else None
        )
        if package is None:
            raise serializers.ValidationError({"ref": "No hosted package has this id."})
        if package.plat != plat:
            raise serializers.ValidationError(
                {"ref": f"{package.name} is a {package.get_plat_display()} package."}
            )
        name = name or package.name
    if not name.isprintable():
        raise serializers.ValidationError(
            {"name": "No line breaks or control characters."}
        )
    try:
        detection = detect.clean(data.get("detection"), plat)
    except serializers.ValidationError as e:
        raise serializers.ValidationError({"detection": e.detail}) from None
    return {
        **data,
        "name": (name or ref)[:255],
        "detection": detection,
        "order": data.get("order", order),
    }


class BaselineItemSerializer(serializers.ModelSerializer):
    # an existing item keeps its id, and its states, across an edit
    id = serializers.IntegerField(required=False)

    class Meta:
        model = BaselineItem
        fields = (
            "id",
            "order",
            "source",
            "ref",
            "name",
            "detection",
            "required",
            "timeout",
        )


class BaselineSerializer(serializers.ModelSerializer):
    items = BaselineItemSerializer(many=True, required=False)
    policies = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Policy.objects.all(), required=False
    )
    deployments = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Deployment.objects.all(), required=False
    )

    class Meta:
        model = Baseline
        fields = (
            "id",
            "name",
            "description",
            "plat",
            "enabled",
            "policies",
            "deployments",
            "items",
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )
        read_only_fields = (
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )

    def validate_name(self, value):
        if not value.isprintable():
            raise serializers.ValidationError("No line breaks or control characters.")
        return value

    def validate_description(self, value):
        return self.validate_name(value) if value else value

    def validate(self, attrs):
        instance = self.instance
        if instance and attrs.get("plat", instance.plat) != instance.plat:
            raise serializers.ValidationError(
                {"plat": "The platform of a baseline is fixed, create a new one."}
            )
        items = attrs.get("items")
        if items is None:
            return attrs
        if len(items) > MAX_ITEMS:
            raise serializers.ValidationError(
                {"items": f"A baseline has at most {MAX_ITEMS} items."}
            )
        plat = instance.plat if instance else attrs["plat"]
        known = set(instance.items.values_list("pk", flat=True)) if instance else set()
        errors, cleaned = [], []
        for n, item in enumerate(items):
            try:
                if item.get("id") is not None and item["id"] not in known:
                    raise serializers.ValidationError(
                        {"id": "Not an item of this baseline."}
                    )
                cleaned.append(_item(item, plat, n))
                errors.append({})
            except serializers.ValidationError as e:
                errors.append(e.detail)
        if any(errors):
            raise serializers.ValidationError({"items": errors})
        attrs["items"] = cleaned
        return attrs

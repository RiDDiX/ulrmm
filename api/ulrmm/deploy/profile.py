# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Profile helpers shared by the Windows and Linux answer-file builders."""

from rest_framework import serializers
from rest_framework.fields import empty


def field_default(field):
    if field.default is not empty:
        return field.default() if callable(field.default) else field.default
    if isinstance(field, serializers.BooleanField):
        return False
    if isinstance(field, serializers.ListField):
        return []
    if isinstance(field, serializers.IntegerField):
        return None
    return ""


def serializer_defaults(serializer_cls) -> dict:
    """Every field of the serializer with its default, nested ones included;
    the wizard renders the profile form from this."""
    out = {}
    for name, field in serializer_cls().fields.items():
        if field.read_only:
            continue
        if isinstance(field, serializers.Serializer):
            out[name] = serializer_defaults(type(field))
        else:
            out[name] = field_default(field)
    return out


def prune_blank(data):
    """The profile without empty strings and nulls, so a field left empty in
    the form counts as not given and gets the serializer's default."""
    if isinstance(data, dict):
        return {k: prune_blank(v) for k, v in data.items() if v is not None and v != ""}
    return data

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import os
from typing import Any, Dict, List, Type

from django.apps import apps
from django.conf import settings
from django.db.models import BooleanField, CharField, Model

from .constants import REPORTING_MODELS, can_read, get_property_fields

SCHEMA_PATH = "reporting/schemas/query_schema.json"

# the queried model plus two levels of forward foreign keys
MAX_DEPTH = 2


def _field_type(field) -> Dict[str, Any]:
    if field.many_to_one or field.name == "id":
        return {"type": "integer"}
    if isinstance(field, CharField) and field.choices:
        return {"type": "string", "enum": [choice[0] for choice in field.choices]}
    if isinstance(field, BooleanField):
        return {"type": "boolean"}
    if "Integer" in field.get_internal_type():
        return {"type": "integer"}
    # datetimes, JSON and one-to-one relations in both directions
    return {"type": "string"}


def _walk(
    model: Type[Model],
    prefix: str,
    depth: int,
    fields: Dict[str, Any],
    related: List[str],
) -> None:
    for field in model._meta.get_fields():
        if field.many_to_many or field.one_to_many:
            continue
        # the paths the query engine accepts for an unrestricted user
        if not can_read(model._meta.label, field.name, unrestricted=True):
            continue
        path = f"{prefix}{field.name}"
        fields[path] = _field_type(field)
        if not field.many_to_one:
            continue
        related.append(path)
        if depth < MAX_DEPTH and can_read(
            field.related_model._meta.label, None, unrestricted=True
        ):
            _walk(field.related_model, f"{path}__", depth + 1, fields, related)


def _names_array(names: List[str]) -> Dict[str, Any]:
    return {"type": "array", "items": {"type": "string", "enum": names}}


def model_schema(model: Type[Model]) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    related: List[str] = []
    _walk(model, "", 0, fields, related)

    paths = list(fields)
    patterns = {f"^{path}(__[a-zA-Z]+)*$": {} for path in paths}
    lookups = {"type": "object", "properties": fields, "patternProperties": patterns}
    order = paths + [f"-{path}" for path in paths]

    return {
        "properties": {
            "model": {"type": "string", "enum": [model.__name__.lower()]},
            "filter": lookups,
            "exclude": lookups,
            "only": _names_array(paths),
            "defer": _names_array(paths),
            "values": _names_array(paths),
            "select_related": _names_array(related),
            "prefetch_related": {"type": "array", "items": {"type": "string"}},
            "order_by": {
                "anyOf": [
                    {"type": "string", "enum": order},
                    _names_array(order),
                ]
            },
            "properties": _names_array(get_property_fields(model)),
        }
    }


def build_query_schema() -> Dict[str, Any]:
    models = [apps.get_model(app, name) for name, app in REPORTING_MODELS]
    return {
        "$id": f"https://{settings.ALLOWED_HOSTS[0]}/static/{SCHEMA_PATH}",
        "type": "object",
        "required": ["model"],
        "properties": {
            "model": {"type": "string", "enum": [m.__name__.lower() for m in models]},
            "custom_fields": {"type": "array", "items": {"type": "string"}},
            "limit": {"type": "integer", "minimum": 0},
            "count": {"type": "boolean"},
            "first": {"type": "boolean"},
            "all": {"type": "boolean"},
            "json": {"type": "boolean"},
            "get": {"type": ["boolean", "object"]},
            "csv": {
                "type": ["boolean", "object"],
                "additionalProperties": {"type": "string"},
            },
        },
        "oneOf": [model_schema(model) for model in models],
    }


def write_query_schema() -> str:
    path = os.path.join(settings.STATICFILES_DIRS[0], SCHEMA_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(build_query_schema(), f)
    return path

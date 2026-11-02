# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Validation and the agent filter for dynamic group rules.

{"match": "all"|"any", "conditions": [{"field", "op", "value"}, ...]}
A custom_field condition puts the field pk in "custom_field".
Each condition is a database filter.
"""

import operator
from functools import reduce

from django.db.models import Exists, OuterRef, Q
from django.db.models.expressions import RawSQL
from rest_framework.serializers import ValidationError

from ulrmm.constants import AgentMonType, AgentPlat, CustomFieldModel, CustomFieldType
from ulrmm.helpers import agent_ver

MAX_CONDITIONS = 20
MAX_IN_VALUES = 100

OPS = {
    "plat": {"eq", "neq", "in"},
    "client": {"eq", "neq", "in"},
    "site": {"eq", "neq", "in"},
    "tag": {"eq", "neq", "in"},
    "hostname": {"contains", "starts"},
    "os": {"contains"},
    "status": {"eq", "neq", "in"},
    "monitoring_type": {"eq", "neq"},
    "agent_version": {"lt", "gte"},
    "software": {"contains"},
    "custom_field": {"eq", "contains"},
    "needs_reboot": {"eq"},
    "patches_failed": {"eq"},
}
STATUSES = ("online", "offline", "overdue")
CHOICES = {
    "plat": AgentPlat.values,
    "status": STATUSES,
    "monitoring_type": AgentMonType.values,
}
PKS = {"client", "site", "tag"}
BOOLS = {"needs_reboot", "patches_failed"}


def _value_error(field: str, value) -> str | None:
    if field in CHOICES:
        if value not in CHOICES[field]:
            return f"must be one of {', '.join(CHOICES[field])}"
    elif field in PKS:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            return "must be an id"
    elif field in BOOLS:
        if not isinstance(value, bool):
            return "must be true or false"
    elif not isinstance(value, str) or not value.strip() or len(value) > 255:
        return "must be text of 1 to 255 characters"
    return None


def _clean_condition(n: int, c) -> dict:
    def fail(msg: str):
        raise ValidationError(f"Condition {n}: {msg}")

    if not isinstance(c, dict):
        fail("must be an object")
    field, op = c.get("field"), c.get("op")
    if not isinstance(field, str) or field not in OPS:
        fail(f"unknown field {field!r}")
    if not isinstance(op, str) or op not in OPS[field]:
        fail(f"{field} does not support op {op!r}")
    allowed = {"field", "op", "value"}
    if field == "custom_field":
        allowed.add("custom_field")
    if set(c) - allowed:
        fail(f"unknown keys {sorted(set(c) - allowed)}")

    value = c.get("value")
    out = {"field": field, "op": op, "value": value}

    if field == "custom_field":
        from core.models import CustomField

        pk = c.get("custom_field")
        cf = None
        if isinstance(pk, int) and not isinstance(pk, bool):
            cf = CustomField.objects.filter(pk=pk, model=CustomFieldModel.AGENT).first()
        if not cf:
            fail("custom_field must be the id of an agent custom field")
        out["custom_field"] = pk
        if cf.type == CustomFieldType.CHECKBOX:
            if op != "eq" or not isinstance(value, bool):
                fail("a checkbox field only takes eq with true or false")
        elif err := _value_error(field, value):
            fail(f"value {err}")
    else:
        if op == "in" and (
            not isinstance(value, list) or not value or len(value) > MAX_IN_VALUES
        ):
            fail(f"value must be a list of 1 to {MAX_IN_VALUES} entries")
        for v in value if op == "in" else [value]:
            if err := _value_error(field, v):
                fail(f"value {err}")
        # an unreadable version sorts as 0: gte would match every agent
        if field == "agent_version" and agent_ver(value.strip()) == agent_ver(""):
            fail("value must be an agent version like 1.07.10.2026")

    if isinstance(value, str):
        out["value"] = value.strip()
    return out


def clean_rules(rules) -> dict:
    """Validated copy of rules, raises ValidationError."""
    from clients.models import Client, Site

    from .models import Tag

    if not isinstance(rules, dict) or set(rules) - {"match", "conditions"}:
        raise ValidationError("Rules must be an object with match and conditions.")
    match = rules.get("match", "all")
    if match not in ("all", "any"):
        raise ValidationError("match must be all or any.")
    conditions = rules.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise ValidationError("Add at least one condition.")
    if len(conditions) > MAX_CONDITIONS:
        raise ValidationError(f"At most {MAX_CONDITIONS} conditions.")

    cleaned = [_clean_condition(n, c) for n, c in enumerate(conditions, 1)]

    for field, model in (("client", Client), ("site", Site), ("tag", Tag)):
        pks = set()
        for c in cleaned:
            if c["field"] == field:
                pks.update(c["value"] if c["op"] == "in" else [c["value"]])
        if pks and model.objects.filter(pk__in=pks).count() != len(pks):
            raise ValidationError(f"Unknown {field} id in the conditions.")

    return {"match": match, "conditions": cleaned}


def _status_q(status: str) -> Q:
    # Q objects from core/stats.py. Agent.status is computed in python
    from core.stats import _offline_q, _overdue_q

    if status == "online":
        return Q(last_seen__isnull=False) & ~_offline_q()
    if status == "overdue":
        return _offline_q() & _overdue_q()
    return Q(last_seen__isnull=True) | (_offline_q() & ~_overdue_q())


def _software_q(name: str) -> Q:
    from software.models import InstalledSoftware

    table = InstalledSoftware._meta.db_table
    return Q(
        pk__in=RawSQL(
            f"SELECT s.agent_id FROM {table} s CROSS JOIN LATERAL "
            "jsonb_array_elements(CASE WHEN jsonb_typeof(s.software) = 'array' "
            "THEN s.software ELSE '[]'::jsonb END) e "
            "WHERE strpos(lower(e->>'name'), lower(%s)) > 0",
            (name,),
        )
    )


def _version_q(op: str, version: str) -> Q:
    from agents.models import Agent

    # agent_ver() orders dated and old semver versions, the database can't
    target = agent_ver(version)
    seen = Agent.objects.order_by().values_list("version", flat=True).distinct()
    return Q(version__in=[v for v in seen if (agent_ver(v) < target) == (op == "lt")])


def _custom_field_q(c: dict) -> Q:
    from agents.models import AgentCustomField
    from core.models import CustomField

    kind = (
        CustomField.objects.filter(pk=c["custom_field"])
        .values_list("type", flat=True)
        .first()
    )
    value = c["value"]
    if kind is None:
        return Q(pk__in=[])
    if kind == CustomFieldType.CHECKBOX:
        lookup = {"bool_value": value}
    elif kind == CustomFieldType.MULTIPLE:
        lookup = (
            {"multiple_value__contains": [value]}
            if c["op"] == "eq"
            else {"multiple_value__icontains": value}
        )
    elif c["op"] == "eq":
        lookup = {"string_value__iexact": value}
    else:
        lookup = {"string_value__icontains": value}

    return Q(
        Exists(
            AgentCustomField.objects.filter(
                agent_id=OuterRef("pk"), field_id=c["custom_field"], **lookup
            )
        )
    )


def condition_q(c: dict) -> Q:
    from winupdate.models import WinUpdate

    from .models import Tag

    field, op, value = c["field"], c["op"], c["value"]
    if op == "neq":
        return ~condition_q({**c, "op": "eq"})
    values = value if op == "in" else [value]

    if field == "plat":
        return Q(plat__in=values)
    if field == "client":
        return Q(site__client_id__in=values)
    if field == "site":
        return Q(site_id__in=values)
    if field == "tag":
        return Q(
            Exists(
                Tag.agents.through.objects.filter(
                    agent_id=OuterRef("pk"), tag_id__in=values
                )
            )
        )
    if field == "status":
        return reduce(operator.or_, (_status_q(s) for s in values))
    if field == "monitoring_type":
        return Q(monitoring_type=value)
    if field == "hostname":
        if op == "starts":
            return Q(hostname__istartswith=value)
        return Q(hostname__icontains=value)
    if field == "os":
        return Q(operating_system__icontains=value)
    if field == "agent_version":
        return _version_q(op, value)
    if field == "software":
        return _software_q(value)
    if field == "custom_field":
        return _custom_field_q(c)
    if field == "needs_reboot":
        return Q(needs_reboot=value)
    if field == "patches_failed":
        failed = Q(
            Exists(
                WinUpdate.objects.filter(
                    agent_id=OuterRef("pk"),
                    action="approve",
                    installed=False,
                    result="failed",
                )
            )
        )
        return failed if value else ~failed
    raise ValueError(field)


def rules_q(rules: dict) -> Q:
    """Agent filter for stored rules. No conditions match no agent."""
    conditions = (rules or {}).get("conditions") or []
    if not conditions:
        return Q(pk__in=[])
    join = operator.or_ if rules.get("match") == "any" else operator.and_
    return reduce(join, (condition_q(c) for c in conditions))

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Rows of the snapshot -> objects here, through the serializers the API
uses, so an import is checked like an edit in the dashboard. A row that does
not pass is left out with the reason; it never stops the others."""

from django.db import DataError, IntegrityError, transaction
from rest_framework.exceptions import ValidationError

from checks.serializers import CheckSerializer
from core.models import CustomField
from scripts.models import Script
from ulrmm.constants import AgentPlat, CheckType
from winupdate.models import WinUpdatePolicy
from winupdate.serializers import WinUpdatePolicySerializer

WINDOWS_ONLY = (CheckType.WINSVC, CheckType.EVENT_LOG)
SERVICE_PLATS = (AgentPlat.LINUX, AgentPlat.FREEBSD)


def key(*names) -> tuple:
    return tuple((n or "").lower() for n in names)


def reason(errors) -> str:
    """The first message of a serializer's errors."""
    while isinstance(errors, (dict, list)) and errors:
        if isinstance(errors, dict):
            name, errors = next(iter(errors.items()))
            if name != "non_field_errors" and isinstance(errors, list) and errors:
                return f"{name}: {errors[0]}"[:300]
        else:
            errors = errors[0]
    return str(errors)[:300] or "not valid"


def save(serializer, **extra):
    """(object, "") or (None, reason); a failed row rolls back alone."""
    if not serializer.is_valid():
        return None, reason(serializer.errors)
    try:
        with transaction.atomic():
            return serializer.save(**extra), ""
    except ValidationError as e:
        return None, reason(e.detail)
    except (IntegrityError, DataError):
        return None, "it does not fit into this installation"


class Refs:
    """Scripts and agent custom fields here, by name; loaded once per run,
    after the scripts part has written."""

    def __init__(self):
        self.scripts = {
            key(n, s): pk
            for pk, n, s in Script.objects.values_list("pk", "name", "shell")
        }
        self.fields = {
            n.lower(): pk
            for pk, n in CustomField.objects.filter(model="agent").values_list(
                "pk", "name"
            )
        }

    def script(self, ref):
        return self.scripts.get(key(ref["name"], ref["shell"])) if ref else None


def missing(row, kind: str, available) -> str:
    """Why a check or task cannot be taken, "" when it can. available(ref)
    tells whether a script reference resolves."""
    if kind == "checks":
        if row["fields"]["check_type"] == CheckType.SCRIPT and not available(
            row["script"]
        ):
            return _no_script(row["script"])
        return ""
    for action in row["actions"]:
        if action["type"] == "script" and not available(action["script"]):
            return _no_script(action["script"])
    if not row["actions"]:
        return "it has no actions"
    return ""


def _no_script(ref) -> str:
    if not ref:
        return "its script is not in the source's list"
    return f"script {ref['name']} is not here"


def checks(owner: dict, rows, refs: Refs, skip, prefix: str = "", plat: str = ""):
    """Creates the checks of a policy or agent; returns {ref: check}."""
    made = {}
    for row in rows:
        name = f"{prefix}{row['desc']}"
        why = missing(row, "checks", lambda r: refs.script(r) is not None)
        kind = row["fields"]["check_type"]
        if not why and plat and kind in WINDOWS_ONLY and plat != AgentPlat.WINDOWS:
            why = f"{kind} checks are only supported on Windows agents"
        if not why and plat and kind == CheckType.SYSTEMD and plat not in SERVICE_PLATS:
            why = "Service checks are only supported on Linux and FreeBSD agents"
        if why:
            skip(name, why)
            continue
        data = {**row["fields"], **owner, "script": refs.script(row["script"])}
        if kind == CheckType.EVENT_LOG and data.get("event_id_is_wildcard"):
            data["event_id"] = 0
        check, why = save(CheckSerializer(data=data, partial=True))
        if check is None:
            skip(name, why)
        elif row["ref"]:
            made[row["ref"]] = check
    return made


def tasks(owner: dict, rows, refs: Refs, made_checks: dict, skip, prefix: str = ""):
    """Creates the tasks of a policy or agent; returns the new tasks."""
    from autotasks.serializers import TaskSerializer

    done = []
    for row in rows:
        name = f"{prefix}{row['name']}"
        why = missing(row, "tasks", lambda r: refs.script(r) is not None)
        check = made_checks.get(row["assigned_check"])
        if not why and row["assigned_check"] and check is None:
            why = "its check was not imported"
        field = refs.fields.get(row["custom_field"].lower())
        if not why and row["custom_field"] and field is None:
            why = f"custom field {row['custom_field']} is not here"
        if why:
            skip(name, why)
            continue
        actions = [
            (
                {**a, "script": refs.script(a["script"])}
                if a["type"] == "script"
                else {k: v for k, v in a.items() if v is not None or k != "shell"}
            )
            for a in row["actions"]
        ]
        data = {
            **row["fields"],
            **owner,
            "actions": actions,
            "assigned_check": check.pk if check else None,
            "custom_field": field,
        }
        task, why = save(TaskSerializer(data=data))
        if task is None:
            skip(name, why)
        else:
            done.append(task)
    return done


def patch_policy(values: dict, skip, name: str, **owner) -> None:
    row = WinUpdatePolicy(**owner)
    if owner.get("agent") is not None:
        # a device that only inherits brings nothing; an edited one here stays
        if is_default(WinUpdatePolicy(**values)):
            return
        row = owner["agent"].winupdatepolicy.order_by("pk").first() or row
        if not is_default(row):
            return
    serializer = WinUpdatePolicySerializer(instance=row, data=values, partial=True)
    _, why = save(serializer, **owner)
    if why:
        skip(name, why)


def is_default(row: WinUpdatePolicy) -> bool:
    # an agent's own patch policy as enrollment creates it: everything inherits
    return all(
        getattr(row, f) == "inherit"
        for f in (
            "critical",
            "important",
            "moderate",
            "low",
            "other",
            "drivers",
            "run_time_frequency",
            "reboot_after_install",
        )
    )

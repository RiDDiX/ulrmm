# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
from typing import List, Optional, Type

from django.db.models import Model

from ulrmm.constants import CREDENTIAL_MODEL_LABELS

_READABLE_BY_APP = {
    "agents": "Agent Note AgentCustomField AgentHistory",
    "alerts": "Alert",
    "automation": "Policy",
    "autotasks": "AutomatedTask TaskResult",
    "checks": "Check CheckResult CheckHistory",
    "clients": "Client ClientCustomField Site SiteCustomField",
    "core": "GlobalKVStore",
    "logs": "AuditLog DebugLog PendingAction",
    "software": "ChocoSoftware InstalledSoftware",
    "winupdate": "WinUpdate WinUpdatePolicy",
}
# (model name, app label) pairs that data queries may read
REPORTING_MODELS = tuple(
    (name, app) for app, names in _READABLE_BY_APP.items() for name in names.split()
)

# readable only by superusers: secrets in the key store, cross-tenant logs
SUPERUSER_ONLY_MODELS = frozenset(
    ("core.GlobalKVStore", "logs.AuditLog", "logs.DebugLog")
)

# CoreSettings holds the SMTP, Twilio and mesh credentials
UNREADABLE_MODELS = CREDENTIAL_MODEL_LABELS | frozenset(("core.CoreSettings",))

# fields that hold secrets on models reports may otherwise read
SECRET_FIELDS = {
    # webhook URLs, headers and bodies carry tokens
    "core.URLAction": frozenset(("pattern", "rest_body", "rest_headers")),
    "scripts.Script": frozenset(("env_vars",)),
    "alerts.AlertTemplate": frozenset(("action_env_vars", "resolved_action_env_vars")),
}
# a safety net for fields added later
SECRET_FIELD_NAME = re.compile(r"password|secret|token|api_key")


def can_read(label: str, name: Optional[str], unrestricted: bool = False) -> bool:
    """Whether a report may read field or attribute name of the model label.

    Credential models and CoreSettings are not readable at all, the
    superuser-only reporting models only when unrestricted. On every other
    model only the fields that hold secrets are refused; name None asks about
    the model itself.
    """
    if label in UNREADABLE_MODELS:
        return False
    if label in SUPERUSER_ONLY_MODELS and not unrestricted:
        return False
    if name is None:
        return True
    if name in SECRET_FIELDS.get(label, ()):
        return False
    return not SECRET_FIELD_NAME.search(name)


# shared configuration a restricted role may query without a client scope
UNSCOPED_MODELS = frozenset(("automation.Policy", "software.ChocoSoftware"))

# models without a usable role filter, scoped through a parent:
# label -> (lookup on the model, parent model, parent field it matches)
SCOPE_THROUGH = {
    "clients.ClientCustomField": ("client", "clients.Client", "pk"),
    "clients.SiteCustomField": ("site", "clients.Site", "pk"),
    # agent_id holds the agent's agent_id text, it is not a foreign key
    "checks.CheckHistory": ("agent_id", "agents.Agent", "agent_id"),
}

CUSTOM_FIELD_MODELS = ("agent", "client", "site")

QUERY_OPERATIONS = (
    "only",
    "defer",
    "filter",
    "exclude",
    "limit",
    "get",
    "first",
    "all",
    "custom_fields",
    "properties",
    "json",
    "csv",
    "select_related",
    "prefetch_related",
    "count",
    "values",
    "order_by",
)

# accepted by the old engine, but they need ORM expressions a query cannot hold
UNSUPPORTED_OPERATIONS = ("annotate", "aggregate")

FLAG_OPERATIONS = ("count", "get", "first", "all", "json", "csv")

EXCLUDED_PROPERTIES = frozenset(("pk", "fields_that_trigger_task_update_on_agent"))


def get_property_fields(model: Type[Model]) -> List[str]:
    # the first class in the MRO that defines a name decides what it is
    seen = set()
    names = []
    for klass in model.__mro__:
        for name, attr in vars(klass).items():
            if name in seen:
                continue
            seen.add(name)
            if isinstance(attr, property) and name not in EXCLUDED_PROPERTIES:
                names.append(name)
    return sorted(names)

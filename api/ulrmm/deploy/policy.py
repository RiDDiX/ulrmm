# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The rotation policy an agent runs under: site override, then client
override, then the global settings."""

import secrets

from django.core.cache import cache

from .models import POLICY_FIELDS, POLICY_VER_KEY, RotationPolicy
from .pki import security_settings

TTL = 60


def _version() -> str:
    ver = cache.get(POLICY_VER_KEY)
    if ver is None:
        ver = secrets.token_hex(4)
        cache.add(POLICY_VER_KEY, ver, None)
        ver = cache.get(POLICY_VER_KEY) or ver
    return ver


def global_policy(sec=None) -> dict:
    return {f: getattr(sec or security_settings(), f) for f in POLICY_FIELDS}


def table() -> tuple[dict, dict, dict]:
    """(global, {client pk: override}, {site pk: override}) for bulk lookups."""
    by_client, by_site = {}, {}
    for row in RotationPolicy.objects.all():
        values = {f: getattr(row, f) for f in POLICY_FIELDS}
        if row.client_id is not None:
            by_client[row.client_id] = values
        else:
            by_site[row.site_id] = values
    return global_policy(), by_client, by_site


def resolve(site_id, client_id, tab) -> dict:
    base, by_client, by_site = tab
    out = dict(base)
    for over in (by_client.get(client_id), by_site.get(site_id)):
        if over:
            out.update({k: v for k, v in over.items() if v is not None})
    return out


def effective(agent) -> dict:
    """The policy of an agent (or its agent_id), cached a minute."""
    from agents.models import Agent

    agent_id = getattr(agent, "agent_id", agent)
    key = f"rotpol:{_version()}:{agent_id}"
    hit = cache.get(key)
    if hit is not None:
        return hit
    scope = (
        Agent.objects.filter(agent_id=agent_id)
        .values_list("site_id", "site__client_id")
        .first()
    ) or (None, None)
    out = resolve(scope[0], scope[1], table())
    cache.set(key, out, TTL)
    return out

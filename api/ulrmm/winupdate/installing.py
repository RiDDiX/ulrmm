# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import time

from django.core.cache import cache

# the scan request every sender uses; older agents ignore wua_drivers
SCAN_CMD = {"func": "getwinupdates", "wua_drivers": True}

INSTALLING_TTL = 4 * 60 * 60
CHECKIN_GRACE = 60


def _key(agent_pk: int) -> str:
    return f"winupdate-installing-{agent_pk}"


def _get_installing(agent_pk: int) -> dict[str, float]:
    key = _key(agent_pk)
    cached = cache.get(key) or {}
    installing = cached if isinstance(cached, dict) else dict.fromkeys(cached, 0)
    cutoff = time.time() - INSTALLING_TTL
    active = {
        guid: marked_at for guid, marked_at in installing.items() if marked_at >= cutoff
    }
    if active != installing:
        if active:
            cache.set(key, active, INSTALLING_TTL)
        else:
            cache.delete(key)
    return active


def get_installing(agent_pk: int) -> set[str]:
    return set(_get_installing(agent_pk))


def mark_installing(agent_pk: int, guids: list[str]) -> None:
    if not guids:
        return
    installing = _get_installing(agent_pk)
    installing.update(dict.fromkeys(guids, time.time()))
    if installing:
        cache.set(_key(agent_pk), installing, INSTALLING_TTL)


def clear_installing(agent_pk: int, guids: list[str]) -> None:
    installing = _get_installing(agent_pk)
    if installing.keys().isdisjoint(guids):
        return
    for guid in guids:
        installing.pop(guid, None)
    if installing:
        cache.set(_key(agent_pk), installing, INSTALLING_TTL)
    else:
        cache.delete(_key(agent_pk))


def clear_all_installing(agent_pk: int) -> None:
    cache.delete(_key(agent_pk))


def clear_stale_installing(agent_pk: int) -> None:
    installing = _get_installing(agent_pk)
    cutoff = time.time() - CHECKIN_GRACE
    fresh = {
        guid: marked_at for guid, marked_at in installing.items() if marked_at >= cutoff
    }
    if fresh == installing:
        return
    if fresh:
        cache.set(_key(agent_pk), fresh, INSTALLING_TTL)
    else:
        cache.delete(_key(agent_pk))

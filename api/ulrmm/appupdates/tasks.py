# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import json
import re
from collections import defaultdict
from zoneinfo import ZoneInfo

from django.db import transaction
from django.utils import timezone as djangotime

from agents.models import Agent, AgentHistory
from logs.models import DebugLog
from ulrmm.celery import app
from ulrmm.constants import (
    AGENT_DEFER,
    AgentHistoryType,
    AgentPlat,
    AppUpdatePolicy,
)
from ulrmm.utils import redis_lock

from .models import AppUpdate, AppUpdateScan, AppUpdateSettings, Source, State

# winget (Febooti.Hash&CRC, BRÖTJE.ProfiTool), brew (openssl@3) and mas ids, never
# an option. the agent checks the same; no comma, ids travel comma-joined
ID_RE = re.compile(r"^(?!-)[\w.+&!@-]{1,128}$")
# the agent takes at most this many ids per upgrade call
IDS_PER_CALL = 100
PLATS = (AgentPlat.WINDOWS, AgentPlat.DARWIN)
LIST_TIMEOUT = 120
UPGRADE_TIMEOUT = 600
CONCURRENCY = 10
# what an update run picks up
OPEN = (State.AVAILABLE, State.FAILED)
NO_ANSWER = (
    "No answer from the agent in time. Agent update required: "
    "older agents have no app updates."
)
LIST = {"func": "appupdates", "payload": {"action": "list"}}


def notify(event: dict) -> None:
    # the notify app is optional here
    try:
        from notify.dispatch import dispatch
    except ImportError:
        return
    try:
        dispatch(event)
    except Exception as e:
        DebugLog.error(message=f"App update notification failed: {e}")


def effective(agent: Agent, enabled: bool) -> tuple[bool, str]:
    """(on, where that comes from). agent > site > global"""
    if agent.app_updates != AppUpdatePolicy.INHERIT:
        return agent.app_updates == AppUpdatePolicy.ON, "agent"
    if agent.site.app_updates != AppUpdatePolicy.INHERIT:
        return agent.site.app_updates == AppUpdatePolicy.ON, "site"
    return enabled, "global"


def _answer(ret):
    # JSON text or msgpack, both are fine
    if isinstance(ret, str) and ret[:1] in ("[", "{"):
        try:
            return json.loads(ret)
        except ValueError:
            pass
    return ret


def _error(ret) -> str:
    if ret == "timeout":
        return NO_ANSWER
    if ret == "natsdown":
        return "NATS is not reachable."
    if isinstance(ret, str) and ret:
        return ret[:500]
    return "Unexpected answer from the agent."


def parse_list(ret) -> dict[tuple[str, str], dict]:
    """(source, app id) -> fields from the agent's list answer.
    Raises ValueError with the text to show."""
    ret = _answer(ret)
    if not isinstance(ret, list):
        raise ValueError(_error(ret))

    rows = {}
    for item in ret:
        if not isinstance(item, dict):
            continue
        source, app_id = item.get("source"), item.get("id")
        if source not in Source.values or not isinstance(app_id, str):
            continue
        if not ID_RE.fullmatch(app_id):
            continue
        rows[(source, app_id)] = {
            "name": str(item.get("name") or app_id)[:255],
            "installed": str(item.get("installed") or "")[:100],
            "available": str(item.get("available") or "")[:100],
        }
    return rows


def store(agent: Agent, rows: dict, error: str = "") -> None:
    """Rows the agent no longer lists go away, excluded ones stay as the marker."""
    now = djangotime.now()
    with transaction.atomic():
        AppUpdateScan.objects.update_or_create(
            agent=agent, defaults={"collected_at": now, "error": error}
        )
        if error:
            return

        existing = {
            (u.source, u.app_id): u for u in AppUpdate.objects.filter(agent=agent)
        }
        new, changed, gone = [], [], []
        for key, fields in rows.items():
            u = existing.pop(key, None)
            if u is None:
                new.append(
                    AppUpdate(
                        agent=agent, source=key[0], app_id=key[1], seen_at=now, **fields
                    )
                )
                continue
            # a failure stays visible until a newer version shows up
            same_failure = (
                u.state == State.FAILED and u.available == fields["available"]
            )
            if u.state != State.EXCLUDED and not same_failure:
                u.state = State.AVAILABLE
                u.last_error = ""
            for k, v in fields.items():
                setattr(u, k, v)
            u.seen_at = now
            changed.append(u)

        for u in existing.values():
            if u.state == State.EXCLUDED:
                u.available = ""
                changed.append(u)
            else:
                gone.append(u.pk)

        AppUpdate.objects.bulk_create(new)
        AppUpdate.objects.bulk_update(
            changed,
            ["name", "installed", "available", "seen_at", "state", "last_error"],
        )
        AppUpdate.objects.filter(pk__in=gone).delete()


async def _ask(agent: Agent, datas: list[dict], timeout: int, sem) -> list:
    """One agent's calls in a row, its package manager runs once at a time."""
    answers = []
    async with sem:
        for data in datas:
            try:
                answers.append(await agent.nats_cmd(data, timeout=timeout))
            except Exception as e:
                answers.append(str(e))
            # an old agent, the other calls would only wait as long
            if answers[-1] == "timeout":
                break
    return answers + ["timeout"] * (len(datas) - len(answers))


async def _ask_all(calls: list[tuple[Agent, list[dict]]], timeout: int) -> list:
    sem = asyncio.Semaphore(CONCURRENCY)
    return await asyncio.gather(*(_ask(a, d, timeout, sem) for a, d in calls))


def collect(agents: list[Agent]) -> int:
    """Asks each agent for its pending app updates. Returns how many answered."""
    answers = asyncio.run(_ask_all([(a, [LIST]) for a in agents], LIST_TIMEOUT))
    ok = 0
    for agent, (ret,) in zip(agents, answers):
        try:
            rows = parse_list(ret)
        except ValueError as e:
            store(agent, {}, str(e))
            continue
        store(agent, rows)
        ok += 1
    return ok


def _results(ret) -> dict[str, tuple[bool, str]] | str:
    """app id -> (ok, output tail), or the error text for the whole call."""
    ret = _answer(ret)
    results = ret.get("results") if isinstance(ret, dict) else None
    if not isinstance(results, list):
        return _error(ret)
    return {
        r["id"]: (r.get("ok") is True, str(r.get("output_tail") or "")[-500:])
        for r in results
        if isinstance(r, dict) and isinstance(r.get("id"), str)
    }


def apply(due: list[tuple[Agent, list[AppUpdate]]], username: str) -> tuple[int, int]:
    """Upgrades the rows, one call per source and IDS_PER_CALL ids.
    Returns (done, failed)."""
    per_agent = []
    for agent, rows in due:
        by_source = defaultdict(list)
        for u in rows:
            by_source[u.source].append(u)
        agent_calls = []
        for source, group in by_source.items():
            for i in range(0, len(group), IDS_PER_CALL):
                items = group[i : i + IDS_PER_CALL]
                ids = ",".join(u.app_id for u in items)
                data = {
                    "func": "appupdates",
                    "payload": {"action": "upgrade", "source": source, "ids": ids},
                }
                agent_calls.append((data, items))
        per_agent.append((agent, agent_calls))
    calls = [(a, data, items) for a, cs in per_agent for data, items in cs]

    AppUpdate.objects.filter(
        pk__in=[u.pk for *_, items in calls for u in items]
    ).update(state=State.UPDATING, last_error="")
    answers = [
        ret
        for rets in asyncio.run(
            _ask_all([(a, [d for d, _ in cs]) for a, cs in per_agent], UPGRADE_TIMEOUT)
        )
        for ret in rets
    ]

    done = failed = 0
    for (agent, data, items), ret in zip(calls, answers):
        results = _results(ret)
        lines = []
        for u in items:
            if isinstance(results, str):
                ok, tail = False, results
            else:
                ok, tail = results.get(u.app_id, (False, "No result from the agent."))
            u.state = State.DONE if ok else State.FAILED
            u.last_error = "" if ok else (tail or "Update failed.")[-500:]
            line = f"{u.app_id} {u.installed} -> {u.available}: "
            lines.append(line + ("ok" if ok else f"failed\n{u.last_error}"))
        AppUpdate.objects.bulk_update(items, ["state", "last_error"])

        failures = [u.app_id for u in items if u.state == State.FAILED]
        done += len(items) - len(failures)
        failed += len(failures)
        AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.APP_UPDATE,
            username=username[:255],
            command=f"{data['payload']['source']} upgrade {data['payload']['ids']}",
            results="\n".join(lines),
        )
        if failures:
            message = f"App updates failed on {agent.hostname}: {', '.join(failures)}"
            DebugLog.error(agent=agent, message=message)
            notify(
                {
                    "source": "appupdate",
                    "severity": "warning",
                    "title": f"App updates failed on {agent.effective_name}",
                    "body": message,
                    "agent": agent,
                    "dedupe_key": f"appupdate:{agent.agent_id}",
                }
            )
    return done, failed


def online(qs) -> list[Agent]:
    return [a for a in qs if a.is_online]


def due_agents(s: AppUpdateSettings, now) -> list[tuple[Agent, list[AppUpdate]]]:
    """Online agents with effective on, at s.hour in their time zone."""
    pending = AppUpdate.objects.filter(state__in=OPEN).exclude(available="")
    agents = (
        Agent.objects.defer(*AGENT_DEFER)
        .select_related("site")
        .filter(plat__in=PLATS, pk__in=pending.values("agent_id"))
        .order_by("pk")
    )
    due = []
    for agent in online(agents):
        if not effective(agent, s.enabled)[0]:
            continue
        if now.astimezone(ZoneInfo(agent.timezone)).hour != s.hour:
            continue
        rows = list(pending.filter(agent=agent).exclude(app_id__in=s.exclusions))
        if rows:
            due.append((agent, rows))
            # the rest waits for the next day's run
            if len(due) >= s.max_per_run:
                break
    return due


@app.task(bind=True)
def collect_app_updates_task(self) -> str:
    with redis_lock("appupdates-collect", self.app.oid) as acquired:
        if not acquired:
            return "App update collection already running"
        agents = online(Agent.objects.defer(*AGENT_DEFER).filter(plat__in=PLATS))
        return f"{collect(agents)} of {len(agents)} agents listed their app updates"


@app.task(bind=True)
def apply_app_updates_task(self, pks: list[int] | None = None, username="system"):
    if pks is not None:
        # dashboard run, the view picked and marked the rows
        grouped = defaultdict(list)
        for u in AppUpdate.objects.select_related("agent").filter(pk__in=pks):
            grouped[u.agent].append(u)
        done, failed = apply(list(grouped.items()), username)
        return f"{done} app updates installed, {failed} failed"

    with redis_lock("appupdates-apply", self.app.oid) as acquired:
        if not acquired:
            return "App updates already running"
        due = due_agents(AppUpdateSettings.load(), djangotime.now())
        done, failed = apply(due, "system")
        return f"{done} app updates installed, {failed} failed on {len(due)} agents"

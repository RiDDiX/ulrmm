# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The backup settings of a device: builtin defaults, then the global, client,
site, group and tag policies, the assigned policy and the device's own
overrides."""

import hashlib
import json
import logging
import secrets
from datetime import UTC, date, datetime, time, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from celery.schedules import crontab
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from patches import recurrence

from .models import (
    LINUX_FILES_METHOD,
    BackupPolicy,
    HoldStatus,
    Image,
    NativeInventory,
    Pairing,
    PolicyChangeHold,
    StorageTarget,
)

logger = logging.getLogger(__name__)
VER_KEY = "imaging:polver"
TTL = 60
GLOBAL_NAME = "Global default"
HOLD_CAUSES = ("tag", "group_rule", "site_move", "beat")
DEFAULT_ORIGIN = {"level": "default", "id": None, "name": GLOBAL_NAME}
DEVICE_ORIGIN = {"level": "device", "id": None, "name": ""}
DEFAULTS = {
    "network_mode": "internet",
    "compression": "gzip",
    "compression_level": 6,
    "schedule": {"kind": "none"},
    "schedule_events": [],
    "min_spacing_minutes": 60,
    "catch_up": "run_asap",
    "catch_up_delay_minutes": 10,
    "windows_allowed": [],
    "windows_blackout": [],
    "stop_at_window_end": False,
    "timezone": "",
    "keep_last": 0,
    "gfs": {"hourly": 0, "daily": 0, "weekly": 0, "monthly": 0, "yearly": 0},
    "quota_bytes": 0,
    "volumes": [],
    "auto_setup": "safe",
    "hooks": [],
    "throttle": {"default_kbps": 0, "rules": []},
    "on_battery": "defer",
    "pause_on_battery": True,
    "pause_max_minutes": 30,
    "keep_awake": True,
    "priority": "background",
    "smart": "warn",
    "rpo_hours": 0,
    "alert_failures": 3,
}
SCHEDULE_KEYS = ("schedule", "timezone", "min_spacing_minutes")
SNAPSHOT_KEYS = {"client": "client", "site": "site", "group": "groups", "tag": "tags"}
PROFILE_FIELDS = (
    "effective",
    "target_id",
    "destination",
    "network_mode",
    "compression",
    "compression_level",
    "schedule_time",
    "timezone",
    "keep_last",
    "volumes",
    "next_run",
)


def canonical(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(doc) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def _version() -> str:
    ver = cache.get(VER_KEY)
    if ver is None:
        ver = secrets.token_hex(4)
        cache.add(VER_KEY, ver, None)
        ver = cache.get(VER_KEY) or ver
    return ver


def invalidate():
    transaction.on_commit(
        lambda: cache.set(VER_KEY, secrets.token_hex(4), None), robust=True
    )


def _row(p):
    return {
        "id": p.pk,
        "name": p.name,
        "scope": p.scope,
        "client": p.client_id,
        "site": p.site_id,
        "group": p.group_id,
        "tag": p.tag_id,
        "priority": p.priority,
        "created_at": p.created_at,
        "config": p.config,
        "enforced": p.enforced,
        "hooks_pinned": p.hooks_pinned,
    }


def global_policy():
    policy = BackupPolicy.objects.filter(scope="global").first()
    if policy is None:
        policy, _ = BackupPolicy.objects.get_or_create(
            scope="global", defaults={"name": GLOBAL_NAME, "config": {}}
        )
    return policy


def table() -> dict:
    """Policies by level and the target rows, cached under the version key."""
    key = f"imaging:poltab:{_version()}"
    hit = cache.get(key)
    if hit is not None:
        return hit
    global_policy()
    tab = {
        "global": None,
        "client": {},
        "site": {},
        "group": {},
        "tag": {},
        "policies": {},
        "targets": {},
        "default": None,
    }
    for p in BackupPolicy.objects.order_by("pk"):
        row = tab["policies"][p.pk] = _row(p)
        if p.scope == "global":
            tab["global"] = row
        elif p.scope in ("client", "site"):
            tab[p.scope][row[p.scope]] = row
        elif p.scope in ("group", "tag"):
            tab[p.scope].setdefault(row[p.scope], []).append(row)
    for t in StorageTarget.objects.order_by("pk"):
        tab["targets"][t.pk] = {
            "id": t.pk,
            "name": t.name,
            "kind": t.kind,
            "scope": t.scope,
            "client": t.client_id,
            "site": t.site_id,
            "unreachable_since": t.unreachable_since,
        }
        if t.is_default:
            tab["default"] = t.pk
    cache.set(key, tab, TTL)
    return tab


def group_sets() -> dict:
    from groups.models import DeviceGroup

    return {
        g.pk: {
            "kind": g.kind,
            "modified_by": g.modified_by,
            "agents": set(g.agents().values_list("pk", flat=True)),
        }
        for g in DeviceGroup.objects.all()
    }


def memberships(agent, groups) -> dict:
    return {
        "client": agent.site.client_id,
        "site": agent.site_id,
        "groups": sorted(pk for pk, g in groups.items() if agent.pk in g["agents"]),
        "tags": sorted(agent.tags.values_list("pk", flat=True)),
    }


def _files(agent) -> bool:
    cap = NativeInventory.objects.filter(agent=agent).values_list(
        "capability", flat=True
    )
    return bool(cap) and (cap[0] or {}).get("method") == LINUX_FILES_METHOD


def builtin(tab, files) -> dict:
    # the file stream pads to the block grid; level 1 squeezes that as well
    return {
        "target": tab["default"],
        **DEFAULTS,
        "compression_level": 1 if files else 6,
    }


def _shared(members, tab):
    rows = [p for g in members.get("groups", ()) for p in tab["group"].get(g, ())]
    rows += [p for t in members.get("tags", ()) for p in tab["tag"].get(t, ())]
    # higher priority wins; at equal priority the older policy is applied last
    rows.sort(key=lambda p: (p["created_at"], p["id"]), reverse=True)
    rows.sort(key=lambda p: p["priority"])
    return rows


def compute(profile, members, tab, files):
    """({field: {value, origin, locked}}, conflicts) for one membership set."""
    fields = {
        k: {"value": v, "origin": DEFAULT_ORIGIN, "locked": False}
        for k, v in builtin(tab, files).items()
    }
    shared = _shared(members, tab)
    layers = [
        tab["global"],
        tab["client"].get(members.get("client")),
        tab["site"].get(members.get("site")),
        *shared,
        tab["policies"].get(profile.policy_id) if profile.policy_id else None,
    ]
    for p in filter(None, layers):
        origin = {"level": p["scope"], "id": p["id"], "name": p["name"]}
        for key, value in p["config"].items():
            if key in fields and not fields[key]["locked"]:
                fields[key] = {
                    "value": value,
                    "origin": origin,
                    "locked": key in p["enforced"],
                }
    for key, value in (profile.overrides or {}).items():
        if key in fields and not fields[key]["locked"]:
            fields[key] = {"value": value, "origin": DEVICE_ORIGIN, "locked": False}
    if fields["compression"]["value"] == "none":
        fields["compression_level"] = {**fields["compression_level"], "value": 0}
    seen = {}
    for p in shared:
        for key in p["config"]:
            seen.setdefault((key, p["priority"]), []).append(p["id"])
    conflicts = [
        {"field": key, "policies": sorted(ids)}
        for (key, _), ids in sorted(seen.items())
        if len(ids) > 1
    ]
    return fields, conflicts


def values(fields, agent) -> dict:
    out = {k: f["value"] for k, f in fields.items()}
    out["timezone"] = out["timezone"] or agent.timezone
    return out


def _column_schedule(profile):
    if profile.schedule_time is None:
        return {"kind": "none"}
    return {"kind": "daily", "time": profile.schedule_time.strftime("%H:%M")}


def _local(day, at, zone):
    # the recurrence rule: a spring-gap time moves forward, an ambiguous one runs first
    return datetime.combine(day, at, tzinfo=zone).astimezone(UTC)


def _cron(expr, zone, after):
    parts = expr.split()
    c = crontab(
        minute=parts[0],
        hour=parts[1],
        day_of_month=parts[2],
        month_of_year=parts[3],
        day_of_week=parts[4],
    )
    first = after.astimezone(zone).date()
    for i in range(367):
        day = first + timedelta(days=i)
        if (
            day.month in c.month_of_year
            and day.day in c.day_of_month
            and day.isoweekday() % 7 in c.day_of_week
        ):
            for hour in sorted(c.hour):
                for minute in sorted(c.minute):
                    start = _local(day, time(hour, minute), zone)
                    if start > after:
                        return start
    return None


def _calendar(schedule, zone, after):
    rule = SimpleNamespace(
        **{
            **schedule,
            "run_time": time.fromisoformat(schedule["run_time"]),
            "dates": [date.fromisoformat(d) for d in schedule["dates"]],
            "excluded_dates": [
                date.fromisoformat(d) for d in schedule["excluded_dates"]
            ],
            "start_date": schedule["start_date"]
            and date.fromisoformat(schedule["start_date"]),
            "end_date": schedule["end_date"]
            and date.fromisoformat(schedule["end_date"]),
        }
    )
    starts = recurrence.upcoming(rule, zone, after, timedelta(0), 1)
    return starts[0] if starts else None


def _occurrence(effective, state, after, agent):
    schedule = effective["schedule"]
    zone = ZoneInfo(effective["timezone"] or agent.timezone)
    kind = schedule["kind"]
    if kind == "daily":
        local = after.astimezone(zone)
        at = _local(local.date(), time.fromisoformat(schedule["time"]), zone)
        if at <= after:
            at = _local(
                local.date() + timedelta(days=1),
                time.fromisoformat(schedule["time"]),
                zone,
            )
        return at
    if kind == "interval":
        last = state.last_success_at if state else None
        return last + timedelta(hours=schedule["hours"]) if last else after
    if kind == "calendar":
        return _calendar(schedule, zone, after)
    if kind == "cron":
        return _cron(schedule["expr"], zone, after)
    return None


def next_occurrence(effective, state, after, agent):
    """The next due time in UTC, at least min_spacing after the newest point."""
    occurrence = _occurrence(effective, state, after, agent)
    if occurrence is None:
        return None
    newest = (
        Image.objects.filter(agent=agent)
        .order_by("-created_at")
        .values_list("created_at", flat=True)
        .first()
    )
    if newest:
        occurrence = max(
            occurrence, newest + timedelta(minutes=effective["min_spacing_minutes"])
        )
    return occurrence


def missed(effective, state, old, now, agent):
    """Occurrences from the old due time up to now, at most 1,000."""
    schedule = effective.get("schedule") or {"kind": "none"}
    count, at = 0, old
    while at is not None and at <= now and count < 1000 and schedule["kind"] != "none":
        count += 1
        at = (
            at + timedelta(hours=schedule["hours"])
            if schedule["kind"] == "interval"
            else _occurrence(effective, state, at, agent)
        )
    return count


def rpo(effective, agent, now):
    """How old the last verified point may get before the device is stale."""
    if effective.get("rpo_hours"):
        return timedelta(hours=effective["rpo_hours"])
    schedule = effective.get("schedule") or {"kind": "none"}
    if schedule["kind"] == "interval":
        return timedelta(hours=2 * schedule["hours"])
    if schedule["kind"] == "daily":
        return timedelta(hours=48)
    if schedule["kind"] in ("calendar", "cron"):
        first = _occurrence(effective, None, now, agent)
        second = first and _occurrence(effective, None, first, agent)
        return 2 * (second - first) if second else None
    return None


def _ranges(ranges, zone, now, days_ahead):
    """(start, end) in UTC of the weekly ranges from yesterday on."""
    today = now.astimezone(zone).date()
    for offset in range(-1, days_ahead + 1):
        day = today + timedelta(days=offset)
        for r in ranges:
            if day.isoweekday() not in r["days"]:
                continue
            start, end = time.fromisoformat(r["start"]), time.fromisoformat(r["end"])
            # an end at or before the start runs past midnight
            yield _local(day, start, zone), _local(
                day + timedelta(days=1) if end <= start else day, end, zone
            )


def window(effective, agent, now):
    """(allowed, stop_at) of the backup windows at `now` (contract 7.4)."""
    zone = ZoneInfo(effective["timezone"] or agent.timezone)
    allowed = [
        end
        for start, end in _ranges(effective["windows_allowed"], zone, now, 0)
        if start <= now < end
    ]
    blackout = list(_ranges(effective["windows_blackout"], zone, now, 7))
    if (effective["windows_allowed"] and not allowed) or any(
        start <= now < end for start, end in blackout
    ):
        return False, None
    if not effective["stop_at_window_end"]:
        return True, None
    ends = [max(allowed)] if allowed else []
    ends += [start for start, _ in blackout if now < start <= now + timedelta(days=7)]
    return True, min(ends) if ends else None


def target_of(tab, target_id):
    # a target that is gone falls back to the default, as the materialised columns do
    return tab["targets"].get(target_id) or tab["targets"][tab["default"]]


def pinned_hooks(fields, profile, tab) -> dict:
    """The pinned script hashes of the level the effective hooks come from."""
    origin = fields["hooks"]["origin"]
    if origin["level"] == "device":
        return profile.hooks_pinned or {}
    return (tab["policies"].get(origin["id"]) or {}).get("hooks_pinned") or {}


def render(agent, fields, tab, profile) -> dict:
    """The config document an agent receives; no secret, no float, no hook:
    hooks travel only in the sealed claim."""
    v = {k: f["value"] for k, f in fields.items()}
    target = target_of(tab, v["target"])
    return {
        "schema": 1,
        "agent_id": agent.agent_id,
        "target": {"id": target["id"], "kind": target["kind"], "name": target["name"]},
        "network_mode": v["network_mode"],
        "compression": v["compression"],
        "compression_level": v["compression_level"],
        "volumes": v["volumes"],
        "auto_setup": v["auto_setup"],
        "smart": v["smart"],
        "priority": v["priority"],
        "keep_awake": v["keep_awake"],
        "on_battery": v["on_battery"],
        "pause_on_battery": v["pause_on_battery"],
        "pause_max_minutes": v["pause_max_minutes"],
        "throttle": v["throttle"],
        "schedule_events": v["schedule_events"],
        "hooks": [],
        "timezone": v["timezone"] or agent.timezone,
    }


def _differences(old, new):
    out = [k for k in ("client", "site") if old.get(k) != new.get(k)]
    for k in ("groups", "tags"):
        out += [(k, pk) for pk in sorted(set(old.get(k, ())) ^ set(new.get(k, ())))]
    return out


def _hold(agent, profile, state, current, cause, author, tab, groups, files):
    """The memberships to apply: the current ones, or the snapshot while a
    change waits for confirmation. The profile row is locked already."""
    from accounts.models import User

    from .service import agent_allowed, audit

    held = values(compute(profile, state.memberships, tab, files)[0], agent)
    proposed = values(compute(profile, current, tab, files)[0], agent)
    held_hash, proposed_hash = digest(held), digest(proposed)
    hold = (
        PolicyChangeHold.objects.select_for_update()
        .filter(agent=agent, status=HoldStatus.PENDING)
        .first()
    )
    stored, editors_ok = cause, False
    # a change that moves hooks applies by itself only for a user who may run scripts
    hooks_moved = held["hooks"] != proposed["hooks"]

    def may(user):
        return agent_allowed(user, agent, "can_manage_images") and (
            not hooks_moved or agent_allowed(user, agent, "can_run_scripts")
        )

    if cause == "beat":
        diff = _differences(state.memberships, current)
        dynamic = all(
            isinstance(d, tuple)
            and d[0] == "groups"
            and groups.get(d[1], {}).get("kind") == "dynamic"
            for d in diff
        )
        stored, author = "unknown", None
        if dynamic:
            stored = "group_member"
            names = {groups[pk]["modified_by"] for _, pk in diff}
            editors = list(User.objects.filter(username__in=names - {None}))
            refused = [u for u in editors if not may(u)]
            editors_ok = len(editors) == len(names) and not refused
            author = refused[0] if refused else None
    else:
        editors_ok = author is not None and may(author)
    # while a change is held nothing applies by itself, whoever causes the next event
    if hold is None:
        if held_hash == proposed_hash or editors_ok:
            return current
        if PolicyChangeHold.objects.filter(
            agent=agent,
            status=HoldStatus.REJECTED,
            confirmed_by__isnull=False,
            proposed_hash=proposed_hash,
        ).exists():
            return state.memberships
    elif held_hash == proposed_hash:
        # nothing is left to confirm
        _withdraw(agent)
        return current
    changed = hold is None or hold.proposed_hash != proposed_hash
    # only a new membership event names a new cause and author
    if hold is None or hold.proposed_memberships != current:
        hold = hold or PolicyChangeHold(agent=agent)
        hold.cause = stored
        hold.author = author
    if changed:
        who = hold.author.username if hold.author else None
        audit(
            agent,
            who or "imaging",
            f"Backup settings change of {agent.hostname} held for confirmation "
            f"({hold.cause} by {who or 'unknown'}).",
        )
    hold.held_hash = held_hash
    hold.proposed_hash = proposed_hash
    hold.proposed_memberships = current
    hold.save()
    return state.memberships


def _withdraw(agent):
    from .service import audit

    for hold in PolicyChangeHold.objects.select_for_update().filter(
        agent=agent, status=HoldStatus.PENDING
    ):
        hold.status = HoldStatus.REJECTED
        hold.confirmed_at = timezone.now()
        hold.save(update_fields=["status", "confirmed_at"])
        audit(agent, "imaging", f"Held backup settings change {hold.pk} withdrawn.")


def resolve_device(agent, *, cause, author=None, tab=None, groups=None, members=None):
    """Resolve and materialise one device; returns (profile, state)."""
    from .service import backup_rows, update_usage
    from .tasks import wake_imaging_agent

    tab = tab or table()
    files = _files(agent)
    with transaction.atomic():
        profile, state = backup_rows(agent, lock=True)
        first = state.config_version == 0
        if members is None:
            groups = group_sets() if groups is None else groups
            current = memberships(agent, groups)
            members = state.memberships or current
            if state.memberships and state.memberships == current:
                _withdraw(agent)
            elif cause in HOLD_CAUSES and state.memberships:
                members = _hold(
                    agent, profile, state, current, cause, author, tab, groups, files
                )
        fields, _ = compute(profile, members, tab, files)
        vals = values(fields, agent)
        now = timezone.now()
        old = profile.effective or {
            "schedule": _column_schedule(profile),
            "timezone": profile.timezone,
            "min_spacing_minutes": DEFAULTS["min_spacing_minutes"],
        }
        target = target_of(tab, vals["target"])
        before = [getattr(profile, f) for f in PROFILE_FIELDS]
        kept = (
            state.effective_hash,
            state.memberships,
            state.config_hash,
            state.schedule_since,
        )
        old_mode = profile.network_mode
        schedule = vals["schedule"]
        profile.effective = vals
        profile.target_id = target["id"]
        profile.destination = target["name"]
        profile.network_mode = vals["network_mode"]
        profile.compression = vals["compression"]
        profile.compression_level = vals["compression_level"]
        profile.schedule_time = (
            time.fromisoformat(schedule["time"])
            if schedule["kind"] == "daily"
            else None
        )
        profile.timezone = vals["timezone"]
        profile.keep_last = vals["keep_last"]
        profile.volumes = vals["volumes"]
        if any(old.get(k) != vals[k] for k in SCHEDULE_KEYS) or (
            profile.next_run is None and schedule["kind"] != "none"
        ):
            profile.next_run = next_occurrence(vals, state, now, agent)
        # the beat resolves every device; unchanged rows are not written
        if [getattr(profile, f) for f in PROFILE_FIELDS] != before:
            profile.save()
        if vals["network_mode"] != old_mode:
            Pairing.objects.filter(agent=agent).exclude(
                network_mode=vals["network_mode"]
            ).delete()
        if schedule["kind"] != "none" and old.get("schedule", {}).get("kind") in (
            None,
            "none",
        ):
            state.schedule_since = now
        state.effective_hash = digest(vals)
        state.memberships = members
        text = canonical(render(agent, fields, tab, profile))
        config_hash = hashlib.sha256(text).hexdigest()
        if config_hash != state.config_hash:
            state.config_version += 1
            state.config_doc = text.decode("utf-8")
            state.config_hash = config_hash
            state.pending_since = now
            agent_id = agent.agent_id
            transaction.on_commit(
                lambda: wake_imaging_agent.delay(agent_id), robust=True
            )
        if (
            state.effective_hash,
            state.memberships,
            state.config_hash,
            state.schedule_since,
        ) != kept:
            state.save()
        if first:
            update_usage(agent, state)
    return profile, state


def resolve_now(agent_pks, *, cause, author=None):
    from agents.models import Agent

    tab, groups = table(), group_sets()
    for agent in (
        Agent.objects.filter(pk__in=agent_pks).select_related("site").order_by("pk")
    ):
        # one device whose settings cannot resolve must not stop the others
        try:
            resolve_device(agent, cause=cause, author=author, tab=tab, groups=groups)
        except Exception:
            logger.exception("Backup settings of agent %s not resolved", agent.agent_id)


def resolve_many(agent_pks, *, cause, author=None):
    pks = sorted(set(agent_pks))
    if pks:
        transaction.on_commit(
            lambda: resolve_now(pks, cause=cause, author=author), robust=True
        )


def rows(agent):
    """(profile, state) of a device, resolved once if it never was."""
    from .service import backup_rows

    profile, state = backup_rows(agent)
    if not state.config_version:
        profile, state = resolve_device(agent, cause="enrol")
    return profile, state


def _hold_view(agent, profile, state, tab, files):
    hold = PolicyChangeHold.objects.filter(
        agent=agent, status=HoldStatus.PENDING
    ).first()
    if hold is None:
        return None
    held = values(compute(profile, state.memberships, tab, files)[0], agent)
    proposed = values(compute(profile, hold.proposed_memberships, tab, files)[0], agent)
    return {
        "id": hold.pk,
        "cause": hold.cause,
        "author": hold.author.username if hold.author else None,
        "created_at": hold.created_at,
        # what the hold applies now, so a confirm binds to the change it shows
        "proposed_hash": digest(proposed),
        "changes": [
            {"field": k, "held": held[k], "proposed": proposed[k]}
            for k in held
            if held[k] != proposed[k]
        ],
    }


def live_hash(agent, profile, hold, tab):
    """The proposed_hash of a hold's view, for answers that show only the hold."""
    proposed = compute(profile, hold.proposed_memberships, tab, _files(agent))[0]
    return digest(values(proposed, agent))


def effective(agent, profile=None, state=None) -> dict:
    """The effective view with origins, locks, conflicts and the pending hold."""
    if profile is None or state is None:
        profile, state = rows(agent)
    tab, files = table(), _files(agent)
    members = state.memberships or memberships(agent, group_sets())
    fields, conflicts = compute(profile, members, tab, files)
    return {
        "fields": fields,
        "conflicts": conflicts,
        "hold": _hold_view(agent, profile, state, tab, files),
    }


def reaches(policy, profile, members) -> bool:
    """Whether a policy row of the table reaches one device by its snapshot."""
    scope = policy["scope"]
    if scope == "global":
        return True
    if scope == "assigned":
        return profile.policy_id == policy["id"]
    got = (members or {}).get(SNAPSHOT_KEYS[scope])
    return got == policy[scope] or (isinstance(got, list) and policy[scope] in got)


def reach_context():
    """The reads reach() needs, done once for a list of policies."""
    from agents.models import Agent

    from .models import DeviceBackupState

    fresh = list(
        Agent.objects.exclude(backup_state__memberships__has_key="site").values_list(
            "pk", "site_id", "site__client_id"
        )
    )
    return {
        "everyone": set(Agent.objects.values_list("pk", flat=True)),
        "snapshots": list(
            DeviceBackupState.objects.values_list("agent_id", "memberships")
        ),
        "fresh": fresh,
        "tags": set(
            Agent.tags.through.objects.filter(
                agent_id__in=[pk for pk, _, _ in fresh]
            ).values_list("agent_id", "tag_id")
        ),
    }


def reach(policy, groups=None, ctx=None):
    """Agent pks a policy reaches now, by the stored membership snapshots."""
    scope = policy.scope
    if ctx is None and scope in ("global", "assigned"):
        from agents.models import Agent

        if scope == "global":
            return set(Agent.objects.values_list("pk", flat=True))
        return set(policy.profile_set.values_list("agent_id", flat=True))
    if scope == "global":
        return set(ctx["everyone"])
    if scope == "assigned":
        return {p.agent_id for p in policy.profile_set.all()}
    ctx = ctx or reach_context()
    key = SNAPSHOT_KEYS[scope]
    value = getattr(policy, f"{scope}_id")
    out = set()
    for agent_id, members in ctx["snapshots"]:
        got = (members or {}).get(key)
        if got == value or (isinstance(got, list) and value in got):
            out.add(agent_id)
    # devices not resolved yet follow their current membership
    if scope == "client":
        out |= {pk for pk, _, client in ctx["fresh"] if client == value}
    elif scope == "site":
        out |= {pk for pk, site, _ in ctx["fresh"] if site == value}
    elif scope == "tag":
        out |= {pk for pk, tag in ctx["tags"] if tag == value}
    else:
        groups = group_sets() if groups is None else groups
        members = groups.get(value, {}).get("agents", set())
        out |= {pk for pk, _, _ in ctx["fresh"] if pk in members}
    return out

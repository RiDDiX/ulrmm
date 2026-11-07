# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""maintenance windows + sleep/wake schedules. one pass/min.

per (schedule, agent, occurrence) a ScheduleRun. every step fails open:
sleep only if we woke it, not server, idle >=15min. error/timeout/unknown
=> leave awake.

maint: wake, keepawake till end, scan+install per policy, then idle+sleep.
sleep: idle then suspend.
wake: wol + keepawake for duration.

win re-sleeps after ~120s; resend keepawake each pass while it answers.
agent drops prior hold on restart.
"""

import asyncio
import datetime as dt
import time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db.models import Q

from accounts.models import User
from agents.models import Agent
from agents.utils import wake_agents
from core.utils import get_mesh_ws_url, wake_on_lan
from logs.models import AuditLog, DebugLog
from ulrmm.constants import AgentMonType, DebugLogType
from ulrmm.permissions import _has_perm
from winupdate.installing import SCAN_CMD, mark_installing
from winupdate.posix import managed_reason

from .models import MaintenanceSchedule, RunState, ScheduleKind, ScheduleRun
from .recurrence import current

# a maintenance window also wakes and suspends, so it needs those flags too
KIND_PERMS = {
    ScheduleKind.MAINTENANCE: (
        "can_manage_patch_policies",
        "can_send_wol",
        "can_reboot_agents",
    ),
    ScheduleKind.SLEEP: ("can_reboot_agents",),
    ScheduleKind.WAKE: ("can_send_wol",),
}
ACTIVE = (
    RunState.NEW,
    RunState.WAKING,
    RunState.SCANNING,
    RunState.SCANNED,
    RunState.INSTALLING,
    RunState.INSTALLED,
    RunState.REBOOTING,
    RunState.IDLE_WAIT,
)
PINGED = (RunState.NEW, RunState.WAKING, RunState.REBOOTING, RunState.IDLE_WAIT)
IDLE_SECS = 900
WAKE_SPAN = dt.timedelta(minutes=30)
WAKE_RETRY = dt.timedelta(minutes=5)
MAX_WAKES = 4
SCAN_WAIT = dt.timedelta(minutes=30)
REBOOT_WAIT = dt.timedelta(minutes=3)
HOLD_FOR = 45
HOLD_POLL = 5
KEEP_RUNS = dt.timedelta(days=60)


def kind_allowed(request, kind) -> bool:
    return all(_has_perm(request, p) for p in KIND_PERMS[kind])


def target_agents(schedule):
    return Agent.objects.filter(
        Q(agent_id__in=schedule.agents)
        | Q(site_id__in=schedule.sites)
        | Q(site__client_id__in=schedule.clients)
    )


def eligible(schedule) -> tuple[set[int], str]:
    """Targets the schedule may act on now, or why none."""
    if not schedule.enabled:
        return set(), "the schedule is disabled"

    username = schedule.modified_by or schedule.created_by
    user = User.objects.filter(
        username=username, is_active=True, is_installer_user=False, agent=None
    ).first()
    if not user or not kind_allowed(SimpleNamespace(user=user), schedule.kind):
        return set(), f"{username} no longer holds the permission for it"

    scope = Agent.objects.filter_by_role(user).values("pk")  # type: ignore
    return (
        set(target_agents(schedule).filter(pk__in=scope).values_list("pk", flat=True)),
        "",
    )


def window_agents() -> set[int]:
    """Agents in an open maintenance run, the hourly install task leaves them alone."""
    return set(
        ScheduleRun.objects.filter(
            state__in=ACTIVE, schedule__kind=ScheduleKind.MAINTENANCE
        ).values_list("agent_id", flat=True)
    )


def scan_finished(agent) -> None:
    _report(agent, RunState.SCANNING, RunState.SCANNED)


def install_finished(agent, rebooting: bool) -> None:
    to = RunState.REBOOTING if rebooting else RunState.INSTALLED
    _report(agent, RunState.INSTALLING, to)


def _report(agent, frm: str, to: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    for run in ScheduleRun.objects.filter(agent=agent, state=frm).select_related(
        "schedule", "agent"
    ):
        _move(run, to, now)


def _log_type(run) -> str:
    if run.schedule.kind == ScheduleKind.MAINTENANCE:
        return DebugLogType.WIN_UPDATES
    return DebugLogType.AGENT_ISSUES


def _move(run, state: str, now, detail: str = "", warn: bool = False, **fields) -> bool:
    detail = detail[:255]
    moved = ScheduleRun.objects.filter(pk=run.pk, state=run.state).update(
        state=state, changed=now, detail=detail, **fields
    )
    if not moved:
        return False

    run.state, run.changed, run.detail = state, now, detail
    for k, v in fields.items():
        setattr(run, k, v)

    msg = (
        f"{run.schedule.name} on {run.agent.hostname}: {RunState(state).label.lower()}"
    )
    log = DebugLog.warning if warn else DebugLog.info
    log(agent=run.agent, log_type=_log_type(run), message=f"{msg}. {detail}".strip())
    return True


async def _agather(cmds, timeout: int) -> list:
    return await asyncio.gather(*(a.nats_cmd(d, timeout=timeout) for a, d in cmds))


def _ping(agents) -> dict[int, bool | None]:
    """True answered, False did not, None nats itself is down (unknown)."""
    if not agents:
        return {}
    ret = {}
    cmds = [(a, {"func": "ping"}) for a in agents]
    for agent, r in zip(agents, asyncio.run(_agather(cmds, 5))):
        ret[agent.pk] = None if r == "natsdown" else r == "pong"
    return ret


def _add_hold(holds: dict, run) -> None:
    # per device the run with the latest end, a shorter one must not cut it
    old = holds.get(run.agent_id)
    if old is None or run.ends > old.ends:
        holds[run.agent_id] = run


def _keepawake(runs) -> None:
    if not runs:
        return
    cmds = [
        (r.agent, {"func": "keepawake", "until": int(r.ends.timestamp())}) for r in runs
    ]
    for run, r in zip(runs, asyncio.run(_agather(cmds, 10))):
        if r != "ok":
            DebugLog.warning(
                agent=run.agent,
                log_type=_log_type(run),
                message=f"Keeping {run.agent.hostname} awake for {run.schedule.name} failed: {r}",
            )


def _wake(runs) -> None:
    agents = {r.agent.pk: r.agent for r in runs}
    sent = wake_agents(Agent.objects.filter(pk__in=agents), None)
    mesh = [
        a.mesh_node_id
        for a in agents.values()
        if a.mesh_node_id and a.hex_mesh_node_id != "error"
    ]
    try:
        if mesh:
            asyncio.run(wake_on_lan(uri=get_mesh_ws_url(), mesh_node_ids=mesh))
    except Exception:
        mesh = []

    for run in runs:
        agent = run.agent
        via = sent.get(agent.pk, []) + (
            ["MeshCentral"] if agent.mesh_node_id in mesh else []
        )
        AuditLog.audit_power_action(
            "system", agent, f"wake ({run.schedule.name})", {"via": via}
        )
        DebugLog.info(
            agent=agent,
            log_type=_log_type(run),
            message=f"Wake-on-LAN for {run.schedule.name} sent to {agent.hostname} via {', '.join(via) or 'nothing'}",
        )


def _hold(runs, holds: dict) -> None:
    # hold what answers right away, the next pass takes the run on from there
    waiting = {r.agent.pk: r for r in runs if r.state == RunState.WAKING}
    for run in waiting.values():
        _add_hold(holds, run)
    end = time.monotonic() + HOLD_FOR
    while waiting and time.monotonic() < end:
        time.sleep(HOLD_POLL)
        for pk, ok in _ping([r.agent for r in waiting.values()]).items():
            if ok:
                waiting.pop(pk)
                _keepawake([holds[pk]])


def _scan(run, now) -> None:
    agent = run.agent
    if agent.is_posix and not getattr(settings, "ULRMM_POSIX_PATCH_AUTOMATION", False):
        _after_install(run, now, "POSIX patch automation is off, nothing installed")
        return
    if reason := managed_reason(agent):
        _after_install(run, now, f"{reason}, nothing installed")
        return

    if not _move(run, RunState.SCANNING, now, "awake, scanning for updates"):
        return
    if agent.is_posix:
        from winupdate.tasks import posix_refresh_task

        posix_refresh_task.delay(agent.pk, "scan")
    else:
        agent.delete_superseded_updates()
        asyncio.run(agent.nats_cmd(SCAN_CMD, wait=False))


def _install(run, now) -> None:
    agent = run.agent
    agent.delete_superseded_updates()
    agent.approve_updates()
    guids = agent.get_approved_update_guids(automatic=True)
    if not guids:
        _after_install(run, now, "no approved updates")
        return

    if not _move(run, RunState.INSTALLING, now, f"installing {len(guids)} updates"):
        return
    AuditLog.audit_power_action(
        "system", agent, f"install {len(guids)} updates ({run.schedule.name})"
    )
    if agent.is_posix:
        from winupdate.tasks import posix_install_updates_task

        mark_installing(agent.pk, guids)
        posix_install_updates_task.delay(agent.pk, guids, "system")
    else:
        result = asyncio.run(
            agent.nats_cmd({"func": "installwinupdates", "guids": guids}, wait=False)
        )
        if result != "natsdown":
            mark_installing(agent.pk, guids)
        # like the hourly task, so it does not install again the same day
        agent.patches_last_installed = now
        agent.save(update_fields=["patches_last_installed"])


def _after_install(run, now, detail: str = "") -> None:
    if not run.woke:
        _move(
            run, RunState.DONE, now, "left awake, it was awake when the window opened"
        )
    elif run.agent.monitoring_type == AgentMonType.SERVER:
        _move(run, RunState.DONE, now, "left awake, servers never sleep")
    else:
        _move(
            run,
            RunState.IDLE_WAIT,
            now,
            detail or "waiting for 15 minutes without input",
        )


def _busy(run) -> bool:
    # never sleep a device another maintenance run still works on
    return (
        ScheduleRun.objects.filter(
            agent=run.agent, state__in=ACTIVE, schedule__kind=ScheduleKind.MAINTENANCE
        )
        .exclude(pk=run.pk)
        .exclude(state=RunState.IDLE_WAIT)
        .exists()
    )


def _idle(run, now, answered: bool | None = True) -> None:
    # the 5 s ping decides, a stale connection would hold the idle call 20 s
    if answered is None or _busy(run):
        return
    if not answered:
        _move(run, RunState.LEFT_AWAKE, now, "not reachable, asleep or off")
        return

    agent = run.agent
    r = asyncio.run(agent.nats_cmd({"func": "idle"}, timeout=20))
    # int seconds, -1 without an interactive session; anything else is unknown
    if isinstance(r, bool) or not isinstance(r, int) or r < -1:
        _move(
            run,
            RunState.LEFT_AWAKE,
            now,
            f"user input unknown ({str(r)[:100]})",
            warn=True,
        )
        return
    if 0 <= r < IDLE_SECS:
        return

    AuditLog.audit_power_action("system", agent, f"suspend ({run.schedule.name})")
    r = asyncio.run(agent.nats_cmd({"func": "suspend"}, timeout=10))
    if r != "ok":
        _move(run, RunState.LEFT_AWAKE, now, f"sleep failed: {str(r)[:100]}", warn=True)
        return
    by = "maintenance window"
    if run.schedule.kind != ScheduleKind.MAINTENANCE:
        by = "sleep schedule"
    agent.record_power_event("sleep", f"rmm: {by} ({run.schedule.name})")
    _move(run, RunState.SLEPT, now, "no user input for 15 minutes")


def _sleep_step(run, now, answered) -> None:
    if run.agent.monitoring_type == AgentMonType.SERVER:
        _move(run, RunState.SKIPPED, now, "servers never sleep")
        return
    if run.state == RunState.NEW:
        if answered is None:
            return
        if not answered:
            _move(run, RunState.SKIPPED, now, "not reachable, asleep or off")
            return
        _move(run, RunState.IDLE_WAIT, now, "waiting for 15 minutes without input")
    _idle(run, now, answered)


def _step(run, now, refuse: str, answered, wake: list) -> None:
    s, st = run.schedule, run.state
    if refuse:
        _move(run, RunState.REFUSED, now, refuse, warn=True)
        return
    if now >= run.ends or (st == RunState.WAKING and now - run.changed >= WAKE_SPAN):
        if st == RunState.WAKING:
            _move(
                run,
                RunState.FAILED,
                now,
                f"no answer after {run.wakes} wake attempts",
                warn=True,
            )
        else:
            _move(run, RunState.TIMEOUT, now, "the window ended, left awake", warn=True)
        return

    if s.kind == ScheduleKind.SLEEP:
        _sleep_step(run, now, answered)
        return

    if st == RunState.NEW:
        if answered is None:
            return
        if s.kind == ScheduleKind.WAKE and answered:
            _move(run, RunState.DONE, now, "already awake")
            return
        # a maintenance window wakes every device; online can be stale
        wake.append(run)
        if not answered:
            _move(
                run, RunState.WAKING, now, "asleep or off, waking", woke=True, wakes=1
            )
        else:
            _scan(run, now)

    elif st == RunState.WAKING:
        if answered and s.kind == ScheduleKind.WAKE:
            _move(run, RunState.DONE, now, f"awake, held until {run.ends:%H:%M} UTC")
        elif answered:
            _scan(run, now)
        elif run.wakes < MAX_WAKES and now - run.changed >= run.wakes * WAKE_RETRY:
            run.wakes += 1
            ScheduleRun.objects.filter(pk=run.pk).update(wakes=run.wakes)
            wake.append(run)

    elif st == RunState.SCANNING:
        if now - run.changed >= SCAN_WAIT:
            DebugLog.warning(
                agent=run.agent,
                log_type=_log_type(run),
                message=f"The update scan on {run.agent.hostname} did not report, installing the approved updates known",
            )
            _install(run, now)

    elif st == RunState.SCANNED:
        _install(run, now)

    elif st == RunState.INSTALLED:
        _after_install(run, now)

    elif st == RunState.REBOOTING:
        if answered and now - run.changed >= REBOOT_WAIT:
            _after_install(run, now)

    elif st == RunState.IDLE_WAIT:
        _idle(run, now, answered)


def _open_runs(now) -> None:
    for s in MaintenanceSchedule.objects.filter(enabled=True):
        span = dt.timedelta(minutes=s.duration)
        for agent in target_agents(s).only("pk", "time_zone"):
            start = current(s, ZoneInfo(agent.timezone), now, span)
            if start is None:
                continue
            ScheduleRun.objects.get_or_create(
                schedule=s,
                agent=agent,
                occurrence=start,
                defaults={"ends": start + span, "changed": now},
            )


def run_pass(now) -> None:
    allowed = {s.pk: eligible(s) for s in MaintenanceSchedule.objects.all()}
    _open_runs(now)

    runs = []
    for run in ScheduleRun.objects.filter(state__in=ACTIVE).select_related(
        "schedule", "agent"
    ):
        pks, why = allowed[run.schedule_id]
        refuse = "" if run.agent_id in pks else why or "no target in its owner's scope"
        runs.append((run, refuse))

    # refused devices are never contacted
    holds: dict = {}
    woken = ScheduleRun.objects.filter(
        schedule__kind=ScheduleKind.WAKE, state=RunState.DONE, woke=True, ends__gt=now
    ).select_related("schedule", "agent")
    for run in [r for r, no in runs if not no] + [
        r for r in woken if r.agent_id in allowed[r.schedule_id][0]
    ]:
        if run.ends > now and (
            run.woke or run.schedule.kind == ScheduleKind.MAINTENANCE
        ):
            _add_hold(holds, run)

    ping = {r.agent_id: r.agent for r, no in runs if not no and r.state in PINGED}
    ping.update((pk, r.agent) for pk, r in holds.items())
    answered = _ping(list(ping.values()))
    # before the steps, so a suspend of this pass still wins over it
    _keepawake([r for pk, r in holds.items() if answered.get(pk)])
    wake: list = []
    for run, refuse in runs:
        try:
            _step(run, now, refuse, answered.get(run.agent_id), wake)
        except Exception as e:
            _move(run, RunState.LEFT_AWAKE, now, f"error: {e}", warn=True)

    if wake:
        _wake(wake)
        _hold(wake, holds)

    ScheduleRun.objects.filter(occurrence__lt=now - KEEP_RUNS).delete()

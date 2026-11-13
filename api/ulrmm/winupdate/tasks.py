# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import calendar
import datetime as dt
import time
from contextlib import ExitStack
from zoneinfo import ZoneInfo

from celery.exceptions import Retry
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone as djangotime

from agents.models import Agent, AgentHistory
from logs.models import DebugLog
from patches import maintenance, mirror
from software.models import InstalledSoftware
from ulrmm.celery import app
from ulrmm.constants import (
    AGENT_DEFER,
    AgentHistoryType,
    AgentPlat,
    DebugLogType,
)
from ulrmm.helpers import agent_ver
from ulrmm.utils import redis_lock

from .installing import SCAN_CMD, clear_installing, mark_installing
from .models import WinUpdate
from .posix import (
    PACKAGE_MANAGERS,
    ParsedPackages,
    build_script_payload,
    is_protected_remove_target,
    is_valid_guid,
    is_valid_remove_target,
    managed_reason,
    parse_packages_output,
    run_packages_script,
)

# oldest agent that understands the Windows update NATS calls used here
MIN_AGENT_VER = "1.3.0"
CHUNK = 40
LOG = DebugLogType.WIN_UPDATES

# error keys of posix_packages.sh that name an inventory source, not a manager
SOURCE_ALIASES = {"system_profiler": ["app"], "brew": ["brew", "brew-cask"]}

_BUSY = object()


def _lock_key(agent_pk: int) -> str:
    return f"posix-packages-{agent_pk}"


def _supported(agent) -> bool:
    return agent_ver(agent.version) >= agent_ver(MIN_AGENT_VER)


def _chunks(items: list, size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _publish_install(agent, guids: list[str]) -> bool:
    result = asyncio.run(
        agent.nats_cmd({"func": "installwinupdates", "guids": guids}, wait=False)
    )
    if result == "natsdown":
        return False
    mark_installing(agent.pk, guids)
    return True


def _queue_posix_install(agent, guids: list[str]) -> None:
    mark_installing(agent.pk, guids)
    posix_install_updates_task.delay(agent.pk, guids)


# --- Windows scheduling ------------------------------------------------------


@app.task
def auto_approve_updates_task() -> None:
    if getattr(settings, "ULRMM_DISABLE_APPROVE_UPDATES_TASK", False):
        return

    agents = Agent.objects.only(
        "pk", "agent_id", "version", "last_seen", "overdue_time", "offline_time", "plat"
    )
    for agent in agents:
        try:
            agent.delete_superseded_updates()
            agent.approve_updates()
        except Exception as e:
            # the agent is still scanned below
            DebugLog.error(
                agent=agent,
                log_type=LOG,
                message=f"Approving updates on {agent.hostname} failed: {e}",
            )
            continue

    online = [a for a in agents if a.is_online and _supported(a)]
    posix = [a.pk for a in online if a.is_posix]
    if posix:
        posix_refresh_all_task.delay(posix)

    for chunk in _chunks([a for a in online if not a.is_posix], CHUNK):
        for agent in chunk:
            asyncio.run(agent.nats_cmd(SCAN_CMD, wait=False))
        time.sleep(1)


def _is_install_time(policy, now) -> bool:
    if policy.run_time_hour != now.hour:
        return False
    if policy.run_time_frequency == "daily":
        return now.weekday() in (policy.run_time_days or [])
    if policy.run_time_frequency == "monthly":
        # day 31 means the last day in shorter months, kept in memory only
        last_day = calendar.monthrange(now.year, now.month)[1]
        return now.day == min(policy.run_time_day, last_day)
    return False


def _run_schedule(agent) -> None:
    agent.delete_superseded_updates()
    guids = agent.get_approved_update_guids(automatic=True)
    if not guids:
        return

    policy = agent.get_patch_policy()
    tz = ZoneInfo(agent.timezone)
    now = dt.datetime.now(tz)

    last = agent.patches_last_installed
    if last and last.astimezone(tz).strftime("%d/%m/%Y") == now.strftime("%d/%m/%Y"):
        return
    if not _is_install_time(policy, now):
        return

    if agent.is_posix:
        # the task records patches_last_installed itself
        _queue_posix_install(agent, guids)
        return

    DebugLog.info(
        agent=agent,
        log_type=LOG,
        message=f"Installing windows updates on {agent.hostname}",
    )
    if not _publish_install(agent, guids):
        DebugLog.warning(
            agent=agent,
            log_type=LOG,
            message=f"Windows updates not sent to {agent.hostname}: nats is down",
        )
        return
    agent.patches_last_installed = djangotime.now()
    agent.save(update_fields=["patches_last_installed"])


@app.task
def check_agent_update_schedule_task() -> None:
    if getattr(settings, "ULRMM_DISABLE_WINUPDATES_INSTALL_TASK", False):
        return

    posix_automation = getattr(settings, "ULRMM_POSIX_PATCH_AUTOMATION", False)
    busy = maintenance.window_agents()

    for agent in Agent.online_agents(min_version=MIN_AGENT_VER):
        if (agent.is_posix and not posix_automation) or agent.pk in busy:
            continue
        # one broken agent must not stop the schedule of the others
        try:
            _run_schedule(agent)
        except Exception as e:
            DebugLog.error(
                agent=agent,
                log_type=LOG,
                message=f"Scheduled patch install on {agent.hostname} failed: {e}",
            )


@app.task
def patch_failed_email_task(pk: int) -> None:
    from core.utils import get_core_settings

    # a failure reported after this point queues the next mail
    cache.delete(f"patch-failed-email-{pk}")
    agent = Agent.objects.filter(pk=pk).first()
    if agent is None:
        return
    titles = list(
        agent.winupdates.filter(result="failed", installed=False)
        .order_by("title")
        .values_list("title", "kb", "fail_count")
    )
    if not titles:
        return
    lines = "\n".join(
        f"- {title or kb} (failed {count} times)" for title, kb, count in titles
    )
    _, sent = get_core_settings().send_mail(
        agent._outage_subject("patch installation failed"),
        f"These updates failed to install on {agent.hostname}:\n{lines}",
        alert_template=agent.alert_template,
    )
    if not sent:
        DebugLog.warning(
            agent=agent,
            log_type=LOG,
            message=f"Failed patch mail for {agent.hostname} was not sent",
        )


def _bulk_agents(pks: list[int]) -> list:
    agents = Agent.objects.defer(*AGENT_DEFER).filter(pk__in=pks)
    return [
        agent for agent in agents if _supported(agent) and not managed_reason(agent)
    ]


@app.task
def bulk_install_updates_task(pks: list[int]) -> None:
    for chunk in _chunks(_bulk_agents(pks), CHUNK):
        for agent in chunk:
            agent.delete_superseded_updates()
            try:
                agent.approve_updates()
            except Exception:
                pass
            guids = agent.get_approved_update_guids()
            if not guids:
                continue
            if agent.is_posix:
                _queue_posix_install(agent, guids)
            else:
                _publish_install(agent, guids)
        time.sleep(1)


@app.task
def bulk_check_for_updates_task(pks: list[int]) -> None:
    for chunk in _chunks(_bulk_agents(pks), CHUNK):
        for agent in chunk:
            if agent.is_posix:
                posix_refresh_task.delay(agent.pk, "scan")
                continue
            agent.delete_superseded_updates()
            asyncio.run(agent.nats_cmd(SCAN_CMD, wait=False))
        time.sleep(1)


# --- Linux / macOS through posix_packages.sh ---------------------------------


def _log(agent, level: str, message: str) -> None:
    getattr(DebugLog, level)(agent=agent, log_type=LOG, message=message)


def _parse_reply(agent, r, mode: str) -> "ParsedPackages | None":
    """The parsed script output when the script exited 0, else None."""
    if isinstance(r, dict):
        parsed = parse_packages_output(r.get("stdout"))
        retcode = r.get("retcode")
        ok = retcode == 0
        detail = "; ".join(parsed.errors) or str(r.get("stderr", ""))[-500:]
        if not ok:
            detail = f"exit code {retcode}: {detail}"
    else:
        parsed, ok, detail = None, False, r

    errors = parsed.errors if parsed else []
    if ok and errors and (mode == "inventory" or parsed.reboot_required is not None):
        _log(
            agent,
            "warning",
            f"Package {mode} on {agent.hostname} finished with errors: {detail}",
        )
    elif not ok or errors:
        _log(agent, "error", f"Package {mode} on {agent.hostname} failed: {detail}")
    return parsed if ok else None


def _error_keys(parsed: ParsedPackages) -> set[str]:
    return {error.split(":", 1)[0] for error in parsed.errors}


def _package_key(guid: str) -> str:
    # manager:name:arch, the version may contain colons itself
    return ":".join((guid or "").split(":")[:3])


def _import_updates(agent, parsed: ParsedPackages) -> None:
    guids = [u["guid"] for u in parsed.updates]
    known = set(agent.winupdates.filter(guid__in=guids).values_list("guid", flat=True))

    # a manager that failed this run keeps its rows until it answers again
    failed = _error_keys(parsed) & {*PACKAGE_MANAGERS, "softwareupdate"}
    stale = agent.winupdates.filter(installed=False).exclude(guid__in=guids)
    for manager in failed:
        stale = stale.exclude(guid__startswith=f"{manager}:")

    carried = {
        _package_key(guid): action
        for guid, action in stale.filter(action__in=("approve", "ignore"))
        .order_by("id")
        .values_list("guid", "action")
    }

    with transaction.atomic():
        new = []
        for update in parsed.updates:
            fields = {
                key: update[key]
                for key in (
                    "kb",
                    "title",
                    "description",
                    "severity",
                    "categories",
                    "kb_article_ids",
                )
            }
            fields.update(installed=False, downloaded=False)
            if update["guid"] in known:
                agent.winupdates.filter(guid=update["guid"]).update(**fields)
            else:
                action = carried.get(_package_key(update["guid"]), "nothing")
                new.append(
                    WinUpdate(agent=agent, guid=update["guid"], action=action, **fields)
                )
        WinUpdate.objects.bulk_create(new)
        stale.delete()

        agent.needs_reboot = bool(parsed.reboot_required)
        agent.save(update_fields=["needs_reboot"])

    mirror.mirror_agent_updates(agent)


def _save_software(agent, parsed: ParsedPackages) -> None:
    row = InstalledSoftware.latest_for(agent)
    if row is None:
        InstalledSoftware.objects.update_or_create(
            agent=agent, defaults={"software": parsed.software}
        )
        return

    failed: set[str] = set()
    for key in _error_keys(parsed):
        key = key.removesuffix("-inventory")
        failed.update(SOURCE_ALIASES.get(key, [key]))
    failed -= {item.get("source") for item in parsed.software}

    stored = row.software if isinstance(row.software, list) else []
    kept = [i for i in stored if isinstance(i, dict) and i.get("source") in failed]
    row.software = parsed.software + kept
    row.save(update_fields=["software"])
    InstalledSoftware.objects.filter(agent=agent).exclude(pk=row.pk).delete()


def _import_audit(agent, parsed: ParsedPackages) -> None:
    # FreeBSD vulnerability findings, from the pkg audit in the scan
    if parsed.audit is not None and agent.plat == AgentPlat.FREEBSD:
        from vulns.tasks import import_pkg_audit

        import_pkg_audit(agent, parsed.audit)


def _import_refresh(agent, r, mode: str) -> str:
    parsed = _parse_reply(agent, r, mode)
    if parsed is None:
        return "failed"
    # an empty inventory never replaces a stored one
    if mode != "scan" and parsed.software:
        _save_software(agent, parsed)
    if mode != "inventory" and parsed.reboot_required is not None:
        _import_updates(agent, parsed)
    _import_audit(agent, parsed)
    return "ok"


def _get_agent(agent_pk: int):
    return Agent.objects.defer(*AGENT_DEFER).get(pk=agent_pk)


@app.task(bind=True)
def posix_refresh_task(self, agent_pk: int, mode: str = "refresh") -> str:
    agent = _get_agent(agent_pk)
    with redis_lock(_lock_key(agent_pk), self.app.oid) as acquired:
        if not acquired:
            _log(
                agent,
                "warning",
                f"Package {mode} on {agent.hostname} skipped, another package "
                "script is still running",
            )
            return f"Package script already running on agent {agent_pk}"

        ret = _import_refresh(agent, run_packages_script(agent, mode), mode)
        if ret == "ok" and mode != "inventory":
            maintenance.scan_finished(agent)
        return ret


async def _refresh_replies(agents: list, payload: dict) -> list:
    async def one(agent):
        try:
            return await agent.nats_cmd(payload, timeout=payload["timeout"] + 30)
        except Exception as e:
            return str(e) or type(e).__name__

    return await asyncio.gather(*(one(agent) for agent in agents))


@app.task(bind=True)
def posix_refresh_all_task(self, agent_pks: list[int]) -> None:
    size = max(1, getattr(settings, "ULRMM_POSIX_REFRESH_CONCURRENCY", 10))
    agents = list(
        Agent.objects.defer(*AGENT_DEFER).filter(pk__in=agent_pks).order_by("pk")
    )
    payload = build_script_payload("refresh")

    for chunk in _chunks(agents, size):
        # the chunk's locks are released before the next chunk starts
        with ExitStack() as locks:
            ready = []
            for agent in chunk:
                if locks.enter_context(redis_lock(_lock_key(agent.pk), self.app.oid)):
                    ready.append(agent)
                else:
                    _log(
                        agent,
                        "warning",
                        f"Package refresh on {agent.hostname} skipped, another "
                        "package script is still running",
                    )

            replies = asyncio.run(_refresh_replies(ready, payload)) if ready else []
            for agent, reply in zip(ready, replies):
                try:
                    _import_refresh(agent, reply, "refresh")
                except Exception as e:
                    _log(
                        agent,
                        "error",
                        f"Package refresh import on {agent.hostname} failed: {e}",
                    )


def _drop_partial_pacman(agent, guids: list[str]) -> list[str]:
    """pacman upgrades the whole system, so it runs only with every pending
    pacman update approved."""
    pacman = [g for g in guids if g.startswith("pacman:")]
    if not pacman:
        return guids

    pending = agent.winupdates.filter(
        installed=False, guid__startswith="pacman:"
    ).exclude(guid__in=pacman)
    if not pending.exists():
        return guids

    # skipped, not failed: the failed patch options must not count it
    clear_installing(agent.pk, pacman)
    _log(
        agent,
        "warning",
        f"Skipped {len(pacman)} pacman updates on {agent.hostname}: pacman only "
        "upgrades the whole system, so all pending pacman updates must be "
        "approved together",
    )
    return [g for g in guids if not g.startswith("pacman:")]


def _install_locked(agent, guids: list[str], username: str) -> str:
    guids = _drop_partial_pacman(agent, guids)
    if not guids:
        return "failed"

    hist = AgentHistory.objects.create(
        agent=agent,
        type=AgentHistoryType.SCRIPT_RUN,
        command=f"posix_packages.sh install {' '.join(guids)}",
        username=username[:50],
    )
    _log(agent, "info", f"Installing {len(guids)} package updates on {agent.hostname}")

    payload = build_script_payload("install", guids)
    payload["id"] = hist.pk
    r = run_packages_script(agent, "install", payload=payload)
    installed = _parse_reply(agent, r, "install")
    if not isinstance(r, dict):
        # no answer at all: nothing is known about the run
        return "failed"

    rescan = _parse_reply(agent, run_packages_script(agent, "scan"), "scan")
    if rescan is not None and rescan.reboot_required is None:
        rescan = None

    results = installed.install_results if installed else []
    codes = {i["guid"]: i["exit_code"] for i in results}
    offered = {u["guid"] for u in rescan.updates} if rescan else set()
    # before the rescan import, which deletes uninstalled rows it does not list
    for guid in guids:
        agent.set_update_result(guid, codes.get(guid) == 0 and guid not in offered)
    if rescan:
        _import_updates(agent, rescan)
        _import_audit(agent, rescan)

    agent.needs_reboot = any(p.reboot_required for p in (installed, rescan) if p)
    agent.patches_last_installed = djangotime.now()
    agent.save(update_fields=["needs_reboot", "patches_last_installed"])

    rebooting = False
    if installed is not None and getattr(
        settings, "ULRMM_POSIX_PATCH_AUTOMATION", False
    ):
        rebooting = agent.handle_patch_reboot(agent.needs_reboot)
    maintenance.install_finished(agent, rebooting)
    return "ok"


def _posix_install_updates(self, agent_pk: int, guids: list[str], username: str):
    agent = _get_agent(agent_pk)
    with redis_lock(_lock_key(agent_pk), self.app.oid) as acquired:
        if not acquired:
            if self.request.retries < self.max_retries:
                raise self.retry(countdown=60)
            _log(
                agent,
                "warning",
                f"Installing {len(guids)} package updates on {agent.hostname} "
                "skipped, another package script is still running",
            )
            return _BUSY
        return _install_locked(agent, guids, username)


@app.task(bind=True, max_retries=30)
def posix_install_updates_task(
    self, agent_pk: int, guids: list[str], username: str = "ulrmm"
) -> str:
    guids = [g for g in guids if is_valid_guid(g)]
    if not guids:
        return "No valid updates to install"

    mark_installing(agent_pk, guids)
    try:
        ret = _posix_install_updates(self, agent_pk, guids, username)
    except Retry:
        # the retry installs the same updates, keep them marked
        raise
    except BaseException:
        clear_installing(agent_pk, guids)
        raise

    if ret is _BUSY:
        return f"Package script still running on agent {agent_pk}"
    clear_installing(agent_pk, guids)
    return ret


def _still_present(agent, source: str, target: str) -> bool:
    row = InstalledSoftware.latest_for(agent)
    if row is None or not isinstance(row.software, list):
        return True
    for item in row.software:
        if not isinstance(item, dict):
            continue
        if source == "app":
            if item.get("location") == target:
                return True
        elif item.get("source") == source and item.get("name") == target:
            return True
    return False


@app.task(bind=True, max_retries=10)
def posix_uninstall_task(
    self, agent_pk: int, source: str, target: str, username: str = "ulrmm"
) -> str:
    agent = _get_agent(agent_pk)
    if not is_valid_remove_target(source, target, agent.plat) or (
        source != "app" and is_protected_remove_target(target)
    ):
        _log(
            agent,
            "warning",
            f"Refused invalid or protected software removal on {agent.hostname}",
        )
        return "failed"

    with redis_lock(_lock_key(agent_pk), self.app.oid) as acquired:
        if not acquired:
            if self.request.retries < self.max_retries:
                raise self.retry(countdown=60)
            _log(
                agent,
                "warning",
                f"Software removal on {agent.hostname} skipped, another package "
                "script is still running",
            )
            return "failed"

        hist = AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.SCRIPT_RUN,
            command=f"posix_packages.sh remove {source} {target}",
            username=username[:50],
        )
        payload = build_script_payload("remove", [source, target])
        payload["id"] = hist.pk
        reply = run_packages_script(agent, "remove", payload=payload)
        removed = _parse_reply(agent, reply, "remove")
        result = None
        if removed:
            wanted = f"{source}:{target}"
            result = next(
                (i for i in removed.install_results if i["guid"] == wanted), None
            )

        inventory = _parse_reply(
            agent, run_packages_script(agent, "inventory"), "inventory"
        )
        present = True
        if inventory is not None:
            _save_software(agent, inventory)
            present = _still_present(agent, source, target)

    exit_code = result["exit_code"] if result else None
    if exit_code == 0 and not present:
        _log(agent, "info", f"Removed {source}:{target} from {agent.hostname}")
        return "ok"

    message = result["message"] if result else str(reply)[:500]
    if exit_code == 0:
        message += "; target is still present in inventory"
    _log(agent, "warning", f"Software removal on {agent.hostname} failed: {message}")
    return "failed"

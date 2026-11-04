# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Software baselines: the items an agent installs after setup or through its
automation policies, one at a time, each checked on the agent afterwards.

pending -> installing -> installed | failed; unsupported when the agent
cannot run the item. Failed items are tried ATTEMPTS times with a growing
pause, installed and unsupported ones are looked at again once a day.
"""

import asyncio
import datetime as dt
import re

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone as djangotime

from agents.models import Agent
from logs.models import DebugLog
from ulrmm.constants import (
    AGENT_DEFER,
    AgentPlat,
    DebugLogType,
    PAStatus,
)
from ulrmm.helpers import agent_ver

from . import detect
from .installs import InstallError, start_choco, start_winget
from .models import (
    Baseline,
    BaselineItem,
    BaselineSource,
    BaselineState,
    BaselineStatus,
)

ATTEMPTS = 3
BACKOFF = dt.timedelta(minutes=30)
RECHECK = dt.timedelta(days=1)
# installing longer than the item timeout plus this is a failure
GRACE = dt.timedelta(minutes=10)
CACHE_TTL = 600
AGENT_LOCK_TTL = 30 * 60
REQUESTER = "baseline"
VERIFYING = "installed, checking the agent"
LINUX_PKG_SCRIPT = settings.BASE_DIR / "software" / "scripts" / "linux_pkg.sh"


def _cache_key(agent) -> str:
    # the scheme of policy checks and tasks: policy assignment changes drop
    # these keys together with theirs
    return agent._policy_cache_key("baselines")


def forget_cache() -> None:
    cache.delete_many_pattern("*_baselines")


def baseline_ids(agent) -> set[int]:
    """Enabled baselines of the agent's active policies and of the
    deployment it enrolled through, for its platform."""
    from automation.models import Policy

    key = _cache_key(agent)
    ids = cache.get(key)
    if not isinstance(ids, list):
        policies = Policy._active_policies(agent)
        ids = (
            list(
                Baseline.objects.filter(
                    enabled=True, plat=agent.plat, policies__in=policies
                )
                .values_list("pk", flat=True)
                .distinct()
            )
            if policies
            else []
        )
        cache.set(key, ids, CACHE_TTL)
    enrolled = Baseline.objects.filter(
        enabled=True, plat=agent.plat, deployments__enrollments__agent=agent
    ).values_list("pk", flat=True)
    return set(ids) | set(enrolled)


def effective_items(agent) -> list[BaselineItem]:
    ids = baseline_ids(agent)
    if not ids:
        return []
    return list(
        BaselineItem.objects.filter(baseline__in=ids)
        .select_related("baseline")
        .order_by("baseline__name", "order", "pk")
    )


def sync(agent) -> list[BaselineState]:
    """The agent's states in item order. New items start pending, states of
    items the agent no longer has are dropped."""
    items = effective_items(agent)
    wanted = {i.pk: i for i in items}
    have = {s.item_id: s for s in BaselineState.objects.filter(agent=agent)}
    gone = [s.pk for item_id, s in have.items() if item_id not in wanted]
    if gone:
        BaselineState.objects.filter(pk__in=gone).delete()
    missing = [
        BaselineState(agent=agent, item=i) for pk, i in wanted.items() if pk not in have
    ]
    if missing:
        BaselineState.objects.bulk_create(missing, ignore_conflicts=True)
        have = {
            s.item_id: s
            for s in BaselineState.objects.filter(agent=agent, item__in=list(wanted))
        }
    states = []
    for item in items:
        if state := have.get(item.pk):
            state.item, state.agent = item, agent
            states.append(state)
    return states


def due(state, now) -> bool:
    if state.status in (BaselineStatus.PENDING, BaselineStatus.INSTALLING):
        return True
    if state.status == BaselineStatus.FAILED:
        pause = BACKOFF * 2 ** max(state.attempts - 1, 0)
        return state.attempts < ATTEMPTS and state.updated <= now - pause
    return state.updated <= now - RECHECK


def summary(rows) -> str:
    """One status for (status, required) pairs: the worst required item."""
    found = {status for status, required in rows if required}
    for status in (
        BaselineStatus.FAILED,
        BaselineStatus.INSTALLING,
        BaselineStatus.PENDING,
        BaselineStatus.UNSUPPORTED,
    ):
        if status in found:
            return status
    return BaselineStatus.INSTALLED if rows else BaselineStatus.PENDING


def package_of(item):
    from packages.models import SoftwarePackage

    if item.source != BaselineSource.PACKAGE or not item.ref.isdecimal():
        return None
    return SoftwarePackage.objects.filter(pk=int(item.ref)).first()


def rule_for(item, package=None) -> dict:
    if item.detection:
        return item.detection
    if item.source == BaselineSource.PACKAGE:
        return (package and package.detection) or {"type": "none"}
    if item.source == BaselineSource.LINUX_PKG:
        return {"type": "inventory", "name": f"^{re.escape(item.ref)}$"}
    return detect.name_rule(item.name or item.ref)


def _unsupported(agent, item, package) -> str:
    from packages.jobs import PKGJOB_MIN_AGENT, supports_job
    from packages.models import PackageKind

    if item.source == BaselineSource.WINGET and agent_ver(agent.version) < agent_ver(
        settings.WINGET_MIN_AGENT
    ):
        return f"winget needs agent {settings.WINGET_MIN_AGENT} or newer"
    if item.source == BaselineSource.LINUX_PKG and agent.plat != AgentPlat.LINUX:
        return "distribution packages install on Linux only"
    if package is not None:
        if package.plat != agent.plat:
            return f"{package.name} is a {package.get_plat_display()} package"
        if package.kind == PackageKind.ARCHIVE and not supports_job(agent):
            return f"archives need agent {PKGJOB_MIN_AGENT} or newer"
    return ""


def _save(state, status: str, detail: str = "", **fields) -> bool:
    state.status, state.detail = status, str(detail)[:500]
    if status != BaselineStatus.INSTALLING:
        state.action = state.install = None
    for key, value in fields.items():
        setattr(state, key, value)
    state.save()
    return True


def _fail(state, detail: str) -> bool:
    item = state.item
    DebugLog.warning(
        f"Baseline {item.baseline.name}: {item.name or item.ref} on "
        f"{state.agent.hostname} failed: {detail}",
        agent=state.agent,
        log_type=DebugLogType.SCRIPTING,
    )
    return _save(state, BaselineStatus.FAILED, detail)


def _installed(state, version: str, detail: str = "") -> bool:
    return _save(
        state,
        BaselineStatus.INSTALLED,
        detail,
        verified_at=djangotime.now(),
        detected_version=version[:255],
    )


def verify(agent, state, ok: bool, detail: str, now, inventory) -> bool:
    """After the install: the rule decides. True once the state is final."""
    rule = rule_for(state.item, package_of(state.item))
    if rule["type"] == "none":
        if ok:
            return _installed(state, "", "unverified, the installer reported success")
        return _fail(state, detail or "the install failed")
    found, version = detect.detect(agent, rule, inventory)
    if found:
        return _installed(state, version)
    if found is None:
        # no answer from the agent, the next round asks again
        if state.detail != VERIFYING:
            state.detail = VERIFYING
            state.save(update_fields=["detail", "updated"])
        elif now > state.updated + GRACE:
            return _fail(state, "installed, but the agent did not answer the check")
        return False
    if not ok:
        return _fail(state, detail or "the install failed")
    seen = f", version {version} is installed" if version else ""
    return _fail(state, f"the install finished but the check does not find it{seen}")


def _follow(agent, state, now, inventory) -> bool:
    """An installing item: True once it is final."""
    item = state.item
    deadline = (state.started_at or now) + dt.timedelta(seconds=item.timeout) + GRACE
    late = f"no result from the agent within {item.timeout // 60 + 10} minutes"
    if item.source in (BaselineSource.WINGET, BaselineSource.CHOCO):
        action = state.action
        if action is None:
            return _fail(state, "the install was cancelled")
        if action.status != PAStatus.COMPLETED:
            return now > deadline and _fail(state, late)
        details = action.details if isinstance(action.details, dict) else {}
        ok = bool(details.get("installed"))
        output = str(details.get("output") or "").strip().splitlines()
        why = "" if ok else (output[-1][:300] if output else "the install failed")
        return verify(agent, state, ok, why, now, inventory)
    if item.source == BaselineSource.PACKAGE:
        from packages.models import OPEN_STATES, InstallState

        install = state.install
        if install is None:
            return _fail(state, "the package install record is gone")
        if install.state in OPEN_STATES:
            return False
        ok = install.state in (InstallState.SUCCEEDED, InstallState.REBOOT_REQUIRED)
        why = install.detail or install.get_state_display()
        return verify(agent, state, ok, why, now, inventory)
    # distribution packages run in baseline_linux_pkg_task
    if state.detail == VERIFYING:
        return verify(agent, state, True, "", now, inventory)
    return now > deadline and _fail(state, late)


def _start(agent, state, package) -> None:
    from packages.models import PackageInstall, RunAs
    from packages.services import start_installs

    from .tasks import baseline_linux_pkg_task

    item = state.item
    state.attempts += 1
    _save(state, BaselineStatus.INSTALLING, started_at=djangotime.now())
    try:
        if item.source == BaselineSource.WINGET:
            state.action = start_winget(agent, item.ref, REQUESTER)
        elif item.source == BaselineSource.CHOCO:
            state.action = start_choco(agent, item.ref, REQUESTER)
        elif item.source == BaselineSource.PACKAGE:
            if package is None:
                raise InstallError("the package was deleted")
            result = start_installs(
                None,
                package,
                [agent],
                RunAs.SYSTEM,
                {"source": "baseline", "baseline": item.baseline.name},
                requested_by=REQUESTER,
            )
            state.install = PackageInstall.objects.filter(
                batch=result["batch"], agent=agent
            ).first()
        else:
            baseline_linux_pkg_task.delay(state.pk)
            return
    except (InstallError, ValueError) as e:
        _fail(state, str(e))
        return
    state.save(update_fields=["action", "install", "updated"])


def step(agent) -> str:
    """One round for an online agent: follow the running install, then check
    and start due items, at most one install at a time."""
    now = djangotime.now()
    states = sync(agent)
    software: list = []

    def inventory():
        # one refresh per round
        if not software:
            software.append(detect.refresh_inventory(agent))
        return software[0]

    running = [s for s in states if s.status == BaselineStatus.INSTALLING]
    if any(not _follow(agent, s, now, inventory) for s in running):
        return "installing"

    started = False
    for state in states:
        if state.status == BaselineStatus.INSTALLING or not due(state, now):
            continue
        package = package_of(state.item)
        if why := _unsupported(agent, state.item, package):
            _save(state, BaselineStatus.UNSUPPORTED, why)
            continue
        if state.item.source == BaselineSource.PACKAGE and package is None:
            _fail(state, "the package was deleted")
            continue
        rule = rule_for(state.item, package)
        found, version = detect.detect(agent, rule, inventory)
        if found:
            _installed(state, version)
            continue
        if state.status == BaselineStatus.INSTALLED:
            if found is None:
                # nothing to check against, or no answer: again tomorrow
                state.save(update_fields=["updated"])
                continue
            state.attempts = 0
            _save(state, BaselineStatus.PENDING, "no longer found, installing again")
        if started:
            continue
        # found None: the install runs, the check afterwards decides
        _start(agent, state, package)
        started = True
    return "started" if started else "checked"


def install_linux_pkg(state_pk: int) -> str:
    from packages.models import InstallState
    from packages.utils import parse_result

    state = (
        BaselineState.objects.select_related("item__baseline")
        .filter(pk=state_pk, status=BaselineStatus.INSTALLING)
        .first()
    )
    if state is None:
        return "nothing to install"
    agent = Agent.objects.defer(*AGENT_DEFER).select_related("site__client")
    agent = state.agent = agent.get(pk=state.agent_id)
    item = state.item
    data = {
        "func": "runscriptfull",
        "timeout": item.timeout,
        "payload": {"code": LINUX_PKG_SCRIPT.read_text(), "shell": "shell"},
        "run_as_user": False,
        "env_vars": [f"PKG_NAME={item.ref}"],
    }
    out = asyncio.run(agent.nats_cmd(data, timeout=item.timeout + 30))
    result, fields = parse_result(out, item.timeout)
    ok = result in (InstallState.SUCCEEDED, InstallState.REBOOT_REQUIRED)
    software: list = []

    def inventory():
        if not software:
            software.append(detect.refresh_inventory(agent))
        return software[0]

    verify(agent, state, ok, fields.get("detail", ""), djangotime.now(), inventory)
    return state.status


def tick() -> str:
    """The 5 minute round: online agents with baseline work get a task."""
    from automation.models import Policy
    from deploy.models import Enrollment
    from packages.utils import expire_stale

    from .tasks import baseline_agent_task

    if (
        not Baseline.objects.filter(enabled=True).exists()
        and not BaselineState.objects.exists()
    ):
        return "no baselines"
    # failed package installs end the items that wait for them
    expire_stale()
    pks = set(BaselineState.objects.values_list("agent_id", flat=True))
    pks |= set(
        Enrollment.objects.filter(deployment__baselines__enabled=True).values_list(
            "agent_id", flat=True
        )
    )
    for policy in Policy.objects.filter(
        baselines__enabled=True, active=True
    ).distinct():
        pks |= set(policy.related_agents().values_list("pk", flat=True))

    now = djangotime.now()
    sent = 0
    agents = (
        Agent.objects.filter(pk__in=pks)
        .defer(*AGENT_DEFER)
        .select_related("site__client")
        .order_by("pk")
    )
    for agent in agents.iterator(chunk_size=200):
        if not agent.is_online:
            continue
        if any(due(s, now) for s in sync(agent)):
            baseline_agent_task.delay(agent.pk)
            sent += 1
    return f"{sent} agents with baseline work"


def on_enrolled(sender, agent=None, deployment=None, **kwargs) -> None:
    """deploy.signals.agent_enrolled: pending states for the new agent."""
    if agent is None:
        return
    sync(
        Agent.objects.defer(*AGENT_DEFER)
        .select_related("site__client")
        .get(pk=agent.pk)
    )

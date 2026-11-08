# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from datetime import timedelta

from django.conf import settings
from django.db import DatabaseError, transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone as djangotime

from core.mesh_utils import (
    MESH_RIGHTS_BASE,
    MESH_RIGHTS_CONSOLE,
    MeshSync,
    build_mesh_display_name,
    has_mesh_perms,
    mesh_node_name,
    transform_mesh,
)
from core.utils import get_core_settings, get_mesh_ws_url, make_alpha_numeric
from patches.tasks import prune_patch_events
from reporting.tasks import prune_report_history_task
from ulrmm.celery import app
from ulrmm.constants import (
    AGENT_CHECKS_CACHE_PREFIX,
    AGENT_DEFER,
    AGENT_STATUS_OVERDUE,
    CACHE_DB_FIELDS_TASK_LOCK,
    MINUTE_LOCK_EXPIRE,
    SCHED_TASK_RUNNER_LOCK,
    RESOLVE_ALERTS_LOCK,
    SYNC_MESH_PERMS_TASK_LOCK,
    SYNC_SCHED_TASK_LOCK,
    AgentPlat,
    AlertSeverity,
    AlertType,
    DebugLogType,
    PAAction,
    PAStatus,
    TaskRunStatus,
    TaskStatus,
    TaskSyncStatus,
    TaskType,
)
from ulrmm.helpers import agent_ver, make_random_password, setup_nats_options
from ulrmm.logger import logger
from ulrmm.nats_utils import a_nats_cmd, abulk_nats_command
from ulrmm.permissions import agent_perm_check
from ulrmm.utils import redis_lock, reload_nats


def _get_agent_qs():
    from django.db.models import Prefetch

    from agents.models import Agent
    from autotasks.models import TaskResult
    from checks.models import Check, CheckResult

    policy_paths = [
        f"{owner}{kind}_policy"
        for owner in ("site__", "site__client__")
        for kind in ("server", "workstation")
    ]
    return (
        Agent.objects.defer(*AGENT_DEFER)
        .select_related(
            *policy_paths, "policy", "policy__alert_template", "alert_template"
        )
        .prefetch_related(
            Prefetch("agentchecks", queryset=Check.objects.select_related("script")),
            Prefetch(
                "checkresults",
                queryset=CheckResult.objects.select_related("assigned_check"),
            ),
            Prefetch("taskresults", queryset=TaskResult.objects.select_related("task")),
            "autotasks",
        )
        .order_by("pk")
    )


@app.task
def core_maintenance_tasks():
    from agents.tasks import clear_faults_task, prune_agent_history
    from alerts.tasks import prune_resolved_alerts
    from checks.tasks import prune_check_history
    from logs.tasks import prune_audit_log, prune_debug_log, prune_pending_actions

    delete_expired_tasks()
    remove_orphaned_history_results()

    core = get_core_settings()
    retention = (
        (core.check_history_prune_days, prune_check_history),
        (core.resolved_alerts_prune_days, prune_resolved_alerts),
        (core.agent_history_prune_days, prune_agent_history),
        (core.debug_log_prune_days, prune_debug_log),
        (core.debug_log_prune_days, prune_pending_actions),
        (core.audit_log_prune_days, prune_audit_log),
        (core.patch_event_prune_days, prune_patch_events),
        (core.clear_faults_days, clear_faults_task),
        (core.report_history_prune_days, prune_report_history_task),
    )
    for days, task in retention:
        if days and days > 0:
            task.delay(days)


def delete_expired_tasks() -> None:
    from autotasks.models import AutomatedTask

    expired = AutomatedTask.objects.filter(expire_date__lt=djangotime.now())
    expired.filter(remove_if_not_scheduled=True).delete()


ORPHAN_BATCH = 5000


def remove_orphaned_history_results() -> int:
    from agents.models import Agent
    from checks.models import CheckHistory

    # rows without an agent_id are not orphans of a deleted agent
    orphaned = CheckHistory.objects.filter(agent_id__isnull=False).exclude(
        Exists(Agent.objects.filter(agent_id=OuterRef("agent_id")))
    )
    count = 0
    try:
        # in batches, one statement over all history would hold its locks long
        while pks := list(orphaned.values_list("pk", flat=True)[:ORPHAN_BATCH]):
            count += CheckHistory.objects.filter(pk__in=pks).delete()[0]
        return count
    except Exception as e:
        logger.error("remove_orphaned_history_results failed: %s", e)
        return 0


@app.task
def refresh_nats_config_task() -> bool:
    # agents update themselves and nats-api writes their version straight
    # into the database; their NATS permissions follow here
    return reload_nats(only_if_changed=True)


@app.task
def resolve_pending_actions():
    from agents.models import Agent
    from logs.models import PendingAction

    # loading a scheduled reboot completes it once its time has passed
    # (logs.signals), so rows nobody opens do not stay pending
    list(
        PendingAction.objects.filter(
            action_type=PAAction.SCHED_REBOOT, status=PAStatus.PENDING
        )
        .select_related("agent")
        .only("action_type", "status", "details", "agent__time_zone")
    )

    pending = list(
        PendingAction.objects.filter(
            action_type=PAAction.AGENT_UPDATE, status=PAStatus.PENDING
        )
    )
    if not pending:
        return

    agents = {
        a.pk: a
        for a in Agent.objects.defer("services", "wmi_detail").filter(
            pk__in=[p.agent_id for p in pending]
        )
    }
    latest = agent_ver(settings.LATEST_AGENT_VER)
    done = [
        p.pk
        for p in pending
        if (agent := agents.get(p.agent_id))
        and agent_ver(agent.version) == latest
        and agent.is_online
    ]
    PendingAction.objects.filter(pk__in=done).update(status=PAStatus.COMPLETED)


@app.task(bind=True)
def resolve_alerts_task(self):
    with redis_lock(RESOLVE_ALERTS_LOCK, self.app.oid, MINUTE_LOCK_EXPIRE) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        from agents.models import Agent
        from alerts.models import Alert

        floor = agent_ver("1.6.0")
        open_alerts = Alert.objects.filter(
            alert_type=AlertType.AVAILABILITY, resolved=False
        ).values("agent_id")
        agents = (
            Agent.objects.defer(*AGENT_DEFER)
            .filter(pk__in=open_alerts)
            .select_related("site__client", "alert_template")
            .order_by("pk")
        )
        for agent in agents:
            if agent_ver(agent.version) >= floor and agent.is_online:
                Alert.handle_alert_resolve(agent)
        return "completed"


async def _run_win_task_sync(creates, modifies, deletes):
    import nats

    try:
        nc = await nats.connect(**setup_nats_options())
    except Exception as e:
        logger.error("sync_scheduled_tasks: NATS connection failed: %s", e)
        return []

    async def one(agent, payload):
        return await a_nats_cmd(nc=nc, sub=agent.agent_id, data=payload, timeout=10)

    items = (
        [("create", a, t, one(a, p)) for a, t, p in creates]
        + [("modify", a, t, one(a, p)) for a, t, p in modifies]
        + [("delete", a, t, one(a, p)) for a, t, p in deletes]
    )
    try:
        replies = await asyncio.gather(*(coro for *_, coro in items))
    finally:
        await nc.close()
    return [
        (action, agent, task, reply)
        for (action, agent, task, _), reply in zip(items, replies)
    ]


@app.task(bind=True)
def sync_scheduled_tasks(self):
    with redis_lock(SYNC_SCHED_TASK_LOCK, self.app.oid, MINUTE_LOCK_EXPIRE) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        from autotasks.models import TaskResult

        creates, modifies, deletes = [], [], []
        floor = agent_ver("1.6.0")
        onboarding_floor = agent_ver("2.6.0")

        for agent in _get_agent_qs():
            if agent.is_posix:
                for task in agent.get_tasks_with_policies():
                    if not getattr(task, "task_result", None):
                        TaskResult.objects.get_or_create(
                            agent=agent,
                            task=task,
                            defaults={"sync_status": TaskSyncStatus.SYNCED},
                        )
                continue

            if not agent.is_online or agent_ver(agent.version) < floor:
                continue

            for task in agent.get_tasks_with_policies():
                if (
                    task.task_type == TaskType.ONBOARDING
                    and agent_ver(agent.version) < onboarding_floor
                ):
                    continue
                # never touch a scheduled task this server did not name
                if not task.has_own_task_name():
                    continue
                # no result yet is the class default {}, not None
                tr = (
                    task.task_result
                    if isinstance(task.task_result, TaskResult)
                    else None
                )
                if tr is None or tr.sync_status == TaskSyncStatus.INITIAL:
                    creates.append(
                        (
                            agent,
                            task,
                            {
                                "func": "schedtask",
                                "schedtaskpayload": task.generate_nats_task_payload(),
                            },
                        )
                    )
                elif tr.sync_status == TaskSyncStatus.PENDING_DELETION:
                    deletes.append(
                        (
                            agent,
                            task,
                            {
                                "func": "delschedtask",
                                "schedtaskpayload": {"name": task.win_task_name},
                            },
                        )
                    )
                elif tr.sync_status == TaskSyncStatus.NOT_SYNCED:
                    modifies.append(
                        (
                            agent,
                            task,
                            {
                                "func": "schedtask",
                                "schedtaskpayload": task.generate_nats_task_payload(),
                            },
                        )
                    )

        if not (creates or modifies or deletes):
            return "ok"

        replies = asyncio.run(_run_win_task_sync(creates, modifies, deletes))
        for action, agent, task, reply in replies:
            _apply_win_task_reply(action, agent, task, reply)
        return "ok"


def _apply_win_task_reply(action, agent, task, reply):
    from autotasks.models import TaskResult

    # a policy task has no agent of its own, the result is per target agent
    tr, _ = TaskResult.objects.get_or_create(agent=agent, task=task)
    if action in ("create", "modify"):
        if reply == "ok":
            tr.sync_status = TaskSyncStatus.SYNCED
        else:
            tr.sync_status = (
                TaskSyncStatus.INITIAL
                if action == "create"
                else TaskSyncStatus.NOT_SYNCED
            )
            logger.error("win task %s failed on %s: %s", action, task.pk, reply)
        tr.save(update_fields=["sync_status"])
        return

    # delete
    if reply == "ok" or (
        isinstance(reply, str) and "The system cannot find the file specified" in reply
    ):
        task.delete()
    else:
        try:
            tr.sync_status = TaskSyncStatus.PENDING_DELETION
            tr.save(update_fields=["sync_status"])
        except DatabaseError:
            pass
        logger.error("win task delete failed on %s: %s", task.pk, reply)


def _get_failing_data(agents) -> dict:
    from agents.utils import calculate_agent_checks

    data = {"error": False, "warning": False}
    # an error does not end the loop, a later agent may still set the warning
    for agent in agents:
        if data["error"] and data["warning"]:
            break
        if agent.maintenance_mode:
            # skip this agent, do not hide the agents after it
            continue
        if agent.status == AGENT_STATUS_OVERDUE:
            data["error"] = True
            continue

        checks = calculate_agent_checks(agent)
        if checks["has_failing_checks"]:
            if checks["warning"]:
                data["warning"] = True
            if checks["failing"]:
                data["error"] = True
        else:
            for result in agent.taskresults.all():
                if result.status == TaskStatus.FAILING:
                    if result.task.alert_severity == AlertSeverity.ERROR:
                        data["error"] = True
                    elif result.task.alert_severity == AlertSeverity.WARNING:
                        data["warning"] = True
    return data


@app.task(bind=True)
def cache_db_fields_task(self):
    lock = redis_lock(CACHE_DB_FIELDS_TASK_LOCK, self.app.oid, MINUTE_LOCK_EXPIRE)
    with lock as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        from django.core.cache import cache

        from agents.models import Agent
        from agents.utils import calculate_agent_checks
        from clients.models import Client, Site

        # status reads the alert template of a long silent agent
        failing_prefetch = (
            Agent.objects.defer(*AGENT_DEFER)
            .select_related("alert_template")
            .prefetch_related(
                "agentchecks__script",
                "checkresults__assigned_check",
                "taskresults__task",
                "autotasks",
            )
        )

        for site in Site.objects.all():
            site.failing_checks = _get_failing_data(failing_prefetch.filter(site=site))
            site.save(update_fields=["failing_checks"])

        for client in Client.objects.all():
            client.failing_checks = _get_failing_data(
                failing_prefetch.filter(site__client=client)
            )
            client.save(update_fields=["failing_checks"])

        for agent in _get_agent_qs().iterator(chunk_size=100):
            cache.set(
                f"{AGENT_CHECKS_CACHE_PREFIX}{agent.pk}",
                calculate_agent_checks(agent),
                86400,
            )
        return "ok"


def _sleep_after(node_count: int) -> int:
    if node_count <= 250:
        return 150
    if node_count <= 500:
        return 275
    if node_count <= 800:
        return 300
    if node_count <= 1000:
        return 340
    return 375


@app.task(bind=True)
def sync_mesh_perms_task(self):
    if getattr(settings, "ULRMM_DISABLE_MESH_SYNC_TASK", False):
        return None

    with redis_lock(SYNC_MESH_PERMS_TASK_LOCK, self.app.oid) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"
        try:
            return _run_mesh_sync()
        except Exception as e:
            import traceback

            logger.error(
                "sync_mesh_perms_task failed: %s\n%s", e, traceback.format_exc()
            )
            return "error"


def _eligible_mesh_users(core):
    from accounts.models import User
    from accounts.utils import has_superuser_rights

    users = []
    for user in User.objects.filter(
        is_active=True,
        is_installer_user=False,
        block_dashboard_login=False,
        agent__isnull=True,
    ).select_related("role"):
        info = {
            "_id": user.mesh_user_id,
            "username": user.mesh_username,
            "full_name": build_mesh_display_name(
                user.first_name, user.last_name, core.mesh_company_name
            ),
            "email": (
                f"{make_alpha_numeric(user.username)}.{make_random_password(len=6)}"
                f"@ulrmm-do-not-change-{make_random_password(len=5)}.local"
            ),
        }
        users.append((user, info, has_superuser_rights(user)))
    return users


def _run_mesh_sync():
    from accounts.utils import console_stepup_remaining

    from agents.models import Agent

    core = get_core_settings()
    if core is None:
        return "no core settings"

    uri = get_mesh_ws_url()
    ms = MeshSync(uri)

    if not core.sync_mesh_with_rmm:
        for mesh_user_id in list(ms.mesh_users.keys()):
            ms.delete_user_from_mesh(mesh_user_id=mesh_user_id)
        return "mesh sync disabled"

    nodes_reply = ms.mesh_action(payload={"action": "nodes"})
    if not isinstance(nodes_reply, dict) or "nodes" not in nodes_reply:
        # without the current links every node would look empty and be re-added
        logger.error("sync_mesh_perms_task: MeshCentral sent no node list")
        return "error"
    nodes_by_mesh = nodes_reply["nodes"] or {}
    current_nodes = {n["node_id"]: n for n in transform_mesh(nodes_by_mesh)}
    mesh_node_names = {}
    for node_list in nodes_by_mesh.values():
        for node in node_list:
            mesh_node_names[node["_id"]] = node.get("name", "")

    users = _eligible_mesh_users(core)
    allowed = [
        (info["_id"], (lambda agent: True) if is_super else agent_perm_check(user))
        for user, info, is_super in users
        if has_mesh_perms(user=user)
    ]

    desired_by_node = {}
    desired_everywhere = set()
    for agent in (
        Agent.objects.defer(*AGENT_DEFER)
        .select_related("site")
        .exclude(mesh_node_id__isnull=True)
        .exclude(mesh_node_id="")
    ):
        hex_id = agent.hex_mesh_node_id
        if not hex_id or hex_id == "error":
            continue
        node_id = f"node//{hex_id}"
        desired = {user_id for user_id, allows in allowed if allows(agent)}
        desired_by_node[node_id] = {
            "users": desired,
            "name": mesh_node_name(agent.effective_name),
        }
        desired_everywhere |= desired

    info_by_id = {info["_id"]: info for _user, info, _super in users}

    # global create / delete against the mesh user accounts
    existing_mesh = set(ms.mesh_users.keys())
    for user_id in desired_everywhere - existing_mesh:
        if user_id in info_by_id:
            ms.add_user_to_mesh(user_info=info_by_id[user_id])
    # only accounts that are linked to some node and no longer wanted anywhere;
    # no agent with a usable node id usually means the node ids are not synced
    # yet, and deleting every account then would lock everyone out of MeshCentral
    linked = set()
    for node in current_nodes.values():
        linked.update(node["user_ids"])
    removed = linked - desired_everywhere if desired_by_node else set()
    for user_id in removed:
        ms.delete_user_from_mesh(mesh_user_id=user_id)

    stepup = {
        info["_id"]: console_stepup_remaining(user) > 0 for user, info, _super in users
    }

    node_count = len(desired_by_node)
    sleep_after = _sleep_after(node_count)
    changed = 0
    for node_id, desired in desired_by_node.items():
        current = current_nodes.get(node_id, {"user_ids": [], "rights": {}})
        current_users = set(current["user_ids"]) - removed
        rights = current["rights"]
        wanted = desired["users"]

        to_add = wanted - current_users
        to_delete = current_users - wanted
        to_demote = {
            uid
            for uid in (wanted & current_users)
            if rights.get(uid) != MESH_RIGHTS_BASE
            and not (stepup.get(uid) and rights.get(uid) == MESH_RIGHTS_CONSOLE)
        }

        node_changed = False
        if to_add:
            ms.add_users_to_node(node_id=node_id, user_ids=sorted(to_add))
            node_changed = True
        if to_demote:
            ms.add_users_to_node(node_id=node_id, user_ids=sorted(to_demote))
            node_changed = True
        if to_delete:
            ms.delete_users_from_node(node_id=node_id, user_ids=sorted(to_delete))
            node_changed = True

        desired_name = desired["name"]
        if (
            desired_name
            and node_id in mesh_node_names
            and mesh_node_names[node_id] != desired_name
        ):
            ms.rename_node(node_id=node_id, name=desired_name)
            node_changed = True

        if node_changed:
            changed += 1
            if sleep_after and changed % sleep_after == 0:
                import time

                time.sleep(7)

    # realname pass on a fresh connection
    ms2 = MeshSync(uri)
    mesh_users = ms2.mesh_users
    for user_id in desired_everywhere:
        info = info_by_id.get(user_id)
        if not info:
            continue
        current_real = (mesh_users.get(user_id) or {}).get("realname", "")
        if current_real != info["full_name"]:
            ms2.update_mesh_displayname(user_info=info)
    return "completed"


@app.task(bind=True, max_retries=3)
def rename_mesh_node_task(self, agent_pk):
    if getattr(settings, "ULRMM_DISABLE_MESH_SYNC_TASK", False):
        return

    from agents.models import Agent
    from logs.models import DebugLog

    agent = Agent.objects.defer(*AGENT_DEFER).filter(pk=agent_pk).first()
    if not agent or agent.hex_mesh_node_id == "error":
        return
    name = mesh_node_name(agent.effective_name)
    if not name:
        return

    ms = MeshSync(get_mesh_ws_url())
    try:
        reply = ms.rename_node(
            node_id=f"node//{agent.hex_mesh_node_id}", name=name, wait=True
        )
    except Exception as e:
        reply = str(e)

    if isinstance(reply, dict):
        result = reply.get("result", "no answer")
    elif reply is None:
        result = "no answer"
    else:
        result = str(reply)

    if result == "ok":
        return

    if self.request.retries >= self.max_retries:
        DebugLog.error(
            agent=agent,
            message=f"Unable to rename {agent.hostname} to {name} in MeshCentral: {result}",
            log_type=DebugLogType.AGENT_ISSUES,
        )
        return
    raise self.retry(countdown=60 * 2**self.request.retries)


@app.task(bind=True)
def scheduled_task_runner(self):
    with redis_lock(
        SCHED_TASK_RUNNER_LOCK, self.app.oid, MINUTE_LOCK_EXPIRE
    ) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        from autotasks.models import TaskResult
        from ulrmm import scheduler

        now = djangotime.now()
        runners = {
            TaskType.DAILY: scheduler.should_run_daily_task,
            TaskType.WEEKLY: scheduler.should_run_weekly_task,
            TaskType.MONTHLY: scheduler.should_run_monthly_task,
            TaskType.MONTHLY_DOW: scheduler.should_run_monthly_dow_task,
        }

        due = []
        due_pks = []
        results = (
            TaskResult.objects.filter(task__enabled=True)
            .exclude(agent__plat=AgentPlat.WINDOWS)
            .select_related("agent", "task")
        )
        for result in results:
            if result.locked_at and (now - result.locked_at) < timedelta(seconds=55):
                logger.error(
                    "scheduled_task_runner: task %s is still locked", result.task_id
                )
                continue

            task = result.task
            agent = result.agent
            tt = task.task_type
            if tt in runners:
                run = runners[tt](task, agent, now)
            elif tt == TaskType.RUN_ONCE:
                run = not result.last_run and scheduler.should_run_once_task(
                    task, agent, now
                )
            elif tt == TaskType.ONBOARDING:
                run = not result.last_run and result.run_status not in (
                    TaskRunStatus.RUNNING,
                    TaskRunStatus.COMPLETED,
                )
            else:
                run = False

            if run:
                due.append((agent.agent_id, {"func": "runtask", "taskpk": task.pk}))
                due_pks.append(result.pk)

        if not due:
            return []

        # send only the rows this run claims; others are still locked by a run
        # that read them first
        stale = now - timedelta(seconds=55)
        free = Q(locked_at__isnull=True) | Q(locked_at__lt=stale)
        with transaction.atomic():
            claimed = set(
                TaskResult.objects.select_for_update()
                .filter(free, pk__in=due_pks)
                .values_list("pk", flat=True)
            )
            TaskResult.objects.filter(pk__in=claimed).update(
                run_status=TaskRunStatus.RUNNING, locked_at=now
            )
            due = [item for pk, item in zip(due_pks, due) if pk in claimed]
            if due:
                asyncio.run(abulk_nats_command(items=due))

        return due

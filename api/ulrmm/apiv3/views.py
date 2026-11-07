# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Endpoints the agent and its installer talk to. Agent identity always comes
from the DRF token; ids in the URL or the body are checked against it."""

import asyncio
import logging
import os
import re
from typing import Any, Optional

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from knox.models import AuthToken
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle
from rest_framework.views import APIView

from accounts.models import User
from agents.models import UNINSTALL_CODE_INFO, Agent, AgentHistory, Note
from agents.permissions import AgentInstallerPerms
from agents.serializers import AgentHistoryResultSerializer
from alerts.models import Alert
from alerts.tasks import cache_agents_alert_template
from autotasks.models import AutomatedTask, TaskResult
from autotasks.serializers import TaskGOGetSerializer, TaskResultAgentSerializer
from checks.constants import CHECK_DEFER
from checks.health import run_interval
from checks.models import Check, CheckResult, apply_result, clean_result
from checks.serializers import CheckRunnerGetSerializer
from clients.models import Deployment
from core.tasks import sync_mesh_perms_task
from core.utils import (
    MeshDeviceGroupNotFound,
    download_mesh_agent,
    get_core_settings,
    get_mesh_device_id,
    get_mesh_installer,
    get_mesh_ws_url,
    get_meshagent_url,
)
from deploy import events, identity, pki, signing, tokens
from deploy.models import (
    AgentCertificate,
    Enrollment,
    EnrollmentLimit,
    IdentityState,
    MtlsMode,
    SecurityEventKind,
)
from deploy.signals import agent_enrolled
from importers import link as importers_link
from logs.models import AuditLog, DebugLog
from metrics.state import MAX_BODY as MAX_STATE
from software.drivers import MAX_BODY as MAX_DRIVERS_BODY
from software.drivers import clean_drivers
from metrics.state import clean_state, ingest
from notify.tamper import report_stop
from patches.maintenance import install_finished, scan_finished
from patches.mirror import mirror_agent_updates
from remote.utils import decrypt_secret, encrypt_secret
from software.models import InstalledDrivers, InstalledSoftware, SdioApproval
from software.tasks import apply_sdio_task
from ulrmm.auth import (
    AgentCertAuthentication,
    AgentIdentityAuthentication,
    AgentTokenAuthentication,
    APIAuthentication,
    EnrollmentAuthentication,
    InstallerTokenAuthentication,
)
from ulrmm.constants import (
    AGENT_DEFER,
    ULRMM_MAX_REQUEST_SIZE,
    AgentHistoryType,
    AgentMonType,
    AgentPlat,
    AuditActionType,
    AuditObjType,
    CheckType,
    CustomFieldModel,
    DebugLogType,
    GoArch,
    MeshAgentIdent,
    TaskRunStatus,
    TaskStatus,
)
from ulrmm.helpers import (
    DATED_VER,
    agent_ver,
    get_client_ip,
    make_random_password,
    notify_error,
)
from ulrmm.permissions import _has_install_perm
from ulrmm.utils import AGENT_ID_RE, reload_nats
from winupdate.installing import (
    SCAN_CMD,
    clear_all_installing,
    clear_installing,
    clear_stale_installing,
)
from winupdate.models import DRIVERS_CATEGORY, WinUpdate, WinUpdatePolicy

from .utils import get_agent_config

logger = logging.getLogger("ulrmm")

TRUNCATED = "Content truncated due to excessive request size."
TOO_LARGE = "Request too large"
MESH_UNREACHABLE = "Unable to connect to mesh to get group id information"
NODE_TAKEN = "This mesh node id belongs to another agent"

UNINSTALL_CODE_RE = re.compile(r"[A-Za-z0-9]{32}")
# consumers decode with bytes.fromhex, which ignores case and spaces; only
# plain hex is accepted so one node id has one spelling apart from case
NODE_ID_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){0,127}")

MAX_WUA_UPDATES = 5000
MAX_WUA_TEXT = 64 * 1024
MAX_WUA_URLS = 20
MAX_URL = 2048
MAX_SOFTWARE = 20000
MAX_SOFTWARE_TEXT = 1024

MESH_IDENTS = {
    ("amd64", "windows"): MeshAgentIdent.WIN64,
    ("386", "windows"): MeshAgentIdent.WIN32,
    ("amd64", "darwin"): MeshAgentIdent.DARWIN_UNIVERSAL,
    ("arm64", "darwin"): MeshAgentIdent.DARWIN_UNIVERSAL,
    # MeshCentral builds no FreeBSD arm64 agent
    ("amd64", "freebsd"): MeshAgentIdent.FREEBSD64,
}

# the beat task syncs every few minutes anyway, agents only nudge it
SYNCMESH_DEBOUNCE_KEY = "syncmesh-trigger"
SYNCMESH_DEBOUNCE = 60


# helpers


class AgentTokenView(APIView):
    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsAuthenticated]


def _maybe_sealed(agent, request, data) -> Response:
    """Sealed for the agent's X25519 key when it asks for it (R2 agents)."""
    if request.META.get("HTTP_X_ULRMM_SEAL") != "1":
        return Response(data)
    from deploy import envelope

    return envelope.seal_response(agent, request, data)


def _identity_hints(agent) -> dict:
    """What the dashboard asked an R2 agent to rotate, and the server clock;
    nothing for agents without an active identity."""
    ident = tokens.identity_of(agent)
    if ident is None or ident.state != IdentityState.ACTIVE:
        return {}
    return {"rotate": list(ident.rotate_pending), "now_ms": tokens.now_ms()}


def _answer(result) -> Response:
    status, body = result
    return Response(body, status=status)


class InstallerThrottle(SimpleRateThrottle):
    """Per installer token or deployment, so a mass deployment behind one NAT
    address is not slowed down by its neighbours."""

    scope = "installer"

    def get_cache_key(self, request, view):
        if isinstance(request.auth, Deployment):
            ident = f"dep{request.auth.pk}"
        else:
            ident = getattr(request.auth, "pk", None) or request.user.pk
        return self.cache_format % {"scope": self.scope, "ident": ident}


class InstallerView(APIView):
    authentication_classes = [
        EnrollmentAuthentication,
        InstallerTokenAuthentication,
        APIAuthentication,
    ]
    throttle_classes = [InstallerThrottle]


def _data(request) -> dict:
    data = request.data
    return data if hasattr(data, "get") else {}


def _too_large(request) -> bool:
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return False
    return length > ULRMM_MAX_REQUEST_SIZE


def _token_agent(request, agentid: Optional[str] = None, qs=None) -> Agent:
    """The agent of the token; a URL agent id must be its own."""
    lookup = {"user": request.user}
    if agentid is not None:
        lookup["agent_id"] = agentid
    if qs is None:
        qs = Agent.objects.defer(*AGENT_DEFER)
    return get_object_or_404(qs, **lookup)


def _is_bool(value) -> bool:
    return isinstance(value, bool)


def _pk(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _http_url(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_URL
        and value.lower().startswith(("http://", "https://"))
    )


def _owns_check(agent: Agent, check: Optional[Check]) -> bool:
    if check is None:
        return False
    if check.agent_id:
        return check.agent_id == agent.pk
    return check.pk in {c.pk for c in agent.get_checks_with_policies()}


def _owns_task(agent: Agent, task: Optional[AutomatedTask]) -> bool:
    if task is None:
        return False
    if task.agent_id:
        return task.agent_id == agent.pk
    return task.pk in {t.pk for t in agent.get_tasks_with_policies()}


def _mesh_device_id(core, agent: Optional[Agent] = None):
    """(device id, None) or (None, the 400 to answer with)."""
    try:
        uri = get_mesh_ws_url()
        return asyncio.run(get_mesh_device_id(uri, core.mesh_device_group)), None
    except MeshDeviceGroupNotFound as e:
        DebugLog.error(agent=agent, message=str(e))
        return None, notify_error(str(e))
    except Exception:
        return None, notify_error(MESH_UNREACHABLE)


def _node_id(value):
    # Linux/macOS agents send the id with the newline of `meshagent -nodeid`
    return value.strip() if isinstance(value, str) else value


def _valid_node_id(value) -> bool:
    return isinstance(value, str) and NODE_ID_RE.fullmatch(value) is not None


def _node_holders(node_id: str, agent_pk: Optional[int]) -> list:
    if not node_id:
        return []
    holders = Agent.objects.filter(mesh_node_id__iexact=node_id).only(
        "pk", "hostname", "site_id", "last_seen", "offline_time", "overdue_time"
    )
    if agent_pk is not None:
        holders = holders.exclude(pk=agent_pk)
    return list(holders)


def _claim_node_id(hostname: str, site_id: int, holders: list) -> Optional[Response]:
    """A node id of an agent in another site is refused; one of the same site
    (reinstall without removing the old agent) moves to the new agent."""
    foreign = [h for h in holders if h.site_id != site_id]
    if foreign:
        DebugLog.warning(
            log_type=DebugLogType.AGENT_ISSUES,
            message=f"{hostname} reported the mesh node id of {foreign[0].hostname}, "
            "which belongs to another site. Refused.",
        )
        return notify_error(NODE_TAKEN)
    return None


def _online_holder(caller: str, hostname: str, holders: list):
    """A same-site holder that is still online keeps the id: two live agents
    with one id are a cloned image, moving it would flip it on every sync."""
    for holder in holders:
        if not holder.is_online:
            continue
        if cache.add(f"nodeid-dup-{caller}-{holder.pk}", 1, 3600):
            DebugLog.warning(
                agent=holder,
                log_type=DebugLogType.AGENT_ISSUES,
                message=f"{hostname} and {holder.hostname} report the same mesh "
                "node id. Reinstall the mesh agent on the cloned machine.",
            )
        return holder
    return None


def _release_node_id(holders: list) -> None:
    if not holders:
        return
    Agent.objects.filter(pk__in=[h.pk for h in holders]).update(mesh_node_id="")
    for holder in holders:
        DebugLog.warning(
            agent=holder,
            log_type=DebugLogType.AGENT_ISSUES,
            message=f"The mesh node id of {holder.hostname} moved to a reinstalled "
            "agent of the same site",
        )


# checks


def _agent_run_checks(agent: Agent) -> list[Check]:
    # the server judges metric checks from the state pushes
    return [
        check
        for check in agent.get_checks_with_policies(exclude_overridden=True)
        if check.check_type != CheckType.METRIC
    ]


class CheckRunner(AgentTokenView):
    def get(self, request, agentid=None):
        agent = _token_agent(request, agentid)
        now = djangotime.now()
        due = []
        checks = _agent_run_checks(agent)
        for check in checks:
            result = check.check_result
            if not isinstance(result, CheckResult) or not result.last_run:
                due.append(check)
                continue
            interval = run_interval(
                check.check_type, check.run_interval, agent.check_interval
            )
            if result.last_run < now - djangotime.timedelta(seconds=interval):
                due.append(check)

        return Response(
            {
                "agent": agent.pk,
                "check_interval": agent.check_run_interval(checks),
                "checks": CheckRunnerGetSerializer(
                    due, context={"agent": agent}, many=True
                ).data,
            }
        )

    def patch(self, request):
        data = _data(request)
        if "agent_id" not in data:
            return notify_error("Agent upgrade required")

        agent = _token_agent(request)
        pk = _pk(data.get("id"))
        if pk is None:
            return notify_error("id is required")
        check = Check.objects.defer(*CHECK_DEFER).filter(pk=pk).first()
        # absent and foreign look the same, check pks of others stay unknown
        if not _owns_check(agent, check):
            return notify_error("")

        apply_result(check, agent, clean_result(check.check_type, data))
        return Response("ok")


class RunChecks(AgentTokenView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid)
        listed = CheckRunnerGetSerializer(
            _agent_run_checks(agent), context={"agent": agent}, many=True
        )
        return Response(
            {
                "agent": agent.pk,
                "check_interval": agent.check_interval,
                "checks": listed.data,
            }
        )


class State(AgentTokenView):
    def post(self, request, agentid):
        agent = _token_agent(request, agentid)
        if _too_large(request) or len(request.body) > MAX_STATE:
            return notify_error(TOO_LARGE)
        try:
            state = clean_state(request.data)
        except ValueError:
            return notify_error("state must be an object")
        ingest(agent, state)
        return Response("ok")


class Drivers(AgentTokenView):
    def post(self, request, agentid):
        agent = _token_agent(request, agentid)
        if _too_large(request) or len(request.body) > MAX_DRIVERS_BODY:
            return notify_error(TOO_LARGE)
        try:
            data = clean_drivers(request.data)
        except ValueError as e:
            return notify_error(str(e))
        InstalledDrivers.objects.update_or_create(
            agent=agent, defaults={"received": djangotime.now(), "data": data}
        )
        if SdioApproval.objects.exists():
            apply_sdio_task.delay([agent.pk])
        return Response("ok")


class CheckRunnerInterval(AgentTokenView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid)
        return Response(
            {
                "agent": agent.pk,
                "check_interval": agent.check_run_interval(),
                **_identity_hints(agent),
            }
        )


# automated tasks


class TaskRunner(AgentTokenView):
    def get(self, request, pk, agentid):
        agent = _token_agent(
            request, agentid, Agent.objects.select_related("policy", "site")
        )
        task = (
            AutomatedTask.objects.select_related("agent", "policy")
            .filter(pk=pk)
            .first()
        )
        if not _owns_task(agent, task):
            return notify_error("")
        return Response(TaskGOGetSerializer(task, context={"agent": agent}).data)

    def patch(self, request, pk, agentid):
        agent = _token_agent(request, agentid)
        task = (
            AutomatedTask.objects.select_related("custom_field").filter(pk=pk).first()
        )
        if not _owns_task(agent, task):
            return notify_error("")

        if _too_large(request):
            data = {"stdout": "", "stderr": TRUNCATED, "retcode": 1}
        else:
            data = request.data

        serializer = TaskResultAgentSerializer(
            instance=TaskResult.objects.filter(task=task, agent=agent).first(),
            data=data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        task_result = serializer.save(
            agent=agent,
            task=task,
            last_run=djangotime.now(),
            run_status=TaskRunStatus.COMPLETED,
        )

        AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.TASK_RUN,
            command=task.name,
            script_results={
                "stdout": task_result.stdout,
                "stderr": task_result.stderr,
                "retcode": task_result.retcode,
                "execution_time": task_result.execution_time,
            },
        )

        # collector writes happen on every run: the agent schedules the runs
        # itself, so a later run cannot be told apart from a replay
        if task.custom_field:
            if not task_result.stderr:
                task_result.save_collector_results()
                status = TaskStatus.PASSING
            else:
                status = TaskStatus.FAILING
        else:
            status = (
                TaskStatus.FAILING if task_result.retcode != 0 else TaskStatus.PASSING
            )
        task_result.status = status
        task_result.save(update_fields=["status"])

        if status == TaskStatus.PASSING:
            if Alert.create_or_return_task_alert(task, agent=agent, skip_create=True):
                Alert.handle_alert_resolve(task_result)
        else:
            Alert.handle_alert_failure(task_result)

        return Response("ok")


class AgentHistoryResult(AgentTokenView):
    def patch(self, request, pk, agentid):
        agent = _token_agent(request, agentid)
        hist = get_object_or_404(
            AgentHistory.objects.select_related("custom_field").filter(agent=agent),
            pk=pk,
        )
        # a history row takes one result, a second write is never legitimate
        if hist.script_results or hist.results:
            return notify_error("")

        if _too_large(request):
            if hist.type == AgentHistoryType.CMD_RUN:
                data = {"results": TRUNCATED}
            else:
                data = {
                    "script_results": {
                        "stdout": "",
                        "stderr": TRUNCATED,
                        "retcode": 1,
                        "execution_time": 0,
                    }
                }
        else:
            data = request.data

        serializer = AgentHistoryResultSerializer(
            instance=hist, data=data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        results = hist.script_results
        stdout = results.get("stdout") if isinstance(results, dict) else None
        if not isinstance(stdout, str):
            return Response("ok")

        if hist.custom_field:
            self._collect(hist, stdout)
        if hist.save_to_agent_note:
            # the note author is the agent's own user
            Note.objects.create(agent=hist.agent, user=request.user, note=stdout)
        return Response("ok")

    def _collect(self, hist, stdout: str) -> None:
        field = hist.custom_field
        targets = {
            CustomFieldModel.AGENT: lambda: hist.agent,
            CustomFieldModel.CLIENT: lambda: hist.agent.client,
            CustomFieldModel.SITE: lambda: hist.agent.site,
        }
        if field.model not in targets:
            DebugLog.warning(
                agent=hist.agent,
                log_type=DebugLogType.SCRIPTING,
                message=f"Collector field {field.name} has an unknown model "
                f"{field.model}, result not saved",
            )
            return

        value = stdout.strip()
        if not hist.collector_all_output:
            value = value.split("\n")[-1].strip()
        field.get_or_create_field_value(targets[field.model]()).save_to_field(value)


# check-in and agent state


class CheckIn(AgentTokenView):
    def post(self, request):
        agent = _token_agent(request)
        data = _data(request)
        clear_stale_installing(agent.pk)

        code = data.get("uninstall_code")
        if isinstance(code, str) and UNINSTALL_CODE_RE.fullmatch(code):
            try:
                stored = decrypt_secret(agent.uninstall_code, UNINSTALL_CODE_INFO)
            except (InvalidToken, ValueError, TypeError, AttributeError):
                stored = None
            if stored != code:
                Agent.objects.filter(pk=agent.pk).update(
                    uninstall_code=encrypt_secret(code, UNINSTALL_CODE_INFO)
                )

        report_stop(agent, data.get("stop_reason"))

        hints = _identity_hints(agent)
        answer = {"ok": True, **hints} if hints else "ok"
        if hints:
            from deploy import envelope

            # the service just started: its sessions are gone
            envelope.forget(agent.agent_id)
        if agent.plat != AgentPlat.WINDOWS:
            return Response(answer)
        if not agent.choco_installed:
            asyncio.run(agent.nats_cmd({"func": "installchoco"}, wait=False))
        asyncio.run(agent.nats_cmd(SCAN_CMD, wait=False))
        return Response(answer)


class SyncMeshNodeID(AgentTokenView):
    def post(self, request):
        agent = _token_agent(request)
        data = _data(request)
        node_id = _node_id(data.get("nodeid"))
        if not _valid_node_id(node_id):
            return notify_error("nodeid must be a hex string")

        # compared unstripped, so rows stored with the newline heal
        if node_id.lower() != (agent.mesh_node_id or "").lower():
            holders = _node_holders(node_id, agent.pk)
            refused = _claim_node_id(agent.hostname, agent.site_id, holders)
            if refused:
                return refused
            if _online_holder(agent.agent_id, agent.hostname, holders):
                return notify_error(NODE_TAKEN)
            with transaction.atomic():
                _release_node_id(holders)
                agent.mesh_node_id = node_id
                agent.save(update_fields=["mesh_node_id"])

        if data.get("run_sync_task") is True and cache.add(
            SYNCMESH_DEBOUNCE_KEY, 1, SYNCMESH_DEBOUNCE
        ):
            sync_mesh_perms_task.delay()
        return Response("ok")


class Choco(AgentTokenView):
    def post(self, request):
        installed = _data(request).get("installed")
        if not _is_bool(installed):
            return notify_error("installed must be a boolean")
        agent = _token_agent(request)
        agent.choco_installed = installed
        agent.save(update_fields=["choco_installed"])
        return Response("ok")


def _str_list(value, limit: Optional[int] = 255) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item[:limit] for item in value if isinstance(item, str)]


def _text(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


# keys the agent always sends, an item without one of them is broken
WUA_KEYS = (
    "guid",
    "title",
    "installed",
    "downloaded",
    "description",
    "severity",
    "categories",
    "category_ids",
    "more_info_urls",
    "support_url",
    "revision_number",
)


def _clean_wua(item) -> Optional[dict[str, Any]]:
    """The stored fields of one WUA update, None for an unusable item."""
    if not isinstance(item, dict) or any(key not in item for key in WUA_KEYS):
        return None
    guid = item.get("guid")
    if not isinstance(guid, str) or not guid or len(guid) > 255:
        return None
    if not _is_bool(item.get("installed")) or not _is_bool(item.get("downloaded")):
        return None

    revision = item.get("revision_number")
    if isinstance(revision, bool) or not isinstance(revision, int):
        revision = None
    elif not -(2**31) <= revision < 2**31:
        revision = None

    # links end up as <a href> in the dashboard
    urls = [u for u in _str_list(item.get("more_info_urls"), MAX_URL) if _http_url(u)]
    support_url = item.get("support_url")
    kb_ids = _str_list(item.get("kb_article_ids"), limit=None)
    if any(len(kb_id) > 255 for kb_id in kb_ids):
        return None
    kb = f"KB{kb_ids[0]}" if kb_ids and kb_ids[0] else None
    if kb and len(kb) > 100:
        return None
    category_ids = _str_list(item.get("category_ids"))
    return {
        "guid": guid,
        "kb": kb,
        "title": _text(item.get("title"), MAX_WUA_TEXT),
        "installed": item["installed"],
        "downloaded": item["downloaded"],
        "description": _text(item.get("description"), MAX_WUA_TEXT),
        "severity": _text(item.get("severity"), 255),
        "categories": _str_list(item.get("categories")),
        "category_ids": category_ids,
        "kb_article_ids": kb_ids,
        "more_info_urls": urls[:MAX_WUA_URLS],
        "support_url": support_url if _http_url(support_url) else "",
        "revision_number": revision,
        # older agents send no type, their installed drivers carry the category
        "is_driver": item.get("type") == "driver" or DRIVERS_CATEGORY in category_ids,
    }


class WinUpdates(AgentTokenView):
    def put(self, request):
        needs_reboot = _data(request).get("needs_reboot")
        if not _is_bool(needs_reboot):
            return notify_error("needs_reboot must be a boolean")

        agent = _token_agent(request)
        clear_all_installing(agent.pk)
        rebooting = agent.handle_patch_reboot(needs_reboot)
        agent.delete_superseded_updates()
        install_finished(agent, rebooting)
        return Response("ok")

    def patch(self, request):
        data = _data(request)
        guid, success = data.get("guid"), data.get("success")
        if not isinstance(guid, str) or not guid:
            return notify_error("guid is required")
        if not _is_bool(success):
            return notify_error("success must be a boolean")

        agent = _token_agent(request)
        if not agent.set_update_result(guid, success):
            return notify_error("Unknown update guid")
        return Response("ok")

    def post(self, request):
        if _too_large(request):
            return notify_error(TOO_LARGE)

        agent = _token_agent(request)
        data = _data(request)
        if "wua_updates" not in data:
            return notify_error("wua_updates is required")
        updates = data["wua_updates"]
        if updates and (
            not isinstance(updates, list) or len(updates) > MAX_WUA_UPDATES
        ):
            return notify_error("wua_updates must be a list")

        items = [_clean_wua(item) for item in updates or []]
        valid = [item for item in items if item is not None]
        if not valid:
            # a scan that reports nothing is broken, not an empty machine
            DebugLog.warning(
                agent=agent,
                log_type=DebugLogType.WIN_UPDATES,
                message=f"Update scan on {agent.hostname} returned no updates, "
                "keeping the known updates",
            )
            return notify_error("Empty payload")
        if len(valid) < len(items):
            DebugLog.warning(
                agent=agent,
                log_type=DebugLogType.WIN_UPDATES,
                message=f"Update scan on {agent.hostname} sent "
                f"{len(items) - len(valid)} malformed updates, they were skipped",
            )

        # a skipped item still names an update the machine has, keep its row
        returned = {
            i["guid"]
            for i in updates
            if isinstance(i, dict) and isinstance(i.get("guid"), str)
        }
        installed = [item["guid"] for item in valid if item["installed"]]

        with transaction.atomic():
            known: dict[str, WinUpdate] = {}
            for row in agent.winupdates.filter(guid__in=returned).order_by("pk"):
                known[row.guid] = row  # the last row of a guid wins

            new: dict[str, WinUpdate] = {}
            for item in valid:
                row = known.get(item["guid"])
                if row is not None:
                    # known rows only follow the install state and the driver flag
                    row.downloaded = item["downloaded"]
                    row.installed = item["installed"]
                    row.is_driver = item["is_driver"]
                    row.save(update_fields=["downloaded", "installed", "is_driver"])
                elif item["guid"] in new:
                    new[item["guid"]].downloaded = item["downloaded"]
                    new[item["guid"]].installed = item["installed"]
                elif item["kb"] or item["is_driver"]:
                    # driver updates have no KB
                    new[item["guid"]] = WinUpdate(agent=agent, **item)
            WinUpdate.objects.bulk_create(new.values())

            # ignored updates stay, they hold the operator's decision
            agent.winupdates.filter(installed=False).exclude(guid__in=returned).exclude(
                action="ignore"
            ).delete()

        clear_installing(agent.pk, installed)
        agent.delete_superseded_updates()
        mirror_agent_updates(agent)
        scan_finished(agent)
        return Response("ok")


class SupersededWinUpdate(AgentTokenView):
    def post(self, request):
        guid = _data(request).get("guid")
        if not isinstance(guid, str) or not guid:
            return notify_error("guid is required")
        agent = _token_agent(request)
        for update in agent.winupdates.filter(guid=guid):
            update.delete()
        return Response("ok")


class Software(AgentTokenView):
    def post(self, request):
        if _too_large(request):
            return notify_error(TOO_LARGE)

        software = _data(request).get("software")
        if (
            not isinstance(software, list)
            or len(software) > MAX_SOFTWARE
            or not all(isinstance(item, dict) for item in software)
        ):
            return notify_error("software must be a list")
        software = [
            {
                str(key)[:100]: (
                    value[:MAX_SOFTWARE_TEXT] if isinstance(value, str) else value
                )
                for key, value in item.items()
            }
            for item in software
        ]

        agent = _token_agent(request, qs=Agent.objects.only("pk"))
        with transaction.atomic():
            # the agent row lock keeps two reports from creating two rows
            Agent.objects.select_for_update().only("pk").get(pk=agent.pk)
            row = InstalledSoftware.latest_for(agent)
            if row is None:
                InstalledSoftware.objects.update_or_create(
                    agent=agent, defaults={"software": software}
                )
            else:
                row.software = software
                row.save(update_fields=["software"])
                # the newest row is the inventory, older duplicates go
                stale = InstalledSoftware.objects.filter(agent=agent)
                stale.exclude(pk=row.pk).delete()
        return Response("ok")


class AgentConfig(AgentTokenView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid, Agent.objects.only("plat", "goarch"))
        return Response(get_agent_config(agent)._to_dict())


class SelfHeal(AgentTokenView):
    def _agent(self, request, agentid):
        return _token_agent(
            request,
            agentid,
            Agent.objects.only("plat", "goarch", "agent_id", "agent_ident", "hostname"),
        )

    def get(self, request, agentid):
        from agents.utils import get_agent_artifact_sha256, get_agent_url

        agent = self._agent(request, agentid)
        try:
            url = get_agent_url(agent=agent)
            sha256 = get_agent_artifact_sha256(agent=agent)
        except ValueError as e:
            return notify_error(str(e))
        if not sha256:
            return Response("No local build for this agent", status=404)
        version = settings.LATEST_AGENT_VER
        data = {"version": version, "url": url, "sha256": sha256}
        if agent.plat == AgentPlat.WINDOWS:
            # sha256 is the setup; the agent compares its own exe
            from deploy.integrity import WINDOWS_SUM_SUFFIX, _windows_sum
            from ulrmm.agent_ident import agent_artifact_for

            exe_sum = _windows_sum(
                agent_artifact_for(agent, version) + WINDOWS_SUM_SUFFIX
            )
            if exe_sum:
                data["agent_sha256"] = exe_sum
        # the same signed document do_update sends, the agent refuses a bare one
        try:
            data["update_sig"] = signing.sign_agent_update(
                agent.agent_id, url, version, sha256
            )
        except ImproperlyConfigured:
            pass
        return _maybe_sealed(agent, request, data)

    def post(self, request, agentid):
        agent = self._agent(request, agentid)
        actions = _data(request).get("actions")
        if not isinstance(actions, list) or not actions:
            return notify_error("actions must be a non-empty list")

        report = "; ".join(str(action)[:300] for action in actions[:10])
        DebugLog.warning(
            agent=agent,
            log_type=DebugLogType.AGENT_ISSUES,
            message=f"{agent.hostname} repaired itself: {report}",
        )
        return Response("ok")


# mesh


class MeshExe(InstallerView):
    permission_classes = [AgentInstallerPerms]

    def post(self, request):
        data = _data(request)
        goarch, plat = data.get("goarch"), data.get("plat")
        ident = None
        if isinstance(goarch, str) and isinstance(plat, str):
            ident = MESH_IDENTS.get((goarch, plat))
        if ident is None:
            return notify_error("Arch not supported")

        core = get_core_settings()
        mesh_device_id, error = _mesh_device_id(core)
        if error:
            return error

        try:
            return download_mesh_agent(
                _mesh_download_url(core, ident, plat, mesh_device_id)
            )
        except Exception as exc:
            # the download URL carries the mesh login token
            logger.warning(f"meshexe: mesh agent download failed: {type(exc).__name__}")
            return notify_error("Unable to download mesh agent")


def _mesh_download_url(core, ident, plat, device_id):
    return get_meshagent_url(
        ident=ident, plat=plat, mesh_site=core.mesh_site, mesh_device_id=device_id
    )


class MeshReinstall(AgentTokenView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid, Agent.objects.only("plat", "goarch"))
        if agent.plat != AgentPlat.WINDOWS:
            return notify_error("Mesh reinstall is only supported on Windows agents")

        core = get_core_settings()
        mesh_device_id, error = _mesh_device_id(core, agent)
        if error:
            return error

        ident = (
            MeshAgentIdent.WIN64 if agent.goarch == "amd64" else MeshAgentIdent.WIN32
        )
        try:
            path = get_mesh_installer(
                agent.goarch,
                _mesh_download_url(core, ident, agent.plat, mesh_device_id),
                agent.plat,
            )
        except Exception as exc:
            logger.warning(
                f"meshreinstall {agent.agent_id}: mesh agent download failed: "
                f"{type(exc).__name__}"
            )
            return notify_error("Unable to download mesh agent")
        return FileResponse(
            open(path, "rb"), as_attachment=True, filename=os.path.basename(path)
        )


# installer


def _new_agent_error(data) -> Optional[str]:
    agent_id = data.get("agent_id")
    if not isinstance(agent_id, str) or not AGENT_ID_RE.fullmatch(agent_id):
        return "Invalid agent_id"
    hostname = data.get("hostname")
    if (
        not isinstance(hostname, str)
        or not 0 < len(hostname) <= 255
        or _has_control_chars(hostname)
    ):
        return "Invalid hostname"
    description = data.get("description")
    if description is not None and (
        not isinstance(description, str) or len(description) > 255
    ):
        return "Invalid description"
    if data.get("plat") not in AgentPlat.values:
        return "Invalid plat"
    if data.get("goarch") not in GoArch.values:
        return "Invalid goarch"
    if data.get("monitoring_type") not in AgentMonType.values:
        return "Invalid monitoring_type"
    if not _valid_node_id(_node_id(data.get("mesh_node_id") or "")):
        return "Invalid mesh_node_id"
    return None


def _deployment(request) -> Optional[Deployment]:
    """The deployment the request is authenticated by: a signed enrollment
    token, or the knox token of a deployment made before those."""
    if isinstance(request.auth, Deployment):
        return request.auth
    if isinstance(request.auth, AuthToken):
        return request.auth.deploytokens.first()
    return None


def _enrolled(agent: Agent, deployment: Deployment) -> None:
    results = agent_enrolled.send_robust(
        sender=Agent, agent=agent, deployment=deployment
    )
    for receiver, result in results:
        if isinstance(result, Exception):
            logger.error(f"agent_enrolled {receiver} for {agent.agent_id}: {result}")


def _register_agent(request, holders: list, fields: dict, deployment=None):
    """Agent row, its user and token, the default patch policy, the audit
    entry and for a deployment its Enrollment row in one transaction; the
    agent_enrolled signal goes out once that has committed."""
    with transaction.atomic():
        _release_node_id(holders)
        agent = Agent.objects.create(last_seen=djangotime.now(), **fields)
        password = make_random_password(len=60)
        User.objects.create_user(
            username=agent.agent_id, agent=agent, password=password
        )
        # workstations patch on the weekend, servers have no default day
        weekend = agent.monitoring_type == AgentMonType.WORKSTATION
        WinUpdatePolicy.objects.create(
            agent=agent, run_time_days=[5, 6] if weekend else []
        )
        actor = request.user.username
        audit = {
            "username": actor,
            "agent": agent.hostname,
            "agent_id": agent.agent_id,
            "object_type": AuditObjType.AGENT,
            "action": AuditActionType.AGENT_INSTALL,
            "message": f"{actor} installed new agent {agent.hostname}",
            "after_value": Agent.serialize(agent),
            "debug_info": {"ip": getattr(request, "_client_ip", None)},
        }
        AuditLog.objects.create(**audit)
        if deployment is not None:
            Enrollment.objects.create(agent=agent, deployment=deployment)
            transaction.on_commit(lambda: _enrolled(agent, deployment))
        return agent, tokens.create_legacy(agent)


class NewAgent(InstallerView):
    def post(self, request):
        data = _data(request)
        site_id = _pk(data.get("site"))
        if site_id is None:
            return notify_error("site is required")
        if not _has_install_perm(request, site_id):
            raise PermissionDenied()

        deployment = _deployment(request)
        if deployment is not None:
            # the deployment decides the agent type, not the installer
            data = data.copy()
            data["monitoring_type"] = deployment.mon_type
        error = _new_agent_error(data)
        if error:
            return notify_error(error)

        csr = data.get("csr")
        sign = csr is not None and pki.mtls_mode() != MtlsMode.OFF
        if sign:
            try:
                pki.load_csr(csr)
            except pki.CertError as e:
                return notify_error(f"Invalid csr: {e}")

        agent_id = data["agent_id"]
        hostname = data["hostname"]
        mesh_node_id = _node_id(data.get("mesh_node_id") or "")
        holders = _node_holders(mesh_node_id, None)
        refused = _claim_node_id(hostname, site_id, holders)
        if refused:
            return refused
        # the install goes through without the id; syncmesh claims it later
        # once the old holder is offline
        if _online_holder(agent_id, hostname, holders):
            mesh_node_id, holders = "", []

        fields = {
            "agent_id": agent_id,
            "hostname": hostname,
            "site_id": site_id,
            "monitoring_type": data["monitoring_type"],
            "description": data.get("description") or "",
            "mesh_node_id": mesh_node_id,
            "goarch": data["goarch"],
            "plat": data["plat"],
            "agent_ident": str(data.get("agent_ident", ""))[:255],
        }
        # the first NATS config already gets the ACL of this version; agents
        # that send none are older ones
        version = data.get("version")
        if (
            isinstance(version, str)
            and len(version) <= 32
            and DATED_VER.fullmatch(version)
        ):
            fields["version"] = version
        if deployment is not None and deployment.policy_id:
            fields["policy_id"] = deployment.policy_id
        try:
            agent, token = _register_agent(request, holders, fields, deployment)
        except IntegrityError:
            return notify_error(
                "This agent is already registered. Delete the old entry before reinstalling."
            )
        except EnrollmentLimit as e:
            e.record(request, hostname)
            raise

        reload_nats()
        if agent.plat == AgentPlat.WINDOWS:
            sync_mesh_perms_task.delay()
        cache_agents_alert_template.delay()
        try:
            importers_link.on_enroll(agent)
        except Exception as e:
            # an imported device that fails to link never blocks the install
            logger.warning(f"newagent {agent.agent_id}: import link failed: {e!r}")
        body = {"pk": agent.pk, "token": token}
        if sign:
            # without a CA the agent asks for its certificate later
            try:
                issued = pki.issue(agent, csr)
                body.update(cert=issued["cert"], ca=issued["ca"])
            except pki.CAUnavailable as e:
                logger.warning(f"newagent {agent.agent_id}: no certificate: {e}")
        return Response(body)


class AgentCert(AgentTokenView):
    """A client certificate for the agent's own key. Renewal has to present
    an active certificate of the agent. The token is enough while none of
    its active certificates was ever presented: none issued, all reset, or
    the agent lost the answer of its last renewal."""

    authentication_classes = [AgentCertAuthentication]

    def post(self, request, agentid):
        agent = _token_agent(request, agentid, Agent.objects.only("agent_id"))
        if pki.mtls_mode() == MtlsMode.OFF:
            return Response({"detail": "mtls off"}, status=409)
        active = pki.active_certs().filter(agent=agent)
        fingerprint = pki.presented(request)
        if (
            not (fingerprint and active.filter(fingerprint_sha1=fingerprint).exists())
            and active.exclude(last_seen=None).exists()
        ):
            return Response(
                {"detail": "renewal needs the current client certificate"},
                status=403,
            )
        try:
            issued = pki.issue(agent, _data(request).get("csr"))
        except pki.CertError as e:
            return notify_error(f"Invalid csr: {e}")
        except pki.CAUnavailable as e:
            logger.warning(f"agent certificate for {agent.agent_id}: {e}")
            return Response({"detail": "agent CA missing"}, status=409)
        if ident := tokens.identity_of(agent):
            identity.done_rotation(ident, "cert")
        return _maybe_sealed(agent, request, issued)


NATS_BOUND_URI = re.compile(r"/natsws/([A-Za-z0-9_-]{21,150})")


class NatsAuth(APIView):
    """nginx auth_request for the NATS websocket. On /natsws/<agent_id> a
    presented certificate must be an active one of that agent (in required
    mode one has to be presented); on the old /natsws a client certificate
    of any agent in required mode, which agent logs in is up to NATS."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def _refused(self, request, agent, detail) -> Response:
        events.record(
            SecurityEventKind.NATS_REFUSED,
            "warning",
            agent=agent,
            ip=get_client_ip(request.META),
            detail=detail,
        )
        return Response(status=403)

    def _bound(self, request, agent_id) -> Response:
        agent = Agent.objects.filter(agent_id=agent_id).only("agent_id").first()
        ident = tokens.identity_of(agent) if agent is not None else None
        if ident is not None and ident.state != IdentityState.ACTIVE:
            return self._refused(request, agent, f"identity {ident.state}")
        mode = pki.mtls_mode()
        if mode == MtlsMode.OFF:
            return Response(status=204)
        fingerprint = pki.presented(request)
        if not fingerprint:
            if mode == MtlsMode.REQUIRED:
                return self._refused(request, agent, "no client certificate")
            return Response(status=204)
        cert = (
            pki.active_certs()
            .select_related("agent")
            .filter(fingerprint_sha1=fingerprint)
            .first()
        )
        if cert is None or cert.agent.agent_id != agent_id:
            owner = cert.agent.agent_id if cert else f"inactive {fingerprint}"
            return self._refused(
                request,
                agent,
                f"certificate of {owner} used for {agent_id}",
            )
        pki.touch(cert)
        return Response(status=204)

    def get(self, request):
        uri = request.META.get("ULRMM_NATS_URI", "").split("?", 1)[0]
        bound = NATS_BOUND_URI.fullmatch(uri)
        if bound:
            return self._bound(request, bound[1])
        if uri.startswith("/natsws/"):
            return Response(status=403)
        if pki.mtls_mode() != MtlsMode.REQUIRED:
            return Response(status=204)
        fingerprint = pki.presented(request)
        cert = (
            pki.active_certs().filter(fingerprint_sha1=fingerprint).first()
            if fingerprint
            else None
        )
        if cert is None:
            known = (
                AgentCertificate.objects.select_related("agent")
                .filter(fingerprint_sha1=fingerprint)
                .first()
                if fingerprint
                else None
            )
            return self._refused(
                request,
                known.agent if known else None,
                (
                    f"client certificate {fingerprint} is not active"
                    if fingerprint
                    else "no client certificate"
                ),
            )
        pki.touch(cert)
        return Response(status=204)


class IdentityThrottle(SimpleRateThrottle):
    scope = "agent_identity"
    rate = "20/hour"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}


class AgentIdentityView(AgentTokenView):
    authentication_classes = [AgentIdentityAuthentication]
    throttle_classes = [IdentityThrottle]

    def post(self, request, agentid):
        agent = _token_agent(
            request, agentid, Agent.objects.only("agent_id", "hostname")
        )
        return _answer(identity.register(agent, request.data, request))


class UrlAgentThrottle(SimpleRateThrottle):
    """Per agent id of the URL, for the endpoints without a token."""

    scope = "agent_token"
    rate = "60/hour"

    def get_cache_key(self, request, view):
        agentid = view.kwargs.get("agentid", "")
        # no bucket per made-up id; the views refuse those
        if not AGENT_ID_RE.fullmatch(agentid):
            return None
        return self.cache_format % {"scope": self.scope, "ident": agentid}


class RecoverThrottle(UrlAgentThrottle):
    scope = "agent_recover"
    rate = "10/hour"


class RecoverIpThrottle(AnonRateThrottle):
    scope = "agent_recover_ip"
    rate = "10/hour"


class TokenIpThrottle(AnonRateThrottle):
    scope = "agent_token_ip"
    # agents behind one NAT address share it
    rate = "600/hour"


class TokenChallenge(APIView):
    """Open: a released agent has no valid token, the grant checks the
    identity signature over the nonce."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [UrlAgentThrottle, TokenIpThrottle]

    def get(self, request, agentid):
        if not AGENT_ID_RE.fullmatch(agentid):
            return Response({"detail": "Not found."}, status=404)
        return Response(tokens.challenge("grant", agentid))


def _url_agent(agentid):
    if not isinstance(agentid, str) or not AGENT_ID_RE.fullmatch(agentid):
        return None
    return Agent.objects.filter(agent_id=agentid).only("agent_id", "hostname").first()


class TokenGrant(APIView):
    """Legacy token -> token family, signed with the identity key. Inside the
    release window after a quarantine the identity signature alone is
    enough (the credential was revoked)."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [UrlAgentThrottle]

    def post(self, request, agentid):
        ip = get_client_ip(request.META)
        released = True
        if request.META.get("HTTP_AUTHORIZATION"):
            try:
                result = AgentTokenAuthentication().authenticate(request)
            except AuthenticationFailed:
                result = None
            if result is not None:
                if result[0].agent is None or result[0].agent.agent_id != agentid:
                    return Response({"detail": "Not found."}, status=404)
                released = False
        agent = _url_agent(agentid)
        if agent is None:
            return Response({"detail": "token required"}, status=401)
        return _answer(tokens.grant(agent, _data(request), released=released, ip=ip))


class TokenRefresh(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [UrlAgentThrottle]

    def post(self, request, agentid):
        agent = _url_agent(agentid)
        if agent is None:
            return Response(tokens.UNKNOWN[1], status=tokens.UNKNOWN[0])
        return _answer(
            tokens.refresh(agent, _data(request), ip=get_client_ip(request.META))
        )


class RecoverChallenge(APIView):
    """Same answer for unknown agent ids."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [RecoverThrottle, RecoverIpThrottle]

    def get(self, request, agentid):
        return Response(tokens.challenge("recover", agentid[:150]))


class Recover(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [RecoverThrottle, RecoverIpThrottle]

    def post(self, request, agentid):
        return _answer(
            tokens.recover(
                _url_agent(agentid), _data(request), ip=get_client_ip(request.META)
            )
        )


class PinsThrottle(AnonRateThrottle):
    scope = "pins"
    # agents behind one NAT address share it
    rate = "1200/hour"


class Pins(APIView):
    """The signed pin document. Open, so an agent whose pins no longer match
    the server chain can fetch it without trusting the connection."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [PinsThrottle]

    def get(self, request):
        try:
            jws = signing.pin_document()
        except (signing.Unavailable, ImproperlyConfigured) as e:
            logger.warning(f"pin document: {e}")
            return Response(
                {"detail": "pin document unavailable"},
                status=503,
                headers={"Cache-Control": "no-store"},
            )
        return Response({"jws": jws}, headers={"Cache-Control": "no-store"})


AGENT_EVENT_SEVERITY = {
    SecurityEventKind.PIN_MISMATCH: "high",
    SecurityEventKind.PIN_RESCUE: "warning",
    SecurityEventKind.INSECURE_DROPPED: "warning",
    SecurityEventKind.UPDATE_REFUSED: "high",
    SecurityEventKind.TLS_FAILURE: "warning",
    SecurityEventKind.IDENTITY_UNREADABLE: "warning",
    SecurityEventKind.UNSIGNED_COMMAND: "high",
    SecurityEventKind.ENVELOPE_REFUSED: "warning",
    SecurityEventKind.CLOCK_SKEW: "warning",
    SecurityEventKind.INTEGRITY_MISMATCH: "high",
    SecurityEventKind.CONFIG_TAMPERED: "high",
    SecurityEventKind.UPDATE_REVERTED: "high",
}


class SecurityEventThrottle(SimpleRateThrottle):
    scope = "agent_security_event"
    rate = "30/hour"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}


class SecurityEventReport(AgentTokenView):
    throttle_classes = [SecurityEventThrottle]

    def post(self, request, agentid):
        agent = _token_agent(request, agentid, Agent.objects.only("agent_id"))
        data = _data(request)
        kind, detail = data.get("kind"), data.get("detail", "")
        if not isinstance(kind, str) or kind not in AGENT_EVENT_SEVERITY:
            return notify_error("Invalid kind")
        if not isinstance(detail, str) or len(detail) > events.MAX_DETAIL:
            return notify_error("Invalid detail")
        events.record(
            kind,
            AGENT_EVENT_SEVERITY[kind],
            agent=agent,
            ip=get_client_ip(request.META),
            detail=detail,
        )
        return Response("ok")


class Installer(InstallerView):
    permission_classes = [AgentInstallerPerms]

    def get(self, request):
        # token check only
        return Response("ok")

    def post(self, request):
        version = _data(request).get("version")
        if not isinstance(version, str) or not version:
            return notify_error("Invalid data")

        latest = settings.LATEST_AGENT_VER
        if "-dev" not in latest and agent_ver(version) < agent_ver(latest):
            return notify_error(
                f"Old installer detected (version {version} ). Latest version is "
                f"{latest} Please generate a new installer from the RMM"
            )
        return Response("ok")

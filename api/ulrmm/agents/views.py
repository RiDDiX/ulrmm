# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import io
import random
import re
import string
import unicodedata
from decimal import Decimal
from functools import wraps
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.db import transaction
from django.db.models import Count, Exists, OuterRef, Prefetch, Subquery
from django.db.models.functions import Coalesce
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from django.utils.dateparse import parse_date, parse_datetime
from knox.models import AuthToken
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from accounts.utils import (
    DELETE_NEEDS_TOTP,
    console_stepup_remaining,
    has_superuser_rights,
    verify_fresh_totp,
)
from clients.models import (
    Client,
    ClientCustomField,
    InstallerToken,
    Site,
    SiteCustomField,
)
from core.mesh_utils import MESH_RIGHTS_CONSOLE, MeshSync
from core.meshtoken import get_login_token
from core.models import CoreSettings, CustomField
from core.tasks import rename_mesh_node_task, sync_mesh_perms_task
from core.utils import (
    SERVER_SCRIPT_STEPUP,
    MeshDeviceGroupNotFound,
    get_core_settings,
    get_mesh_ws_url,
    remove_mesh_agent,
    stepup_denied,
    wake_on_lan,
)
from logs.models import AuditLog, DebugLog, PendingAction
from remote.utils import decrypt_secret
from scripts.models import Script, check_env_vars
from scripts.serializers import keep_masked_env_vars
from scripts.views import GLOBAL_PLACEHOLDER
from scripts.tasks import bulk_command_task, bulk_script_task
from ulrmm.agent_ident import (
    UnknownAgentIdentity,
    agent_artifact,
    agent_ident,
    agent_ident_for,
    agent_task_prefix,
    render_agent_script,
)
from ulrmm.constants import AGENT_DEFER, AGENT_STATUS_OFFLINE, AGENT_STATUS_ONLINE
from ulrmm.constants import AgentHistoryType, AgentMonType, AgentPlat, GoArch
from ulrmm.constants import AgentTerminalShellChoices, AuditActionType, AuditObjType
from ulrmm.constants import CustomFieldModel, DebugLogType, EvtLogNames
from ulrmm.constants import PAAction, PAStatus
from ulrmm.exceptions import NatsDown
from ulrmm.helpers import (
    agent_ver,
    date_is_in_past,
    notify_error,
    save_or_update_existing,
    self_signed_cert_pem,
)
from ulrmm.nats_utils import abulk_nats_command
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
    _may_assign_policy,
    _patch_policy_guard,
)
from ulrmm.throttles import VaultRevealThrottle
from ulrmm.utils import reload_nats
from winupdate.models import WinUpdate, WinUpdatePolicy
from winupdate.serializers import WinUpdatePolicySerializer
from winupdate.tasks import bulk_check_for_updates_task, bulk_install_updates_task

from .models import UNINSTALL_CODE_INFO, Agent, AgentCustomField, AgentHistory, Note
from .perf import parse_perf, perf_command
from .permissions import AgentHistoryPerms, AgentMaintenancePerms, AgentNotesPerms
from .permissions import AgentPerms, AgentRegistryPerms, AgentTerminalPerms
from .permissions import AgentWOLPerms, EvtLogPerms, InstallAgentPerms, MeshPerms
from .permissions import ManageProcPerms, RebootAgentPerms, RecoverAgentPerms
from .permissions import RunBulkPerms, RunScriptPerms, SendCMDPerms, UpdateAgentPerms
from .serializers import AgentCustomFieldSerializer, AgentHistorySerializer
from .serializers import AgentHostnameSerializer, AgentNoteSerializer
from .serializers import AgentSerializer, AgentTableSerializer
from .serializers import AgentTerminalDefaultsSerializer
from .tasks import bulk_recover_agents_task, send_agent_update_task
from .tasks import run_script_email_results_task
from .utils import (
    get_agent_display,
    get_agent_url,
    get_install_agent_url,
    get_validated_agent,
    send_nats_command,
    wake_agents,
)

NO_CONTACT = "Unable to contact the agent"
CUSTOM_SHELL_MISSING = "Enter the path of the custom shell"
UNREACHABLE = ("timeout", "natsdown")
# matches the limit of the dashboard's command dialog
MAX_CMD_TIMEOUT = 3600
INSTALLER_MAX_HOURS = 168

_INT_TEXT = re.compile(r"\s*-?\d+\s*")
# an API base URL that is safe inside the generated shell and PowerShell text
# agents refuse a plain http server
_API_URL = re.compile(r"https://[A-Za-z0-9.\-_~:\[\]/]+")


class _Refused(Exception):
    """Input the view answers with 400 and this text."""


def _as_int(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INT_TEXT.fullmatch(value):
        return int(value)
    return None


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _audit_agent(request, agent: Agent, action, message: str, **extra) -> None:
    who = {"username": request.user.username, "debug_info": _ip(request)}
    target = {"agent": agent.hostname, "agent_id": agent.agent_id}
    AuditLog.objects.create(
        object_type=AuditObjType.AGENT,
        action=action,
        message=message,
        **who,
        **target,
        **extra,
    )


def _ip(request) -> dict[str, Any]:
    return {"ip": getattr(request, "_client_ip", None)}


def _url_part(value) -> str:
    # node ids use @ and $ in place of + and /; MeshCentral expects them as is
    return quote(str(value or ""), safe="@$")


def _agent_or_404(agent_id: str, *, defer=AGENT_DEFER) -> Agent:
    return get_object_or_404(
        Agent.objects.defer(*defer).select_related("site__client"), agent_id=agent_id
    )


def _ask(agent: Agent, data: dict, timeout: int) -> Any:
    return asyncio.run(agent.nats_cmd(data, timeout=timeout))


def _paged(request, rows):
    """Optional ?limit= and ?offset=; without them every row is returned."""
    params = request.query_params
    if "limit" not in params and "offset" not in params:
        return rows
    limit = _as_int(params.get("limit", "0"))
    offset = _as_int(params.get("offset", "0"))
    if limit is None or offset is None or limit < 0 or offset < 0:
        raise _Refused("limit and offset must be whole numbers")
    return rows[offset : offset + limit] if limit else rows[offset:]


# agent list and detail


class GetAgents(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]

    # groups.views.GroupAgents narrows the rows through this hook
    def base_queryset(self, request):
        return Agent.objects.filter_by_role(request.user)

    def get(self, request):
        params = request.query_params
        agents = self.base_queryset(request)

        mon_type = params.get("monitoring_type")
        if mon_type:
            if mon_type not in AgentMonType.values:
                return notify_error("monitoring type does not exist")
            agents = agents.filter(monitoring_type=mon_type)

        site, client = params.get("site"), params.get("client")
        if site:
            if _as_int(site) is None:
                return notify_error("site must be a number")
            agents = agents.filter(site_id=_as_int(site))
        elif client:
            if _as_int(client) is None:
                return notify_error("client must be a number")
            agents = agents.filter(site__client_id=_as_int(client))

        if params.get("detail", "true") != "true":
            rows = (
                agents.defer(*AGENT_DEFER).select_related("site__client").order_by("pk")
            )
            return Response(AgentHostnameSerializer(rows, many=True).data)

        approved = WinUpdate.objects.filter(
            agent_id=OuterRef("pk"), action="approve", installed=False
        )
        pending = (
            PendingAction.objects.filter(
                agent_id=OuterRef("pk"), status=PAStatus.PENDING
            )
            .order_by()
            .values("agent_id")
            .annotate(n=Count("pk"))
            .values("n")
        )
        rows = (
            agents.select_related("site__client", "policy", "alert_template")
            .prefetch_related(
                Prefetch(
                    "custom_fields",
                    queryset=AgentCustomField.objects.select_related("field"),
                ),
                "tags",
            )
            .annotate(
                has_patches_pending=Exists(approved),
                has_patches_failed=Exists(approved.filter(result="failed")),
                _pending_actions_count=Coalesce(Subquery(pending), 0),
            )
            .defer(
                "services", "created_by", "created_time", "modified_by", "modified_time"
            )
            .order_by("pk")
        )
        return Response(AgentTableSerializer(rows, many=True).data)


class _AgentEditSerializer(serializers.ModelSerializer):
    # normalized in the view, so "", "none" and "null" can mean the global default
    default_shell = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, max_length=32
    )

    class Meta:
        model = Agent
        fields = (
            ("maintenance_mode", "policy", "block_policy_inheritance")
            + ("monitoring_type", "description")
            + ("overdue_email_alert", "overdue_text_alert", "overdue_dashboard_alert")
            + ("offline_time", "overdue_time", "check_interval", "time_zone", "site")
            + ("default_shell", "default_shell_custom")
        ) + (
            "display_name",
            "asset_tag",
            "purchase_date",
            "purchase_price",
            "vendor",
            "warranty_end",
            "lifecycle_notes",
        )
        extra_kwargs = {"purchase_price": {"min_value": Decimal("0")}}

    def validate_display_name(self, value: str) -> str:
        # U+2028/2029 are separators (Z*), not C*, but break lines all the same
        if any(
            unicodedata.category(ch).startswith("C") or ch in "\u2028\u2029"
            for ch in value
        ):
            raise serializers.ValidationError(
                "Display name must not contain control characters."
            )
        return value


_USE_GLOBAL = AgentTerminalShellChoices.USE_GLOBAL
_CUSTOM = AgentTerminalShellChoices.CUSTOM
_DEFAULT_SHELLS = {
    AgentPlat.WINDOWS: (
        {_USE_GLOBAL, "cmd", "powershell", _CUSTOM},
        "Invalid default shell for Windows agent. Use global default, 'cmd', "
        "'powershell' or 'custom'.",
    ),
    AgentPlat.LINUX: (
        {_USE_GLOBAL, "bash", _CUSTOM},
        "Invalid default shell for Linux agent. Use global default, 'bash' or "
        "'custom'.",
    ),
    AgentPlat.DARWIN: (
        {_USE_GLOBAL, "bash", _CUSTOM},
        "Invalid default shell for macOS agent. Use global default, 'bash' or "
        "'custom'.",
    ),
    AgentPlat.FREEBSD: (
        {_USE_GLOBAL, "sh", "bash", _CUSTOM},
        "Invalid default shell for FreeBSD agent. Use global default, 'sh', "
        "'bash' or 'custom'.",
    ),
}


def _shell_error(agent: Agent, attrs: dict) -> Optional[dict[str, list[str]]]:
    """Checks the default shell for the agent's OS and stores it normalized."""
    shell = (attrs.get("default_shell", agent.default_shell) or "").strip().lower()
    if shell in ("", "none", "null"):
        shell = _USE_GLOBAL
    if shell not in AgentTerminalShellChoices.values:
        given = attrs.get("default_shell")
        return {"default_shell": [f'"{given}" is not a valid choice.']}

    allowed, message = _DEFAULT_SHELLS.get(
        agent.plat, ({_USE_GLOBAL}, "Invalid default shell for this agent OS.")
    )
    if shell not in allowed:
        return {"default_shell": [message]}

    custom = attrs.get("default_shell_custom", agent.default_shell_custom)
    if shell == _CUSTOM and not (custom or "").strip():
        return {"default_shell_custom": ["Custom shell path must be provided."]}

    attrs["default_shell"] = shell
    return None


class GetUpdateDeleteAgent(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]

    def get(self, request, agent_id):
        related = ("site__client", "policy", "alert_template")
        agent = get_object_or_404(
            Agent.objects.select_related(*related), agent_id=agent_id
        )
        reveal = _has_perm(request, "can_manage_alerttemplates")
        return Response(
            AgentSerializer(agent, context={"reveal_env_vars": reveal}).data
        )

    def put(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        try:
            return self._edit(request, agent)
        except _Refused as e:
            return notify_error(str(e))

    def _edit(self, request, agent: Agent) -> Response:
        # everything is validated before anything is written
        serializer = _AgentEditSerializer(
            instance=agent, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        if error := _shell_error(agent, serializer.validated_data):
            return Response(error, status=400)

        site = serializer.validated_data.get("site")
        if site is not None and not _has_perm_on_site(request.user, site.pk):
            raise PermissionDenied("You do not have access to the target site.")
        # the same rule as for clients and sites; the form re-sends the
        # current policy on every edit
        chosen = serializer.validated_data.get("policy")
        if (
            chosen is not None
            and chosen.pk != agent.policy_id
            and not _may_assign_policy(request.user, chosen)
        ):
            raise _Refused("You cannot assign this policy.")

        policy = self._patch_policy(request, agent)
        fields = self._custom_fields(request, agent)

        old_name = agent.display_name
        with transaction.atomic():
            with _patch_policy_guard(request, Agent.objects.filter(pk=agent.pk)):
                agent = serializer.save()
                if policy is not None:
                    policy.save()
            for field in fields:
                save_or_update_existing(
                    field,
                    AgentCustomField,
                    agent=agent,
                    field=field.validated_data.get("field"),
                )

        if agent.display_name != old_name and get_core_settings().sync_mesh_with_rmm:
            rename_mesh_node_task.delay(agent.pk)
        sync_mesh_perms_task.delay()
        return Response("The agent was updated successfully")

    def _patch_policy(self, request, agent: Agent):
        if "winupdatepolicy" not in request.data:
            return None
        items = request.data["winupdatepolicy"]
        if not isinstance(items, list) or not items or not isinstance(items[0], dict):
            raise _Refused("winupdatepolicy must hold one patch policy")

        policy = agent.winupdatepolicy.order_by("pk").first() or WinUpdatePolicy(
            agent=agent
        )
        serializer = WinUpdatePolicySerializer(
            instance=policy, data=items[0], partial=True
        )
        serializer.is_valid(raise_exception=True)
        # the edit form sends the unchanged policy along on every save
        changed = any(
            getattr(policy, name) != value
            for name, value in serializer.validated_data.items()
        )
        if changed and not _has_perm(request, "can_manage_patch_policies"):
            raise PermissionDenied("You cannot change patch policies.")
        return serializer

    def _custom_fields(self, request, agent: Agent) -> list:
        items = request.data.get("custom_fields")
        if items is None:
            return []
        if not isinstance(items, list):
            raise _Refused("custom_fields must be a list")

        prepared, seen = [], set()
        for item in items:
            if not isinstance(item, dict):
                raise _Refused("Invalid custom field")
            field_pk = _as_int(item.get("field"))
            if field_pk is not None:
                if field_pk in seen:
                    raise _Refused("A custom field is listed twice")
                seen.add(field_pk)
            existing = (
                AgentCustomField.objects.filter(agent=agent, field_id=field_pk).first()
                if field_pk is not None
                else None
            )
            serializer = AgentCustomFieldSerializer(
                instance=existing,
                data={**item, "agent": agent.pk},
                partial=existing is not None,
            )
            serializer.is_valid(raise_exception=True)
            prepared.append(serializer)
        return prepared

    def delete(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if not verify_fresh_totp(request.user, request.data.get("totp_code")):
            return notify_error(DELETE_NEEDS_TOTP)

        try:
            ident = agent_ident_for(agent)
        except UnknownAgentIdentity:
            ident = None

        name = agent.hostname
        reachable = False
        if ident is not None:
            if agent.plat == AgentPlat.LINUX:
                code = render_agent_script(settings.LINUX_AGENT_SCRIPT, ident)
            elif agent.plat == AgentPlat.DARWIN:
                code = render_agent_script(settings.MAC_UNINSTALL, ident)
            elif agent.plat == AgentPlat.FREEBSD:
                code = render_agent_script(settings.FREEBSD_AGENT_SCRIPT, ident)
            else:
                # current agents use their own stored code; older ones need the key
                code = "foo"
            try:
                reachable = _ask(agent, {"func": "ping"}, 2) == "pong"
            except Exception:
                reachable = False
            asyncio.run(agent.nats_cmd({"func": "uninstall", "code": code}, wait=False))

        node = agent.hex_mesh_node_id
        agent.delete()
        reload_nats()

        try:
            if node != "error":
                asyncio.run(remove_mesh_agent(get_mesh_ws_url(), node))
        except Exception as exc:
            DebugLog.error(
                log_type=DebugLogType.AGENT_ISSUES,
                message=f"Unable to remove agent {name} from meshcentral database: {exc}",
            )
        sync_mesh_perms_task.delay()

        if ident is None:
            return Response(f"{name} was removed, uninstall its agent manually")
        if not reachable:
            return Response(f"{name} was offline, uninstall it manually")
        return Response(f"{name} will now be uninstalled.")


class RevealUninstallCode(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [VaultRevealThrottle]

    def post(self, request, agent_id):
        if not has_superuser_rights(request.user):
            raise PermissionDenied()
        agent = _agent_or_404(agent_id)
        if denied := stepup_denied(
            request, "Showing the uninstall code of a device needs it."
        ):
            return denied
        if not agent.uninstall_code:
            return notify_error("This agent has not reported an uninstall code yet.")
        try:
            code = decrypt_secret(agent.uninstall_code, UNINSTALL_CODE_INFO)
        except InvalidToken:
            return notify_error("The stored code can no longer be read.")

        _audit_agent(
            request,
            agent,
            AuditActionType.VIEW,
            f"{request.user.username} revealed the uninstall code of {agent.hostname}",
        )
        response = Response({"uninstall_code": code})
        response["Cache-Control"] = "no-store"
        return response


# commands and scripts


@api_view(["POST"])
@permission_classes([IsAuthenticated, SendCMDPerms])
def send_raw_cmd(request, agent_id):
    agent = _agent_or_404(agent_id)
    data = request.data
    cmd, shell = data.get("cmd"), data.get("shell")
    timeout = _as_int(data.get("timeout"))
    run_as_user = data.get("run_as_user", False)
    if not _text(cmd) or not _text(shell) or timeout is None:
        return notify_error("cmd, shell and timeout are required")
    if not isinstance(run_as_user, bool):
        return notify_error("run_as_user must be true or false")
    timeout = min(max(timeout, 1), MAX_CMD_TIMEOUT)

    custom = data.get("custom_shell")
    if shell == "custom":
        if not isinstance(custom or "", str):
            return notify_error("custom_shell must be text")
        # the dialog's placeholder choice, never an interpreter
        if not _text(custom):
            return notify_error(CUSTOM_SHELL_MISSING)
        shell = custom

    history = AgentHistory.objects.create(
        agent=agent,
        type=AgentHistoryType.CMD_RUN,
        command=cmd,
        username=request.user.username[:50],
    )
    # audited before sending, so a command that times out is on record too
    AuditLog.audit_raw_command(
        request.user.username, agent, cmd, shell, debug_info=_ip(request)
    )
    reply = _ask(
        agent,
        {
            "func": "rawcmd",
            "timeout": timeout,
            "payload": {"command": cmd, "shell": shell},
            "run_as_user": run_as_user,
            "id": history.pk,
        },
        timeout + 2,
    )
    if reply in UNREACHABLE:
        return notify_error(NO_CONTACT)
    return Response(reply)


def _script_output_failed(reply) -> bool:
    return not isinstance(reply, str) or reply in UNREACHABLE


def _collector_target(custom_field: CustomField, agent: Agent):
    if custom_field.model == CustomFieldModel.AGENT:
        row, _ = AgentCustomField.objects.get_or_create(agent=agent, field=custom_field)
    elif custom_field.model == CustomFieldModel.SITE:
        row, _ = SiteCustomField.objects.get_or_create(
            site=agent.site, field=custom_field
        )
    else:
        row, _ = ClientCustomField.objects.get_or_create(
            client=agent.client, field=custom_field
        )
    return row


def _check_keystore_placeholders(request, values) -> None:
    # placeholders resolve to key store values the output can echo back
    if any(
        isinstance(v, str) and GLOBAL_PLACEHOLDER.search(v) for v in values
    ) and not _has_perm(request, "can_view_global_keystore"):
        raise PermissionDenied("Key store values need the key store permission.")


@api_view(["POST"])
@permission_classes([IsAuthenticated, RunScriptPerms])
def run_script(request, agent_id):
    agent = _agent_or_404(agent_id)
    data = request.data

    script_pk = _as_int(data.get("script"))
    output = data.get("output")
    args, env_vars = data.get("args"), data.get("env_vars")
    timeout = _as_int(data.get("timeout"))
    run_as_user = data.get("run_as_user")
    if (
        script_pk is None
        or not isinstance(output, str)
        or not isinstance(args, list)
        or not isinstance(env_vars, list)
        or timeout is None
        or timeout < 1
        or not isinstance(run_as_user, bool)
    ):
        return notify_error(
            "script, output, args, env_vars, timeout and run_as_user are required"
        )
    script = get_object_or_404(Script, pk=script_pk)
    req_timeout = timeout + 3
    env_vars = keep_masked_env_vars(env_vars, script.env_vars)
    check_env_vars(env_vars, script)
    _check_keystore_placeholders(request, args + env_vars)

    custom_field = None
    if output == "collector":
        custom_field = CustomField.objects.filter(
            pk=_as_int(data.get("custom_field"))
        ).first()
        if custom_field is None or custom_field.model not in CustomFieldModel.values:
            return notify_error("Custom Field was invalid")

    if data.get("run_on_server", False):
        if not get_core_settings().server_scripts_enabled:
            return notify_error("This feature is disabled.")
        if not _has_perm(request, "can_run_server_scripts"):
            raise PermissionDenied()
        if denied := stepup_denied(request, SERVER_SCRIPT_STEPUP):
            return denied

    AuditLog.audit_script_run(
        username=request.user.username,
        agent=agent,
        script=script.name,
        debug_info=_ip(request),
    )
    history = AgentHistory.objects.create(
        agent=agent,
        type=AgentHistoryType.SCRIPT_RUN,
        script=script,
        username=request.user.username[:50],
    )

    if data.get("run_on_server", False):
        # looked up per call, tests replace it on core.utils
        from core.utils import run_server_script

        parsed_args = script.parse_script_args(agent, script.shell, args)
        parsed_env = script.parse_script_env_vars(agent, script.shell, env_vars)
        stdout, stderr, seconds, retcode = run_server_script(
            body=script.script_body,
            args=parsed_args,
            env_vars=parsed_env,
            shell=script.shell,
            timeout=req_timeout,
        )
        results = {
            "stdout": stdout,
            "stderr": stderr,
            "execution_time": f"{seconds:.4f}",
            "retcode": retcode,
        }
        history.script_results = {**results, "id": history.pk}
        history.save(update_fields=["script_results"])
        return Response(results)

    run = {
        "scriptpk": script.pk,
        "args": args,
        "timeout": req_timeout,
        "history_pk": history.pk,
        "run_as_user": run_as_user,
        "env_vars": env_vars,
    }
    started = f"{script.name} will now be run on {agent.hostname}"

    if output == "email":
        emails = data.get("emails", [])
        if data.get("emailMode") == "default":
            emails = []
        elif not isinstance(emails, list) or not all(
            isinstance(e, str) for e in emails
        ):
            return notify_error("emails must be a list of addresses")
        # same arguments as a direct run, except the timeout name
        mailed = {key: value for key, value in run.items() if key != "timeout"}
        run_script_email_results_task.delay(
            agentpk=agent.pk, emails=emails, nats_timeout=req_timeout, **mailed
        )
        return Response(started)

    if output not in ("wait", "collector", "note"):
        agent.run_script(**run)
        return Response(started)

    reply = agent.run_script(**run, wait=True)
    # a failed run is reported, never saved as if it were the script's output
    if _script_output_failed(reply):
        return notify_error(NO_CONTACT)

    if output == "collector":
        text = reply.strip()
        if not data.get("save_all_output", False):
            text = text.split("\n")[-1].strip()
        _collector_target(custom_field, agent).save_to_field(text)
    elif output == "note":
        Note.objects.create(agent=agent, user=request.user, note=reply)
    return Response(reply)


# recovery and power


@api_view(["POST"])
@permission_classes([IsAuthenticated, RecoverAgentPerms])
def recover(request, agent_id):
    agent = _agent_or_404(agent_id)
    mode = request.data.get("mode")
    if mode not in ("agent", "mesh"):
        return notify_error("Invalid recovery mode")

    if mode == "agent":
        try:
            uri = get_mesh_ws_url()
            url = get_agent_url(agent=agent)
        except ValueError as e:
            return notify_error(str(e))
        AuditLog.audit_power_action(
            request.user.username, agent, "recover agent", debug_info=_ip(request)
        )
        agent.recover("agent", uri, wait=False, agent_url=url)
        return Response("Recovery will be attempted shortly")

    AuditLog.audit_power_action(
        request.user.username, agent, "recover mesh", debug_info=_ip(request)
    )
    message, failed = agent.recover("mesh", "")
    if failed:
        return notify_error(f"Unable to complete recovery: {message}")
    return Response("Successfully completed recovery")


_POWER_EVENTS = {"rebootnow": "restart", "shutdown": "shutdown", "suspend": "sleep"}


def _power(request, agent: Agent, func: str, action: str) -> Response:
    AuditLog.audit_power_action(
        request.user.username, agent, action, debug_info=_ip(request)
    )
    if _ask(agent, {"func": func}, 10) != "ok":
        return notify_error(NO_CONTACT)
    agent.record_power_event(_POWER_EVENTS[func], f"rmm: {request.user.username}")
    return Response("ok")


class Reboot(APIView):
    permission_classes = [IsAuthenticated, RebootAgentPerms]

    def post(self, request, agent_id):
        return _power(request, _agent_or_404(agent_id), "rebootnow", "reboot")

    def patch(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        if agent.plat != AgentPlat.WINDOWS:
            return notify_error(f"Not currently implemented for {agent.plat}")

        try:
            when = dt.datetime.strptime(request.data.get("datetime"), "%Y-%m-%dT%H:%M")
        except (TypeError, ValueError):
            return notify_error("Invalid date")
        if date_is_in_past(datetime_obj=when, agent_tz=agent.timezone):
            return notify_error("Date cannot be set in the past")

        suffix = "".join(random.choices(string.ascii_letters, k=10))
        task_name = f"{agent_task_prefix()}SchedReboot_{suffix}"
        expire = when + dt.timedelta(minutes=5)
        payload = {"type": "schedreboot", "name": task_name, "trigger": "runonce"}
        payload.update(
            enabled=True,
            delete_expired_task_after=True,
            start_when_available=False,
            multiple_instances=2,
        )
        for prefix, moment in (("start", when), ("expire", expire)):
            payload.update(
                {
                    f"{prefix}_year": moment.year,
                    f"{prefix}_month": moment.month,
                    f"{prefix}_day": moment.day,
                    f"{prefix}_hour": moment.hour,
                    f"{prefix}_min": moment.minute,
                }
            )

        AuditLog.audit_power_action(
            request.user.username,
            agent,
            f"reboot at {when:%Y-%m-%d %H:%M}",
            debug_info=_ip(request),
        )
        reply = _ask(agent, {"func": "schedtask", "schedtaskpayload": payload}, 10)
        if reply != "ok":
            return notify_error(str(reply))

        PendingAction.objects.create(
            agent=agent,
            action_type=PAAction.SCHED_REBOOT,
            details={"taskname": task_name, "time": str(when)},
        )
        return Response(
            {
                "time": when.strftime("%B %d, %Y at %I:%M %p"),
                "agent": agent.hostname,
                "task_name": task_name,
            }
        )


class Shutdown(APIView):
    permission_classes = [IsAuthenticated, RebootAgentPerms]

    def post(self, request, agent_id):
        return _power(request, _agent_or_404(agent_id), "shutdown", "shutdown")


def _can_sleep(agent: Agent) -> bool:
    # agents that report their NICs also understand the suspend command
    return isinstance(agent.wmi_detail, dict) and "nics" in agent.wmi_detail


class Suspend(APIView):
    permission_classes = [IsAuthenticated, RebootAgentPerms]

    def post(self, request, agent_id):
        agent = _agent_or_404(agent_id, defer=("services",))
        if not _can_sleep(agent):
            return notify_error(f"Update the agent on {agent.hostname} to use sleep")
        return _power(request, agent, "suspend", "suspend")


class KeepAwake(APIView):
    permission_classes = [IsAuthenticated, RebootAgentPerms]
    MAX_MINUTES = 360

    def post(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        if "ac" in request.data:
            return self._ac(request, agent)
        minutes = _as_int(request.data.get("minutes", 0))
        if minutes is None:
            return notify_error("minutes must be a whole number")
        if not 0 <= minutes <= self.MAX_MINUTES:
            return notify_error(f"minutes must be between 0 and {self.MAX_MINUTES}")

        until = djangotime.now() + dt.timedelta(minutes=minutes) if minutes else None
        AuditLog.audit_power_action(
            request.user.username,
            agent,
            "keep awake" if minutes else "keep awake off",
            debug_info={**_ip(request), "minutes": minutes},
        )
        reply = _ask(
            agent,
            {"func": "keepawake", "until": int(until.timestamp()) if until else 0},
            10,
        )
        if reply in UNREACHABLE:
            return notify_error(NO_CONTACT)
        if reply != "ok":
            return notify_error(f"The agent refused: {reply}")

        agent.keep_awake_until = until
        agent.save(update_fields=["keep_awake_until"])
        return Response({"keep_awake_until": until})

    # stay awake on power: the agent keeps it across restarts, only this
    # flag changes, a running hold stays
    def _ac(self, request, agent):
        ac = request.data["ac"]
        if not isinstance(ac, bool):
            return notify_error("ac must be true or false")
        if agent.plat != AgentPlat.DARWIN:
            return notify_error("Stay awake on power is only available on macOS")
        if agent_ver(agent.version) < agent_ver(settings.KEEPAWAKE_AC_MIN_AGENT):
            return notify_error(
                f"Stay awake on power needs agent {settings.KEEPAWAKE_AC_MIN_AGENT} "
                f"or newer on {agent.hostname}"
            )
        AuditLog.audit_power_action(
            request.user.username,
            agent,
            "stay awake on power" if ac else "stay awake on power off",
            debug_info={**_ip(request), "ac": ac},
        )
        reply = _ask(agent, {"func": "keepawakeac", "ac": ac}, 10)
        if reply in UNREACHABLE:
            return notify_error(NO_CONTACT)
        if reply != "ok":
            return notify_error(f"The agent refused: {reply}")

        agent.keep_awake_ac = ac
        agent.save(update_fields=["keep_awake_ac"])
        return Response({"keep_awake_ac": ac})


@api_view(["POST"])
@permission_classes([IsAuthenticated, AgentWOLPerms])
def wol(request, agent_id):
    agent = _agent_or_404(agent_id, defer=("services",))
    AuditLog.audit_power_action(
        request.user.username, agent, "wake", debug_info=_ip(request)
    )

    sent = wake_agents(Agent.objects.filter(pk=agent.pk), request.user)
    via = list(sent.get(agent.pk, []))
    mesh_error = "Missing mesh node id"
    if agent.mesh_node_id and agent.hex_mesh_node_id != "error":
        try:
            asyncio.run(
                wake_on_lan(uri=get_mesh_ws_url(), mesh_node_ids=[agent.mesh_node_id])
            )
            via.append("MeshCentral")
        except Exception as e:
            mesh_error = str(e)

    if not via:
        return notify_error(mesh_error)
    return Response(f"Wake-on-LAN sent to {agent.hostname} via {', '.join(via)}")


# live data from the agent


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentPerms])
def ping(request, agent_id):
    agent = _agent_or_404(agent_id)
    try:
        online = _ask(agent, {"func": "ping"}, 3) == "pong"
    except Exception:
        online = False
    status = AGENT_STATUS_ONLINE if online else AGENT_STATUS_OFFLINE
    return Response({"name": agent.hostname, "status": status})


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentPerms])
def perf(request, agent_id):
    agent = _agent_or_404(agent_id)
    result: dict[str, Any] = {
        "cpu_percent": None,
        "mem_total": None,
        "mem_used": None,
        "mem_percent": None,
        "collected_at": djangotime.now().isoformat(),
        "error": None,
    }
    if not agent.is_online:
        return Response({**result, "error": "offline"})

    command = perf_command(agent.plat)
    if command is None:
        return Response({**result, "error": "unsupported"})

    shell, text = command
    data = {
        "func": "rawcmd",
        "timeout": 10,
        "payload": {"command": text, "shell": shell},
        "run_as_user": False,
    }
    try:
        reply = _ask(agent, data, 20)
    except Exception:
        reply = None
    if not isinstance(reply, str) or reply in UNREACHABLE:
        return Response({**result, "error": "unreachable"})

    result.update(parse_perf(agent.plat, reply))
    if result["cpu_percent"] is None and result["mem_total"] is None:
        result["error"] = "unparseable"
    return Response(result)


class WMI(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]

    def post(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        if _ask(agent, {"func": "sysinfo"}, 20) != "ok":
            return notify_error(NO_CONTACT)
        return Response("Agent WMI data refreshed successfully")


class AgentProcesses(APIView):
    permission_classes = [IsAuthenticated, ManageProcPerms]

    # GET is the list route only, DELETE needs a pid; the other pairing is 405
    def get(self, request, agent_id, pid=None):
        if pid is not None:
            self.http_method_not_allowed(request)
        agent = _agent_or_404(agent_id)
        reply = _ask(agent, {"func": "procs"}, 5)
        if reply in UNREACHABLE:
            return notify_error(NO_CONTACT)
        return Response(reply)

    def delete(self, request, agent_id, pid=None):
        if pid is None:
            self.http_method_not_allowed(request)
        agent = _agent_or_404(agent_id)
        AuditLog.audit_power_action(
            request.user.username,
            agent,
            f"end process {pid}",
            debug_info=_ip(request),
        )
        reply = _ask(agent, {"func": "killproc", "procpid": int(pid)}, 15)
        if reply in UNREACHABLE:
            return notify_error(NO_CONTACT)
        if reply != "ok":
            return notify_error(str(reply))
        return Response(f"Process with PID: {pid} was ended successfully")


@api_view(["GET"])
@permission_classes([IsAuthenticated, EvtLogPerms])
def get_event_log(request, agent_id, logtype, days):
    agent = _agent_or_404(agent_id)
    if logtype not in EvtLogNames.values:
        return notify_error("Unknown event log")

    timeout = 180 if logtype == EvtLogNames.SECURITY else 30
    data = {
        "func": "eventlog",
        "timeout": timeout,
        "payload": {"logname": logtype, "days": str(days)},
    }
    reply = _ask(agent, data, timeout + 2)
    if reply in UNREACHABLE:
        return notify_error(NO_CONTACT)
    return Response(reply)


# MeshCentral


def _mesh_url(core, token: str, agent: Agent) -> str:
    return f"{core.mesh_site}/?login={token}&gotonode={_url_part(agent.mesh_node_id)}"


class AgentMeshCentral(APIView):
    permission_classes = [IsAuthenticated, MeshPerms]

    def get(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        core = get_core_settings()
        display = get_agent_display(agent)

        if core.sync_mesh_with_rmm:
            mesh_user = request.user.mesh_user_id
        else:
            mesh_user = f"user//{core.mesh_api_superuser}"
        token = get_login_token(key=core.mesh_token, user=mesh_user)

        AuditLog.audit_mesh_session(
            username=request.user.username, agent=agent, debug_info=_ip(request)
        )
        return Response(
            {
                "hostname": agent.hostname,
                "effective_name": agent.effective_name,
                "control": f"{_mesh_url(core, token, agent)}&viewmode=11&hide=31",
                "status": agent.status,
                "plat": agent.plat,
                "client": agent.site.client.name,
                "site": agent.site.name,
                "display": display,
                # the pop-out pill names an announced shutdown, restart or sleep
                "planned_offline": agent.planned_offline,
                "power_event": agent.power_event,
                "power_event_at": agent.power_event_at,
                "power_event_by": agent.power_event_by,
            }
        )

    def post(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        AuditLog.audit_power_action(
            request.user.username, agent, "recover mesh", debug_info=_ip(request)
        )
        data = {"func": "recover", "payload": {"mode": "mesh"}}
        if _ask(agent, data, 90) != "ok":
            return notify_error(NO_CONTACT)
        return Response(f"Repaired mesh agent on {agent.hostname}")


class AgentMeshConsole(APIView):
    """MeshCentral terminal and file URLs, behind the console step-up."""

    permission_classes = [IsAuthenticated, MeshPerms]

    def post(self, request, agent_id):
        agent = _agent_or_404(agent_id)
        user = request.user
        # API keys never carry a step-up
        remaining = (
            console_stepup_remaining(user) if isinstance(request.auth, AuthToken) else 0
        )
        if remaining <= 0:
            raise PermissionDenied("Confirm with a two-factor code first.")

        core = get_core_settings()
        if not core.sync_mesh_with_rmm:
            return notify_error(
                "Terminal and file access need Sync Mesh with RMM turned on."
            )
        if getattr(settings, "ULRMM_DISABLE_MESH_SYNC_TASK", False):
            return notify_error(
                "Terminal and file access need the MeshCentral sync task, which "
                "ULRMM_DISABLE_MESH_SYNC_TASK turns off."
            )
        node = agent.hex_mesh_node_id
        if node == "error":
            return notify_error("Missing mesh node id")

        mesh = MeshSync(get_mesh_ws_url())
        mesh_user = user.mesh_user_id
        if mesh_user not in mesh.mesh_users:
            return notify_error(
                "Your MeshCentral account is not synced yet. Try again in a few "
                "minutes."
            )
        granted = mesh.add_users_to_node(
            node_id=f"node//{node}",
            user_ids=[mesh_user],
            rights=MESH_RIGHTS_CONSOLE,
            wait=True,
        )
        if not isinstance(granted, dict) or granted.get("result") != "ok":
            return notify_error("MeshCentral did not grant terminal and file access.")

        AuditLog.audit_mesh_session(
            username=user.username,
            agent=agent,
            debug_info=_ip(request),
            session="a terminal and file session",
        )
        token = get_login_token(key=core.mesh_token, user=mesh_user)
        url = f"{_mesh_url(core, token, agent)}&hide=31"
        return Response(
            {
                "terminal": f"{url}&viewmode=12",
                "file": f"{url}&viewmode=13",
                "remaining": remaining,
            }
        )


class WebVNC(APIView):
    permission_classes = [IsAuthenticated, MeshPerms]

    def get(self, request, agent_id, port):
        agent = _agent_or_404(agent_id)
        port = _as_int(port)
        if port is None or not 1 <= port <= 65535:
            return notify_error("Invalid port")
        node = agent.hex_mesh_node_id
        if node == "error":
            return notify_error("Missing mesh node id")

        core = get_core_settings()
        reply = MeshSync(get_mesh_ws_url()).mesh_action(
            payload={
                "action": "getcookie",
                "tag": "novnc",
                "nodeid": f"node//{node}",
                "tcpaddr": None,
                "tcpport": port,
            },
            wait=True,
        )
        cookie = reply.get("cookie") if isinstance(reply, dict) else None
        if not cookie:
            return notify_error("MeshCentral did not return a VNC session cookie.")

        AuditLog.audit_mesh_session(
            username=request.user.username,
            agent=agent,
            debug_info=_ip(request),
            session="a VNC session",
        )
        host = urlsplit(core.mesh_site or "").netloc
        relay = f"wss%3A%2F%2F{host}%2Fmeshrelay.ashx%3Fauth%3D{_url_part(cookie)}"
        vnc = (
            f"{core.mesh_site}/novnc/vnc.html?ws={relay}&show_dot=1&l=en"
            f"&resize=scale&name={quote(agent.hostname, safe='')}"
        )
        return Response(
            {
                "hostname": agent.hostname,
                "vnc": vnc,
                "client": agent.site.client.name,
                "site": agent.site.name,
            }
        )


# history and notes


class AgentHistoryView(APIView):
    permission_classes = [IsAuthenticated, AgentHistoryPerms]

    def get(self, request, agent_id=None):
        rows = (
            AgentHistory.objects.filter(agent=_agent_or_404(agent_id))
            if agent_id
            else AgentHistory.objects.filter_by_role(request.user)
        )
        rows = rows.select_related("script").order_by("pk")
        try:
            rows = _paged(request, rows)
        except _Refused as e:
            return notify_error(str(e))
        return Response(AgentHistorySerializer(rows, many=True).data)


_SCRIPT_RUN_COLUMNS = ("id", "time", "username", "script", "script_results", "agent")


class _ScriptRunSerializer(serializers.ModelSerializer):
    script_name = serializers.ReadOnlyField(source="script.name")
    agent_id = serializers.ReadOnlyField(source="agent.agent_id")

    class Meta:
        model = AgentHistory
        fields = _SCRIPT_RUN_COLUMNS + ("script_name", "agent_id")
        read_only_fields = _SCRIPT_RUN_COLUMNS


def _as_date(value) -> Optional[dt.date]:
    if not isinstance(value, str):
        return None
    try:
        day = parse_date(value)
        if day is None:
            moment = parse_datetime(value)
            day = moment.date() if moment else None
    except ValueError:
        return None
    return day


class ScriptRunHistory(APIView):
    permission_classes = [IsAuthenticated, AgentHistoryPerms]

    def get(self, request):
        params = request.query_params
        rows = (
            AgentHistory.objects.filter_by_role(request.user)
            .filter(type=AgentHistoryType.SCRIPT_RUN)
            .select_related("script", "agent")
            .defer(*(f"agent__{name}" for name in AGENT_DEFER))
            .order_by("-time")
        )

        if params.get("start") and params.get("end"):
            start, end = _as_date(params["start"]), _as_date(params["end"])
            if start is None or end is None:
                return notify_error("start and end must be dates")
            rows = rows.filter(time__date__gte=start, time__date__lte=end)

        if params.get("scriptname"):
            rows = rows.filter(script__name=params["scriptname"])

        if "limit" in params:
            limit = _as_int(params["limit"])
            if limit is None or limit < 0:
                return notify_error("limit must be a whole number")
            rows = rows[:limit]

        return Response(_ScriptRunSerializer(rows, many=True).data)


class GetAddNotes(APIView):
    permission_classes = [IsAuthenticated, AgentNotesPerms]

    def get(self, request, agent_id=None):
        if agent_id:
            agent = _agent_or_404(agent_id)
            notes = Note.objects.filter(agent=agent)
        else:
            notes = Note.objects.filter_by_role(request.user)
        notes = notes.select_related("agent", "user").order_by("pk")
        try:
            notes = _paged(request, notes)
        except _Refused as e:
            return notify_error(str(e))
        return Response(AgentNoteSerializer(notes, many=True).data)

    def post(self, request):
        agent_id = request.data.get("agent_id")
        if not _text(agent_id):
            return notify_error("agent_id is required")
        agent = _agent_or_404(agent_id)
        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()
        if "note" not in request.data:
            return notify_error("Cannot add an empty note")

        text = request.data["note"]
        new_note = AgentNoteSerializer(
            data={"agent": agent.pk, "user": request.user.pk, "note": text}
        )
        new_note.is_valid(raise_exception=True)
        new_note.save()
        return Response("Note added!")


class GetEditDeleteNote(APIView):
    permission_classes = [IsAuthenticated, AgentNotesPerms]

    def _note(self, request, pk) -> Note:
        note = get_object_or_404(Note.objects.select_related("agent", "user"), pk=pk)
        if not _has_perm_on_agent(request.user, note.agent.agent_id):
            raise PermissionDenied()
        return note

    def get(self, request, pk):
        return Response(AgentNoteSerializer(self._note(request, pk)).data)

    def put(self, request, pk):
        # the serializer keeps the agent and author, only the text changes
        serializer = AgentNoteSerializer(
            instance=self._note(request, pk), data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("Note edited!")

    def delete(self, request, pk):
        self._note(request, pk).delete()
        return Response("Note was deleted!")


# bulk


@api_view(["POST"])
@permission_classes([IsAuthenticated, AgentMaintenancePerms])
def agent_maintenance(request):
    kind = request.data.get("type")
    pk = _as_int(request.data.get("id"))
    action = request.data.get("action")
    if kind not in ("Client", "Site") or pk is None:
        return notify_error("Invalid data")
    if not isinstance(action, bool):
        return notify_error("action must be true or false")

    agents = Agent.objects.filter_by_role(request.user)
    if kind == "Client":
        get_object_or_404(Client, pk=pk)
        if not _has_perm_on_client(request.user, pk):
            raise PermissionDenied()
        agents = agents.filter(site__client_id=pk)
        target = {"target": "client", "client": pk}
    else:
        get_object_or_404(Site, pk=pk)
        if not _has_perm_on_site(request.user, pk):
            raise PermissionDenied()
        agents = agents.filter(site_id=pk)
        target = {"target": "site", "site": pk}

    pks = list(agents.order_by("pk").values_list("pk", flat=True))
    count = Agent.objects.filter(pk__in=pks).update(maintenance_mode=action)
    AuditLog.audit_bulk_action(
        request.user.username,
        f"{'enable' if action else 'disable'} maintenance mode",
        {**target, "maintenance_mode": action},
        pks,
        0,
        debug_info=_ip(request),
    )

    if not count:
        return Response(
            "No agents have been put in maintenance mode. You might not have "
            "permissions to the resources."
        )
    state = "enabled" if action else "disabled"
    return Response(f"Maintenance mode has been {state} on {count} agents")


_BULK_FLAGS = {
    "suspend": "can_reboot_agents",
    "wake": "can_send_wol",
    "package": "can_install_packages",
}
_BULK_NEEDS = {
    "command": ("cmd", "shell", "timeout", "run_as_user"),
    "script": ("script", "args", "timeout", "run_as_user", "env_vars"),
    "patch": ("patchMode",),
    "package": ("package",),
    "suspend": (),
    "wake": (),
}
_BULK_TARGET_KEYS = ("target", "client", "site", "agents", "group", "monType", "osType")
_NONE_FOUND = "No agents were found meeting the selected criteria"


def _bulk_queryset(request, data: dict):
    """The agents a bulk request names, always within the user's scope."""
    user = request.user
    agents = Agent.objects.filter_by_role(user)
    target = data["target"]

    if target == "client":
        pk = _as_int(data.get("client"))
        if pk is None:
            raise _Refused("Choose a client.")
        if not _has_perm_on_client(user, pk):
            raise PermissionDenied()
        agents = agents.filter(site__client_id=pk)
    elif target == "site":
        pk = _as_int(data.get("site"))
        if pk is None:
            raise _Refused("Choose a site.")
        if not _has_perm_on_site(user, pk):
            raise PermissionDenied()
        agents = agents.filter(site_id=pk)
    elif target == "agents":
        ids = data.get("agents")
        if not isinstance(ids, list) or not ids:
            raise _Refused("Must select at least 1 agent")
        agents = agents.filter(agent_id__in=[i for i in ids if isinstance(i, str)])
    elif target == "group":
        from groups.models import DeviceGroup

        if not str(data.get("group")).isdecimal():
            raise _Refused("Choose a group.")
        group = get_object_or_404(DeviceGroup, pk=int(data["group"]))
        agents = agents.filter(pk__in=group.agents().values("pk"))
    elif target != "all":
        raise _Refused("Something went wrong")

    if data["monType"] == "servers":
        agents = agents.filter(monitoring_type=AgentMonType.SERVER)
    elif data["monType"] == "workstations":
        agents = agents.filter(monitoring_type=AgentMonType.WORKSTATION)
    if data["osType"] in AgentPlat.values:
        agents = agents.filter(plat=data["osType"])
    return agents.order_by("pk")


def _check_bulk_input(mode: str, data: dict) -> None:
    missing = [key for key in _BULK_NEEDS[mode] if key not in data]
    if missing:
        raise _Refused(f"{', '.join(missing)} missing")
    if mode in ("command", "script"):
        if _as_int(data["timeout"]) is None or _as_int(data["timeout"]) < 1:
            raise _Refused("timeout must be a whole number of seconds")
        if not isinstance(data["run_as_user"], bool):
            raise _Refused("run_as_user must be true or false")
    if mode == "command" and (not _text(data["cmd"]) or not _text(data["shell"])):
        raise _Refused("cmd and shell are required")
    if mode == "command" and not isinstance(data.get("custom_shell") or "", str):
        raise _Refused("custom_shell must be text")
    if mode == "command" and data["shell"] == "custom":
        if not _text(data.get("custom_shell")):
            raise _Refused(CUSTOM_SHELL_MISSING)
    if mode == "script" and data.get("custom_field") is not None:
        if _as_int(data["custom_field"]) is None:
            raise _Refused("custom_field must be a custom field id")
    if mode == "script" and (
        not isinstance(data["args"], list) or not isinstance(data["env_vars"], list)
    ):
        raise _Refused("args and env_vars must be lists")
    if mode == "patch" and data["patchMode"] not in ("install", "scan"):
        raise _Refused("patchMode must be install or scan")


@api_view(["POST"])
@permission_classes([IsAuthenticated, RunBulkPerms])
def bulk(request):
    # a plain copy: the audit entry adds keys to it
    data = dict(request.data.items())
    try:
        return _bulk(request, data)
    except _Refused as e:
        return notify_error(str(e))


def _bulk(request, data: dict) -> Response:
    for key in ("mode", "target", "monType", "osType"):
        if key not in data:
            raise _Refused(f"{key} missing")
    mode = data["mode"]
    if mode not in _BULK_NEEDS:
        raise _Refused("Something went wrong")

    flag = _BULK_FLAGS.get(mode)
    if mode == "patch" and data.get("patchMode") == "install":
        flag = "can_install_patches_now"
    if flag and not _has_perm(request, flag):
        raise PermissionDenied()
    _check_bulk_input(mode, data)

    script = None
    if mode == "script":
        script_pk = _as_int(data["script"])
        if script_pk is None:
            raise _Refused("Choose a script.")
        script = get_object_or_404(Script, pk=script_pk)
        data["env_vars"] = keep_masked_env_vars(data["env_vars"], script.env_vars)
        check_env_vars(data["env_vars"], script)
        _check_keystore_placeholders(request, data["args"] + data["env_vars"])

    agents = _bulk_queryset(request, data)
    if mode == "package":
        return _bulk_package(request, data, agents)
    if mode == "wake":
        return _bulk_wake(request, data, agents)

    rows = list(
        agents.defer("services") if mode == "suspend" else agents.defer(*AGENT_DEFER)
    )
    outdated = 0
    if mode == "suspend":
        sleepers = [a for a in rows if _can_sleep(a)]
        outdated, rows = len(rows) - len(sleepers), sleepers
    online = [a for a in rows if a.is_online]
    offline = len(rows) - len(online)

    skipped = f", {offline} offline agents were skipped" if offline else ""
    if outdated:
        skipped += f", {outdated} agents need the agent update first"
    if outdated and not online:
        raise _Refused(
            f"No agent meeting the selected criteria can go to sleep{skipped}"
        )
    if not online:
        if not offline:
            raise _Refused(_NONE_FOUND)
        raise _Refused(
            f"All {offline} agents meeting the selected criteria are offline"
        )

    pks = [a.pk for a in online]
    AuditLog.audit_bulk_action(
        request.user.username, mode, data, pks, offline, debug_info=_ip(request)
    )
    username = request.user.username[:50]
    history = "Check the History tab on the agent to view the results."

    if mode == "command":
        shell = data["shell"]
        if shell == "custom":
            shell = data["custom_shell"]
        bulk_command_task.delay(
            agent_pks=pks,
            cmd=data["cmd"],
            shell=shell,
            timeout=_as_int(data["timeout"]),
            username=username,
            run_as_user=data["run_as_user"],
        )
        return Response(
            f"Command will now be run on {len(pks)} agents{skipped}. {history}"
        )

    if mode == "script":
        extras = ("custom_field", "collector_all_output", "save_to_agent_note")
        if all(key in data for key in extras):
            field, collect_all, to_note = (data[key] for key in extras)
            field = _as_int(field) if field is not None else None
            collect_all, to_note = bool(collect_all), bool(to_note)
        else:
            # older dashboards do not send these
            field, collect_all, to_note = None, False, False
        bulk_script_task.delay(
            script_pk=script.pk,
            agent_pks=pks,
            args=data["args"],
            timeout=_as_int(data["timeout"]),
            username=username,
            run_as_user=data["run_as_user"],
            env_vars=data["env_vars"],
            custom_field_pk=field,
            collector_all_output=collect_all,
            save_to_agent_note=to_note,
        )
        return Response(
            f"{script.name} will now be run on {len(pks)} agents{skipped}. {history}"
        )

    if mode == "patch":
        if data["patchMode"] == "install":
            bulk_install_updates_task.delay(pks)
            return Response(
                f"Pending updates will now be installed on {len(pks)} agents{skipped}"
            )
        bulk_check_for_updates_task.delay(pks)
        return Response(f"Patch status scan will now run on {len(pks)} agents{skipped}")

    try:
        asyncio.run(
            abulk_nats_command(
                items=[(a.agent_id, {"func": "suspend"}) for a in online]
            )
        )
    except NatsDown:
        raise _Refused("Unable to contact the agents")
    Agent.objects.filter(pk__in=[a.pk for a in online]).update(
        power_event="sleep",
        power_event_at=djangotime.now(),
        power_event_by=f"rmm: {username}"[:255],
    )
    return Response(f"{len(pks)} agents will now go to sleep{skipped}")


def _bulk_package(request, data: dict, agents) -> Response:
    from packages.models import SoftwarePackage
    from packages.services import start_installs

    if not str(data.get("package")).isdecimal():
        raise _Refused("Choose a package.")
    package = get_object_or_404(SoftwarePackage, pk=int(data["package"]))
    rows = list(agents.filter(plat=package.plat).defer(*AGENT_DEFER))
    target = {key: data[key] for key in _BULK_TARGET_KEYS if key in data}
    try:
        result = start_installs(request.user, package, rows, data.get("run_as"), target)
    except ValueError as e:
        raise _Refused(str(e))
    return Response(result)


def _bulk_wake(request, data: dict, agents) -> Response:
    # offline agents are the point here, online ones are woken all the same
    rows = list(agents.defer("services"))
    if not rows:
        raise _Refused(_NONE_FOUND)

    pks = [a.pk for a in rows]
    AuditLog.audit_bulk_action(
        request.user.username, "wake", data, pks, 0, debug_info=_ip(request)
    )
    sent = wake_agents(rows, request.user)
    native = sum(1 for pk in pks if sent.get(pk))

    mesh_ids = [
        a.mesh_node_id for a in rows if a.mesh_node_id and a.hex_mesh_node_id != "error"
    ]
    mesh = f"{len(mesh_ids)} through MeshCentral"
    if mesh_ids:
        try:
            asyncio.run(wake_on_lan(uri=get_mesh_ws_url(), mesh_node_ids=mesh_ids))
        except Exception as e:
            mesh = f"MeshCentral failed: {e}"

    return Response(
        f"Wake-on-LAN sent for {len(rows)} agents: {native} from the server or a "
        f"neighbor agent, {mesh}"
    )


# versions, updates, installers


@api_view(["GET"])
@permission_classes([IsAuthenticated, AgentPerms])
def get_agent_versions(request):
    agents = (
        Agent.objects.filter_by_role(request.user)
        .defer(*AGENT_DEFER)
        .select_related("site__client")
        .order_by("pk")
    )
    hosts = AgentHostnameSerializer(agents, many=True).data
    return Response({"versions": [settings.LATEST_AGENT_VER], "agents": hosts})


@api_view(["POST"])
@permission_classes([IsAuthenticated, UpdateAgentPerms])
def update_agents(request):
    ids = request.data.get("agent_ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return notify_error("agent_ids must be a list of agent ids")

    latest = agent_ver(settings.LATEST_AGENT_VER)
    agents = (
        Agent.objects.filter_by_role(request.user)
        .filter(agent_id__in=ids)
        .only("pk", "agent_id", "version")
        .order_by("pk")
    )
    outdated = [a.agent_id for a in agents if agent_ver(a.version) < latest]
    send_agent_update_task.delay(agent_ids=outdated, force=False)
    return Response("ok")


@api_view(["POST"])
@permission_classes([IsAuthenticated, UpdateAgentPerms])
def force_update_agents(request):
    ids = list(
        Agent.objects.filter_by_role(request.user)
        .order_by("pk")
        .values_list("agent_id", flat=True)
    )
    send_agent_update_task.delay(agent_ids=ids, force=True)
    return Response("Agents will be updated shortly")


_INSTALL_METHODS = ("exe", "powershell", "bash", "manual", "mac", "freebsd")
_FREEBSD_ARCHS = (GoArch.AMD64, GoArch.ARM64)


def _flag(data, key: str) -> int:
    value = data.get(key, 0)
    if isinstance(value, bool):
        return int(value)
    value = _as_int(value)
    if value not in (0, 1):
        raise _Refused("rdp, ping and power must be 0 or 1")
    return value


@api_view(["POST"])
@permission_classes([IsAuthenticated, InstallAgentPerms])
def install_agent(request):
    try:
        return _install_agent(request)
    except _Refused as e:
        return notify_error(str(e))


def _install_agent(request):
    data = request.data
    method = data.get("installMethod")
    server_cert = self_signed_cert_pem()
    if getattr(settings, "ULRMM_INSECURE", False) and not server_cert:
        raise _Refused(
            "The certificate of this self-signed server (CERT_FILE) cannot be "
            "read, agents could not verify the server."
        )

    # scope first: a refused site is a 403 whatever else is wrong
    client_id, site_id = _as_int(data.get("client")), _as_int(data.get("site"))
    site = Site.objects.filter(pk=site_id).first() if site_id is not None else None
    if site is None or site.client_id != client_id:
        raise _Refused("Choose a client and one of its sites.")
    if not _has_perm_on_site(request.user, site.pk):
        raise PermissionDenied()

    expires = _as_int(data.get("expires"))
    if expires is None:
        raise _Refused("Please enter a valid number of hours")
    if not 1 <= expires <= INSTALLER_MAX_HOURS:
        raise _Refused(
            f"An installer token can be valid for {INSTALLER_MAX_HOURS} hours at most."
        )

    plat, goarch = data.get("plat"), data.get("goarch")
    if plat not in AgentPlat.values or goarch not in GoArch.values:
        raise _Refused("Invalid platform or architecture")
    if method == "exe":
        raise _Refused("Use the Standard EXE or PowerShell method.")
    if method not in _INSTALL_METHODS:
        raise _Refused("Choose an install method.")
    if (method == "freebsd") != (plat == AgentPlat.FREEBSD):
        raise _Refused("FreeBSD agents install with the FreeBSD method only.")
    if plat == AgentPlat.FREEBSD and goarch not in _FREEBSD_ARCHS:
        raise _Refused("FreeBSD agents are built for amd64 and arm64 only.")

    agent_type = data.get("agenttype")
    if agent_type not in AgentMonType.values:
        raise _Refused("Choose server or workstation.")
    api = data.get("api")
    if not isinstance(api, str) or not _API_URL.fullmatch(api):
        raise _Refused("api must be the https address of this server")
    rdp, ping_on, power = _flag(data, "rdp"), _flag(data, "ping"), _flag(data, "power")

    installer = User.objects.filter(is_installer_user=True).order_by("pk").first()
    if installer is None:
        raise _Refused("No installer user exists. Run create_installer_user first.")

    inno = agent_artifact(settings.LATEST_AGENT_VER, plat, goarch)
    download_url = get_install_agent_url(goarch=goarch, plat=plat)

    try:
        # the token only outlives the request together with its site binding
        with transaction.atomic():
            auth_token, token = AuthToken.objects.create(
                user=installer, expiry=dt.timedelta(hours=expires)
            )
            InstallerToken.objects.create(auth_token=auth_token, site=site)
            return _installer_body(
                method=method,
                inno=inno,
                download_url=download_url,
                client=str(client_id),
                site=str(site.pk),
                agent_type=agent_type,
                api=api,
                token=token,
                switches={"rdp": rdp, "ping": ping_on, "power": power},
                server_cert=server_cert,
                plat=plat,
                goarch=goarch,
            )
    except MeshDeviceGroupNotFound as e:
        DebugLog.error(log_type=DebugLogType.AGENT_ISSUES, message=str(e))
        raise _Refused(str(e))


def _with_server_cert(text: str, empty: str, pem: str) -> str:
    """Fills the empty certificate line of an install script."""
    if not pem:
        return text
    if text.count(empty) != 1:
        raise _Refused("The install script has no place for the server certificate.")
    return text.replace(empty, empty.replace("''", f"'{pem}'"), 1)


def _pem_lines(pem: str) -> list[str]:
    body = re.sub(r"-----[A-Z ]+-----|\s", "", pem)
    return ["-----BEGIN CERTIFICATE-----", body, "-----END CERTIFICATE-----"]


def _installer_body(
    *,
    method,
    plat,
    inno,
    download_url,
    client,
    site,
    agent_type,
    api,
    token,
    switches,
    server_cert,
    goarch,
):
    flags = (
        f"-m install --api {api} --client-id {client} --site-id {site} "
        f"--agent-type {agent_type}"
    )

    if method in ("bash", "freebsd"):
        # looked up per call, tests replace them on agents.utils
        from . import utils

        generate = (
            utils.generate_linux_install
            if method == "bash"
            else utils.generate_freebsd_install
        )
        response = generate(
            client=client,
            site=site,
            agent_type=agent_type,
            arch=goarch,
            token=token,
            api=api,
            download_url=download_url,
        )
        if not server_cert:
            return response
        text = b"".join(response.streaming_content).decode()
        return FileResponse(
            io.BytesIO(
                _with_server_cert(text, "\nserverCert=''\n", server_cert).encode()
            ),
            as_attachment=True,
            filename=response.filename,
        )

    if method == "manual":
        ident = agent_ident()
        exe = f"C:\\Program Files\\{ident['identWinProgDir']}\\{ident['identWinExe']}"
        cmd = f"{inno} /VERYSILENT /SUPPRESSMSGBOXES && ping 127.0.0.1 -n 7 && "
        cert = ""
        if server_cert:
            path = f"{ident['identWinProgPath']}\\server.pem"
            echo = "& ".join(f"echo {line}" for line in _pem_lines(server_cert))
            cmd += f'({echo})> "{path}" && '
            cert = f' -cert "{path}"'
        cmd += f'"{exe}" {flags} --auth {token}{cert}'
        for name in ("rdp", "ping", "power"):
            if switches[name]:
                cmd += f" --{name}"
        return Response({"cmd": cmd, "url": download_url})

    if method == "mac":
        from .utils import install_artifact_sha256

        check = ""
        if sha256 := install_artifact_sha256(plat, goarch):
            check = f"echo '{sha256}  {inno}' | shasum -a 256 -c && "
        cmd, cert, ca = "", "", ""
        if server_cert:
            # a self-signed server: curl and the agent verify it with its certificate
            path = f"{settings.AGENT_NIX_CONF}.server.pem"
            lines = " ".join(f"'{line}'" for line in _pem_lines(server_cert))
            cmd = f"printf '%s\\n' {lines} | sudo tee {path} >/dev/null && "
            cert, ca = f" -cert {path}", f"--cacert {path} "
        # printf is a shell builtin: the token never shows in the process list
        cmd += (
            f"curl -fL --proto '=https' --proto-redir '=https' {ca}-o {inno} "
            f"'{download_url}' && {check}chmod +x {inno} && "
            "f=$(sudo mktemp) && "
            f"printf '%s' '{token}' | sudo tee \"$f\" >/dev/null && "
            f'sudo ./{inno} {flags} -auth-file "$f"{cert}'
        )
        return Response({"cmd": cmd, "url": download_url})

    from .utils import install_artifact_sha256

    template = render_agent_script(
        settings.BASE_DIR / "core" / "installer.ps1", agent_ident()
    )
    values = {
        "innosetupchange": inno,
        "clientchange": client,
        "sitechange": site,
        "apichange": api,
        "atypechange": agent_type,
        "powerchange": str(switches["power"]),
        "rdpchange": str(switches["rdp"]),
        "pingchange": str(switches["ping"]),
        "downloadchange": download_url,
        "tokenchange": token,
        "sha256change": install_artifact_sha256(plat, goarch),
        "enrollchange": "",
    }
    # one pass, so a value is never read as another placeholder
    pattern = re.compile("|".join(re.escape(key) for key in values))
    script = pattern.sub(lambda m: values[m.group(0)], template)
    script = _with_server_cert(script, "\n$cert = ''\n", server_cert)
    response = HttpResponse(script, content_type="text/plain")
    response["Content-Disposition"] = 'attachment; filename="rmm-installer.ps1"'
    return response


@api_view(["GET"])
@permission_classes([IsAuthenticated, RecoverAgentPerms])
def bulk_agent_recovery(request):
    if not has_superuser_rights(request.user):
        raise PermissionDenied("Only superusers can recover all agents at once.")
    bulk_recover_agents_task.delay()
    return Response("Agents will now be recovered")


# registry (agent 2.10.0 and newer)


def _registry_view(method: str):
    """Registry endpoint: registry rights, agent 2.10.0 or newer, gets the agent."""

    def decorate(func):
        @api_view([method])
        @permission_classes([IsAuthenticated, AgentRegistryPerms])
        @wraps(func)
        def view(request, agent_id):
            found = get_validated_agent(agent_id)
            return found if isinstance(found, Response) else func(request, found)

        return view

    return decorate


def _registry_change(request, agent: Agent, func: str, payload: dict, timeout=30):
    """Sends a registry change. Audited with names and paths, never the data."""
    audited = {key: value for key, value in payload.items() if key != "data"}
    _audit_agent(
        request,
        agent,
        AuditActionType.MODIFY,
        f"{request.user.username} ran {func.replace('_', ' ')} on {agent.hostname}",
        after_value={"func": func, **audited},
    )
    return send_nats_command(agent, func, payload, timeout)


def _value_reply(reply: dict, name: str, kind: str, value) -> Response:
    return Response(
        {
            "status": "success",
            "data": {
                "name": reply.get("name") or name,
                "type": reply.get("type") or kind,
                "data": reply.get("data") or value,
            },
        }
    )


@_registry_view("GET")
def browse_registry(request, agent: Agent):

    params = request.query_params
    path = _text(params.get("path")) or "Computer"
    if path.lower() == "computer":
        path = "Computer"
    page, size = _as_int(params.get("page", "1")), _as_int(
        params.get("page_size", "200")
    )
    if page is None or size is None:
        return notify_error("page and page_size must be integers")
    # agents before 2.10 crash on page < 1, newer ones cap at 1000
    page, size = max(page, 1), min(max(size, 1), 1000)

    reply = send_nats_command(
        agent,
        "registry_browse",
        {"path": path, "page": str(page), "page_size": str(size)},
        30,
    )
    if isinstance(reply, Response):
        return reply
    return Response(
        {
            "path": reply.get("path") or path,
            "subkeys": reply.get("subkeys") or [],
            "values": reply.get("values") or [],
            "has_more": reply.get("has_more") or False,
            "page": page,
            "page_size": size,
        }
    )


@_registry_view("POST")
def create_registry_key(request, agent: Agent):
    path = _text(request.data.get("path"))
    if not path:
        return notify_error("Registry path is required")

    reply = _registry_change(request, agent, "registry_create_key", {"path": path})
    if isinstance(reply, Response):
        return reply
    return Response({"status": "success", "path": path})


@_registry_view("DELETE")
def delete_registry_key(request, agent: Agent):
    path = _text(request.query_params.get("path"))
    if not path:
        return notify_error("Registry path is required")

    reply = _registry_change(request, agent, "registry_delete_key", {"path": path})
    if isinstance(reply, Response):
        return reply
    return Response({"status": "success", "deleted_path": path})


@_registry_view("POST")
def rename_registry_key(request, agent: Agent):
    old_path = _text(request.data.get("old_path"))
    new_path = _text(request.data.get("new_path"))
    if not old_path or not new_path:
        return notify_error("Both 'old_path' and 'new_path' are required")
    if old_path == new_path:
        return notify_error("Old and new path cannot be the same")

    reply = _registry_change(
        request,
        agent,
        "registry_rename_key",
        {"old_path": old_path, "new_path": new_path},
        timeout=60,
    )
    if isinstance(reply, Response):
        return reply
    return Response({"status": "success", "old_path": old_path, "new_path": new_path})


def _value_name(data):
    # "" names the key's default value, so only a missing name is refused
    name = data.get("name")
    return name if isinstance(name, str) else None


@_registry_view("POST")
def create_registry_value(request, agent: Agent):
    path = _text(request.data.get("path"))
    kind = _text(request.data.get("type")).upper()
    name = _value_name(request.data)
    if not path:
        return notify_error("Registry path is required")
    if not kind:
        return notify_error("Registry value type is required")
    if name is None:
        return notify_error("Registry value name is required")

    value = request.data.get("data")
    reply = _registry_change(
        request,
        agent,
        "registry_create_value",
        {"path": path, "type": kind, "name": name, "data": value},
    )
    if isinstance(reply, Response):
        return reply
    return _value_reply(reply, name, kind, value)


@_registry_view("DELETE")
def delete_registry_value(request, agent: Agent):
    path = _text(request.query_params.get("path"))
    name = _value_name(request.query_params)
    if not path:
        return notify_error("Registry path is required")
    if name is None:
        return notify_error("Registry value name is required")

    reply = _registry_change(
        request, agent, "registry_delete_value", {"path": path, "name": name}
    )
    if isinstance(reply, Response):
        return reply
    return Response({"status": "success", "name": name})


@_registry_view("POST")
def rename_registry_value(request, agent: Agent):
    path = _text(request.data.get("path"))
    old_name = _text(request.data.get("old_name"))
    new_name = _text(request.data.get("new_name"))
    for given, error in (
        (path, "Registry path is required"),
        (old_name, "Old value name is required"),
        (new_name, "New value name is required"),
    ):
        if not given:
            return notify_error(error)
    if old_name == new_name:
        return notify_error("Old and new value names cannot be the same")

    reply = _registry_change(
        request,
        agent,
        "registry_rename_value",
        {"path": path, "old_name": old_name, "new_name": new_name},
    )
    if isinstance(reply, Response):
        return reply
    return Response(
        {
            "status": "success",
            "old_name": old_name,
            "new_name": reply.get("new_name") or new_name,
        }
    )


@_registry_view("POST")
def modify_registry_value(request, agent: Agent):
    path = _text(request.data.get("path"))
    name = _value_name(request.data)
    kind = _text(request.data.get("type")).upper()
    if not path:
        return notify_error("Registry path is required")
    if name is None:
        return notify_error("Registry value name is required")
    if not kind:
        return notify_error("Registry value type is required")

    value = request.data.get("data")
    reply = _registry_change(
        request,
        agent,
        "registry_modify_value",
        {"path": path, "name": name, "type": kind, "data": value},
    )
    if isinstance(reply, Response):
        return reply
    return _value_reply(reply, name, kind, value)


class AgentTerminalDefaults(APIView):
    permission_classes = [IsAuthenticated, AgentTerminalPerms]

    def get(self, request, agent_id):
        visible = Agent.objects.filter_by_role(request.user).defer(*AGENT_DEFER)
        agent = get_object_or_404(visible, agent_id=agent_id)
        context = {
            "core_settings": CoreSettings.objects.first(),
            "supports_new_terminal": agent_ver(agent.version) >= agent_ver("2.11.0"),
        }
        return Response(AgentTerminalDefaultsSerializer(agent, context=context).data)

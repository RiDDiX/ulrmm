# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import contextlib
import json
import re

import psutil
import redis
import requests
from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import serializers

from accounts.utils import has_superuser_rights
from logs.models import AuditLog
from scripts.models import check_env_vars
from scripts.permissions import ScriptsPerms
from ulrmm.constants import (
    AGENT_DEFER,
    AuditActionType,
    AuditObjType,
    PAStatus,
    ScriptShell,
)
from ulrmm.helpers import (
    days_until_cert_expires,
    get_issues_url,
    get_nats_ports,
    notify_error,
)
from ulrmm.logger import logger
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import (
    _has_perm,
    _has_perm_on_agent,
    _has_perm_on_client,
    _has_perm_on_site,
    _may_assign_policy,
)
from ulrmm.throttles import BrandingThrottle
from ulrmm.utils import (
    get_celery_queue_len,
    get_latest_version,
    localhost_port_is_open,
    runcmd_placeholder_text,
)

from .about import about
from .decorators import monitoring_view, monitoring_view_v2
from .models import CoreSettings, CustomField, GlobalKVStore, Schedule, URLAction
from .permissions import CoreSettingsPerms, CustomFieldPerms, GlobalKeyStorePerms
from .permissions import RunServerScriptPerms, SchedulePerms, ServerMaintPerms
from .permissions import URLActionPerms, WebTerminalPerms
from .serializers import (
    BrandingSerializer,
    CoreSettingsSerializer,
    CustomFieldSerializer,
    KeyStoreSerializer,
    PublicBrandingSerializer,
    ScheduleSerializer,
    URLActionSerializer,
)
from .stats import fleet_stats
from .tasks import sync_mesh_perms_task
from .utils import (
    SERVER_SCRIPT_STEPUP,
    clear_entire_cache,
    find_and_replace_db_values_str,
    get_branding,
    get_core_settings,
    run_server_script,
    run_test_url_rest_action,
    stepup_denied,
)

SECRET_MASK = "********"


@api_view()
@permission_classes([AllowAny])
def home(request):
    return Response({"status": "ok"})


class PublicBranding(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [BrandingThrottle]

    def get(self, request):
        return Response(PublicBrandingSerializer(get_branding()).data)


def _branding_audit(branding) -> dict:
    import hashlib

    data = BrandingSerializer(branding).data
    for field in ("logo", "favicon"):
        value = getattr(branding, field)
        if value:
            data[field] = "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return data


class EditBranding(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(BrandingSerializer(get_branding()).data)

    def put(self, request):
        branding = get_branding()
        before = _branding_audit(branding)
        serializer = BrandingSerializer(branding, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        after = _branding_audit(serializer.instance)
        if before != after:
            AuditLog.audit_object_changed(
                request.user.username,
                AuditObjType.CORE,
                before,
                after,
                name="Branding",
                debug_info=get_debug_info(),
            )
        return Response("ok")


def _save_ok(serializer) -> Response:
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response("ok")


def _delete_ok(model, pk) -> Response:
    get_object_or_404(model, pk=pk).delete()
    return Response("ok")


class GetEditCoreSettings(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(CoreSettingsSerializer(CoreSettings.objects.first()).data)

    def put(self, request):
        data = request.data.copy()
        if getattr(settings, "HOSTED", False):
            for key in ("mesh_site", "mesh_token", "mesh_token_clear", "mesh_username"):
                data.pop(key, None)
            data["sync_mesh_with_rmm"] = True
            data["enable_server_scripts"] = False
            data["enable_server_webterminal"] = False

        core = CoreSettings.objects.first()
        serializer = CoreSettingsSerializer(core, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        # a default slot is an assignment like a client's or site's
        for key in ("workstation_policy", "server_policy"):
            chosen = serializer.validated_data.get(key)
            if (
                chosen is not None
                and chosen.pk != getattr(core, f"{key}_id")
                and not _may_assign_policy(request.user, chosen)
            ):
                return notify_error("You cannot assign this policy.")
        response = _save_ok(serializer)
        sync_mesh_perms_task.delay()
        return response


@api_view()
def version(request):
    return Response(settings.APP_VER)


@api_view()
@authentication_classes([])
@permission_classes([AllowAny])
def health(request):
    """Liveness for update.sh and the dashboard reconnect after a restart."""
    try:
        with connection.cursor() as c:
            c.execute("SELECT 1")
            c.fetchone()
        db = True
    except Exception:
        db = False
    r = Response(
        {
            "status": "ok" if db else "degraded",
            "version": settings.ULRMM_VERSION,
            "db": db,
        },
        status=200 if db else 503,
    )
    r["Cache-Control"] = "no-store"
    return r


@api_view()
def about_info(request):
    if request.user.is_installer_user:
        return notify_error("")
    return Response(about())


@api_view(["POST"])
@permission_classes([IsAuthenticated, CoreSettingsPerms])
def email_test(request):
    core = get_core_settings()
    message, ok = core.send_mail(
        subject="Test from UniversalLocal RMM",
        body="This is a test message",
        test=True,
    )
    if not ok:
        return notify_error(message)
    return Response("Email test ok!")


@api_view()
def dashboard_info(request):
    from reporting.permissions import can_manage_reports, can_view_reports

    if request.user.is_installer_user:
        return notify_error("")

    user, core = request.user, get_core_settings()
    return Response(
        {
            "version": settings.ULRMM_VERSION,
            "latest_version": get_latest_version(),
            "dark_mode": user.dark_mode,
            "show_community_scripts": user.show_community_scripts,
            "dbl_click_action": user.agent_dblclick_action,
            "default_agent_tbl_tab": user.default_agent_tbl_tab,
            "url_action": user.url_action_id,
            "client_tree_sort": user.client_tree_sort,
            "client_tree_splitter": user.client_tree_splitter,
            "loading_bar_color": user.loading_bar_color,
            "clear_search_when_switching": user.clear_search_when_switching,
            "hosted": bool(getattr(settings, "HOSTED", False)),
            "date_format": user.date_format,
            "default_date_format": core.date_format,
            "ai_scripts_enabled": bool(core.ai_api_key),
            "issues_url": get_issues_url(),
            "dash_info_color": user.dash_info_color,
            "dash_positive_color": user.dash_positive_color,
            "dash_negative_color": user.dash_negative_color,
            "dash_warning_color": user.dash_warning_color,
            "run_cmd_placeholder_text": runcmd_placeholder_text(),
            "server_scripts_enabled": core.server_scripts_enabled,
            "web_terminal_enabled": core.web_terminal_enabled,
            "block_local_user_logon": core.block_local_user_logon,
            "sso_enabled": core.sso_enabled,
            "can_view_reports": can_view_reports(user),
            "can_manage_reports": can_manage_reports(user),
            "can_manage_server_updates": not getattr(settings, "HOSTED", False)
            and _has_perm(request, "can_manage_server_updates"),
            "can_run_autotasks": _has_perm(request, "can_run_autotasks"),
            "is_superuser": has_superuser_rights(user),
        }
    )


class FleetStats(APIView):
    def get(self, request):
        from agents.models import Agent

        agents = Agent.objects.filter_by_role(request.user).defer(*AGENT_DEFER)
        return Response(fleet_stats(agents))


def _audit_maint(request, message: str) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.CORE,
        action=AuditActionType.MODIFY,
        message=message,
        debug_info={"ip": getattr(request, "_client_ip", "")},
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated, ServerMaintPerms])
def server_maintenance(request):
    import ulrmm.utils as ulrmm_utils
    from alerts.models import Alert
    from autotasks.tasks import remove_orphaned_win_tasks
    from logs.models import PendingAction

    action = request.data.get("action")
    if not action:
        return notify_error("The data is incorrect")

    user = request.user.username
    if action == "reload_nats":
        ulrmm_utils.reload_nats()
        _audit_maint(request, f"{user} reloaded the NATS configuration.")
        return Response("Nats configuration was reloaded successfully.")

    if action == "rm_orphaned_tasks":
        remove_orphaned_win_tasks.delay()
        _audit_maint(request, f"{user} started removing orphaned tasks.")
        return Response("The task has been initiated.")

    if action == "prune_db":
        if hasattr(request.data, "getlist"):
            prune_tables = request.data.getlist("prune_tables")
        else:
            prune_tables = request.data.get("prune_tables")
        if not prune_tables or not isinstance(prune_tables, list):
            return notify_error("The data is incorrect.")
        count = 0
        if "audit_logs" in prune_tables:
            qs = AuditLog.objects.filter(action=AuditActionType.CHECK_RUN)
            count += qs.count()
            qs.delete()
        if "pending_actions" in prune_tables:
            qs = PendingAction.objects.filter(status=PAStatus.COMPLETED)
            count += qs.count()
            qs.delete()
        if "alerts" in prune_tables:
            qs = Alert.objects.all()
            count += qs.count()
            qs.delete()
        tables = ", ".join(
            t for t in ("audit_logs", "pending_actions", "alerts") if t in prune_tables
        )
        _audit_maint(
            request, f"{user} pruned {count} records from the database ({tables})."
        )
        return Response(f"{count} records were pruned from the database")

    return notify_error("The data is incorrect")


class GetAddCustomFields(APIView):
    permission_classes = [IsAuthenticated, CustomFieldPerms]

    def get(self, request):
        qs = CustomField.objects.all().order_by("pk")
        if "model" in request.query_params:
            qs = qs.filter(model=request.query_params["model"])
        return Response(CustomFieldSerializer(qs, many=True).data)

    def patch(self, request):
        if not isinstance(request.data, dict) or "model" not in request.data:
            return notify_error("The request was invalid")
        qs = CustomField.objects.filter(model=request.data["model"]).order_by("pk")
        return Response(CustomFieldSerializer(qs, many=True).data)

    def post(self, request):
        return _save_ok(CustomFieldSerializer(data=request.data))


class GetUpdateDeleteCustomFields(APIView):
    permission_classes = [IsAuthenticated, CustomFieldPerms]

    def get(self, request, pk):
        return Response(
            CustomFieldSerializer(get_object_or_404(CustomField, pk=pk)).data
        )

    def put(self, request, pk):
        field = get_object_or_404(CustomField, pk=pk)
        return _save_ok(CustomFieldSerializer(field, data=request.data, partial=True))

    def delete(self, request, pk):
        return _delete_ok(CustomField, pk)


class GetAddKeyStore(APIView):
    permission_classes = [IsAuthenticated, GlobalKeyStorePerms]

    def get(self, request):
        return Response(
            KeyStoreSerializer(
                GlobalKVStore.objects.all().order_by("pk"), many=True
            ).data
        )

    def post(self, request):
        return _save_key(KeyStoreSerializer(data=request.data))


KEY_EXISTS = "A key with this name already exists"


def _save_key(serializer) -> Response:
    if not serializer.is_valid():
        if any(e.code == "unique" for e in serializer.errors.get("name", [])):
            return notify_error(KEY_EXISTS)
        raise serializers.ValidationError(serializer.errors)
    try:
        with transaction.atomic():
            serializer.save()
    except IntegrityError:
        # a parallel request took the name after the check above
        return notify_error(KEY_EXISTS)
    return Response("ok")


class UpdateDeleteKeyStore(APIView):
    permission_classes = [IsAuthenticated, GlobalKeyStorePerms]

    def put(self, request, pk):
        obj = get_object_or_404(GlobalKVStore, pk=pk)
        return _save_key(KeyStoreSerializer(obj, data=request.data, partial=True))

    def delete(self, request, pk):
        return _delete_ok(GlobalKVStore, pk)


def _masked_rest_parts(row: dict) -> dict:
    try:
        headers = json.loads(row.get("rest_headers") or "")
    except ValueError:
        headers = None
    if isinstance(headers, dict):
        row["rest_headers"] = json.dumps(
            {name: SECRET_MASK for name in headers}, indent=2
        )
    elif row.get("rest_headers"):
        row["rest_headers"] = SECRET_MASK
    if row.get("rest_body"):
        row["rest_body"] = SECRET_MASK
    return row


class GetAddURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    def get(self, request):
        rows = URLActionSerializer(
            URLAction.objects.all().order_by("pk"), many=True
        ).data
        # headers and bodies carry webhook tokens: running needs only the id
        if not _has_perm(request, "can_edit_core_settings"):
            rows = [_masked_rest_parts(dict(row)) for row in rows]
        return Response(rows)

    def post(self, request):
        return _save_ok(URLActionSerializer(data=request.data))


class UpdateDeleteURLAction(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def put(self, request, pk):
        action = get_object_or_404(URLAction, pk=pk)
        return _save_ok(URLActionSerializer(action, data=request.data, partial=True))

    def delete(self, request, pk):
        return _delete_ok(URLAction, pk)


class GetAddSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def get(self, request):
        return Response(
            ScheduleSerializer(Schedule.objects.all().order_by("pk"), many=True).data
        )

    def post(self, request):
        serializer = ScheduleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()
        return Response(ScheduleSerializer(obj).data)


class UpdateDeleteSchedule(APIView):
    permission_classes = [IsAuthenticated, SchedulePerms]

    def put(self, request, pk):
        obj = get_object_or_404(Schedule, pk=pk)
        serializer = ScheduleSerializer(obj, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()
        return Response(ScheduleSerializer(obj).data)

    def delete(self, request, pk):
        try:
            with transaction.atomic():
                get_object_or_404(Schedule, pk=pk).delete()
        except IntegrityError:
            return notify_error(SCHEDULE_IN_USE)
        return Response(pk)


SCHEDULE_IN_USE = "This schedule is currently in use."


class RunURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    def patch(self, request):
        from agents.models import Agent
        from clients.models import Client, Site

        data = request.data
        if "agent_id" in data:
            instance = get_object_or_404(Agent, agent_id=data["agent_id"])
            if not _has_perm_on_agent(request.user, instance.agent_id):
                raise PermissionDenied()
        elif "site" in data:
            instance = get_object_or_404(Site, pk=data["site"])
            if not _has_perm_on_site(request.user, instance.pk):
                raise PermissionDenied()
        elif "client" in data:
            instance = get_object_or_404(Client, pk=data["client"])
            if not _has_perm_on_client(request.user, instance.pk):
                raise PermissionDenied()
        else:
            return notify_error("received an incorrect request")

        action_id = data.get("action")
        if not action_id:
            return notify_error("The action is required.")
        action = get_object_or_404(URLAction, pk=action_id)

        new_url = find_and_replace_db_values_str(
            text=action.pattern, instance=instance, escape="url"
        )
        new_url = requests.utils.requote_uri(new_url)
        AuditLog.audit_url_action(
            request.user.username,
            action,
            instance,
            debug_info={"ip": getattr(request, "_client_ip", "")},
        )
        return Response(new_url)


class _RunTestInputSerializer(serializers.Serializer):
    pattern = serializers.CharField()
    # blank as the model allows: a GET webhook may have no headers
    rest_body = serializers.CharField(allow_blank=True, allow_null=True)
    rest_headers = serializers.CharField(allow_blank=True, allow_null=True)
    rest_method = serializers.ChoiceField(
        choices=["get", "post", "put", "delete", "patch"]
    )
    run_instance_type = serializers.ChoiceField(
        choices=["agent", "client", "site", "none"]
    )
    run_instance_id = serializers.CharField(allow_null=True)

    def validate(self, attrs):
        iid = attrs["run_instance_id"]
        if attrs["run_instance_type"] in ("client", "site") and iid:
            try:
                int(iid)
            except ValueError:
                raise serializers.ValidationError(
                    {"run_instance_id": "Must be a number."}
                )
        attrs["rest_body"] = attrs["rest_body"] or ""
        attrs["rest_headers"] = attrs["rest_headers"] or ""
        return attrs


class RunTestURLAction(APIView):
    permission_classes = [IsAuthenticated, URLActionPerms]

    def post(self, request):
        serializer = _RunTestInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        global_re = re.compile(r"\{\{\s*global\.")
        if any(
            global_re.search(data[field] or "")
            for field in ("pattern", "rest_body", "rest_headers")
        ) and not _has_perm(request, "can_view_global_keystore"):
            raise PermissionDenied()

        itype = data["run_instance_type"]
        iid = data["run_instance_id"]
        if itype == "agent" and not _has_perm_on_agent(request.user, iid):
            raise PermissionDenied()
        if itype == "site" and not _has_perm_on_site(request.user, iid):
            raise PermissionDenied()
        if itype == "client" and not _has_perm_on_client(request.user, iid):
            raise PermissionDenied()

        result_text, replaced_url, replaced_body = run_test_url_rest_action(
            url=data["pattern"],
            body=data["rest_body"],
            headers=data["rest_headers"],
            method=data["rest_method"],
            instance_type=itype,
            instance_id=iid,
        )

        AuditLog.audit_url_action_test(
            username=request.user.username,
            url=data["pattern"],
            body=replaced_body,
            headers=data["rest_headers"],
            instance_type=itype,
            instance_id=iid,
            debug_info={"ip": getattr(request, "_client_ip", "")},
        )
        return Response(
            {"url": replaced_url, "result": result_text, "body": replaced_body}
        )


class TwilioSMSTest(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        core = get_core_settings()
        if core.sms_is_configured:
            message, ok = core.send_sms("UniversalLocal RMM Test SMS", test=True)
        else:
            message = "All fields are required, including at least 1 recipient"
            ok = False
        return Response("SMS Test sent successfully!") if ok else notify_error(message)


class ScriptDraftView(APIView):
    """A script draft for the prompt from the OpenAI chat API."""

    permission_classes = [IsAuthenticated, ScriptsPerms]

    def post(self, request):
        core = get_core_settings()
        if not core.ai_api_key:
            return notify_error(
                "No OpenAI API key is set. Add one in Global Settings > AI scripts."
            )
        prompt = request.data.get("prompt")
        if not prompt:
            return notify_error("The prompt is empty.")

        body = {
            "model": core.ai_model,
            "messages": [{"role": "user", "content": str(prompt)[:8000]}],
            "temperature": 0.5,
            "max_tokens": 1000,
            "n": 1,
            "stop": None,
        }
        headers = {"Authorization": f"Bearer {core.ai_api_key}"}
        try:
            answer = requests.post(
                "https://api.openai.com/v1/chat/completions",
                json=body,
                headers=headers,
                timeout=30,
            ).json()
        except Exception as e:
            return notify_error(f"The request to OpenAI failed: {e}")

        error = answer.get("error") if isinstance(answer, dict) else None
        if error:
            if isinstance(error, dict):
                error = error.get("message")
            return notify_error(f"OpenAI answered with an error: {error}")
        try:
            return Response(answer["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            return notify_error("OpenAI sent no script draft back.")


@api_view(["POST"])
@permission_classes([IsAuthenticated, WebTerminalPerms])
def webterm_perms(request):
    core = CoreSettings.objects.first()
    if not core or not core.web_terminal_enabled:
        return Response(
            "This feature is disabled. It can be enabled in Global Settings.",
            status=412,
        )
    return Response("ok")


def _raw_text(**kwargs):
    # script text and arguments go through untouched, empty ones included
    return serializers.CharField(allow_blank=True, trim_whitespace=False, **kwargs)


class _ServerScriptInputSerializer(serializers.Serializer):
    code = _raw_text()
    args = serializers.ListField(child=_raw_text(), required=False, default=list)
    env_vars = serializers.ListField(child=_raw_text(), required=False, default=list)
    timeout = serializers.IntegerField(min_value=1, max_value=290)
    shell = serializers.ChoiceField(choices=ScriptShell.values)


class TestRunServerScript(APIView):
    permission_classes = [IsAuthenticated, RunServerScriptPerms]

    def post(self, request):
        core = CoreSettings.objects.first()
        if not core or not core.server_scripts_enabled:
            return notify_error(
                "This feature is disabled. It can be enabled in Global Settings."
            )

        denied = stepup_denied(request, SERVER_SCRIPT_STEPUP)
        if denied is not None:
            return denied

        serializer = _ServerScriptInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if not data["code"].startswith("#!"):
            return notify_error("Missing shebang!")

        check_env_vars(data["env_vars"])

        stdout, stderr, exec_time, retcode = run_server_script(
            body=data["code"],
            args=data["args"],
            env_vars=data["env_vars"],
            timeout=data["timeout"],
            shell=data["shell"],
        )
        response = {
            "stdout": stdout,
            "stderr": stderr,
            "execution_time": f"{exec_time:.4f}",
            "retcode": retcode,
        }
        AuditLog.audit_test_script_run(
            username=request.user.username,
            before_value={
                "body": data["code"],
                "args": data["args"],
                "env_vars": data["env_vars"],
                "timeout": data["timeout"],
                "shell": data["shell"],
            },
            after_value=response,
            agent=None,
            debug_info={"ip": getattr(request, "_client_ip", "")},
        )
        return Response(response)


@api_view()
@permission_classes([IsAuthenticated, ServerMaintPerms])
def clear_cache(request):
    clear_entire_cache()
    _audit_maint(request, f"{request.user.username} cleared the server cache.")
    return Response("Cache was cleared!")


def _service_states(units: dict) -> dict:
    from .utils import sysd_svc_is_running

    return {label: sysd_svc_is_running(unit) for label, unit in units.items()}


def _cert_status():
    try:
        days = days_until_cert_expires()
        return days, days < 0
    except Exception:
        logger.error("monitoring: TLS certificate could not be read")
        return None, True


def _redis_ping() -> bool:
    with contextlib.suppress(Exception):
        return bool(redis.from_url(settings.REDIS_URL).ping())
    return False


@csrf_exempt
@monitoring_view
def status(request):
    from agents.models import Agent
    from clients.models import Client, Site

    cert_days, cert_expired = _cert_status()
    ret = {
        "version": settings.ULRMM_VERSION,
        "latest_agent_version": settings.LATEST_AGENT_VER,
        "agent_count": Agent.objects.count(),
        "client_count": Client.objects.count(),
        "site_count": Site.objects.count(),
        "disk_usage_percent": round(psutil.disk_usage("/").percent),
        "mem_usage_percent": round(psutil.virtual_memory().percent),
        "days_until_cert_expires": cert_days,
        "cert_expired": cert_expired,
        "redis_ping": _redis_ping(),
        "services_running": _service_states(
            {
                "django": "rmm.service",
                "mesh": "meshcentral.service",
                "daphne": "daphne.service",
                "celery": "celery.service",
                "celerybeat": "celerybeat.service",
                "redis": "redis-server.service",
                "postgres": "postgresql.service",
                "mongo": "mongod.service",
                "nats": "nats.service",
                "nats-api": "nats-api.service",
                "nginx": "nginx.service",
            }
        ),
    }
    return JsonResponse(ret, json_dumps_params={"indent": 2})


@csrf_exempt
@monitoring_view_v2
def status_v2(request):
    from agents.models import Agent
    from clients.models import Client, Site

    cert_days, cert_expired = _cert_status()
    try:
        queue_len = get_celery_queue_len()
    except Exception:
        queue_len = -1
    std_port, ws_port = get_nats_ports()
    mesh_port = getattr(settings, "MESH_PORT", None) or 4430
    ret = {
        "version": settings.ULRMM_VERSION,
        "latest_agent_version": settings.LATEST_AGENT_VER,
        "agent_count": Agent.objects.count(),
        "client_count": Client.objects.count(),
        "site_count": Site.objects.count(),
        "disk_usage_percent": round(psutil.disk_usage("/").percent),
        "mem_usage_percent": round(psutil.virtual_memory().percent),
        "days_until_cert_expires": cert_days,
        "cert_expired": cert_expired,
        "redis_ping": _redis_ping(),
        "celery_queue_len": queue_len,
        "celery_queue_health": "healthy" if 0 <= queue_len < 2000 else "unhealthy",
        "nats_std_ping": localhost_port_is_open(std_port),
        "nats_ws_ping": localhost_port_is_open(ws_port),
        "mesh_ping": localhost_port_is_open(mesh_port),
        "services_running": _service_states(
            {
                "mesh": "meshcentral.service",
                "daphne": "daphne.service",
                "celery": "celery.service",
                "celerybeat": "celerybeat.service",
                "redis": "redis-server.service",
                "nats": "nats.service",
                "nats-api": "nats-api.service",
            }
        ),
    }
    return JsonResponse(ret, json_dumps_params={"indent": 2})

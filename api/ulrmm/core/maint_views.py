# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

from django.conf import settings
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm
from ulrmm.utils import get_latest_version

from . import releases, server_ops
from .models import ReleaseRepo
from .utils import stepup_denied

STEPUP_WHY = "Server updates and backups need it."


class ServerUpdatePerms(permissions.BasePermission):
    def has_permission(self, r, view) -> bool:
        if getattr(settings, "HOSTED", False):
            return False
        return _has_perm(r, "can_manage_server_updates")


def _audit(request, action, message: str) -> None:
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.CORE,
        action=action,
        message=message,
        debug_info={"ip": getattr(request, "_client_ip", "")},
    )


class ServerUpdate(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request):
        refresh = request.query_params.get("refresh") == "1"
        return Response(
            {
                "current_version": settings.ULRMM_VERSION,
                "latest_version": get_latest_version(),
                "runner_installed": server_ops.runner_installed(),
                "busy": server_ops.busy_with(),
                "state": server_ops.read_state("update"),
                "pending": server_ops.pending_changes(refresh=refresh),
            }
        )

    def post(self, request):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        data = request.data if isinstance(request.data, dict) else {}
        mode = data.get("mode") or "git"
        if mode not in ("git", "release"):
            return notify_error("Unknown update mode.")
        version = data.get("version") or None
        if mode == "release":
            if version is not None and not (
                isinstance(version, str) and releases.VERSION_RE.fullmatch(version)
            ):
                return notify_error("Invalid version.")
            if not server_ops.runner_installed():
                return notify_error("The maintenance runner is not installed.")
            # the runner reads release.json right after request, so it is first
            server_ops.write_release_request(version)
        else:
            # a stale release.json would turn this git update into a release install
            server_ops.drop_release_request()
        try:
            server_ops.request_action("update")
        except server_ops.MaintError as e:
            if mode == "release":
                server_ops.drop_release_request()
            return notify_error(str(e))
        what = (
            f"a release update to {version or 'the latest release'}"
            if mode == "release"
            else "a server update"
        )
        _audit(
            request,
            AuditActionType.EXEC_COMMAND,
            f"{request.user.username} started {what} from the dashboard "
            f"(installed {settings.ULRMM_VERSION})",
        )
        return Response("The update has started.")


class ServerUpdateSources(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request):
        refresh = request.query_params.get("refresh") == "1"
        return Response(releases.sources_status(refresh))


REPO_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
# printable ASCII without spaces, it goes into an Authorization header
TOKEN_RE = re.compile(r"[\x21-\x7e]*")


class ReleaseRepoSerializer(serializers.ModelSerializer):
    token = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=512
    )
    has_token = serializers.SerializerMethodField()
    kind = serializers.SerializerMethodField()
    api = serializers.SerializerMethodField()

    class Meta:
        model = ReleaseRepo
        fields = [
            "id",
            "name",
            "repo_url",
            "token",
            "has_token",
            "enabled",
            "position",
            "kind",
            "api",
        ]

    def get_has_token(self, obj) -> bool:
        return bool(obj.token)

    def _api(self, obj):
        try:
            return releases.repo_api(obj.repo_url)
        except ValueError:
            return None, None

    def get_kind(self, obj):
        return self._api(obj)[0]

    def get_api(self, obj):
        return self._api(obj)[1]

    def validate_name(self, value):
        if not REPO_NAME_RE.fullmatch(value):
            raise serializers.ValidationError(
                "Use lower-case letters, digits and dashes, at most 32."
            )
        configured = getattr(settings, "ULRMM_RELEASE_SOURCES", None)
        # "gitea" stays taken while the Gitea source is off for want of a token
        builtin = {
            s["name"]
            for s in (releases.DEFAULT_SOURCES if configured is None else configured)
        }
        # "git" is what the updater hook sees for a git update
        if value in builtin | {"git"}:
            raise serializers.ValidationError("A built-in source has this name.")
        if self.instance is not None and value != self.instance.name:
            raise serializers.ValidationError("The name cannot be changed.")
        return value

    def validate_repo_url(self, value):
        value = value.strip()
        try:
            releases.repo_api(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))
        return value

    def validate_token(self, value):
        value = value.strip()
        if not TOKEN_RE.fullmatch(value):
            raise serializers.ValidationError("The token has invalid characters.")
        return value

    def validate(self, attrs):
        if self.instance is None and ReleaseRepo.objects.count() >= releases.MAX_REPOS:
            raise serializers.ValidationError(
                f"At most {releases.MAX_REPOS} repositories."
            )
        # token stays with the API it was saved for
        old = self.instance
        if (
            old is not None
            and old.token
            and "repo_url" in attrs
            and "token" not in attrs
            and self._api(old) != releases.repo_api(attrs["repo_url"])
        ):
            raise serializers.ValidationError(
                {
                    "token": "Enter the token again for the new repository, "
                    "or remove it."
                }
            )
        return attrs


FIELD_LABELS = {"name": "Name", "repo_url": "Repository URL", "token": "Token"}


def _first_error(errors) -> str:
    """The first message of a DRF error dict with its field, for the toast."""
    field = None
    while isinstance(errors, (dict, list)) and errors:
        if isinstance(errors, dict):
            field, errors = next(iter(errors.items()))
        else:
            errors = errors[0]
    text = str(errors) or "Invalid input."
    label = FIELD_LABELS.get(field)
    return f"{label}: {text}" if label else text


def _audit_repo(request, action, verb: str, repo: ReleaseRepo) -> None:
    # log has_token, not the token
    AuditLog.objects.create(
        username=request.user.username,
        object_type=AuditObjType.CORE,
        action=action,
        message=f"{request.user.username} {verb} the release repository {repo.name}",
        after_value={
            "name": repo.name,
            "repo_url": repo.repo_url,
            "enabled": repo.enabled,
            "position": repo.position,
            "has_token": bool(repo.token),
        },
        debug_info={"ip": getattr(request, "_client_ip", "")},
    )


class ServerUpdateRepos(APIView):
    """Release repositories besides the built-in sources."""

    permission_classes = [ServerUpdatePerms]

    def get(self, request):
        return Response(
            ReleaseRepoSerializer(ReleaseRepo.objects.all(), many=True).data
        )

    def post(self, request):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        s = ReleaseRepoSerializer(data=request.data)
        if not s.is_valid():
            return notify_error(_first_error(s.errors))
        repo = s.save()
        releases.forget_status()
        _audit_repo(request, AuditActionType.ADD, "added", repo)
        return Response(ReleaseRepoSerializer(repo).data)


class ServerUpdateRepo(APIView):
    permission_classes = [ServerUpdatePerms]

    def put(self, request, pk):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        repo = get_object_or_404(ReleaseRepo, pk=pk)
        # a missing token keeps the stored one, an empty one removes it
        s = ReleaseRepoSerializer(repo, data=request.data, partial=True)
        if not s.is_valid():
            return notify_error(_first_error(s.errors))
        repo = s.save()
        releases.forget_status()
        _audit_repo(request, AuditActionType.MODIFY, "changed", repo)
        return Response(ReleaseRepoSerializer(repo).data)

    def delete(self, request, pk):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        repo = get_object_or_404(ReleaseRepo, pk=pk)
        _audit_repo(request, AuditActionType.DELETE, "removed", repo)
        repo.delete()
        releases.forget_status()
        return Response("The repository was removed.")


class ServerUpdateProgress(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request):
        data = server_ops.read_progress()
        data["state"] = server_ops.read_state("update")
        return Response(data)


class ServerTaskLog(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request, action):
        try:
            offset = int(request.query_params.get("offset", 0))
        except ValueError:
            offset = 0
        try:
            log = server_ops.read_log(action, offset)
        except server_ops.MaintError as e:
            return notify_error(str(e))
        return Response(
            {
                **log,
                "state": server_ops.read_state(action),
                "version": settings.ULRMM_VERSION,
            }
        )


class ServerBackups(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request):
        return Response(
            {
                "backups": server_ops.list_backups(),
                "settings": server_ops.read_backup_conf(),
                "runner_installed": server_ops.runner_installed(),
                "busy": server_ops.busy_with(),
                "state": server_ops.read_state("backup"),
                "disk": server_ops.disk_usage(),
                "can_download": True,
            }
        )

    def post(self, request):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        try:
            server_ops.request_action("backup")
        except server_ops.MaintError as e:
            return notify_error(str(e))
        _audit(
            request,
            AuditActionType.EXEC_COMMAND,
            f"{request.user.username} started a server backup from the dashboard",
        )
        return Response("The backup has started.")


class ServerBackupSettings(APIView):
    permission_classes = [ServerUpdatePerms]

    def put(self, request):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        try:
            conf = server_ops.validate_backup_conf(request.data)
        except server_ops.MaintError as e:
            return notify_error(str(e))
        # the runner applies the schedule; refuse before anything is written
        if busy := server_ops.busy_with():
            return notify_error(
                "Another maintenance task is queued."
                if busy == "queued"
                else f"A {busy} is running, try again when it has finished."
            )
        try:
            server_ops.write_backup_conf(conf)
            server_ops.request_action("schedule")
        except server_ops.MaintError as e:
            return notify_error(str(e))
        except OSError:
            return notify_error("The backup settings could not be written.")
        AuditLog.objects.create(
            username=request.user.username,
            object_type=AuditObjType.CORE,
            action=AuditActionType.MODIFY,
            message=f"{request.user.username} changed the server backup settings",
            after_value=conf,
            debug_info={"ip": getattr(request, "_client_ip", "")},
        )
        return Response(conf)


class ServerBackupFile(APIView):
    permission_classes = [ServerUpdatePerms]

    def get(self, request, kind, name):
        # a backup holds both databases and local_settings.py: role holders
        # and superusers only, with the step-up, and every download audited
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        try:
            path = server_ops.backup_path(kind, name)
        except server_ops.MaintError as e:
            return Response(str(e), status=404)
        _audit(
            request,
            AuditActionType.VIEW,
            f"{request.user.username} downloaded the server backup {kind}/{name}",
        )
        return FileResponse(
            path.open("rb"),
            as_attachment=True,
            filename=name,
            content_type="application/x-tar",
        )

    def delete(self, request, kind, name):
        if denied := stepup_denied(request, STEPUP_WHY):
            return denied
        try:
            server_ops.delete_backup(kind, name)
        except server_ops.MaintError as e:
            return Response(str(e), status=404)
        except OSError:
            return notify_error("The backup could not be deleted.")
        _audit(
            request,
            AuditActionType.DELETE,
            f"{request.user.username} deleted the server backup {kind}/{name}",
        )
        return Response("The backup was deleted.")

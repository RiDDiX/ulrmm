# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import os
import re
import subprocess
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import RunScriptPerms
from core.utils import clear_entire_cache
from logs.models import AuditLog
from ulrmm.constants import AuditObjType, ScriptShell, ScriptType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm
from ulrmm.utils import git_auth_env

from .models import Script, ScriptSnippet, check_env_vars, script_uses
from .permissions import ScriptsPerms, TestScriptPerms
from .serializers import (
    ScriptSerializer,
    ScriptSnippetSerializer,
    ScriptTableSerializer,
)

EXTENSIONS = {
    ScriptShell.POWERSHELL: ".ps1",
    ScriptShell.CMD: ".bat",
    ScriptShell.PYTHON: ".py",
    ScriptShell.SHELL: ".sh",
    ScriptShell.NUSHELL: ".nu",
    ScriptShell.DENO: ".ts",
}
GLOBAL_PLACEHOLDER = re.compile(r"\{\{\s*global\.")
UNSAFE_FILENAME = re.compile(r"[\\/\x00-\x1f\x7f]")
# transports git may use for the library; ext:: and fd:: run commands
GIT_PROTOCOLS = "file:git:http:https:ssh"


def _reveal(request) -> dict:
    return {"reveal_env_vars": _has_perm(request, "can_manage_scripts")}


class GetAddScripts(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    def get(self, request):
        community = request.query_params.get("showCommunityScripts", True)
        hidden = request.query_params.get("showHiddenScripts", False)

        scripts = Script.objects.all()
        if not community or community == "false":
            scripts = scripts.filter(script_type=ScriptType.USER_DEFINED)
        if hidden != "true":
            scripts = scripts.filter(hidden=False)
        scripts = scripts.order_by("category", "pk")

        return Response(
            ScriptTableSerializer(scripts, many=True, context=_reveal(request)).data
        )

    def post(self, request):
        serializer = ScriptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        script = serializer.save()
        return Response(f"{script.name} was added!")


class GetUpdateDeleteScript(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    def get(self, request, pk):
        script = get_object_or_404(Script, pk=pk)
        return Response(ScriptSerializer(script, context=_reveal(request)).data)

    def put(self, request, pk):
        script = get_object_or_404(Script, pk=pk)
        data = request.data

        if script.script_type == ScriptType.BUILT_IN:
            # library scripts only take the two per-row toggles
            data = {k: data[k] for k in ("favorite", "hidden") if k in data}
            if not data:
                return notify_error("Community scripts cannot be edited.")

        serializer = ScriptSerializer(instance=script, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        script = serializer.save()

        # policy checks are cached per site with the script inlined
        if script.script.filter(policy__isnull=False).exists():
            clear_entire_cache()

        return Response(f"{script.name} was edited!")

    def delete(self, request, pk):
        script = get_object_or_404(Script, pk=pk)

        if script.script_type == ScriptType.BUILT_IN:
            return notify_error("Community scripts cannot be deleted")

        # deleting would take the checks with it and leave tasks pointing nowhere
        checks, tasks, templates = script_uses().get(script.pk, [0, 0, 0])
        if checks or tasks or templates:
            return notify_error(
                f"{script.name} is used by {checks} checks, {tasks} tasks and "
                f"{templates} alert templates. Remove it there first."
            )

        script.delete()
        return Response(f"{script.name} was deleted!")


def _save_snippet(data, snippet=None):
    if snippet is None:
        serializer = ScriptSnippetSerializer(data=data)
    else:
        serializer = ScriptSnippetSerializer(instance=snippet, data=data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response("Snippet saved.")


class GetAddScriptSnippets(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    def get(self, request):
        data = ScriptSnippetSerializer(
            ScriptSnippet.objects.order_by("pk"), many=True
        ).data
        return Response(data)

    def post(self, request):
        return _save_snippet(request.data)


class GetUpdateDeleteScriptSnippet(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    def get(self, request, pk):
        return Response(
            ScriptSnippetSerializer(get_object_or_404(ScriptSnippet, pk=pk)).data
        )

    def put(self, request, pk):
        return _save_snippet(request.data, get_object_or_404(ScriptSnippet, pk=pk))

    def delete(self, request, pk):
        snippet = get_object_or_404(ScriptSnippet, pk=pk)
        snippet.delete()
        return Response("Snippet removed")


def _text_list():
    return serializers.ListField(
        child=serializers.CharField(
            max_length=4096, allow_blank=True, trim_whitespace=False
        ),
        max_length=100,
    )


class _TestScriptInput(serializers.Serializer):
    code = serializers.CharField(
        max_length=1024 * 1024, allow_blank=True, trim_whitespace=False
    )
    timeout = serializers.IntegerField(min_value=1, max_value=7200)
    args = _text_list()
    shell = serializers.ChoiceField(choices=ScriptShell.choices)
    run_as_user = serializers.BooleanField()
    env_vars = _text_list()


class TestScript(APIView):
    permission_classes = [IsAuthenticated, RunScriptPerms, TestScriptPerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        data = _TestScriptInput(data=request.data)
        data.is_valid(raise_exception=True)
        data = data.validated_data
        check_env_vars(data["env_vars"])

        # the agent echoes key store values back, so they need the key store right
        if any(
            GLOBAL_PLACEHOLDER.search(v) for v in data["args"] + data["env_vars"]
        ) and not _has_perm(request, "can_view_global_keystore"):
            raise PermissionDenied("Key store values need the key store permission.")

        shell = data["shell"]
        nats_data = {
            "func": "runscriptfull",
            "timeout": data["timeout"],
            "script_args": Script.parse_script_args(agent, shell, data["args"]),
            "payload": {
                "code": Script.replace_with_snippets(data["code"]),
                "shell": shell,
            },
            "run_as_user": data["run_as_user"],
            "env_vars": Script.parse_script_env_vars(agent, shell, data["env_vars"]),
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }

        reply = asyncio.run(
            agent.nats_cmd(nats_data, timeout=data["timeout"], wait=True)
        )

        AuditLog.audit_test_script_run(
            username=request.user.username,
            agent=agent,
            # resolved placeholders stay out of the audit row
            before_value={**nats_data, "script_args": data["args"]},
            after_value=reply,
            debug_info={"ip": request._client_ip},
        )
        if reply in ("timeout", "natsdown"):
            return notify_error("Unable to contact the agent")
        return Response(reply)


@api_view(["GET"])
@permission_classes([IsAuthenticated, ScriptsPerms])
def download(request, pk):
    script = get_object_or_404(Script, pk=pk)
    expand = request.query_params.get("with_snippets", True)
    expand = bool(expand) and expand != "false"

    name = UNSAFE_FILENAME.sub("", script.name)
    return Response(
        {
            "filename": f"{name}{EXTENSIONS.get(script.shell, '')}",
            "code": script.code if expand else script.code_no_snippets,
        }
    )


LIBRARY_SYNC_LOCK = "community_scripts_sync"


class LibrarySyncError(Exception):
    pass


def _library_url() -> str:
    # same default as update.sh: ulrmm-scripts.git next to the server repo
    url = getattr(settings, "ULRMM_SCRIPTS_GIT_URL", "")
    if not url and (base := getattr(settings, "ULRMM_GIT_URL", "")):
        url = f"{base.rsplit('/', 1)[0]}/ulrmm-scripts.git"
    return url


def _scrub(text: str) -> str:
    if token := getattr(settings, "ULRMM_GIT_TOKEN", ""):
        text = text.replace(token, "***")
    return re.sub(r"(://)[^/@\s]*@", r"\1***@", text).strip()[:500]


def _git(step: str, root: Path, *args: str, env=None, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ["git", "-c", "credential.helper=", "-c", "protocol.ext.allow=never"]
            + ["-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={
                **(env or os.environ),
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ALLOW_PROTOCOL": GIT_PROTOCOLS,
            },
        )
    except subprocess.TimeoutExpired:
        raise LibrarySyncError(f"{step} timed out after {timeout} s")
    except OSError as e:
        raise LibrarySyncError(f"{step} failed: {e}")
    if r.returncode != 0:
        raise LibrarySyncError(
            f"{step} failed: {_scrub(r.stderr) or f'exit code {r.returncode}'}"
        )
    return r.stdout.strip()


def sync_library() -> tuple[str, str]:
    """Check out main in SCRIPTS_DIR, returns (commit before, commit now)."""
    url = _library_url()
    if not url:
        raise LibrarySyncError(
            "no library configured, set ULRMM_SCRIPTS_GIT_URL or ULRMM_GIT_URL"
        )
    if re.match(r"https?://[^/]*@", url, re.I):
        raise LibrarySyncError(
            "the library url must not carry credentials, the token comes from "
            "ULRMM_GIT_TOKEN"
        )
    root = Path(settings.SCRIPTS_DIR)
    if not (root / ".git").is_dir():
        try:
            root.mkdir(parents=True, exist_ok=True)
            # the forced checkout below would wipe whatever lives there
            stray = any(root.iterdir())
        except OSError as e:
            raise LibrarySyncError(f"prepare failed: {e}")
        if stray:
            raise LibrarySyncError(
                f"prepare failed: {root} is not empty and not a git checkout "
                "of the library"
            )
        _git("prepare", root, "init", "-q")
    try:
        before = _git("prepare", root, "rev-parse", "-q", "--verify", "HEAD")
    except LibrarySyncError:
        before = ""
    # old clone: origin can point at another repo with a different history
    if "origin" in _git("set remote", root, "remote").split():
        _git("set remote", root, "remote", "set-url", "origin", url)
    else:
        _git("set remote", root, "remote", "add", "origin", url)
    with git_auth_env(url) as env:
        _git(
            "fetch",
            root,
            "fetch",
            "--quiet",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
            env=env,
            timeout=120,
        )
    commit = _git(
        "fetch",
        root,
        "rev-parse",
        "-q",
        "--verify",
        "refs/remotes/origin/main^{commit}",
    )
    _git("checkout", root, "checkout", "-q", "-f", "-B", "main", commit)
    _git("checkout", root, "reset", "-q", "--hard", commit)
    _git("checkout", root, "clean", "-q", "-df")
    return before, commit


class SyncCommunityScripts(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    def post(self, request):
        if not cache.add(LIBRARY_SYNC_LOCK, request.user.pk, 600):
            return notify_error("The script library is being synced already.")
        try:
            before, commit = sync_library()
            result = Script.load_community_scripts()
        except LibrarySyncError as e:
            return notify_error(f"Script library not synced, {e}")
        finally:
            cache.delete(LIBRARY_SYNC_LOCK)

        AuditLog.audit_object_changed(
            username=request.user.username,
            object_type=AuditObjType.SCRIPT,
            before={"commit": before},
            after={"commit": commit, **result},
            name="library",
            debug_info=get_debug_info(),
        )
        if "error" in result:
            return notify_error(
                f"Library at {commit[:7]} not loaded, nothing changed: "
                f"{result['error']}"
            )
        counts = ", ".join(
            f"{result[k]} {k}"
            for k in ("added", "updated", "removed", "retired", "skipped")
        )
        return Response(
            {
                "commit": commit,
                **result,
                "message": f"Library at {commit[:7]}: {counts}",
            }
        )

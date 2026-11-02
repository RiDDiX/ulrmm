# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from deploy import envelope
from logs.models import PendingAction
from packages import jobs
from packages.models import InstallState, PackageInstall
from software import sdio
from software.models import SdioJob
from ulrmm.auth import AgentTokenAuthentication
from ulrmm.constants import AGENT_DEFER, ULRMM_MAX_REQUEST_SIZE, PAAction, PAStatus
from ulrmm.helpers import notify_error

# tail of the install output kept on the pending action
MAX_OUTPUT = 2**20


def _choco_installed(output: str, name: str) -> bool:
    """Chocolatey prints one of these two sentences, matched word by word."""
    output = output.lower()
    fresh = ("install", "of", name, "was", "successful", "installed")
    present = (name, "already", "installed", "--force", "reinstall")
    return all(w in output for w in fresh) or all(w in output for w in present)


# winget exit codes that leave the package installed
WINGET_REBOOT = 0x8A150109
WINGET_INSTALLED = frozenset({0, 0x8A15002B, 0x8A150061, WINGET_REBOOT})


class _ResultV4(APIView):
    """The agent's answer to an open pending action of one kind, accepted once."""

    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsAuthenticated]
    kind = ""

    def patch(self, request, agentid, pk):
        try:
            too_large = int(request.META.get("CONTENT_LENGTH") or 0) > (
                ULRMM_MAX_REQUEST_SIZE
            )
        except ValueError:
            too_large = False
        if too_large:
            return notify_error("Request too large")

        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER), user=request.user, agent_id=agentid
        )
        action = get_object_or_404(PendingAction, agent=agent, pk=pk)
        if action.action_type != self.kind or action.status != PAStatus.PENDING:
            return notify_error("")

        data = request.data if hasattr(request.data, "get") else {}
        results = data.get("results")
        if not isinstance(results, str):
            return notify_error("results must be a string")
        details = action.details if isinstance(action.details, dict) else {}
        if error := self.finish(details, results, data):
            return error
        action.details = details
        action.status = PAStatus.COMPLETED
        action.save(update_fields=["details", "status"])
        return Response("ok")


class ChocoResultV4(_ResultV4):
    kind = PAAction.CHOCO_INSTALL

    def finish(self, details, results, data):
        name = details.get("name")
        name = name.lower() if isinstance(name, str) else ""
        details["output"] = results[-MAX_OUTPUT:]
        details["installed"] = _choco_installed(results, name)


class WingetResultV4(_ResultV4):
    kind = PAAction.WINGET_INSTALL

    def finish(self, details, results, data):
        code = data.get("exit_code")
        # uint32 from the agent, -1 when winget did not run or was killed
        if isinstance(code, bool) or not isinstance(code, int):
            return notify_error("exit_code must be an integer")
        if not -(2**31) <= code < 2**32:
            return notify_error("exit_code is out of range")
        details["output"] = results[-MAX_OUTPUT:]
        details["exit_code"] = code
        details["installed"] = code in WINGET_INSTALLED
        details["reboot"] = code == WINGET_REBOOT


SDIO_STATES = ("downloading", "installing", "done", "failed")
SDIO_RESULTS = ("ok", "reboot", "fail", "refused")
SDIO_OUTPUT = 64 << 10


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**53


def _sdio_result(r) -> dict | None:
    if not isinstance(r, dict) or r.get("result") not in SDIO_RESULTS:
        return None
    code = r.get("exit")
    if isinstance(code, bool) or not (code is None or isinstance(code, int)):
        return None
    out = {"result": r["result"], "exit": code}
    for k in ("pack", "sig", "signer", "msg"):
        out[k] = str(r.get(k) or "")[:500]
    return out


class SdioJobV4(APIView):
    """Plan and progress of an approved SDIO driver install on this agent."""

    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def _job(self, request, agentid, job):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER), user=request.user, agent_id=agentid
        )
        return get_object_or_404(SdioJob, agent=agent, pk=job, state__in=sdio.ACTIVE)

    def get(self, request, agentid, job):
        job = self._job(request, agentid, job)
        try:
            return Response(sdio.job_plan(job))
        except (sdio.SdioError, OSError) as e:
            job.state, job.detail = "failed", str(e)[:500]
            job.save(update_fields=["state", "detail", "updated"])
            return notify_error(job.detail)

    def patch(self, request, agentid, job):
        try:
            too_large = int(request.META.get("CONTENT_LENGTH") or 0) > (
                ULRMM_MAX_REQUEST_SIZE
            )
        except ValueError:
            too_large = False
        if too_large:
            return notify_error("Request too large")
        job = self._job(request, agentid, job)
        data = request.data if hasattr(request.data, "get") else {}
        state = data.get("state")
        if state not in SDIO_STATES:
            return notify_error("unknown state")
        fields = ["state", "detail", "updated"]
        job.state = state
        job.detail = str(data.get("detail") or "")[:500]
        done, total = data.get("done"), data.get("total")
        if state == "downloading" and _count(done) and _count(total) and done <= total:
            job.done, job.total = done, total
            fields += ["done", "total"]
        if state in ("done", "failed"):
            results = data.get("results")
            results = (
                [_sdio_result(r) for r in results] if isinstance(results, list) else []
            )
            job.results = [r for r in results if r][:50]
            job.output = str(data.get("output") or "")[-SDIO_OUTPUT:]
            fields += ["results", "output"]
            if state == "done" and any(
                r["result"] not in ("ok", "reboot") for r in job.results
            ):
                job.state = "failed"
        job.save(update_fields=fields)
        return Response("ok")


class PkgJobV4(APIView):
    """Plan and progress of a package install the agent runs itself."""

    authentication_classes = [AgentTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def _job(self, request, agentid, job):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER), user=request.user, agent_id=agentid
        )
        return get_object_or_404(
            PackageInstall.objects.select_related("package", "agent").defer(
                *(f"agent__{f}" for f in AGENT_DEFER)
            ),
            agent=agent,
            pk=job,
            state=InstallState.RUNNING,
            total_bytes__isnull=False,
            package__isnull=False,
        )

    def get(self, request, agentid, job):
        install = self._job(request, agentid, job)
        return envelope.seal_response(install.agent, request, jobs.plan(install))

    def patch(self, request, agentid, job):
        try:
            too_large = int(request.META.get("CONTENT_LENGTH") or 0) > (
                ULRMM_MAX_REQUEST_SIZE
            )
        except ValueError:
            too_large = False
        if too_large:
            return notify_error("Request too large")
        install = self._job(request, agentid, job)
        data = request.data if hasattr(request.data, "get") else {}
        if error := jobs.report(install, data):
            return notify_error(error)
        return Response("ok")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import uuid

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent, AgentHistory
from logs.models import AuditLog
from packages.views import _stepup_denied
from ulrmm.constants import (
    AGENT_DEFER,
    AgentHistoryType,
    AgentPlat,
    AuditObjType,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from winupdate.posix import (
    REMOVABLE_SOURCES,
    is_protected_remove_target,
    is_valid_remove_target,
    managed_reason,
)
from winupdate.tasks import posix_refresh_task, posix_uninstall_task

from . import catalog, installs, sdio, tasks, winget
from .drivers import STALE, boot_infs, removable
from .installs import CHOCO_NAME
from .models import (
    ChocoSoftware,
    InstalledDrivers,
    InstalledSoftware,
    SdioApproval,
    SdioCatalog,
    SdioIndex,
    WingetCatalog,
)
from .permissions import (
    CatalogInstallPerms,
    DriverPerms,
    SdioApprovalPerms,
    SoftwarePerms,
    UninstallSoftwarePerms,
)
from .serializers import InstalledSoftwareSerializer

CATALOG_SOURCES = ("all", "choco", "winget")
CATALOG_ROWS = 500
MAX_SEARCH = 100
# an empty winget catalog asks for a download at most this often
WINGET_RETRY = 60 * 60


@api_view(["GET"])
def chocos(request):
    latest = ChocoSoftware.objects.last()
    return Response(latest.chocos if latest else {})


def _chocos() -> list[tuple[str, str, str, str]]:
    latest = ChocoSoftware.objects.last()
    items = latest.chocos if latest and isinstance(latest.chocos, list) else []
    return [
        ("choco", c["name"], c["name"], "")
        for c in items
        if isinstance(c, dict) and isinstance(c.get("name"), str)
    ]


def _wingets() -> list[tuple[str, str, str, str]]:
    packages = WingetCatalog.objects.values_list("packages", flat=True).first()
    return [
        ("winget", *p)
        for p in (packages if isinstance(packages, list) else [])
        if isinstance(p, list) and len(p) == 3 and all(isinstance(v, str) for v in p)
    ]


def _rank(q: str, pid: str, name: str) -> int | None:
    """0 exact, 1 prefix, 2 substring of the id or the name, None no match."""
    pid, name = pid.casefold(), name.casefold()
    if not q or q in (pid, name):
        return 0
    if pid.startswith(q) or name.startswith(q):
        return 1
    if q in pid or q in name:
        return 2
    return None


@api_view(["GET"])
def software_catalog(request):
    """Chocolatey and winget packages for the install dialog."""
    source = request.query_params.get("source") or "all"
    search = request.query_params.get("search") or ""
    if source not in CATALOG_SOURCES:
        return notify_error("source must be all, choco or winget")
    if len(search) > MAX_SEARCH:
        return notify_error(f"Search for at most {MAX_SEARCH} characters.")

    wingets = _wingets()
    rows = (_chocos() if source != "winget" else []) + (
        wingets if source != "choco" else []
    )
    q = search.strip().casefold()
    found = []
    for row in rows:
        rank = _rank(q, row[1], row[2])
        if rank is not None:
            found.append((rank, row[2].casefold(), row[0], row))
    found.sort(key=lambda f: f[:3])

    if not wingets and cache.add("winget-catalog-queued", 1, WINGET_RETRY):
        tasks.refresh_winget_task.delay()
    meta = WingetCatalog.objects.filter(pk=1).values("checked", "updated", "error")
    return Response(
        {
            "rows": [
                {"source": r[0], "id": r[1], "name": r[2], "version": r[3]}
                for *_, r in found[:CATALOG_ROWS]
            ],
            "total": len(found),
            "truncated": len(found) > CATALOG_ROWS,
            "winget": {
                "count": len(wingets),
                **(meta.first() or {"checked": None, "updated": None, "error": ""}),
            },
        }
    )


def _save_inventory(agent, software: list) -> None:
    with transaction.atomic():
        rows = InstalledSoftware.objects.select_for_update().filter(agent=agent)
        keep = rows.order_by("-pk").first()
        if keep is None:
            InstalledSoftware.objects.update_or_create(
                agent=agent, defaults={"software": software}
            )
            return
        keep.software = software
        keep.save(update_fields=["software"])
        rows.exclude(pk=keep.pk).delete()


class GetSoftware(APIView):
    permission_classes = [IsAuthenticated, SoftwarePerms]

    def get(self, request, agent_id=None):
        if not agent_id:
            visible = InstalledSoftware.objects.filter_by_role(request.user)
            return Response(
                InstalledSoftwareSerializer(visible.order_by("pk"), many=True).data
            )

        latest = InstalledSoftware.latest_for(
            get_object_or_404(Agent, agent_id=agent_id)
        )
        if latest is None:
            return Response([])
        return Response(InstalledSoftwareSerializer(latest).data)

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            return notify_error(f"Not available for {agent.plat}")

        source = request.data.get("source", "choco")
        if source == "winget":
            return self._winget(request, agent)
        if source != "choco":
            return notify_error("source must be choco or winget")

        name = request.data.get("name")
        if not isinstance(name, str) or not CHOCO_NAME.fullmatch(name):
            return notify_error("name must be a chocolatey package id")
        try:
            installs.start_choco(
                agent, name, request.user.username, {"ip": request._client_ip}
            )
        except installs.InstallError as e:
            return notify_error(str(e))

        return Response(
            f"{name} will be installed shortly on {agent.hostname}. "
            "Check the Pending Actions menu to see the status/output"
        )

    def _winget(self, request, agent):
        name = request.data.get("name")
        if not isinstance(name, str) or not winget.ID_RE.fullmatch(name):
            return notify_error("name must be a winget package id")
        try:
            action = installs.start_winget(
                agent, name, request.user.username, {"ip": request._client_ip}
            )
        except installs.InstallError as e:
            return notify_error(str(e))
        title = action.details["name"]

        return Response(
            f"{title} will be installed shortly on {agent.hostname}. "
            "Check the Pending Actions menu to see the status/output"
        )

    def put(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            posix_refresh_task.delay(agent.pk, "inventory")
            return Response(
                f"A software inventory refresh was queued on {agent.hostname}"
            )

        reply = asyncio.run(agent.nats_cmd({"func": "softwarelist"}, timeout=15))
        # an error answer must not overwrite the last good inventory
        if not isinstance(reply, list) or not all(isinstance(i, dict) for i in reply):
            return notify_error("Unable to contact the agent")

        _save_inventory(agent, reply)
        return Response("ok")


class _WindowsUninstall(serializers.Serializer):
    name = serializers.CharField(max_length=255, trim_whitespace=False)
    command = serializers.CharField(max_length=8192, trim_whitespace=False)
    timeout = serializers.IntegerField(min_value=1, max_value=86400)
    run_as_user = serializers.BooleanField()


class UninstallSoftware(APIView):
    permission_classes = [IsAuthenticated, UninstallSoftwarePerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if reason := managed_reason(agent):
            return notify_error(reason)
        if agent.is_posix:
            name = request.data.get("name")
            source = request.data.get("source")
            location = request.data.get("location")
            if not isinstance(name, str) or not isinstance(source, str):
                return notify_error("name and source must be strings")
            if source not in REMOVABLE_SOURCES.get(agent.plat, ()):
                return notify_error(
                    f"Source {source} cannot be removed on {agent.plat}"
                )
            if source == "app":
                # apps of the same name exist in several places, name and
                # location together pick the row
                if not isinstance(location, str):
                    return notify_error("location is required to uninstall an app")
            elif not is_valid_remove_target(source, name, agent.plat):
                return notify_error("Invalid software name")
            if not agent.is_online:
                return notify_error("The agent must be online to uninstall software")

            inventory = InstalledSoftware.latest_for(agent)
            row = next(
                (
                    item
                    for item in (inventory.software if inventory else [])
                    if isinstance(item, dict)
                    and item.get("source") == source
                    and item.get("name") == name
                    and (source != "app" or item.get("location") == location)
                ),
                None,
            )
            if row is None:
                return notify_error("Software was not found in the agent inventory")

            target = row.get("location") if source == "app" else row.get("name")
            if not is_valid_remove_target(source, target, agent.plat):
                return notify_error("The stored software target is invalid")
            if source != "app" and is_protected_remove_target(target):
                return notify_error("This protected system package cannot be removed")

            command = f"posix_packages.sh remove {source} {target}"
            AuditLog.audit_script_run(
                username=request.user.username,
                script=command,
                agent=agent,
                debug_info={"ip": request._client_ip},
            )
            posix_uninstall_task.delay(agent.pk, source, target, request.user.username)
            return Response(
                f"{name} will be uninstalled on {agent.hostname}. The software list refreshes when it is done."
            )

        data = _WindowsUninstall(data=request.data)
        data.is_valid(raise_exception=True)
        data = data.validated_data
        name, uninstall_cmd = data["name"], data["command"]

        from ulrmm.agent_ident import UnknownAgentIdentity, agent_ident_for

        try:
            guard = agent_ident_for(agent)["identWinProgDir"].lower()
        except UnknownAgentIdentity as e:
            return notify_error(str(e))
        if all(i in uninstall_cmd.lower() for i in (guard, "unins")):
            return notify_error(
                "The UniversalLocal RMM Agent cannot be uninstalled from here."
            )

        user = request.user.username
        hist = AgentHistory(
            agent=agent, type=AgentHistoryType.CMD_RUN, username=user[:50]
        )
        hist.command = uninstall_cmd
        hist.save()
        dbg = {"ip": request._client_ip}
        AuditLog.audit_raw_command(
            username=user, agent=agent, cmd=uninstall_cmd, shell="cmd", debug_info=dbg
        )
        nats_data = dict(func="rawcmd", id=hist.pk, timeout=data["timeout"])
        nats_data["payload"] = {"command": uninstall_cmd, "shell": "cmd"}
        nats_data["run_as_user"] = data["run_as_user"]
        asyncio.run(agent.nats_cmd(nats_data, wait=False))
        return Response(f"{name} will now be uninstalled on {agent.hostname}.")


class Drivers(APIView):
    permission_classes = [IsAuthenticated, DriverPerms]

    def get(self, request, agent_id):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        row = InstalledDrivers.objects.filter(agent=agent).first()
        if row is None:
            return Response({"detail": "no inventory"}, status=404)
        data = row.data if isinstance(row.data, dict) else {}
        drivers = [d for d in data.get("drivers") or [] if isinstance(d, dict)]
        blocked = boot_infs(drivers)
        found = catalog.catalog_fields(agent, drivers)
        packs = sdio.driver_fields(agent, drivers)
        index = SdioIndex.load()
        return Response(
            {
                "received": row.received,
                "stale": djangotime.now() - row.received > STALE,
                "drivers": [
                    {**d, "removable": removable(d.get("inf", ""), blocked), **c, **p}
                    for d, c, p in zip(drivers, found, packs)
                ],
                "problems": data.get("problems") or [],
                "errors": data.get("errors") or [],
                "sdio_index": {"updated": index.updated, "error": index.error},
            }
        )


class RefreshDrivers(APIView):
    permission_classes = [IsAuthenticated, DriverPerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        if agent.plat != AgentPlat.WINDOWS:
            return notify_error("Driver inventory is only available on Windows")
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline")
        asyncio.run(agent.nats_cmd({"func": "drivers"}, wait=False))
        return Response(f"{agent.hostname} will send its driver list shortly")


def _windows_inventory(agent):
    """(InstalledDrivers, None) or (None, error response)."""
    if agent.plat != AgentPlat.WINDOWS:
        return None, notify_error("The driver catalog is only available on Windows")
    row = InstalledDrivers.objects.filter(agent=agent).first()
    if row is None:
        return None, notify_error(f"{agent.hostname} has not sent its drivers yet")
    return row, None


class CheckDriverCatalog(APIView):
    """Searches the catalog for this agent's drivers now. Only public data is
    fetched, so the list permission is enough."""

    permission_classes = [IsAuthenticated, DriverPerms]

    def get(self, request, agent_id):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        return Response({"progress": cache.get(tasks.check_progress_key(agent.pk))})

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        row, error = _windows_inventory(agent)
        if error:
            return error
        keys = {k for ks in catalog.inventory_keys(row.data) for k in ks}
        if not keys:
            return notify_error("No device of this agent can be looked up")
        if cache.get(tasks.SCAN_LOCK):
            return notify_error(
                "A catalog check is running, try again in a few minutes"
            )
        tasks.check_agent_catalog_task.delay(agent.pk)
        return Response(
            {
                "detail": f"Checking {len(keys)} hardware ids of {agent.hostname} "
                "in the Microsoft Update Catalog",
                "keys": len(keys),
                "seconds": min(len(keys) * 3, 600),
            }
        )


class InstallCatalogDriver(APIView):
    """Downloads a catalog cab to the server and installs it as a driver package."""

    permission_classes = [IsAuthenticated, CatalogInstallPerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        row, error = _windows_inventory(agent)
        if error:
            return error
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline")
        device_id = request.data.get("device_id")
        update_id = request.data.get("update_id")
        if not isinstance(update_id, str) or not catalog.UUID_RE.fullmatch(update_id):
            return notify_error("update_id is not a catalog update id")
        drivers = row.data.get("drivers") if isinstance(row.data, dict) else None
        driver = next(
            (
                d
                for d in (drivers if isinstance(drivers, list) else [])
                if isinstance(d, dict)
                and isinstance(device_id, str)
                and d.get("device_id") == device_id
            ),
            None,
        )
        if driver is None:
            return notify_error("This device is not in the driver inventory")
        offered = catalog.catalog_fields(agent, [driver])[0]["catalog"]
        if not offered or offered["update_id"] != update_id:
            return notify_error("The catalog does not offer this update for the device")

        job = uuid.uuid4().hex
        if not cache.add(tasks.agent_job_key(agent.agent_id), job, tasks.JOB_TTL):
            return notify_error(
                f"A catalog driver is being installed on {agent.hostname} already"
            )
        tasks.set_job(
            job,
            agent=agent.agent_id,
            state="resolving",
            detail="",
            batch=None,
            package=None,
        )
        try:
            tasks.catalog_install_task.delay(
                job, agent.pk, device_id, update_id, request.user.pk
            )
        except Exception:
            cache.delete(tasks.agent_job_key(agent.agent_id))
            raise
        return Response({"job": job})


class CatalogJob(APIView):
    permission_classes = [IsAuthenticated, CatalogInstallPerms]

    def get(self, request, agent_id, job):
        data = cache.get(tasks.job_key(job))
        if not isinstance(data, dict) or data.get("agent") != agent_id:
            return Response({"detail": "This job has expired"}, status=404)
        return Response(
            {k: data.get(k) for k in ("state", "detail", "batch", "package")}
        )


def _approval_row(a: SdioApproval, devices: int) -> dict:
    return {
        "id": a.pk,
        "hwid": a.hwid,
        "version": a.version,
        "desc": a.desc,
        "provider": a.provider,
        "date": a.date,
        "created_by": a.created_by,
        "created": a.created,
        "devices": devices,
    }


def _approval_devices(user, approvals) -> dict[int, int]:
    """Agents in the user's scope with a device that is offered the version."""
    wanted = {(a.hwid.upper(), a.version): a.pk for a in approvals}
    counts = dict.fromkeys(wanted.values(), 0)
    if not wanted:
        return counts
    rows = InstalledDrivers.objects.filter(
        agent__plat=AgentPlat.WINDOWS,
        agent__in=Agent.objects.filter_by_role(user),
    ).select_related("agent")
    for row in rows.iterator(chunk_size=100):
        drivers = sdio._drivers(row.data)
        cached = sdio.cached_for(drivers)
        os_ = sdio.os_info(row.agent)
        hit = set()
        for d in drivers:
            for e in sdio.offers(row.agent, d, cached, os_):
                if (
                    pk := wanted.get((e["hwid"].upper(), e.get("version")))
                ) is not None:
                    hit.add(pk)
        for pk in hit:
            counts[pk] += 1
    return counts


class SdioApprovals(APIView):
    permission_classes = [IsAuthenticated, SdioApprovalPerms]

    def get(self, request):
        index = SdioIndex.load()
        approvals = list(SdioApproval.objects.order_by("-created"))
        devices = _approval_devices(request.user, approvals)
        return Response(
            {
                "index": {
                    "updated": index.updated,
                    "torrent_time": index.torrent_time,
                    "error": index.error,
                    "files": index.files,
                    "http_packs": len(index.http_packs),
                },
                "approvals": [_approval_row(a, devices[a.pk]) for a in approvals],
            }
        )

    def post(self, request):
        if denied := _stepup_denied(request, "Approving drivers for all devices"):
            return denied
        hwid, version = request.data.get("hwid"), request.data.get("version")
        if not isinstance(hwid, str) or not isinstance(version, str):
            return notify_error("hwid and version are required")
        hwid = hwid.upper()
        row = SdioCatalog.objects.filter(hwid=hwid).first()
        same = [
            e
            for e in (row.entries if row else [])
            if isinstance(e, dict) and e.get("version") == version
        ]
        if not same:
            return notify_error(
                "No SDIO pack has this driver version for the hardware id"
            )
        http = set(SdioIndex.load().http_packs)
        entry = next((e for e in same if e.get("pack") in http), None)
        if entry is None:
            return notify_error(
                f"{same[0].get('pack')} is only in the BitTorrent swarm, "
                "the agent cannot download it"
            )
        try:
            with transaction.atomic():
                approval = SdioApproval.objects.create(
                    hwid=hwid,
                    version=version,
                    desc=str(entry.get("desc") or "")[:255],
                    provider=str(entry.get("provider") or "")[:128],
                    date=str(entry.get("date") or "")[:10],
                    created_by=request.user.username,
                )
        except IntegrityError:
            return Response({"detail": "This driver is approved already"}, status=409)
        AuditLog.audit_object_add(
            request.user.username,
            AuditObjType.SOFTWARE_PACKAGE,
            {"sdio_approval": _approval_row(approval, 0)},
            name=f"SDIO driver {approval.desc} {version} for {hwid}",
            debug_info=get_debug_info(),
        )
        tasks.apply_sdio_task.delay()
        return Response(_approval_row(approval, 0), status=201)


class SdioApprovalDetail(APIView):
    permission_classes = [IsAuthenticated, SdioApprovalPerms]

    def delete(self, request, pk):
        if denied := _stepup_denied(request, "Changing driver approvals"):
            return denied
        approval = get_object_or_404(SdioApproval, pk=pk)
        before = _approval_row(approval, 0)
        approval.delete()
        AuditLog.audit_object_delete(
            request.user.username,
            AuditObjType.SOFTWARE_PACKAGE,
            {"sdio_approval": before},
            name=f"SDIO driver {before['desc']} {before['version']} for {before['hwid']}",
            debug_info=get_debug_info(),
        )
        return Response("The approval was removed")


@api_view(["GET"])
@permission_classes([IsAuthenticated, SdioApprovalPerms])
def sdio_offers(request):
    """Newer pack drivers of the devices in the user's scope."""
    return Response(
        {"offers": sdio.fleet_offers(Agent.objects.filter_by_role(request.user))}
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated, SdioApprovalPerms])
def sdio_progress(request):
    """Phase and counts of a running index refresh, null when none runs."""
    return Response({"progress": sdio.get_progress()})


class RefreshSdio(APIView):
    permission_classes = [IsAuthenticated, SdioApprovalPerms]

    def post(self, request):
        if cache.get(tasks.SDIO_LOCK):
            return Response(
                {"detail": "The SDIO index is being refreshed already"}, status=409
            )
        tasks.refresh_sdio_task.delay()
        return Response("The SDIO index is refreshed in the background")

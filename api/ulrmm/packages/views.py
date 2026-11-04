# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import fcntl
import hashlib
import json
import os
import re
import shutil
import uuid
from contextlib import suppress

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from core.utils import stepup_denied
from logs.models import AuditLog, DebugLog
from software.drivers import OEM_INF_RE, boot_infs
from software.models import InstalledDrivers
from ulrmm.constants import (
    AGENT_DEFER,
    AgentPlat,
    AuditActionType,
    DebugLogType,
)
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info
from ulrmm.permissions import _has_perm_on_agent

from .models import (
    ARCHIVE_PLATS,
    OPEN_STATES,
    PLATS,
    InstallState,
    PackageInstall,
    PackageKind,
    SoftwarePackage,
)
from .permissions import InstallPackagePerms, PackagePerms
from .serializers import PackageInstallSerializer, SoftwarePackageSerializer
from .services import start_installs
from .utils import (
    CHUNK_SIZE,
    HEAD_SIZE,
    REMOVE_DRIVER_TIMEOUT,
    SHA256_RE,
    TOKEN_RE,
    UPLOAD_HEADROOM,
    IncomingUpload,
    archive_type,
    clean_filename,
    download_key,
    expire_stale,
    load_upload,
    magic_ok,
    packages_dir,
    parse_result,
    remove_driver_payload,
    remove_stale_uploads,
    remove_upload,
    upload_paths,
)

MAX_INSTALLS = 200
_RANGE_RE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")


def _duplicate(sha256: str) -> Response | None:
    if dup := SoftwarePackage.objects.filter(sha256=sha256).first():
        return notify_error(f"This file is uploaded already, as {dup.name}.")
    return None


# args and the unsigned flag decide what runs as SYSTEM
STEPUP = (
    "Uploading and editing packages needs the same 60 minute step-up as "
    "terminal and files."
)


def _gib(size: int) -> str:
    return f"{size / (1 << 30):.1f} GiB"


def create_package(request, *, original: str, path: str, size: int, head, sha256):
    """The package row for an uploaded file at path, moved to its sha256 name.
    Archives take kind and plat from the request, other kinds from the name."""
    data = request.data
    try:
        filename, kind = clean_filename(original)
    except ValueError as e:
        return notify_error(str(e))
    wanted = data.get("kind") or kind
    if wanted == PackageKind.ARCHIVE and archive_type(filename):
        kind = PackageKind.ARCHIVE
    elif wanted != kind:
        return notify_error(f"{filename} cannot be uploaded as {wanted}.")
    plat = PLATS.get(kind) or data.get("plat")
    if kind == PackageKind.ARCHIVE and plat not in ARCHIVE_PLATS:
        return notify_error("Choose the platform the archive installs on.")
    if not size:
        return notify_error(f"{filename} is empty.")
    if not magic_ok(kind, head, filename):
        return notify_error(f"{filename} is not a valid {kind} file.")
    if dup := _duplicate(sha256):
        return dup

    serializer = SoftwarePackageSerializer(
        data=data, context={"kind": kind, "plat": plat}
    )
    serializer.is_valid(raise_exception=True)
    try:
        with transaction.atomic():
            package = serializer.save(
                filename=filename, kind=kind, plat=plat, sha256=sha256, size=size
            )
            os.replace(path, package.file_path)
    except IntegrityError:
        # a concurrent upload of the same file or name got there first
        return _duplicate(sha256) or notify_error(
            f"A package named {serializer.validated_data['name']} exists already."
        )
    return Response(SoftwarePackageSerializer(package).data)


class GetAddPackages(APIView):
    permission_classes = [IsAuthenticated, PackagePerms]

    def get(self, request):
        packages = SoftwarePackage.objects.order_by("name")
        data = SoftwarePackageSerializer(packages, many=True).data
        # after a restore without the large files
        for row, package in zip(data, packages):
            row["file_missing"] = not os.path.isfile(package.file_path)
        return Response(data)

    def post(self, request):
        if denied := stepup_denied(request, STEPUP):
            return denied
        # set before request.data is read, or the body never hits this handler
        incoming = IncomingUpload(request)
        request._request.upload_handlers = [incoming]
        try:
            return self._add(request, incoming)
        finally:
            incoming.cleanup()

    def _add(self, request, incoming: IncomingUpload):
        # parsing the body is what streams the file into incoming
        request.data
        if not incoming.done:
            return notify_error("Choose a file to upload.")
        response = create_package(
            request,
            original=incoming.original,
            path=incoming.path,
            size=incoming.size,
            head=incoming.head,
            sha256=incoming.sha.hexdigest(),
        )
        if response.status_code == 200:
            incoming.path = ""
        return response


class Uploads(APIView):
    """Starts a chunked upload of any size, staged in PACKAGES_DIR/.uploads."""

    permission_classes = [IsAuthenticated, PackagePerms]

    def post(self, request):
        if denied := stepup_denied(request, STEPUP):
            return denied
        name, size = request.data.get("filename"), request.data.get("size")
        if not isinstance(name, str) or not name:
            return notify_error("Choose a file to upload.")
        try:
            filename, kind = clean_filename(name)
        except ValueError as e:
            return notify_error(str(e))
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            return notify_error("size must be the file size in bytes.")
        free = shutil.disk_usage(packages_dir()).free
        if free < size + UPLOAD_HEADROOM:
            return notify_error(
                f"Not enough free space for {filename}: it needs "
                f"{_gib(size + UPLOAD_HEADROOM)} with headroom, the server has "
                f"{_gib(free)} free."
            )
        remove_stale_uploads()
        uid = uuid.uuid4().hex
        part, meta = upload_paths(uid)
        with open(part, "xb"):
            pass
        # the finished file is served by nginx, whatever the umask
        os.chmod(part, 0o644)
        with open(meta, "x", encoding="utf-8") as fh:
            json.dump(
                {
                    "filename": filename,
                    "kind": kind,
                    "size": size,
                    "user": request.user.username,
                },
                fh,
            )
        return Response(
            {"id": uid, "chunk_size": CHUNK_SIZE, "received": 0}, status=201
        )


def append_chunk(request, info: dict, part: str, meta: str) -> Response:
    """Writes the Content-Range chunk of a staged upload at its offset."""
    m = _RANGE_RE.fullmatch(request.headers.get("Content-Range", ""))
    if not m:
        return notify_error("Send the chunk with Content-Range: bytes start-end/size.")
    start, end, total = (int(g) for g in m.groups())
    length = end - start + 1
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or -1)
    except ValueError:
        declared = -1
    if (
        total != info["size"]
        or end < start
        or end >= total
        or length > CHUNK_SIZE
        or declared != length
    ):
        return notify_error("The chunk does not fit this upload.")

    with open(part, "r+b") as fh:
        # one writer per upload, a second request gets the offset
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return Response({"received": info["received"]}, status=409)
        received = os.fstat(fh.fileno()).st_size
        if start != received:
            return Response({"received": received}, status=409)
        fh.seek(start)
        left = length
        try:
            while left:
                buf = request._request.read(min(left, 1 << 20))
                if not buf:
                    break
                fh.write(buf)
                left -= len(buf)
            fh.flush()
        except OSError as e:
            fh.truncate(start)
            return notify_error(f"Storing the chunk failed: {e.strerror}")
        if left:
            fh.truncate(start)
            return notify_error("The chunk was cut short, send it again.")
    os.utime(meta)
    return Response({"received": start + length})


def _own_upload(request, uid: str, root: str = "") -> dict:
    info = load_upload(uid, root)
    if not info or info.get("user") != request.user.username:
        raise Http404
    return info


class UploadDetail(APIView):
    """Status, the next chunk with Content-Range, or abort."""

    permission_classes = [IsAuthenticated, PackagePerms]

    def get(self, request, uid):
        info = _own_upload(request, uid)
        return Response(
            {
                "id": uid,
                "filename": info["filename"],
                "size": info["size"],
                "received": info["received"],
                "chunk_size": CHUNK_SIZE,
            }
        )

    def put(self, request, uid):
        return append_chunk(request, _own_upload(request, uid), *upload_paths(uid))

    def delete(self, request, uid):
        info = _own_upload(request, uid)
        remove_upload(uid)
        return Response(f"The upload of {info['filename']} was cancelled.")


class FinishUpload(APIView):
    """Checks the complete file and adds it to the catalog."""

    permission_classes = [IsAuthenticated, PackagePerms]

    def post(self, request, uid):
        info = _own_upload(request, uid)
        if denied := stepup_denied(request, STEPUP):
            return denied
        part, _ = upload_paths(uid)
        with open(part, "rb") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return notify_error("A chunk is still being stored, try again.")
            size = os.fstat(fh.fileno()).st_size
            if size != info["size"]:
                return notify_error(
                    f"The upload is not complete: {size} of {info['size']} bytes."
                )
            sha, head = hashlib.sha256(), fh.read(HEAD_SIZE)
            sha.update(head)
            while buf := fh.read(1 << 20):
                sha.update(buf)
            response = create_package(
                request,
                original=info["filename"],
                path=part,
                size=size,
                head=head,
                sha256=sha.hexdigest(),
            )
        if response.status_code == 200:
            remove_upload(uid)
        return response


class EditDeletePackage(APIView):
    permission_classes = [IsAuthenticated, PackagePerms]

    def put(self, request, pk):
        package = get_object_or_404(SoftwarePackage, pk=pk)
        if denied := stepup_denied(request, STEPUP):
            return denied
        serializer = SoftwarePackageSerializer(
            instance=package, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(SoftwarePackageSerializer(package).data)

    def delete(self, request, pk):
        package = get_object_or_404(SoftwarePackage, pk=pk)
        expire_stale()
        if package.installs.filter(state__in=OPEN_STATES).exists():
            return notify_error(
                f"{package.name} is being installed right now. "
                "Delete it once those installs are done."
            )
        path = package.file_path
        package.delete()
        with suppress(FileNotFoundError):
            os.unlink(path)
        return Response(f"{package.name} was deleted")


class InstallPackage(APIView):
    permission_classes = [IsAuthenticated, InstallPackagePerms]

    def post(self, request, pk):
        package = get_object_or_404(SoftwarePackage, pk=pk)
        agent_id = request.data.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            return notify_error("Choose an agent.")
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()
        if agent.plat != package.plat:
            return notify_error(
                f"{package.name} is a {package.get_plat_display()} package, "
                f"{agent.hostname} is not."
            )
        try:
            result = start_installs(
                request.user, package, [agent], request.data.get("run_as")
            )
        except ValueError as e:
            return notify_error(str(e))
        return Response(result)


class RemoveDriver(APIView):
    """pnputil /delete-driver for one oem*.inf of the agent's inventory."""

    permission_classes = [IsAuthenticated, InstallPackagePerms]

    def post(self, request):
        agent_id, inf = request.data.get("agent_id"), request.data.get("inf")
        if not isinstance(agent_id, str) or not agent_id:
            return notify_error("Choose an agent.")
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()
        if agent.plat != AgentPlat.WINDOWS:
            return notify_error("Drivers can only be removed on Windows.")
        if not isinstance(inf, str) or not OEM_INF_RE.fullmatch(inf):
            return notify_error(
                "Only third-party driver packages (oem<number>.inf) can be removed."
            )
        inf = inf.lower()
        inventory = InstalledDrivers.objects.filter(agent=agent).first()
        drivers = (inventory.data.get("drivers") or []) if inventory else []
        rows = [d for d in drivers if str(d.get("inf", "")).lower() == inf]
        if not rows:
            return notify_error(f"{inf} is not in the driver list of {agent.hostname}.")
        if inf in boot_infs(drivers):
            return notify_error(
                f"{inf} belongs to a device {agent.hostname} needs to boot, "
                "it cannot be removed from here."
            )
        if not agent.is_online:
            return notify_error(f"{agent.hostname} is offline.")

        # the same lock as package installs, pnputil and installers collide
        lock = f"pkg_install_{agent.agent_id}"
        if not cache.add(lock, f"driver {inf}", REMOVE_DRIVER_TIMEOUT + 60):
            return notify_error(
                f"A package install is running on {agent.hostname}, try again later."
            )
        try:
            out = asyncio.run(
                agent.nats_cmd(
                    remove_driver_payload(inf), timeout=REMOVE_DRIVER_TIMEOUT + 30
                )
            )
        finally:
            cache.delete(lock)
        state, fields = parse_result(out, REMOVE_DRIVER_TIMEOUT)

        username = request.user.username
        what = " ".join(s for s in (rows[0].get("provider"), rows[0].get("class")) if s)
        AuditLog._agent_entry(
            username,
            agent,
            get_debug_info(),
            action=AuditActionType.EXEC_COMMAND,
            message=f"{username} removes driver {inf} ({what}) from "
            f"{agent.hostname}: {state}",
            after_value={
                "inf": inf,
                "state": state,
                "exit_code": fields.get("exit_code"),
            },
        )
        message = f"driver {inf} removal on {agent.hostname}: {state}"
        if fields.get("detail"):
            message += f", {fields['detail']}"
        if state in (InstallState.SUCCEEDED, InstallState.REBOOT_REQUIRED):
            DebugLog.info(message, agent=agent, log_type=DebugLogType.SCRIPTING)
            # windows keeps listing a deleted driver until the next reboot
            with transaction.atomic():
                inv = (
                    InstalledDrivers.objects.select_for_update()
                    .filter(agent=agent)
                    .first()
                )
                if inv:
                    inv.data["drivers"] = [
                        d
                        for d in inv.data.get("drivers") or []
                        if str(d.get("inf", "")).lower() != inf
                    ]
                    inv.save(update_fields=["data"])
        else:
            DebugLog.warning(message, agent=agent, log_type=DebugLogType.SCRIPTING)

        asyncio.run(agent.nats_cmd({"func": "drivers"}, wait=False))
        return Response(
            {
                "state": state,
                "exit_code": fields.get("exit_code"),
                "detail": fields.get("detail", ""),
                "output": fields.get("output", ""),
            }
        )


class PackageInstalls(APIView):
    permission_classes = [IsAuthenticated, InstallPackagePerms]

    def get(self, request):
        expire_stale()
        installs = PackageInstall.objects.filter(
            agent__in=Agent.objects.filter_by_role(request.user)  # type: ignore
        )
        params = request.query_params
        if batch := params.get("batch"):
            try:
                installs = installs.filter(batch=uuid.UUID(batch))
            except ValueError:
                return notify_error("batch is not a valid id.")
        if agent := params.get("agent"):
            installs = installs.filter(agent__agent_id=agent)
        if package := params.get("package"):
            if not package.isdecimal():
                return notify_error("package is not a valid id.")
            installs = installs.filter(package_id=int(package))

        installs = (
            installs.select_related("agent")
            .defer(*(f"agent__{f}" for f in AGENT_DEFER))
            .order_by("-created", "-pk")
        )
        # a batch is bounded by the agents it went to, the history is not
        if not batch:
            installs = installs[:MAX_INSTALLS]
        return Response(PackageInstallSerializer(installs, many=True).data)


class DownloadPackage(APIView):
    """The agent script downloads the file with the PKG_URL token.
    Only while that install is running."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, token):
        pk = cache.get(download_key(token)) if TOKEN_RE.fullmatch(token) else None
        install = (
            PackageInstall.objects.select_related("package")
            .filter(pk=pk, state=InstallState.RUNNING, package__isnull=False)
            .first()
            if pk
            else None
        )
        if not install or not SHA256_RE.fullmatch(install.package.sha256):
            return HttpResponse(status=404)

        package = install.package
        if settings.DEBUG:
            response = FileResponse(
                open(package.file_path, "rb"), content_type="application/octet-stream"
            )
        else:
            response = HttpResponse(content_type="application/octet-stream")
            response["X-Accel-Redirect"] = f"/private/packages/{package.sha256}"
        response["Content-Disposition"] = f'attachment; filename="{package.filename}"'
        return response

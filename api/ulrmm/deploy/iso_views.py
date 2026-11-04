# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""ISO builder API: the base image library, a plan of what goes into an image,
a seed ISO built on the spot, and full builds as background jobs. Built
images land in the library as kind "built"; base images can also be uploaded
in chunks. Downloads are audited without any secret value.
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import uuid
from types import SimpleNamespace
from urllib.parse import quote, unquote, urlparse

from django.conf import settings
from django.core.cache import cache
from django.http import FileResponse, HttpResponse, StreamingHttpResponse
from django.utils.http import content_disposition_header
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import has_superuser_rights
from clients.permissions import DeploymentPerms
from core.utils import stepup_denied
from logs.models import AuditLog
from packages.utils import (
    CHUNK_SIZE,
    TOKEN_RE,
    UPLOAD_HEADROOM,
    remove_upload,
    upload_paths,
)
from packages.views import _gib, _own_upload, append_chunk
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm_on_site
from ulrmm.util_settings import get_backend_url

from . import checksums, iso, iso_layout, matrix, tasks
from .bundle import _safe
from .models import BaseIso
from .views import CHUNK, _body, _BuilderBase

JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_NAME = re.compile(r"[^A-Za-z0-9._-]+")
# what the job status shows; path and user stay on the server
_HIDDEN = ("path", "user")
_FIELDS = (
    "id name filename size sha256 label os bios efi udf status error "
    "source_url added kind built_by target expected_sha256"
).split()
LINK_TTL = 10 * 60


def render_for(user, data: dict):
    """(deployment, target_id, clean profile, files, family) for a render
    request without an HTTP request; raises ValueError when it fails."""
    request = SimpleNamespace(user=user, data=data)
    built = _BuilderBase()._build(request)
    if isinstance(built, Response):
        raise ValueError(str(built.data))
    deployment, _module, target_id, clean, files, _secrets = built
    return deployment, target_id, clean, files, _family(target_id)


def _family(target_id: str) -> str:
    tgt = next((t for t in matrix.all_targets() if t["id"] == target_id), {})
    return tgt.get("family", "linux")


def _row(row: BaseIso) -> dict:
    out = {f: getattr(row, f) for f in _FIELDS}
    out["added"] = row.added.isoformat()
    live = (BaseIso.Status.DOWNLOADING, BaseIso.Status.VERIFYING)
    out["progress"] = tasks.dl_progress(row.pk) if row.status in live else None
    return out


def _may_see(user, row: BaseIso) -> bool:
    # built images carry the admin password and enrollment token of their site
    if row.kind != BaseIso.Kind.BUILT:
        return True
    if row.deployment_id is None:
        return has_superuser_rights(user)
    return _has_perm_on_site(user, row.deployment.site_id)


def iso_name(deployment, target_id: str) -> str:
    parts = (target_id, deployment.site.client.name, deployment.site.name)
    return "-".join(_safe(p) for p in parts)


def _audit(request, what: str, deployment=None) -> None:
    message = f"{request.user.username} {what}"
    if deployment is not None:
        message += f" for a deployment on site {deployment.site.name}"
    AuditLog.objects.create(
        username=request.user.username,
        object_type=(
            AuditObjType.SITE if deployment is not None else AuditObjType.URL_ACTION
        ),
        action=AuditActionType.URL_ACTION,
        message=message,
        debug_info={"ip": getattr(request, "_client_ip", "")},
    )


def _taken(filename: str) -> bool:
    return BaseIso.objects.filter(filename=filename).exists() or os.path.exists(
        tasks.iso_path(filename)
    )


def _register(filename: str, **extra) -> BaseIso:
    return BaseIso.objects.create(
        name=os.path.splitext(filename)[0][:200], filename=filename, **extra
    )


def _bad_name(name):
    """The error text for a name that is no plain .iso file name, else None."""
    if not isinstance(name, str) or not name.lower().endswith(".iso"):
        return "The filename must end in .iso"
    if name != os.path.basename(name) or "\\" in name or name.startswith("."):
        return "The filename must be a plain name inside the ISO folder"
    root = os.path.realpath(settings.ISO_DIR)
    if os.path.dirname(os.path.realpath(tasks.iso_path(name))) != root:
        return "The filename must be a plain name inside the ISO folder"
    return None


def _known_file(name):
    """The error text for a filename that may not be registered, else None."""
    if err := _bad_name(name):
        return err
    if not os.path.isfile(os.path.realpath(tasks.iso_path(name))):
        return "The file does not exist"
    if BaseIso.objects.filter(filename=name).exists():
        return "The file is already registered"
    return None


def _url_filename(url: str) -> str:
    base = _NAME.sub("-", unquote(os.path.basename(urlparse(url).path))).strip("-.")
    if base.lower().endswith(".iso") and not _taken(base):
        return base
    n = BaseIso.objects.count() + 1
    while _taken(f"download-{n}.iso"):
        n += 1
    return f"download-{n}.iso"


class IsoLibrary(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def get(self, request):
        rows = BaseIso.objects.select_related("deployment").order_by("-added", "-id")
        return Response([_row(r) for r in rows if _may_see(request.user, r)])

    def post(self, request):
        data = _body(request)
        if "url" in data:
            url = data["url"]
            if not isinstance(url, str) or urlparse(url).scheme != "https":
                return notify_error("Only https URLs can be downloaded")
            try:
                host = tasks.url_host(url)
            except ValueError:
                host = None
            if not host:
                return notify_error("The URL has no usable host")
            St = BaseIso.Status
            old = BaseIso.objects.filter(source_url=url).order_by("-id")
            busy = old.filter(
                status__in=(St.DOWNLOADING, St.VERIFYING, St.INSPECTING, St.READY)
            ).first()
            if busy:
                return Response(_row(busy))
            sha = data.get("sha256")
            if sha in (None, ""):
                sha = ""
                if data.get("sha256_url"):
                    try:
                        sha = checksums.expected_sha256(url, data["sha256_url"])
                    except ValueError as e:
                        return notify_error(str(e))
            elif not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                return notify_error("The sha256 must be 64 hex characters")
            target = data.get("target")
            target = target if isinstance(target, str) and len(target) <= 32 else ""
            tasks.iso_dir()
            row = old.filter(status=St.ERROR).first()
            if row:
                row.status, row.error = St.DOWNLOADING, ""
            else:
                row = _register(
                    _url_filename(url), source_url=url, status=St.DOWNLOADING
                )
            row.expected_sha256 = sha.lower()
            if target:
                row.target = target
            row.save()
            tasks.download_base_iso.delay(row.pk)
            return Response(_row(row))
        name = data.get("filename")
        err = _known_file(name)
        if err:
            return notify_error(err)
        row = _register(name)
        tasks.inspect_base_iso.delay(row.pk)
        return Response(_row(row))


_PROGRESS = {
    "progressPercent": 0,
    "downloadedBytes": 0,
    "totalBytes": 0,
    "speedBytesPerSec": 0,
    "etaSeconds": None,
}


class IsoProgress(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def get(self, request):
        St = BaseIso.Status
        rows = BaseIso.objects.filter(
            status__in=(St.DOWNLOADING, St.VERIFYING, St.ERROR)
        ).order_by("-added", "-id")
        return Response(
            [
                {
                    **_PROGRESS,
                    "error": r.error,
                    **(tasks.dl_progress(r.pk) or {}),
                    "id": r.pk,
                    "status": r.status,
                    "filename": r.filename,
                    "target": r.target,
                    "source_url": r.source_url,
                }
                for r in rows
            ]
        )


class IsoCancel(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request, pk):
        row = BaseIso.objects.filter(pk=pk).first()
        if row is None or not _may_see(request.user, row):
            return Response("not found", status=404)
        if row.status != BaseIso.Status.DOWNLOADING:
            return notify_error("The image is not downloading")
        tasks.dl_cancel(pk)
        return Response(_row(row))


class IsoRetry(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request, pk):
        row = BaseIso.objects.filter(pk=pk).first()
        if row is None or not _may_see(request.user, row):
            return Response("not found", status=404)
        if row.status != BaseIso.Status.ERROR or not row.source_url:
            return notify_error("The image cannot be retried")
        row.status, row.error = BaseIso.Status.DOWNLOADING, ""
        row.save(update_fields=["status", "error"])
        tasks.download_base_iso.delay(pk)
        return Response(_row(row))


class IsoScan(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request):
        rows = []
        for name in sorted(os.listdir(tasks.iso_dir())):
            if _known_file(name) is None:
                row = _register(name)
                tasks.inspect_base_iso.delay(row.pk)
                rows.append(_row(row))
        return Response(rows)


class IsoVerify(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request, pk):
        row = BaseIso.objects.filter(pk=pk).first()
        if row is None or not _may_see(request.user, row):
            return Response("not found", status=404)
        row.status = BaseIso.Status.INSPECTING
        row.error = ""
        row.save(update_fields=["status", "error"])
        tasks.inspect_base_iso.delay(row.pk)
        return Response(_row(row))


def _drop(row: BaseIso) -> None:
    path = tasks.iso_path(row.filename)
    for p in (path, path + ".part"):
        if os.path.isfile(p):
            os.remove(p)
    row.delete()


class IsoDelete(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def delete(self, request, pk):
        row = BaseIso.objects.filter(pk=pk).first()
        if row is None or not _may_see(request.user, row):
            return Response("not found", status=404)
        _drop(row)
        return Response("ok")


def _ready_row(pk):
    row = BaseIso.objects.filter(pk=pk, status=BaseIso.Status.READY).first()
    if row is None or not os.path.isfile(tasks.iso_path(row.filename)):
        return None
    return row


def _link_key(token: str) -> str:
    return f"isodl:{hashlib.sha256(token.encode()).hexdigest()}"


class IsoLink(APIView):
    """A download link valid for 10 minutes, so the browser streams the file
    from nginx instead of holding it in memory."""

    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request, pk):
        row = _ready_row(pk)
        if row is None:
            return notify_error("The image is not ready")
        if not _may_see(request.user, row):
            return Response("not found", status=404)
        # built images carry answer files and enrollment tokens
        if row.kind == BaseIso.Kind.BUILT and (
            denied := stepup_denied(
                request,
                "Downloading built images needs the same 60 minute step-up as terminal and files.",
            )
        ):
            return denied
        token = secrets.token_urlsafe(32)
        cache.set(_link_key(token), row.pk, LINK_TTL)
        _audit(request, f"downloaded image {row.name}")
        base = get_backend_url(
            settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
        )
        return Response({"url": f"{base}/deploy/iso/download/{token}/"})


class IsoDownload(APIView):
    # the link token is the credential. It is not used up, a browser that
    # resumes a download sends a second request.
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, token):
        pk = cache.get(_link_key(token)) if TOKEN_RE.fullmatch(token) else None
        row = _ready_row(pk) if pk else None
        if row is None:
            return HttpResponse(status=404)
        if settings.DEBUG:
            resp = FileResponse(
                open(tasks.iso_path(row.filename), "rb"),
                content_type="application/x-iso9660-image",
            )
        else:
            resp = HttpResponse(content_type="application/x-iso9660-image")
            resp["X-Accel-Redirect"] = f"/private/iso/{quote(row.filename)}"
        resp["Content-Disposition"] = content_disposition_header(True, row.filename)
        resp["X-Sha256"] = row.sha256
        resp["Cache-Control"] = "no-store"
        return resp


class IsoUploads(APIView):
    """Starts a chunked base image upload, staged in ISO_DIR/.uploads."""

    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request):
        if denied := stepup_denied(
            request,
            "Uploading base images needs the same 60 minute step-up as terminal and files.",
        ):
            return denied
        name, size = request.data.get("filename"), request.data.get("size")
        if err := _bad_name(name):
            return notify_error(err)
        if _taken(name):
            return notify_error(f"An image named {name} exists already")
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            return notify_error("size must be the file size in bytes.")
        if size > tasks.MAX_DOWNLOAD:
            return notify_error("the file is larger than the 14 GiB limit")
        root = tasks.iso_uploads_dir()
        free = shutil.disk_usage(root).free
        if free < size + UPLOAD_HEADROOM:
            return notify_error(
                f"Not enough free space for {name}: it needs "
                f"{_gib(size + UPLOAD_HEADROOM)} with headroom, the server has "
                f"{_gib(free)} free."
            )
        uid = uuid.uuid4().hex
        part, meta = upload_paths(uid, root)
        with open(part, "xb"):
            pass
        with open(meta, "x", encoding="utf-8") as fh:
            json.dump(
                {"filename": name, "size": size, "user": request.user.username}, fh
            )
        return Response(
            {"id": uid, "chunk_size": CHUNK_SIZE, "received": 0}, status=201
        )


class IsoUploadDetail(APIView):
    """Status, the next chunk with Content-Range, or abort."""

    permission_classes = [IsAuthenticated, DeploymentPerms]

    def get(self, request, uid):
        info = _own_upload(request, uid, tasks.iso_uploads_dir())
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
        root = tasks.iso_uploads_dir()
        info = _own_upload(request, uid, root)
        return append_chunk(request, info, *upload_paths(uid, root))

    def delete(self, request, uid):
        root = tasks.iso_uploads_dir()
        info = _own_upload(request, uid, root)
        remove_upload(uid, root)
        return Response(f"The upload of {info['filename']} was cancelled.")


class IsoFinishUpload(APIView):
    """Moves the complete file into ISO_DIR and registers it as a base image."""

    permission_classes = [IsAuthenticated, DeploymentPerms]

    def post(self, request, uid):
        root = tasks.iso_uploads_dir()
        info = _own_upload(request, uid, root)
        if denied := stepup_denied(
            request,
            "Uploading base images needs the same 60 minute step-up as terminal and files.",
        ):
            return denied
        name = info["filename"]
        part, _ = upload_paths(uid, root)
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
            if _taken(name):
                return notify_error(f"An image named {name} exists already")
            dest = tasks.iso_path(name)
            os.replace(part, dest)
        os.chmod(dest, 0o644)
        remove_upload(uid, root)
        row = _register(name)
        tasks.inspect_base_iso.delay(row.pk)
        _audit(request, f"uploaded base image {name}")
        return Response(_row(row))


class _IsoRender(_BuilderBase):
    """The shared part of plan, seed and build: the rendered files, the agent
    and the base image row (None for a seed)."""

    def _layout(self, request, mode, base):
        built = self._build(request)
        if isinstance(built, Response):
            return built
        deployment, _module, target_id, _clean, files, _secrets = built
        try:
            agent = iso_layout.agent_payload(deployment, _family(target_id), target_id)
            if mode == "full":
                data = {
                    "label": base.label,
                    "size": base.size,
                    "os": base.os,
                    "bios": base.bios,
                    "efi": base.efi,
                    "udf": base.udf,
                }
                layout = iso_layout.full(target_id, deployment, files, agent, data)
            else:
                layout = iso_layout.seed(target_id, deployment, files, agent)
        except iso.IsoError as e:
            return notify_error(str(e))
        return deployment, target_id, layout, agent


class IsoPlan(_IsoRender):
    def post(self, request):
        data = _body(request)
        mode = data.get("mode", "seed")
        if mode not in ("seed", "full"):
            return notify_error("The mode must be seed or full")
        base = None
        if mode == "full":
            base = BaseIso.objects.filter(
                pk=data.get("base"), kind=BaseIso.Kind.BASE
            ).first()
            if base is None or base.status != BaseIso.Status.READY:
                return notify_error("Pick a base image that is ready")
        got = self._layout(request, mode, base)
        if isinstance(got, Response):
            return got
        _deployment, _target_id, layout, agent = got
        # the Windows seed leaves the agent out, Setup would not copy it
        names = {path.rsplit("/", 1)[-1] for path, _blob in layout.files}
        if agent and agent[0] not in names:
            agent = None
        return Response(
            {
                "label": layout.label,
                "files": [path for path, _blob in layout.files],
                "notes": layout.notes,
                "agent": agent[0] if agent else None,
                "size_hint": sum(len(blob) for _path, blob in layout.files),
            }
        )


class IsoSeed(_IsoRender):
    def post(self, request):
        got = self._layout(request, "seed", None)
        if isinstance(got, Response):
            return got
        deployment, target_id, layout, _agent = got
        try:
            label = iso.safe_label(layout.label or "ULRMM")
            blob = iso.seed_iso(label, layout.files)
        except iso.IsoError as e:
            return notify_error(str(e))
        resp = StreamingHttpResponse(
            (blob[i : i + CHUNK] for i in range(0, len(blob), CHUNK)),
            content_type="application/x-iso9660-image",
        )
        resp["Content-Length"] = str(len(blob))
        resp["Content-Disposition"] = (
            f'attachment; filename="{iso_name(deployment, target_id)}-seed.iso"'
        )
        resp["Cache-Control"] = "no-store"
        resp["X-Sha256"] = hashlib.sha256(blob).hexdigest()
        resp["X-Volume-Label"] = label
        _audit(request, f"built a {target_id} seed ISO", deployment)
        return resp


class IsoBuild(_BuilderBase):
    def post(self, request):
        resolved = self._resolve(request)
        if isinstance(resolved, Response):
            return resolved
        deployment, _module, target_id, _profile = resolved
        data = _body(request)
        base = BaseIso.objects.filter(
            pk=data.get("base"), kind=BaseIso.Kind.BASE
        ).first()
        if base is None or base.status != BaseIso.Status.READY:
            return notify_error("Pick a base image that is ready")
        windows = _family(target_id) == "windows"
        if windows != (base.os == "windows"):
            return notify_error(
                "A Windows target needs a Windows base image, "
                "any other target a Linux one"
            )
        job_id = uuid.uuid4().hex
        tasks.iso_job_set(
            job_id,
            user=request.user.username,
            state="queued",
            pct=0,
            text="Queued",
            name="",
            size=0,
            sha256="",
            label="",
            notes=[],
            error="",
            path="",
            iso=None,
        )
        body = {k: data.get(k) for k in ("deployment", "target", "profile", "base")}
        tasks.build_iso_task.delay(job_id, body, request.user.username)
        _audit(request, f"started a {target_id} ISO build", deployment)
        return Response({"job": job_id})


class _Job(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def _record(self, request, job_id):
        """(record, None) or (None, Response)."""
        rec = cache.get(tasks.iso_job_key(job_id)) if JOB_ID.match(job_id) else None
        if rec is None:
            return None, Response("not found", status=404)
        if rec.get("user") != request.user.username and not has_superuser_rights(
            request.user
        ):
            raise PermissionDenied()
        return rec, None


class IsoJob(_Job):
    def get(self, request, job_id):
        rec, err = self._record(request, job_id)
        if err:
            return err
        return Response({k: v for k, v in rec.items() if k not in _HIDDEN})

    def delete(self, request, job_id):
        rec, err = self._record(request, job_id)
        if err:
            return err
        # discarding a finished build removes its library row and file
        if rec.get("iso") and (row := BaseIso.objects.filter(pk=rec["iso"]).first()):
            _drop(row)
        if rec.get("path") and os.path.isfile(rec["path"]):
            os.remove(rec["path"])
        cache.delete(tasks.iso_job_key(job_id))
        return Response("ok")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime
import json
import mimetypes
import os
import posixpath
import secrets
import tempfile
import uuid
import zipfile
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import yaml
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import SuspiciousFileOperation
from django.db import DatabaseError, transaction
from django.db.models import Model, Q, QuerySet
from django.forms.models import model_to_dict
from django.http import FileResponse, HttpResponse, QueryDict
from django.shortcuts import get_object_or_404
from django.utils.http import content_disposition_header
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.http import require_GET
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utils import has_superuser_rights
from ulrmm.helpers import notify_error
from ulrmm.logger import logger
from ulrmm.util_settings import get_backend_url

from . import conf
from .constants import can_read
from .models import ReportAsset, ReportDataQuery, ReportHistory
from .models import ReportHTMLTemplate, ReportSchedule, ReportTemplate
from .permissions import GenerateReportPerms, ReportingPerms
from .schema import SCHEMA_PATH, build_query_schema
from .serializers import (
    EmailReportSerializer,
    ReportDataQuerySerializer,
    ReportHistorySerializer,
    ReportHTMLTemplateSerializer,
    ReportPreviewSerializer,
    ReportScheduleSerializer,
    ReportTemplateSerializer,
)
from .storage import report_assets_fs
from .utils import (
    REPORT_FORMATS,
    base64_encode_assets,
    generate_html,
    generate_pdf,
    import_report_bundle,
    normalize_asset_url,
    prep_variables_for_template,
    queue_report_email,
    report_error_message,
    restore_asset_links,
    run_report,
    run_scheduled_report,
)

FORMAT_ERROR = "Report format is incorrect."
MAX_ASSET_PATH = ReportAsset._meta.get_field("file").max_length
TRUE_VALUES = ("true", "True", "1")


def _data(request) -> Mapping:
    if not isinstance(request.data, Mapping):
        raise ValidationError("The request body must be an object")
    return request.data


def _validated_save(serializer, **extra) -> Response:
    serializer.is_valid(raise_exception=True)
    serializer.save(**extra)
    return Response(serializer.data)


def _delete_row(model, pk) -> Response:
    get_object_or_404(model, pk=pk).delete()
    return Response()


def _pdf_response(content: bytes, filename: str) -> HttpResponse:
    response = HttpResponse(content, content_type="application/pdf")
    response["Content-Disposition"] = content_disposition_header(False, filename)
    return response


def _report_response(output, format: str, filename: str):
    if format == "pdf":
        return _pdf_response(output, filename)
    return Response(output)


# values the REST framework encoder writes itself
JSON_TYPES = (
    str,
    int,
    float,
    bool,
    bytes,
    datetime.date,
    datetime.time,
    datetime.timedelta,
    Decimal,
    uuid.UUID,
)


def _plain(value: Any) -> Any:
    """Make the resolved variables of a debug preview JSON friendly."""
    if isinstance(value, Model):
        label = value._meta.label
        fields = [field.name for field in value._meta.fields]
        return {
            name: _plain(item)
            for name, item in model_to_dict(value, fields=fields).items()
            if can_read(label, name)
        }
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, QuerySet)):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, JSON_TYPES):
        return value
    return str(value)


def describe_variables(
    variables: Mapping, prefix: str = "", out: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """Flat map of dotted variable paths to a short type description."""
    out = {} if out is None else out
    for key, value in variables.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out[path] = "Object"
            describe_variables(value, f"{path}.", out)
        elif isinstance(value, (list, tuple, QuerySet)):
            items = list(value)
            out[path] = f"Array ({len(items)} Results)"
            if items and isinstance(items[0], Mapping):
                describe_variables(items[0], f"{path}[0].", out)
            elif items:
                out[f"{path}[0]"] = _type_name(items[0])
        else:
            out[path] = _type_name(value)
    return out


def _type_name(value: Any) -> str:
    # charts, css and database text are text to the template author
    return "str" if isinstance(value, str) else type(value).__name__


# --- report templates


class ReportTemplates(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        templates = ReportTemplate.objects.all()
        depends_on = request.query_params.getlist("dependsOn[]")
        if depends_on:
            templates = templates.filter(depends_on__overlap=depends_on)
        return Response(ReportTemplateSerializer(templates, many=True).data)

    def post(self, request):
        return _validated_save(ReportTemplateSerializer(data=request.data))


class GetEditDeleteReportTemplate(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request, pk):
        row = get_object_or_404(ReportTemplate, pk=pk)
        return Response(ReportTemplateSerializer(row).data)

    def put(self, request, pk):
        row = get_object_or_404(ReportTemplate, pk=pk)
        return _validated_save(
            ReportTemplateSerializer(row, data=request.data, partial=True)
        )

    def delete(self, request, pk):
        return _delete_row(ReportTemplate, pk)


class GenerateReport(APIView):
    permission_classes = [IsAuthenticated, GenerateReportPerms]

    def post(self, request, pk):
        template = get_object_or_404(ReportTemplate, pk=pk)
        data = _data(request)
        format = data.get("format")
        if format not in REPORT_FORMATS:
            return notify_error(FORMAT_ERROR)
        deps = data.get("dependencies") or {}
        if not isinstance(deps, dict):
            return notify_error("dependencies must be an object")

        output, error, _ = run_report(
            user=request.user,
            template=template,
            format=format,
            dependencies=deps,
        )
        if error:
            return notify_error(error)
        return _report_response(output, format, f"{template.name}.pdf")


class EmailReport(APIView):
    permission_classes = [IsAuthenticated, GenerateReportPerms]

    def post(self, request, pk):
        template = get_object_or_404(ReportTemplate, pk=pk)
        if _data(request).get("format") not in REPORT_FORMATS:
            return notify_error(FORMAT_ERROR)
        serializer = EmailReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        format = data["format"]

        output, error, history = run_report(
            template=template,
            dependencies=data["dependencies"],
            format=format,
            user=request.user,
        )
        if error:
            return notify_error(error)

        queue_report_email(
            template,
            history,
            output,
            format,
            data["email_recipients"],
            data["email_settings"],
        )
        return Response()


class GenerateReportPreview(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        serializer = ReportPreviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            html, variables = generate_html(
                template=data["template_md"],
                template_type=data["type"],
                css=data.get("template_css") or "",
                html_template=data.get("template_html"),
                variables=data["template_variables"] or "",
                dependencies=data["dependencies"],
                user=request.user,
            )
            if data["debug"]:
                return Response({"template": html, "variables": _plain(variables)})

            html = normalize_asset_url(html, data["format"])
            output = generate_pdf(html) if data["format"] == "pdf" else html
        except Exception as error:
            return notify_error(report_error_message(error))
        return _report_response(output, data["format"], "preview.pdf")


class GenerateReportVariableAnalysis(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        data = _data(request)
        variables = data.get("variables")
        if variables is None:
            return notify_error("'variables' is required")
        if isinstance(variables, dict):
            variables = yaml.safe_dump(variables)

        try:
            resolved = prep_variables_for_template(
                variables=variables,
                dependencies=data.get("dependencies") or {},
                limit_query_results=1,
                user=request.user,
            )
        except Exception as error:
            return notify_error(report_error_message(error))

        if not resolved:
            return Response()
        return Response(describe_variables(resolved))


class ExportReportTemplate(APIView):
    permission_classes = [IsAuthenticated, GenerateReportPerms]

    def post(self, request, pk):
        template = get_object_or_404(
            ReportTemplate.objects.select_related("template_html"), pk=pk
        )
        base = template.template_html
        # the same fields the import rewrites asset ids in
        sources = [
            template.template_md,
            template.template_css or "",
            template.template_variables or "",
        ]
        if base:
            sources.append(base.html)

        return Response(
            {
                "base_template": (
                    {"name": base.name, "html": base.html} if base else None
                ),
                "template": {
                    field: getattr(template, field) for field in EXPORTED_FIELDS
                },
                "assets": base64_encode_assets("\n".join(sources)),
            }
        )


EXPORTED_FIELDS = (
    "name",
    "template_css",
    "template_md",
    "type",
    "depends_on",
    "template_variables",
)


class ImportReportTemplate(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        data = _data(request)
        raw = data.get("template")
        if not isinstance(raw, str) or not raw:
            return notify_error("'template' is required")
        if len(raw) > conf.max_import_bytes():
            return notify_error(
                f"The import is larger than {conf.max_import_bytes() // (1024 * 1024)} MB"
            )
        try:
            bundle = json.loads(raw)
        except ValueError as error:
            return notify_error(str(error))

        overwrite = data.get("overwrite")
        overwrite = overwrite is True or overwrite in TRUE_VALUES
        try:
            template = import_report_bundle(bundle, overwrite=overwrite)
        except Exception as error:
            return notify_error(report_error_message(error))
        return Response(ReportTemplateSerializer(template).data)


# --- base templates and data queries


class GetAddReportHTMLTemplate(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        templates = ReportHTMLTemplate.objects.all()
        return Response(ReportHTMLTemplateSerializer(templates, many=True).data)

    def post(self, request):
        return _validated_save(ReportHTMLTemplateSerializer(data=request.data))


class GetEditDeleteReportHTMLTemplate(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request, pk):
        row = get_object_or_404(ReportHTMLTemplate, pk=pk)
        return Response(ReportHTMLTemplateSerializer(row).data)

    def put(self, request, pk):
        row = get_object_or_404(ReportHTMLTemplate, pk=pk)
        return _validated_save(
            ReportHTMLTemplateSerializer(row, data=request.data, partial=True)
        )

    def delete(self, request, pk):
        base = get_object_or_404(ReportHTMLTemplate, pk=pk)
        used_by = list(base.htmltemplate.values_list("name", flat=True))
        if used_by:
            return notify_error(
                f"This base template is used by these report templates: {', '.join(used_by)}"
            )
        base.delete()
        return Response()


class GetAddReportDataQuery(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        queries = ReportDataQuery.objects.all()
        return Response(ReportDataQuerySerializer(queries, many=True).data)

    def post(self, request):
        return _validated_save(ReportDataQuerySerializer(data=request.data))


class GetEditDeleteReportDataQuery(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request, pk):
        row = get_object_or_404(ReportDataQuery, pk=pk)
        return Response(ReportDataQuerySerializer(row).data)

    def put(self, request, pk):
        row = get_object_or_404(ReportDataQuery, pk=pk)
        return _validated_save(
            ReportDataQuerySerializer(row, data=request.data, partial=True)
        )

    def delete(self, request, pk):
        return _delete_row(ReportDataQuery, pk)


class QuerySchema(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        # collectstatic copies the generated file to STATIC_ROOT
        candidates = (
            Path(settings.BASE_DIR) / "static" / SCHEMA_PATH,
            Path(settings.STATICFILES_DIRS[0]) / SCHEMA_PATH,
        )
        for path in candidates:
            try:
                with open(path) as f:
                    return Response(json.load(f))
            except (OSError, ValueError):
                continue
        # installs that never ran generate_json_schemas, such as docker
        return Response(build_query_schema())


# --- assets


def _clean(path: Any) -> str:
    if path is None:
        return ""
    if not isinstance(path, str):
        raise SuspiciousFileOperation("The path must be text")
    return path.lstrip("/")


def _relative(path: str) -> str:
    # normalised form, as stored in ReportAsset.file
    return report_assets_fs.relative(report_assets_fs.path(path))


class GetReportAssets(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        try:
            path = _relative(_clean(request.query_params.get("path")))
            if not report_assets_fs.isdir(path):
                return notify_error("The path is invalid")
            folders, files = report_assets_fs.listdir(path)

            entries = []
            for kind, names in (("folder", folders), ("file", files)):
                for name in names:
                    item = posixpath.join(path, name)
                    entries.append(
                        {
                            "name": name,
                            "path": item,
                            "type": kind,
                            "size": (
                                None
                                if kind == "folder"
                                else str(report_assets_fs.size(item))
                            ),
                            "url": report_assets_fs.url(item),
                        }
                    )
        except (SuspiciousFileOperation, OSError):
            return notify_error("The path is invalid")
        return Response(entries)


def _asset_tree(
    path: str, name: str, registered: Dict[str, str], only_folders: bool
) -> Dict[str, Any]:
    folders, files = report_assets_fs.listdir(path)
    children: List[Dict[str, Any]] = [
        _asset_tree(posixpath.join(path, folder), folder, registered, only_folders)
        for folder in folders
    ]
    if not only_folders:
        for file in files:
            item = posixpath.join(path, file)
            # files without a database row cannot be referenced, so they are left out
            if item in registered:
                children.append(
                    {
                        "id": registered[item],
                        "type": "file",
                        "name": file,
                        "path": item,
                        "icon": "description",
                    }
                )
    return dict(
        type="folder",
        name=name,
        path=path,
        children=children,
        selectable=False,
        icon="folder",
        iconColor="yellow-9",
    )


class GetAllAssets(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        only_folders = request.query_params.get("onlyFolders") == "true"
        registered = {
            file: str(asset_id)
            for asset_id, file in ReportAsset.objects.values_list("id", "file")
        }
        try:
            root = _asset_tree("", "Report Assets", registered, only_folders)
        except (SuspiciousFileOperation, OSError):
            return notify_error("Unable to process request")
        return Response([root])


class RenameReportAsset(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def put(self, request):
        data = _data(request)
        path, new_name = data.get("path"), data.get("newName")
        if not isinstance(path, str) or not path or not isinstance(new_name, str):
            return notify_error("'path' and 'newName' are required")

        try:
            if not report_assets_fs.exists(path):
                return notify_error("The file or folder does not exist")
            old = _relative(_clean(path))
            is_folder = report_assets_fs.isdir(old)
            # the upload allowlist holds for stored files too
            if not is_folder and not conf.is_allowed_asset(new_name):
                return notify_error(f"{new_name}: this file type is not allowed")
            new = report_assets_fs.rename(old, new_name)
        except SuspiciousFileOperation as error:
            return notify_error(str(error))
        except OSError as error:
            logger.error(f"reporting: renaming asset {path} failed: {error}")
            return notify_error("The file or folder could not be renamed")

        if is_folder:
            assets = list(ReportAsset.objects.filter(file__startswith=f"{old}/"))
        else:
            assets = list(ReportAsset.objects.filter(file=old))
        for asset in assets:
            asset.file.name = new + asset.file.name[len(old) :]

        # checked here: a bulk update would cut long paths off silently
        error = None
        if any(len(asset.file.name) > MAX_ASSET_PATH for asset in assets):
            error = f"Stored asset paths are limited to {MAX_ASSET_PATH} characters"
        else:
            try:
                ReportAsset.objects.bulk_update(assets, ["file"])
            except DatabaseError as db_error:
                logger.error(f"reporting: updating renamed assets failed: {db_error}")
                error = "The file or folder could not be renamed"
        if error:
            # put it back so disk and database agree again
            os.rename(report_assets_fs.path(new), report_assets_fs.path(old))
            return notify_error(error)
        return Response(new)


class CreateAssetFolder(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        try:
            path = _clean(_data(request).get("path"))
            if not path:
                return notify_error("'path' is required.")
            folder = report_assets_fs.createfolder(path)
        except SuspiciousFileOperation as error:
            return notify_error(str(error))
        except FileNotFoundError:
            return notify_error("The parent folder does not exist")
        except OSError as error:
            logger.error(f"reporting: creating asset folder failed: {error}")
            return notify_error("The folder could not be created")
        return Response(folder)


class DeleteReportAssets(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        data = _data(request)
        if isinstance(data, QueryDict):
            # a form repeats the key once per path
            paths = data.getlist("paths") if "paths" in data else None
        else:
            paths = data.get("paths")
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            return notify_error("'paths' must be a list of paths")

        for path in paths:
            try:
                item = _relative(_clean(path))
                is_folder = report_assets_fs.isdir(item)
                report_assets_fs.delete_tree(item)
            except SuspiciousFileOperation as error:
                return notify_error(str(error))
            except OSError as error:
                logger.error(f"reporting: deleting asset {path} failed: {error}")
                return notify_error(f"{path} could not be deleted")

            if is_folder:
                ReportAsset.objects.filter(file__startswith=f"{item}/").delete()
            else:
                ReportAsset.objects.filter(file=item).delete()
        return Response()


class UploadReportAsset(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request):
        try:
            parent = _relative(_clean(_data(request).get("parentPath")))
            if not report_assets_fs.isdir(parent):
                return notify_error("parentPath doesn't point to a directory")
        except SuspiciousFileOperation as error:
            return notify_error(str(error))

        max_bytes = conf.max_asset_bytes()
        files = list(request.FILES.items())
        for name, file in files:
            if name in ("", ".", "..") or "/" in name or "\\" in name:
                return notify_error(f"{name} is not a valid file name")
            if not conf.is_allowed_asset(name):
                return notify_error(f"{name}: this file type is not allowed")
            if file.size > max_bytes:
                return notify_error(
                    f"{name} is larger than {max_bytes // (1024 * 1024)} MB"
                )

        stored: List[str] = []
        response = {}
        try:
            with transaction.atomic():
                for name, file in files:
                    filename = report_assets_fs.save(
                        posixpath.join(parent, name), file, max_length=100
                    )
                    stored.append(filename)
                    asset = ReportAsset.objects.create(file=filename)
                    response[name] = {"id": asset.id, "filename": filename}
        except (SuspiciousFileOperation, OSError, DatabaseError) as error:
            for filename in stored:
                try:
                    report_assets_fs.delete(filename)
                except Exception:
                    pass
            logger.error(f"reporting: asset upload failed: {error}")
            if isinstance(error, SuspiciousFileOperation):
                return notify_error(str(error))
            return notify_error("The files could not be stored")
        return Response(response)


def _zip_folder(folder: str, target: str) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(folder):
            # links could point outside the asset folder
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            # directory entries keep empty folders in the archive
            for name in dirs:
                full = os.path.join(root, name)
                archive.write(full, os.path.relpath(full, folder))
            for name in files:
                full = os.path.join(root, name)
                if not os.path.islink(full):
                    archive.write(full, os.path.relpath(full, folder))


class DownloadReportAsset(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        try:
            path = _clean(request.query_params.get("path"))
            full = report_assets_fs.path(path)
            if os.path.isdir(full):
                name = os.path.basename(full) or "assets"
                with tempfile.TemporaryDirectory() as tmp:
                    archive = os.path.join(tmp, f"{name}.zip")
                    _zip_folder(full, archive)
                    # the open file outlives the removed folder
                    handle = open(archive, "rb")
                return FileResponse(handle, as_attachment=True, filename=f"{name}.zip")
            if os.path.isfile(full):
                return FileResponse(
                    open(full, "rb"),
                    as_attachment=True,
                    filename=os.path.basename(full),
                )
        except SuspiciousFileOperation as error:
            return notify_error(str(error))
        except OSError as error:
            logger.error(f"reporting: asset download failed: {error}")
            return notify_error("The file could not be read")
        return notify_error("The file or folder does not exist")


class NginxRedirect(APIView):
    """Serve an asset to rendered reports, which have no API token.

    The asset id and its exact stored path together act as the key.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, path):
        raw = request.query_params.get("id")
        try:
            asset_id = uuid.UUID(raw)
        except (TypeError, ValueError, AttributeError):
            return notify_error("There was an error processing the request")

        asset = get_object_or_404(ReportAsset, id=asset_id)
        if asset.file.name != path:
            return Response(status=403)

        response = HttpResponse()
        response["X-Accel-Redirect"] = f"/assets/{quote(path)}"
        response["Content-Type"] = (
            mimetypes.guess_type(path)[0] or "application/octet-stream"
        )
        response["X-Content-Type-Options"] = "nosniff"
        if not conf.is_inline_asset(path):
            response["Content-Disposition"] = content_disposition_header(
                True, posixpath.basename(path)
            )
            response["Content-Security-Policy"] = "sandbox"
        return response


# --- report frames
# The dashboard shows html reports in a sandboxed frame loaded from here, so
# the dashboard's own policy needs no inline script. The token is the only
# key: single use, gone after FRAME_TTL seconds.

FRAME_TTL = 120
FRAME_MAX = 32 * 1024 * 1024
FRAME_KEY = "reporting:frame:"


def _api_url() -> str:
    return get_backend_url(
        settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
    )


def report_frame_policy() -> str:
    """Template markup is not sanitized and runs with the viewer's data, so
    scripts come inline or from the API's static files (plotly), and the
    frame cannot connect, post forms or set a base URL. Images, styles and
    fonts may also load over https, as linked images in templates always
    could. Only the dashboard may embed it.
    """
    api = _api_url()
    assets = f"{api}/reporting/assets/"
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src 'unsafe-inline' 'unsafe-eval' {api}/static/reporting/js/",
            f"style-src 'unsafe-inline' https: {assets}",
            f"img-src data: blob: https: {assets}",
            f"font-src data: https: {assets}",
            "connect-src 'none'",
            "form-action 'none'",
            "base-uri 'none'",
            f"frame-ancestors {settings.CORS_ORIGIN_WHITELIST[0]}",
        )
    )


class ReportFrame(APIView):
    permission_classes = [IsAuthenticated, GenerateReportPerms]

    def post(self, request):
        # refused before the body is parsed
        if int(request.META.get("CONTENT_LENGTH") or 0) > 2 * FRAME_MAX:
            return notify_error("The report is too large to show")
        data = _data(request)
        html = data.get("html")
        if data.get("format") != "html" or not isinstance(html, str):
            return notify_error("html must be a string and format html")
        if len(html.encode()) > FRAME_MAX:
            return notify_error("The report is too large to show")
        token = secrets.token_urlsafe(32)
        cache.set(FRAME_KEY + token, html, FRAME_TTL)
        return Response({"url": f"{_api_url()}/reporting/frame/{token}/"})


@require_GET
@xframe_options_exempt
def report_frame(request, token):
    key = FRAME_KEY + token
    html = cache.get(key)
    # delete is the single use check: of two parallel loads only one wins
    if html is None or not cache.delete(key):
        return HttpResponse(status=404)
    response = HttpResponse(html, content_type="text/html; charset=utf-8")
    response["Content-Security-Policy"] = report_frame_policy()
    response["X-Content-Type-Options"] = "nosniff"
    response["Referrer-Policy"] = "no-referrer"
    response["Cache-Control"] = "no-store"
    return response


# --- schedules and history


class GetAddReportSchedule(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        schedules = ReportSchedule.objects.select_related(
            "report_template", "schedule", "owner"
        )
        return Response(ReportScheduleSerializer(schedules, many=True).data)

    def post(self, request):
        return _validated_save(
            ReportScheduleSerializer(data=request.data, context={"user": request.user}),
            owner=request.user,
        )


class GetEditDeleteReportSchedule(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request, pk):
        row = get_object_or_404(ReportSchedule, pk=pk)
        return Response(ReportScheduleSerializer(row).data)

    def put(self, request, pk):
        schedule = get_object_or_404(ReportSchedule, pk=pk)
        serializer = ReportScheduleSerializer(
            instance=schedule,
            data=request.data,
            partial=True,
            context={"user": request.user},
        )
        serializer.is_valid(raise_exception=True)
        # the last editor's role scope applies from now on
        with transaction.atomic():
            if schedule.owner_id != request.user.pk:
                # earlier runs used another scope, the new owner may not see them
                ReportHistory.objects.filter(schedule=schedule).update(schedule=None)
            serializer.save(owner=request.user)
        return Response(serializer.data)

    def delete(self, request, pk):
        return _delete_row(ReportSchedule, pk)


class RunReportSchedule(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def post(self, request, pk):
        schedule = get_object_or_404(
            ReportSchedule.objects.select_related("report_template"), pk=pk
        )
        _, error = run_scheduled_report(schedule=schedule, user=request.user)
        if error:
            return notify_error(error)
        return Response()


def visible_history(user) -> QuerySet:
    history = ReportHistory.objects.select_related("report_template")
    if has_superuser_rights(user):
        return history
    # stable ids, never run_by: a username can be reused or be "system"
    return history.filter(Q(user=user) | Q(schedule__owner=user))


class GetReportHistory(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def get(self, request):
        history = visible_history(request.user)
        return Response(ReportHistorySerializer(history, many=True).data)


class DeleteReportHistory(APIView):
    permission_classes = [IsAuthenticated, ReportingPerms]

    def delete(self, request, pk):
        get_object_or_404(visible_history(request.user), pk=pk).delete()
        return Response()


class GenerateReportFromHistory(APIView):
    permission_classes = [IsAuthenticated, GenerateReportPerms]

    def post(self, request, pk):
        history = get_object_or_404(visible_history(request.user), pk=pk)
        format = _data(request).get("format")
        if format not in REPORT_FORMATS:
            return notify_error(FORMAT_ERROR)

        try:
            html = normalize_asset_url(restore_asset_links(history.report_data), format)
            output = generate_pdf(html) if format == "pdf" else html
        except Exception as error:
            return notify_error(report_error_message(error))
        return _report_response(
            output,
            format,
            f"{history.report_template.name}_{history.date_created}.pdf",
        )

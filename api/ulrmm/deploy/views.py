# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Builder API: the target matrix, a masked render preview, and a download of
a single answer file or a zip bundle. Nothing generated is stored; downloads
are audited without any secret value.
"""

import json
import re
from xml.sax.saxutils import escape

from django.http import StreamingHttpResponse
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from clients.models import Deployment
from clients.permissions import DeploymentPerms
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm_on_site

from . import bundle, installers, matrix, signing

MASK = "********"
CHUNK = 64 * 1024
# the embedded first-boot files of a Windows answer file (base64)
_PAYLOAD = re.compile(r"<(\w+:)?Extensions\b.*?</(\w+:)?Extensions>", re.DOTALL)

_LANG_TYPE = {
    "xml": "application/xml",
    "yaml": "text/yaml",
    "shell": "text/x-shellscript",
    "powershell": "text/plain",
    "json": "application/json",
    "ini": "text/plain",
    "text": "text/plain",
}


def _body(request) -> dict:
    return request.data if isinstance(request.data, dict) else {}


def _forms(secret: str):
    # the value as written raw, XML-escaped, and JSON or YAML quoted
    yield secret
    yield escape(secret)
    yield json.dumps(secret)[1:-1]
    yield json.dumps(secret, ensure_ascii=False)[1:-1]
    yield secret.replace("\\", "\\\\").replace('"', '\\"')


def _mask(files, secrets):
    forms = {form for s in secrets if s for form in _forms(s)}
    ordered = sorted(forms, key=len, reverse=True)
    out = []
    for f in files:
        body = f["content"]
        if isinstance(body, str):
            for s in ordered:
                body = body.replace(s, MASK)
            if f.get("language") == "xml":
                # the embedded first-boot files are base64; hide the whole
                # payload so the preview leaks nothing
                body = _PAYLOAD.sub("<!-- embedded payload hidden in preview -->", body)
        out.append({**f, "content": body})
    return out


class _BuilderBase(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def _resolve(self, request):
        """(deployment, module, target_id, profile) or a Response to return."""
        data = _body(request)
        pk = data.get("deployment")
        target_id = data.get("target")
        if not isinstance(target_id, str):
            return notify_error("A target is required")
        deployment = (
            Deployment.objects.filter_by_role(request.user)
            .select_related("site__client", "policy")
            .filter(pk=pk if isinstance(pk, int) else -1)
            .first()
        )
        if deployment is None:
            return notify_error("The deployment was not found")
        if not _has_perm_on_site(request.user, deployment.site_id):
            raise PermissionDenied()
        module = matrix.module_for(target_id)
        if module is None:
            return notify_error("Unknown target")
        if not signing.dist_pubkey_ok():
            # the agent build could not verify the enrollment token
            return Response("agent build needed: run update.sh", status=503)
        profile = data.get("profile")
        return (
            deployment,
            module,
            target_id,
            profile if isinstance(profile, dict) else {},
        )

    def _build(self, request):
        """(deployment, module, target_id, clean profile, files, secrets) or
        a Response to return."""
        resolved = self._resolve(request)
        if isinstance(resolved, Response):
            return resolved
        deployment, module, target_id, profile = resolved
        clean = module.validate_profile(target_id, profile)
        try:
            files, secrets = module.render(target_id, deployment, clean)
        except installers.Unavailable as e:
            return Response(str(e), status=503)
        except ValueError as e:
            return notify_error(str(e))
        return deployment, module, target_id, clean, files, secrets


class BuilderMatrix(APIView):
    permission_classes = [IsAuthenticated, DeploymentPerms]

    def get(self, request):
        return Response(matrix.build_matrix())


class BuilderRender(_BuilderBase):
    def post(self, request):
        built = self._build(request)
        if isinstance(built, Response):
            return built
        _deployment, _module, target_id, clean, files, secrets = built
        warnings = list(clean.pop("_warnings", []))
        tgt = next((t for t in matrix.all_targets() if t["id"] == target_id), None)
        if tgt:
            warnings = tgt.get("notes", []) + warnings
        return Response(
            {
                "files": _mask(files, secrets),
                "warnings": warnings,
                "generated": clean.get("_generated", {}),
            }
        )


class BuilderDownload(_BuilderBase):
    def post(self, request):
        built = self._build(request)
        if isinstance(built, Response):
            return built
        deployment, module, target_id, _clean, files, _secrets = built
        as_bundle = bool(_body(request).get("bundle"))

        if as_bundle:
            name, blob = bundle.build_bundle(module, target_id, deployment, files)
            content_type = "application/zip"
        else:
            answer = files[0]
            blob = answer["content"]
            if isinstance(blob, str):
                blob = blob.encode("utf-8")
            content_type = _LANG_TYPE.get(answer.get("language"), "text/plain")
            name = answer["name"]

        resp = StreamingHttpResponse(
            (blob[i : i + CHUNK] for i in range(0, len(blob), CHUNK)),
            content_type=content_type,
        )
        resp["Content-Length"] = str(len(blob))
        resp["Content-Disposition"] = f'attachment; filename="{name}"'
        resp["Cache-Control"] = "no-store"
        self._audit(request, deployment, target_id, as_bundle)
        return resp

    def _audit(self, request, deployment, target_id, as_bundle):
        kind = "bundle" if as_bundle else "answer file"
        AuditLog.objects.create(
            username=request.user.username,
            object_type=AuditObjType.SITE,
            action=AuditActionType.URL_ACTION,
            message=(
                f"{request.user.username} built a {target_id} {kind} for a "
                f"deployment on site {deployment.site.name}"
            ),
            debug_info={"ip": getattr(request, "_client_ip", "")},
        )

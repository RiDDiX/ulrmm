# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Zip bundles for the OS image targets: the answer file(s), the inject
scripts the target needs, and a README. No ISO is ever built on the server.
"""

import io
import re
import zipfile

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    name = _SAFE.sub("-", name).strip("-")
    return name or "deployment"


def bundle_name(deployment, target_id: str) -> str:
    client = _safe(deployment.site.client.name)
    site = _safe(deployment.site.name)
    return f"{_safe(target_id)}-{client}-{site}.zip"


def build_bundle(module, target_id: str, deployment, files) -> tuple[str, bytes]:
    """A zip of the rendered files plus the module's inject scripts and a
    README. files is render()'s unmasked file list."""
    extras = module.bundle_extras(target_id, files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        seen = set()
        for f in files:
            name = f["name"]
            if name in seen:
                continue
            seen.add(name)
            body = f["content"]
            zf.writestr(name, body.encode("utf-8") if isinstance(body, str) else body)
        for name, body in extras:
            if name in seen:
                continue
            seen.add(name)
            zf.writestr(name, body if isinstance(body, bytes) else body.encode("utf-8"))
    return bundle_name(deployment, target_id), buf.getvalue()

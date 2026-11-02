# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Signed manifest of the agent builds this server ships (GET
/api/v3/integrity/). An agent compares the sha256 of its own executable
with the entry for its version and platform.
"""

import logging
import re
import time

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from agents.models import self_built_sha256
from agents.utils import _dist_dir, _dist_sha256
from ulrmm.agent_ident import agent_artifact
from ulrmm.constants import AgentPlat, GoArch

from . import signing

logger = logging.getLogger("ulrmm")

INTEGRITY_TYP = "ulrmm-integrity"
# claim when the dist dir holds only Windows setups and none of the
# <setup>.agent.sha256 files build_agents.sh writes next to them
WINDOWS_SETUP_ONLY = "setup-only"
# the sha256 of the agent exe packed into <setup>, written by build_agents.sh
WINDOWS_SUM_SUFFIX = ".agent.sha256"
_PLATS = [p for p in AgentPlat.values if p != AgentPlat.WINDOWS]
_SHA_RE = re.compile(r"[0-9a-f]{64}")


def _artifact_re():
    plats = "|".join(re.escape(p) for p in _PLATS)
    arches = "|".join(re.escape(a) for a in GoArch.values)
    return re.compile(
        rf"{re.escape(settings.AGENT_ARTIFACT_NAME)}-v(?P<ver>[0-9.]+)"
        rf"-(?:(?P<plat>{plats})-(?P<arch>{arches})"
        rf"|windows-(?P<warch>{arches})\.exe{re.escape(WINDOWS_SUM_SUFFIX)})"
    )


def _windows_sum(name: str) -> str:
    try:
        with open(_dist_dir() / name, "rb") as fh:
            text = fh.read(128).decode("ascii", "replace").strip().lower()
    except OSError:
        return ""
    return text if _SHA_RE.fullmatch(text) else ""


def builds() -> dict:
    """{version: {"<goos>-<goarch>": sha256}} of the posix builds in the dist
    dir, the Windows agent exes from the sums next to their setups, and the
    self-built ones of the current version where their hash is cached (they
    are what agents update to)."""
    out: dict = {}
    pattern = _artifact_re()
    try:
        names = sorted(p.name for p in _dist_dir().iterdir())
    except OSError:
        names = []
    for name in names:
        m = pattern.fullmatch(name)
        if not m:
            continue
        if m["warch"]:
            plat, arch, sha = "windows", m["warch"], _windows_sum(name)
        else:
            plat, arch, sha = m["plat"], m["arch"], _dist_sha256(name)
        if sha:
            out.setdefault(m["ver"], {})[f"{plat}-{arch}"] = sha
    base = (getattr(settings, "SELF_BUILT_AGENTS_URL", "") or "").strip().rstrip("/")
    if base:
        ver = settings.LATEST_AGENT_VER
        for plat in _PLATS:
            for arch in GoArch.values:
                url = f"{base}/{agent_artifact(ver, plat, arch)}"
                if sha := self_built_sha256(url, ver, fetch=False):
                    out.setdefault(ver, {})[f"{plat}-{arch}"] = sha
    return out


def manifest() -> str:
    found = builds()
    claims = {
        "v": 1,
        "typ": INTEGRITY_TYP,
        "iss": signing._https(signing.api_url()),
        "iat": int(time.time()),
        "builds": found,
    }
    if not any(k.startswith("windows-") for v in found.values() for k in v):
        claims["windows"] = WINDOWS_SETUP_ONLY
    return signing.mint(claims, INTEGRITY_TYP)


class IntegrityThrottle(AnonRateThrottle):
    scope = "integrity"
    rate = "120/hour"


class Integrity(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [IntegrityThrottle]

    def get(self, request):
        try:
            jws = manifest()
        except (signing.Unavailable, ImproperlyConfigured) as e:
            logger.warning(f"integrity manifest: {e}")
            return Response(
                {"detail": "integrity manifest unavailable"},
                status=503,
                headers={"Cache-Control": "no-store"},
            )
        return Response({"jws": jws}, headers={"Cache-Control": "no-store"})

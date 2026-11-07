# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from collections import Counter

from cryptography.fernet import InvalidToken
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import AgentPerms
from clients.models import Site
from core.utils import stepup_denied
from logs.models import AuditLog
from remote.utils import decrypt_secret
from ulrmm.constants import AGENT_DEFER, AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.permissions import _has_perm, _has_perm_on_site
from ulrmm.throttles import VaultRevealThrottle

from . import activation, warranty
from .models import HKDF_INFO, License
from .serializers import LicenseSerializer

EXPIRING = dt.timedelta(days=90)


class LicensePerms(BasePermission):
    def has_permission(self, r, view) -> bool:
        if r.method == "GET":
            return _has_perm(r, "can_list_agents")
        return _has_perm(r, "can_manage_credentials")


def _unrestricted(user) -> bool:
    role = user.get_and_set_role_cache()
    if user.is_superuser or (role and role.is_superuser):
        return True
    return bool(role) and not (
        role.can_view_clients.exists() or role.can_view_sites.exists()
    )


def _visible(user):
    """pks of the agents the user sees, None without a client restriction."""
    if _unrestricted(user):
        return None
    return set(Agent.objects.filter_by_role(user).values_list("pk", flat=True))


def _writable(user, site) -> bool:
    # a license for every client belongs to users without a client restriction
    return _has_perm_on_site(user, site.pk) if site else _unrestricted(user)


def _ctx(user, licenses) -> dict:
    visible = _visible(user)
    return {"visible": visible, "activation": activation.matches(licenses, visible)}


def _licenses(user):
    rows = License.objects.select_related("site__client").prefetch_related(
        Prefetch(
            "agents",
            queryset=Agent.objects.only(
                "pk", "agent_id", "hostname", "display_name", "site_id"
            ),
        )
    )
    if _unrestricted(user):
        return rows
    sites = Site.objects.filter_by_role(user).values("pk")
    return rows.filter(Q(site=None) | Q(site__in=sites))


class Licenses(APIView):
    permission_classes = [IsAuthenticated, LicensePerms]

    def get(self, request):
        rows = list(_licenses(request.user).order_by("name", "pk"))
        ctx = _ctx(request.user, rows)
        return Response(LicenseSerializer(rows, many=True, context=ctx).data)

    def post(self, request):
        ctx = {"visible": _visible(request.user)}
        s = LicenseSerializer(data=request.data, context=ctx)
        s.is_valid(raise_exception=True)
        if not _writable(request.user, s.validated_data.get("site")):
            raise PermissionDenied()
        lic = s.save()
        ctx["activation"] = activation.matches([lic], ctx["visible"])
        return Response(LicenseSerializer(lic, context=ctx).data)


class LicenseDetail(APIView):
    permission_classes = [IsAuthenticated, LicensePerms]

    def _get(self, request, pk, write: bool):
        lic = get_object_or_404(_licenses(request.user), pk=pk)
        if write and not _writable(request.user, lic.site):
            raise PermissionDenied()
        return lic

    def get(self, request, pk):
        lic = self._get(request, pk, False)
        return Response(LicenseSerializer(lic, context=_ctx(request.user, [lic])).data)

    def put(self, request, pk):
        lic = self._get(request, pk, True)
        ctx = {"visible": _visible(request.user)}
        s = LicenseSerializer(
            instance=lic, data=request.data, partial=True, context=ctx
        )
        s.is_valid(raise_exception=True)
        if "site" in s.validated_data and not _writable(
            request.user, s.validated_data["site"]
        ):
            raise PermissionDenied()
        lic = s.save()
        ctx["activation"] = activation.matches([lic], ctx["visible"])
        return Response(LicenseSerializer(lic, context=ctx).data)

    def delete(self, request, pk):
        lic = self._get(request, pk, True)
        lic.delete()
        return Response(f"{lic.name} was deleted")


class RevealLicenseKey(APIView):
    permission_classes = [IsAuthenticated, LicensePerms]
    throttle_classes = [VaultRevealThrottle]

    def post(self, request, pk):
        lic = get_object_or_404(_licenses(request.user), pk=pk)
        if not _writable(request.user, lic.site):
            raise PermissionDenied()
        if denied := stepup_denied(request, "Showing a license key needs it."):
            return denied
        if not lic.key:
            return notify_error("No key is stored for this license.")
        try:
            key = decrypt_secret(lic.key, HKDF_INFO)
        except InvalidToken:
            return notify_error("The key can no longer be read, enter it again.")
        AuditLog.objects.create(
            username=request.user.username,
            object_type=AuditObjType.CREDENTIAL,
            action=AuditActionType.VIEW,
            message=f"{request.user.username} revealed the key of license {lic.name}",
            after_value={"license": lic.pk, "name": lic.name, "site": lic.site_id},
            debug_info={"ip": request._client_ip},
        )
        r = Response({"key": key})
        r["Cache-Control"] = "no-store"
        return r


class Summary(APIView):
    permission_classes = [IsAuthenticated, LicensePerms]

    def get(self, request):
        today = djangotime.localdate()
        agents = Agent.objects.filter_by_role(request.user).defer(  # type: ignore
            *(f for f in AGENT_DEFER if f != "wmi_detail")
        )
        vendors = Counter()
        expiring = []
        for a in agents.select_related("site__client").iterator(chunk_size=200):
            # the make comes out of wmi_detail per agent, fine for a few
            # thousand devices
            vendors[warranty.maker(a).capitalize() or "Unknown"] += 1
            if a.warranty_end and a.warranty_end <= today + EXPIRING:
                expiring.append(
                    {
                        "agent_id": a.agent_id,
                        "name": a.effective_name,
                        "client": a.site.client.name,
                        "site": a.site.name,
                        "warranty_end": a.warranty_end,
                        "days_left": (a.warranty_end - today).days,
                    }
                )
        visible = _visible(request.user)
        seats = [
            (lic, sum(visible is None or a.pk in visible for a in lic.agents.all()))
            for lic in _licenses(request.user).filter(seats__isnull=False)
        ]
        over = [
            {"id": lic.pk, "name": lic.name, "seats": lic.seats, "assigned": n}
            for lic, n in seats
            if n > lic.seats
        ]
        return Response(
            {
                "devices": sum(vendors.values()),
                "by_vendor": [
                    {"vendor": v, "count": n} for v, n in vendors.most_common()
                ],
                "warranty_expiring": sorted(expiring, key=lambda x: x["warranty_end"])[
                    :100
                ],
                "licenses_over_seats": over,
            }
        )


class WarrantyLookup(APIView):
    # POST = can_edit_agent on this agent
    permission_classes = [IsAuthenticated, AgentPerms]

    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        status = warranty.refresh(agent, {})
        return Response({"warranty_status": status, "warranty_end": agent.warranty_end})

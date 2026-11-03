# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Rotation policies (global, per client, per site) and the trust matrix."""

import datetime as dt

from django.utils import timezone as djangotime
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from clients.models import Client, Site
from core.permissions import CoreSettingsPerms
from core.utils import stepup_denied
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import notify_error
from ulrmm.middleware import get_debug_info

from . import pki, policy
from .models import (
    POLICY_FIELDS,
    POLICY_LIMITS,
    AgentCertificate,
    AgentCredential,
    AgentIdentity,
    AgentSecuritySettings,
    IdentityState,
    PinSet,
    RotationPolicy,
    SecurityEvent,
    SecurityEventKind,
)
from .mtls_views import _int_param

SCOPES = ("global", "client", "site")
CLONE_WINDOW = dt.timedelta(days=7)
MATRIX_DEFAULT = 200
MATRIX_MAX = 1000
STATUSES = (
    "blocked",
    "quarantined",
    "clone_alert",
    "none",
    "revoked",
    "offline_grace",
    "expired",
    "renewing",
    "valid",
)


class OverrideSerializer(serializers.ModelSerializer):
    class Meta:
        model = RotationPolicy
        fields = POLICY_FIELDS


class GlobalSerializer(serializers.ModelSerializer):
    # null: the lifetime in days from the agent security settings
    cert_ttl_hours = serializers.IntegerField(
        min_value=POLICY_LIMITS["cert_ttl_hours"][0],
        max_value=POLICY_LIMITS["cert_ttl_hours"][1],
        allow_null=True,
    )

    class Meta:
        model = AgentSecuritySettings
        fields = POLICY_FIELDS
        extra_kwargs = {f: {"required": True} for f in POLICY_FIELDS}

    def to_internal_value(self, data):
        # the GET shows cert_days in hours; sent back unchanged it stays linked
        sec = self.instance
        if (
            isinstance(data, dict)
            and sec is not None
            and data.get("cert_ttl_hours") == sec.cert_days * 24
        ):
            data = {**data, "cert_ttl_hours": None}
        return super().to_internal_value(data)


def _global(sec) -> dict:
    out = policy.global_policy(sec)
    if out["cert_ttl_hours"] is None:
        out["cert_ttl_hours"] = sec.cert_days * 24
    return out


def _override(row) -> dict:
    scoped = row.client if row.client_id else row.site
    return {
        "scope": "client" if row.client_id else "site",
        "id": scoped.pk,
        "name": scoped.name,
        "client_name": scoped.client.name if row.site_id else None,
        **{f: getattr(row, f) for f in POLICY_FIELDS},
    }


def _listing() -> dict:
    rows = RotationPolicy.objects.select_related("client", "site__client").order_by(
        "client__name", "site__client__name", "site__name"
    )
    return {
        "global": _global(pki.security_settings()),
        "limits": {f: list(b) for f, b in POLICY_LIMITS.items()},
        "overrides": [_override(r) for r in rows],
    }


class RotationPolicies(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(_listing())

    def put(self, request):
        data = request.data if hasattr(request.data, "get") else {}
        scope, pk, body = data.get("scope"), data.get("id"), data.get("policy")
        if scope not in SCOPES:
            return notify_error("scope must be global, client or site")
        if scope == "global":
            if not isinstance(body, dict):
                return notify_error("policy must be an object")
            target = None
        else:
            if not isinstance(pk, int) or isinstance(pk, bool):
                return notify_error("id must be an integer")
            if body is not None and not isinstance(body, dict):
                return notify_error("policy must be an object or null")
            target = (
                (Client if scope == "client" else Site).objects.filter(pk=pk).first()
            )
            if target is None:
                return Response({"detail": f"{scope} {pk} not found"}, status=404)
        if denied := stepup_denied(request, "Changing rotation policies needs it."):
            return denied
        if scope == "global":
            sec = pki.security_settings()
            before = _global(sec)
            serializer = GlobalSerializer(instance=sec, data=body)
            if not serializer.is_valid():
                return Response({"policy": serializer.errors}, status=400)
            sec = serializer.save()
            after = _global(sec)
            what = "the global rotation policy"
        else:
            lookup = {scope: target}
            row = RotationPolicy.objects.filter(**lookup).first()
            before = {f: getattr(row, f) for f in POLICY_FIELDS} if row else None
            if body is None:
                if row:
                    row.delete()
                after = None
            else:
                # a put replaces the override, left-out fields inherit
                serializer = OverrideSerializer(
                    instance=row or RotationPolicy(**lookup),
                    data={f: body.get(f) for f in POLICY_FIELDS},
                )
                if not serializer.is_valid():
                    return Response({"policy": serializer.errors}, status=400)
                row = serializer.save()
                after = {f: getattr(row, f) for f in POLICY_FIELDS}
            what = f"the rotation policy of {scope} {target.name}"
        if before != after:
            AuditLog.objects.create(
                username=request.user.username,
                object_type=AuditObjType.CORE,
                action=AuditActionType.MODIFY,
                message=f"{request.user.username} changed {what}: {before} -> {after}",
                debug_info=get_debug_info(),
            )
        return Response(_listing())


def _status(ident, cred, live, certs, cloned, pol, now) -> str:
    if ident is not None and ident.state == IdentityState.BLOCKED:
        return "blocked"
    if ident is not None and ident.state == IdentityState.QUARANTINED:
        return "quarantined"
    if cloned:
        return "clone_alert"
    if not certs and cred is None:
        return "none"
    if live is None:
        return "revoked" if certs else "none"
    if live.not_after <= now:
        grace = dt.timedelta(days=pol["offline_grace_days"])
        return "offline_grace" if now - live.not_after <= grace else "expired"
    lifetime = (live.not_after - live.not_before).total_seconds()
    elapsed = (now - live.not_before).total_seconds()
    if lifetime > 0 and elapsed / lifetime >= pol["renew_pct"] / 100:
        return "renewing"
    return "valid"


def _keystore(ident):
    """The scheme the agent keeps its key in, from the "ks:<scheme>" cap."""
    caps = ident.caps if ident is not None and isinstance(ident.caps, list) else []
    return next(
        (c[3:] for c in caps if isinstance(c, str) and c.startswith("ks:")), None
    )


class TrustMatrix(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        params = request.query_params
        status = params.get("status") or None
        if status and status not in STATUSES:
            return notify_error("Invalid status")
        limit = _int_param(params, "limit", MATRIX_DEFAULT, 1, MATRIX_MAX)
        offset = _int_param(params, "offset", 0, 0, 2**31)
        if limit is None or offset is None:
            return notify_error("Invalid limit or offset")
        agents = (
            Agent.objects.filter_by_role(request.user)
            .select_related("site__client")
            .order_by("hostname", "pk")
        )
        if q := params.get("q"):
            agents = agents.filter(hostname__icontains=q)
        agents = list(agents)
        pks = [a.pk for a in agents]
        now = djangotime.now()
        certs = {}
        for cert in AgentCertificate.objects.filter(agent_id__in=pks).order_by(
            "-issued_at", "-pk"
        ):
            certs.setdefault(cert.agent_id, []).append(cert)
        idents = {i.agent_id: i for i in AgentIdentity.objects.filter(agent_id__in=pks)}
        creds = {
            c.agent_id: c for c in AgentCredential.objects.filter(agent_id__in=pks)
        }
        cloned = set(
            SecurityEvent.objects.filter(
                kind=SecurityEventKind.TOKEN_REUSE,
                agent_id__in=pks,
                last_seen__gte=now - CLONE_WINDOW,
            ).values_list("agent_id", flat=True)
        )
        pin_seq = PinSet.objects.order_by("-seq").values_list("seq", flat=True).first()
        tab = policy.table()
        rows, counts = [], {s: 0 for s in STATUSES}
        for agent in agents:
            own = certs.get(agent.pk, [])
            live = next(
                (c for c in own if c.revoked_at is None or c.revoked_at > now), None
            )
            ident, cred = idents.get(agent.pk), creds.get(agent.pk)
            pol = policy.resolve(agent.site_id, agent.site.client_id, tab)
            state = _status(ident, cred, live, own, agent.pk in cloned, pol, now)
            counts[state] += 1
            if status and state != status:
                continue
            seq = ident.pin_seq if ident else 0
            rows.append(
                {
                    "agent_id": agent.agent_id,
                    "hostname": agent.hostname,
                    "client": agent.site.client.name,
                    "site": agent.site.name,
                    "status": state,
                    "fingerprint": live.fingerprint_sha256 if live else None,
                    "cert_not_after": live.not_after if live else None,
                    "countdown_s": (
                        int((live.not_after - now).total_seconds()) if live else None
                    ),
                    "rotated_at": cred.prev_rotated_at if cred else None,
                    "pin_seq": seq,
                    "pin_current": pin_seq is not None and seq == pin_seq,
                    "identity_state": ident.state if ident else None,
                    "rotate_pending": list(ident.rotate_pending) if ident else [],
                    "keystore": _keystore(ident),
                }
            )
        return Response(
            {
                "total": len(rows),
                "counts": counts,
                "pin_seq": pin_seq,
                "agents": rows[offset : offset + limit],
            }
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import binascii
import datetime as dt
import ipaddress

from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from agents.permissions import AgentPerms
from core.permissions import CoreSettingsPerms
from core.utils import stepup_denied
from logs.models import AuditLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.helpers import get_client_ip, get_nats_hosts, notify_error
from ulrmm.middleware import get_debug_info

from . import events, identity, pki, policy, signing
from .models import (
    AgentCredential,
    AgentIdentity,
    AgentSecuritySettings,
    CredentialKind,
    IdentityState,
    MtlsMode,
    SecurityEvent,
    SecurityEventKind,
    SecurityEventSeverity,
)

FIELDS = ("mtls_mode", "cert_days", "backup_pins", "sec2_mode")
SEC2_ONLINE = dt.timedelta(days=7)
MISSING_SHOWN = 50
MAX_REASON = 200
ROTATE_SCOPES = ("agent", "site", "client", "all")
MAX_ROTATE_IDS = 1000
MAX_BACKUP_PINS = 8
EVENTS_DEFAULT = 100
EVENTS_MAX = 200
# a lower rank is weaker and needs the step-up
RANK = {MtlsMode.OFF: 0, MtlsMode.OPTIONAL: 1, MtlsMode.REQUIRED: 2}
CERTS_SHOWN = 10


def _pin_ok(value) -> bool:
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


class AgentSecuritySerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentSecuritySettings
        fields = FIELDS

    def validate_backup_pins(self, value):
        if not isinstance(value, list) or len(value) > MAX_BACKUP_PINS:
            raise serializers.ValidationError(
                f"at most {MAX_BACKUP_PINS} pins as a list"
            )
        for pin in value:
            if not _pin_ok(pin):
                raise serializers.ValidationError(
                    "each pin is the base64 sha256 of a SubjectPublicKeyInfo"
                )
        return list(dict.fromkeys(value))


def _pinset() -> dict | None:
    try:
        pins = signing.current_pinset()
    except signing.Unavailable:
        return None
    return {
        "seq": pins.seq,
        "primary": pins.primary,
        "backup": pins.backup,
        "cmd": [{"kid": c["kid"], "state": c["state"]} for c in pins.cmd or []],
        "sec2": pins.sec2,
        "created": pins.created,
    }


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _nats_standard() -> bool:
    """NATS can be reached without nginx, so natsauth is not asked."""
    if getattr(settings, "USE_NATS_STANDARD", False):
        return True
    return not all(_loopback(host) for host in get_nats_hosts()[:2])


def _payload(sec, user) -> dict:
    fingerprint, not_after = pki.ca_info()
    return {
        "mtls_mode": sec.mtls_mode,
        "cert_days": sec.cert_days,
        # set by the global rotation policy, wins over cert_days
        "cert_ttl_hours": sec.cert_ttl_hours,
        "ca_fingerprint_sha256": fingerprint,
        "ca_not_after": not_after,
        "nats_standard": _nats_standard(),
        "coverage": pki.coverage(user),
        "backup_pins": sec.backup_pins,
        "pins": _pinset(),
        "sec2_mode": sec.sec2_mode,
        "sec2_coverage": sec2_coverage(user),
    }


def sec2_coverage(user=None) -> dict:
    """Agents seen in the last 7 days, those with an active identity and a
    token family; the missing list holds only agents the user may see."""
    recent = Agent.objects.filter(last_seen__gte=djangotime.now() - SEC2_ONLINE)
    ident = AgentIdentity.objects.filter(
        agent=OuterRef("pk"), state=IdentityState.ACTIVE
    ).exclude(nkey=None)
    family = AgentCredential.objects.filter(
        agent=OuterRef("pk"), kind=CredentialKind.FAMILY, revoked_at=None
    )
    recent = recent.annotate(has_id=Exists(ident), has_family=Exists(family))
    scoped = (
        recent
        if user is None
        else recent.filter(pk__in=Agent.objects.filter_by_role(user).values("pk"))
    )
    missing = (
        scoped.filter(Q(has_id=False) | Q(has_family=False))
        .order_by("hostname", "pk")
        .values("agent_id", "hostname", "version", "last_seen")
    )
    return {
        "agents": recent.count(),
        "with_identity": recent.filter(has_id=True).count(),
        "with_family": recent.filter(has_family=True).count(),
        "missing": list(missing[:MISSING_SHOWN]),
    }


def _sec2_refused(request):
    """Response refusing the switch to sec2 required, or None."""
    cov = sec2_coverage(request.user)
    if cov["with_identity"] >= cov["agents"] and cov["with_family"] >= cov["agents"]:
        return None
    if request.data.get("force") is not True:
        return Response(
            {
                "detail": "Not every agent seen in the last 7 days has an identity "
                "and a token family yet. Agents without one lose their connection.",
                "sec2_coverage": cov,
            },
            status=400,
        )
    return stepup_denied(
        request,
        "Requiring signed commands before every agent has an identity needs it.",
    )


def _sec2_changed() -> None:
    """Sessions of every agent dropped, NATS users rendered again."""
    from ulrmm.utils import reload_nats

    from . import envelope

    for agent_id in Agent.objects.values_list("agent_id", flat=True).iterator():
        envelope.forget(agent_id)
    reload_nats()


def _required_refused(request):
    """Response refusing the switch to required, or None."""
    if _nats_standard():
        return notify_error(
            "Agents reach NATS directly while USE_NATS_STANDARD is set or "
            "NATS_STD_BIND_HOST / NATS_WS_BIND_HOST is not a loopback address, "
            "so client certificates cannot be required."
        )
    cov = pki.coverage(request.user)
    if pki.full_coverage(cov):
        return None
    if request.data.get("force") is not True:
        return Response(
            {
                "detail": "Not every agent has presented a client certificate yet. "
                "Agents without one lose their connection.",
                "coverage": cov,
            },
            status=400,
        )
    return stepup_denied(
        request, "Requiring certificates before every agent has one needs it."
    )


class AgentSecurity(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        return Response(_payload(pki.security_settings(), request.user))

    def put(self, request):
        sec = pki.security_settings()
        before = {f: getattr(sec, f) for f in FIELDS}
        serializer = AgentSecuritySerializer(
            instance=sec, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        mode = serializer.validated_data.get("mtls_mode", sec.mtls_mode)
        if RANK[mode] < RANK[before["mtls_mode"]]:
            if denied := stepup_denied(
                request, "Lowering the agent certificate mode needs it."
            ):
                return denied
        if mode == MtlsMode.REQUIRED and before["mtls_mode"] != MtlsMode.REQUIRED:
            if refused := _required_refused(request):
                return refused
        sec2 = serializer.validated_data.get("sec2_mode", before["sec2_mode"])
        if RANK[sec2] < RANK[before["sec2_mode"]]:
            if denied := stepup_denied(
                request, "Lowering the signed command mode needs it."
            ):
                return denied
        if sec2 == MtlsMode.REQUIRED and before["sec2_mode"] != MtlsMode.REQUIRED:
            if refused := _sec2_refused(request):
                return refused
        backup = serializer.validated_data.get("backup_pins", before["backup_pins"])
        if backup != before["backup_pins"]:
            if denied := stepup_denied(
                request, "Changing the backup pins agents trust needs it."
            ):
                return denied

        # a new lifetime in days replaces the one the global policy set in hours
        days = serializer.validated_data.get("cert_days", before["cert_days"])
        extra = {"cert_ttl_hours": None} if days != before["cert_days"] else {}
        sec = serializer.save(**extra)
        after = {f: getattr(sec, f) for f in FIELDS}
        if before != after:
            AuditLog.audit_object_changed(
                request.user.username,
                AuditObjType.CORE,
                before,
                after,
                "Agent security",
                debug_info=get_debug_info(),
            )
        if before["sec2_mode"] != after["sec2_mode"]:
            _sec2_changed()
        return Response(_payload(sec, request.user))


def _agent(agent_id: str) -> Agent:
    return get_object_or_404(
        Agent.objects.only("agent_id", "hostname"), agent_id=agent_id
    )


def _cert(cert, now) -> dict:
    return {
        "serial": cert.serial,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "issued_at": cert.issued_at,
        "revoked_at": cert.revoked_at,
        "last_seen": cert.last_seen,
        "active": cert.is_active(now),
    }


class AgentCert(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]

    def get(self, request, agent_id):
        agent = _agent(agent_id)
        now = djangotime.now()
        certs = list(agent.certificates.order_by("-issued_at", "-pk")[:CERTS_SHOWN])
        active = next((c for c in certs if c.is_active(now)), None)
        return Response(
            {
                "mtls_mode": pki.mtls_mode(),
                "active": _cert(active, now) if active else None,
                "certs": [_cert(c, now) for c in certs],
                "renew_pct": policy.effective(agent)["renew_pct"],
            }
        )


class ResetAgentCert(APIView):
    """Revokes the agent's certificates, so its token alone gets a new one."""

    permission_classes = [IsAuthenticated, AgentPerms]

    def post(self, request, agent_id):
        agent = _agent(agent_id)
        if denied := stepup_denied(request, "Resetting a client certificate needs it."):
            return denied
        revoked = pki.revoke(agent)
        _audit_agent(
            request,
            agent,
            f"{request.user.username} reset the client certificate "
            f"of {agent.hostname} ({revoked} revoked)",
        )
        return Response({"revoked": revoked})


def _int_param(params, name, default, low, high):
    raw = params.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if low <= value <= high else None


class SecurityEvents(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def get(self, request):
        params = request.query_params
        events = SecurityEvent.objects.select_related("agent").order_by("-pk")
        severity, kind = params.get("severity"), params.get("kind")
        if severity:
            if severity not in SecurityEventSeverity.values:
                return notify_error("Invalid severity")
            events = events.filter(severity=severity)
        if kind:
            if kind not in SecurityEventKind.values:
                return notify_error("Invalid kind")
            events = events.filter(kind=kind)
        if agent_id := params.get("agent_id"):
            events = events.filter(agent_uid=agent_id)
        limit = _int_param(params, "limit", EVENTS_DEFAULT, 1, EVENTS_MAX)
        before = _int_param(params, "before", None, 1, 2**63 - 1)
        if limit is None or (params.get("before") and before is None):
            return notify_error("Invalid limit or before")
        if before is not None:
            events = events.filter(pk__lt=before)
        # events of agents outside the user's scope are left out
        events = events.filter(
            Q(agent=None) | Q(agent__in=Agent.objects.filter_by_role(request.user))
        )
        return Response(
            {
                "results": [
                    {
                        "id": e.pk,
                        "kind": e.kind,
                        "severity": e.severity,
                        "agent_id": e.agent_uid,
                        "hostname": e.agent.hostname if e.agent else "",
                        "source_ip": e.source_ip,
                        "detail": e.detail,
                        "count": e.count,
                        "first_seen": e.first_seen,
                        "last_seen": e.last_seen,
                    }
                    for e in events[:limit]
                ],
                "kinds": [
                    {"value": value, "label": label}
                    for value, label in SecurityEventKind.choices
                ],
            }
        )


def identity_payload(agent) -> dict:
    ident = AgentIdentity.objects.filter(agent=agent).first()
    cred = AgentCredential.objects.filter(agent=agent).first()
    return {
        "identity": (
            {
                "kid": ident.kid,
                "state": ident.state,
                "caps": ident.caps,
                "nkey": ident.nkey or "",
                "pin_seq": ident.pin_seq,
                "registered_at": ident.registered_at,
                "rotated_at": ident.rotated_at,
                "last_hs": ident.last_hs,
                "quarantined_at": ident.quarantined_at,
                "reason": ident.reason,
                "release_until": ident.release_until,
                "rotate_pending": ident.rotate_pending,
            }
            if ident
            else None
        ),
        "credential": (
            {
                "kind": cred.kind,
                "access_expires": cred.access_expires,
                "refresh_expires": cred.refresh_expires,
                "generation": cred.generation,
                "rotated_at": cred.prev_rotated_at,
                "revoked_at": cred.revoked_at,
            }
            if cred
            else None
        ),
        "sec2_mode": pki.security_settings().sec2_mode,
    }


class AgentIdentityInfo(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]

    def get(self, request, agent_id):
        return Response(identity_payload(_agent(agent_id)))


def _audit_agent(request, agent, message: str) -> None:
    by = request.user.username
    AuditLog.objects.create(
        agent=agent.hostname,
        agent_id=agent.agent_id,
        username=by,
        message=message,
        object_type=AuditObjType.AGENT,
        action=AuditActionType.MODIFY,
        debug_info=get_debug_info(),
    )


class _Emergency(APIView):
    permission_classes = [IsAuthenticated, AgentPerms]
    stepup_why = ""
    done = ""

    def act(self, request, agent, reason):
        raise NotImplementedError

    def post(self, request, agent_id):
        agent = _agent(agent_id)
        if denied := stepup_denied(request, self.stepup_why):
            return denied
        reason = request.data.get("reason", "")
        if not isinstance(reason, str) or len(reason) > MAX_REASON:
            return notify_error(f"reason: at most {MAX_REASON} characters")
        if self.act(request, agent, reason) is None:
            return Response(
                {"detail": "the agent has no identity in a state that allows this"},
                status=409,
            )
        what = self.done + (f" ({reason})" if reason else "")
        _audit_agent(request, agent, f"{request.user.username} {what} {agent.hostname}")
        return Response(identity_payload(agent))


class QuarantineAgent(_Emergency):
    stepup_why = "Quarantining an agent needs it."
    done = "quarantined"

    def act(self, request, agent, reason):
        return identity.quarantine(
            agent,
            reason or f"by {request.user.username}",
            ip=get_client_ip(request.META),
        )


class ReleaseAgent(_Emergency):
    stepup_why = "Releasing an agent needs it."
    done = "released"

    def act(self, request, agent, reason):
        return identity.release(agent)


class ResetAgentIdentity(_Emergency):
    stepup_why = "Resetting an agent identity needs it."
    done = "reset the identity of"

    def act(self, request, agent, reason):
        return identity.reset_identity(agent)


class BlockAgent(_Emergency):
    stepup_why = "Blocking an agent needs it."
    done = "blocked"

    def act(self, request, agent, reason):
        return identity.block(agent, reason or f"by {request.user.username}")


def _rotate_agents(user, scope, ids):
    agents = Agent.objects.filter_by_role(user).only("pk", "agent_id")
    if scope == "all":
        return agents
    if not isinstance(ids, list) or not ids or len(ids) > MAX_ROTATE_IDS:
        return None
    if scope == "agent":
        if not all(isinstance(i, str) for i in ids):
            return None
        return agents.filter(agent_id__in=ids)
    if not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
        return None
    if scope == "site":
        return agents.filter(site_id__in=ids)
    return agents.filter(site__client_id__in=ids)


class SecurityRotate(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        data = request.data if hasattr(request.data, "get") else {}
        scope, what = data.get("scope"), data.get("what")
        if scope not in ROTATE_SCOPES:
            return notify_error("scope must be agent, site, client or all")
        if (
            not isinstance(what, list)
            or not what
            or not all(w in identity.ROTATABLE for w in what)
        ):
            return notify_error("what must list session, cert, token or identity")
        agents = _rotate_agents(request.user, scope, data.get("ids"))
        if agents is None:
            return notify_error("ids must be a list of agent ids, site or client pks")
        if denied := stepup_denied(request, "Forcing a rotation needs it."):
            return denied
        what = list(dict.fromkeys(what))
        agents = list(agents)
        counts = identity.request_rotation(agents, what)
        detail = f"{', '.join(what)} for {len(agents)} agents ({scope})"
        events.record(
            SecurityEventKind.ROTATION_FORCED,
            SecurityEventSeverity.INFO,
            detail=f"{request.user.username}: {detail}",
        )
        AuditLog.objects.create(
            username=request.user.username,
            object_type=AuditObjType.CORE,
            action=AuditActionType.MODIFY,
            message=f"{request.user.username} forced a rotation: {detail}",
            debug_info=get_debug_info(),
        )
        return Response({"agents": len(agents), "counts": counts})


class RotateCommandKey(APIView):
    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        if denied := stepup_denied(request, "Rotating the command key needs it."):
            return denied
        try:
            row = signing.rotate_command_key()
        except signing.Unavailable as e:
            return notify_error(str(e))
        events.record(
            SecurityEventKind.COMMAND_KEY_ROTATED,
            SecurityEventSeverity.INFO,
            detail=f"next key {row.kid} by {request.user.username}",
        )
        AuditLog.objects.create(
            username=request.user.username,
            object_type=AuditObjType.CORE,
            action=AuditActionType.MODIFY,
            message=f"{request.user.username} started a command key rotation "
            f"(next key {row.kid})",
            debug_info=get_debug_info(),
        )
        return Response({"kid": row.kid, "state": row.state, "pins": _pinset()})


class PromotePins(APIView):
    """After the chain moved to a backup pin: the backup list is cleared,
    agents get the new set with the next seq."""

    permission_classes = [IsAuthenticated, CoreSettingsPerms]

    def post(self, request):
        sec = pki.security_settings()
        backup = list(sec.backup_pins or [])
        try:
            primary = signing.spki_pins()
        except Exception as e:
            return notify_error(f"server chain unreadable: {e}")
        if not backup or not set(primary) & set(backup):
            return notify_error(
                "The server chain does not use one of the backup pins yet."
            )
        if denied := stepup_denied(request, "Promoting the backup pins needs it."):
            return denied
        sec.backup_pins = []
        sec.save()
        AuditLog.audit_object_changed(
            request.user.username,
            AuditObjType.CORE,
            {"backup_pins": backup},
            {"backup_pins": []},
            "Agent security",
            debug_info=get_debug_info(),
        )
        return Response({"pins": _pinset()})

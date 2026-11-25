# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import errno
import hashlib
import hmac
import os
import re
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError, transaction
from django.db.models import Q, Value
from django.db.models.functions import Greatest, Least
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.exceptions import (
    APIException,
    NotAuthenticated,
    PermissionDenied,
    ValidationError,
)
from rest_framework.response import Response

from agents.models import Agent
from core.models import CoreSettings
from core.utils import get_core_settings, stepup_denied
from logs.models import AuditLog
from ulrmm.constants import CORESETTINGS_CACHE_KEY, AuditActionType, AuditObjType
from ulrmm.permissions import _has_perm, _is_restricted

from . import blocks
from . import resolver
from .models import (
    ACTIVE_STATUSES,
    LINUX_FILES_METHOD,
    MODE_CHANGED,
    OPEN_RUNS,
    RECEIVING_REASON,
    SELECTABLE_KINDS,
    WINDOWS_METHOD,
    Authority,
    BackupPolicy,
    BackupRun,
    DeviceBackupState,
    HoldStatus,
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    Pairing,
    PolicyChangeHold,
    Profile,
    RunStatus,
    StorageTarget,
    Transfer,
)
from .serializers import (
    CaptureGrantSerializer,
    CompleteCaptureSerializer,
    CompleteRestoreSerializer,
    ConfigSerializer,
    HookConfirmSerializer,
    ImageSerializer,
    ManifestSerializer,
    ProfileSerializer,
    RestoreGrantSerializer,
    NativeRestoreSerializer,
    TargetSerializer,
)
from .service import (
    CHANGED_PATH,
    NO_INTERNAL,
    agent_allowed,
    audit,
    capability,
    check_path,
    covers,
    has_flag,
    masked_hooks,
    not_covered,
    internal_available,
    keyed_hooks,
    origin,
    queue_capture,
    script_hash,
    set_status,
    storage_encryption,
    script_names,
    suspended_hooks,
    usage_later,
)
from .storage import (
    CHUNK_SIZE,
    DESTINATION,
    NO_SPACE,
    OTHER_STORE,
    UNCONFIRMED_STORAGE,
    DamagedFile,
    StoreUnavailable,
    UnconfirmedStorage,
    check_root,
    claim_store,
    directory,
    free_bytes,
    image_file,
    imaging_root,
    newest_files,
    remove_image_file,
)
from .tasks import verify_image

VIEW = "can_view_images"
MANAGE = "can_manage_images"
RESTORE = "can_restore_images"
CAPTURE = Transfer.Direction.CAPTURE
RECOVERY = Transfer.Direction.RESTORE
BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{43})\Z")
NUMBER = re.compile(r"\d{1,19}\Z", re.ASCII)
RENEW_LIMIT = timedelta(days=7)
STORED = Q(offset__gt=0) | Q(status__in=(ImageStatus.VERIFYING, ImageStatus.VERIFIED))
REPLACED = "The store that held this point was replaced in Global Settings."
DISCARDABLE = (ImageStatus.WAITING, ImageStatus.UPLOADING, ImageStatus.FAILED)


class ImageBusy(APIException):
    status_code = 409
    default_detail = "The image is being verified. Retry shortly."


def _lock_image(image):
    # verify_image holds verifying and rechecked rows for the whole read. Fail
    # fast there instead of parking a worker; other holders are short requests.
    nowait = image.status in (ImageStatus.VERIFYING, ImageStatus.VERIFIED)
    try:
        with transaction.atomic():
            locked = (
                Image.objects.select_for_update(nowait=nowait)
                .filter(pk=image.pk)
                .first()
            )
    except DatabaseError:
        if not nowait:
            raise
        raise ImageBusy() from None
    if locked is None:
        raise Http404
    return locked


def renew(grant, window=timedelta(hours=1)):
    # Activity slides the grant up to renew_until. The filter keeps a grant that
    # was revoked or expired meanwhile from coming back.
    now = timezone.now()
    Transfer.objects.filter(
        pk=grant.pk, expires_at__gt=now, renew_until__isnull=False
    ).update(
        expires_at=Least("renew_until", Greatest("expires_at", Value(now + window)))
    )


def _agent(user, agent_id, *flags, lock=False):
    agents = Agent.objects
    if lock:
        agents = agents.select_for_update()
    agent = get_object_or_404(agents, agent_id=agent_id)
    if not agent_allowed(user, agent, *flags):
        raise PermissionDenied()
    return agent


def _validated(serializer_class, data):
    serializer = serializer_class(data=data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


def _storage(manager=False):
    problem = ""
    try:
        with directory() as root:
            free = free_bytes(root)
    except StoreUnavailable:
        free, problem = None, OTHER_STORE
    except OSError:
        free = None
    storage = {"configured": free is not None, "internal": internal_available()}
    if manager:
        storage["problem"] = problem
        storage["location"] = imaging_root()
        storage["free_bytes"] = free
        storage["reserve_bytes"] = settings.ULRMM_IMAGING_RESERVE_BYTES
    return storage


def sync_state(agent, state):
    if not state.protocol:
        name = "legacy"
    elif state.acked_hash == state.config_hash and state.ack_status == "applied":
        name = "synced"
    elif state.ack_status == "error" and state.acked_version == state.config_version:
        name = "error"
    else:
        name = "pending"
    return {
        "state": name,
        "config_version": state.config_version,
        "acked_version": state.acked_version,
        "acked_at": state.acked_at,
        "pending_since": state.pending_since,
        "offline": not agent.is_online,
        "errors": state.ack_errors,
    }


def run_row(run, show_output, log_from=None):
    """A run for an answer; hook output only for callers who may run scripts."""
    # the name the claim carried; a result without one looks the script up
    known = {
        (h["phase"], h["script_id"]): h["script_name"]
        for h in run.claimed_hooks
        if "script_name" in h
    }
    for h in run.hooks:
        if "script_name" in h:
            known[(h["phase"], h["script_id"])] = h["script_name"]
    lost = [
        h["script_id"] for h in run.hooks if (h["phase"], h["script_id"]) not in known
    ]
    names = script_names(lost) if lost else {}
    hooks = [
        {
            **h,
            "script_name": known.get(
                (h["phase"], h["script_id"]), names.get(h["script_id"], "")
            ),
        }
        for h in run.hooks
    ]
    if not show_output:
        hooks = [
            {k: v for k, v in h.items() if k not in ("stdout", "stderr")} for h in hooks
        ]
    row = {
        "id": str(run.id),
        "image": str(run.image_id),
        "trigger": run.trigger,
        "status": run.status,
        "step": run.step,
        "deferred_reason": run.deferred_reason,
        "reason": run.reason,
        "pause_reason": run.pause_reason,
        "counters": run.counters,
        "warnings": run.warnings,
        "hooks": hooks,
        "output_hidden": not show_output,
        "cancel_requested": run.cancel_requested,
        "cancelled_by": run.cancelled_by.username if run.cancelled_by else None,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
    }
    if log_from is not None:
        skip = max(0, log_from - run.log_start)
        row.update(log=run.log[skip:], log_start=run.log_start + skip)
    return row


def masked_view(view, show_args):
    """An effective view without hook env values, and args only for script users."""
    fields = dict(view["fields"])
    hooks = fields["hooks"]
    fields["hooks"] = {**hooks, "value": masked_hooks(hooks["value"], show_args)}
    hold = view["hold"]
    if hold:
        hold = {
            **hold,
            "changes": [
                (
                    {
                        **c,
                        "held": masked_hooks(c["held"], show_args),
                        "proposed": masked_hooks(c["proposed"], show_args),
                    }
                    if c["field"] == "hooks"
                    else c
                )
                for c in hold["changes"]
            ],
        }
    return {**view, "fields": fields, "hold": hold}


def _device_answer(request, agent, supported, profile, state, storage):
    from .native import readiness, shown_checks

    user = request.user
    view = resolver.effective(agent, profile, state)
    fields = view["fields"]
    show_args = agent_allowed(user, agent, "can_run_scripts")
    tab = resolver.table()
    ready, reason = readiness(
        agent, state, fields, tab, supported.get("native") or supported
    )
    can_manage = agent_allowed(user, agent, MANAGE)
    runs = (
        BackupRun.objects.filter(image__agent=agent)
        .select_related("cancelled_by")
        .defer("log")
    )
    active = runs.filter(
        status__in=OPEN_RUNS, image__status__in=ACTIVE_STATUSES
    ).first()
    return {
        "capability": supported,
        "storage": storage,
        "can_manage": can_manage,
        "can_restore": agent_allowed(user, agent, RESTORE),
        "config": ProfileSerializer(profile).data,
        "policy": (
            {"id": profile.policy_id, "name": profile.policy.name}
            if profile.policy_id
            else None
        ),
        "at_rest": storage_encryption(profile.destination),
        "pairing": _pairing_metadata(agent, user),
        "images": ImageSerializer(
            Image.objects.filter(agent=agent).order_by("-created_at"), many=True
        ).data,
        "effective": masked_view(view, show_args),
        "overrides": {
            **profile.overrides,
            **(
                {"hooks": masked_hooks(profile.overrides["hooks"], show_args)}
                if "hooks" in profile.overrides
                else {}
            ),
        },
        "enforced_by": {
            k: {"id": f["origin"]["id"], "name": f["origin"]["name"]}
            for k, f in fields.items()
            if f["locked"]
        },
        "sync": sync_state(agent, state),
        "checks": shown_checks(agent, state, fields, tab),
        "ready": ready,
        "not_ready_reason": reason,
        "active_run": run_row(active, show_args) if active else None,
        "runs": [run_row(r, show_args) for r in runs.order_by("-created_at")[:10]],
        "hold": masked_view(view, show_args)["hold"],
        "hooks_suspended": suspended_hooks(
            fields["hooks"]["value"],
            resolver.pinned_hooks(fields, profile, tab),
            fields["hooks"]["origin"],
        ),
        "can_run_scripts": show_args,
        "usage": _usage(state, fields, tab),
    }


def _usage(state, fields, tab):
    ids = {int(k) for k in state.usage} | {fields["target"]["value"]}
    return [
        {
            "target": pk,
            "name": tab["targets"][pk]["name"],
            "stored_bytes": state.usage.get(str(pk), 0),
            "quota_bytes": fields["quota_bytes"]["value"],
        }
        for pk in sorted(ids)
        if pk in tab["targets"]
    ]


def _device_save(request, agent, supported, profile, fields):
    body = request.data if isinstance(request.data, dict) else {}
    unknown = set(body) - {"set", "reset"}
    if unknown or not ({"set", "reset"} & set(body)):
        raise ValidationError(
            {
                k: [
                    "Send the changed settings under set and the reset ones under reset."
                ]
                for k in (unknown or ["set"])
            }
        )
    changes = body.get("set", {})
    reset = body.get("reset", [])
    if not isinstance(changes, dict):
        raise ValidationError({"set": ["Send the changed settings as an object."]})
    if not isinstance(reset, list) or not all(
        isinstance(k, str) and k in fields for k in reset
    ):
        raise ValidationError({"reset": ["Unknown setting."]})
    serializer = ConfigSerializer(data=changes)
    if not serializer.is_valid():
        raise ValidationError({"set": serializer.errors})
    config = serializer.validated_data
    if "hooks" in config:
        # a kept value comes from the device's own hooks, then the inherited ones
        config["hooks"] = keyed_hooks(
            config["hooks"],
            (profile.overrides.get("hooks", []), fields["hooks"]["value"]),
            "set",
        )
    locked = {
        k: [f"Enforced by backup policy {fields[k]['origin']['name']}."]
        for k in config
        if fields[k]["locked"]
    }
    if locked:
        raise ValidationError({"set": locked})
    offered = {
        v["mount"]
        for v in (supported.get("native") or {}).get("volumes", [])
        if v["kind"] in SELECTABLE_KINDS
    }
    for selector in config.get("volumes", ()):
        if selector not in offered:
            raise ValidationError(
                {
                    "set": {
                        "volumes": [
                            f"{selector} is not an extra volume on this device."
                        ]
                    }
                }
            )
    if "target" in config:
        target = resolver.table()["targets"][config["target"]]
        if not covers(target, agent.site.client_id, agent.site_id):
            raise ValidationError({"set": {"target": [not_covered(target)]}})
    overrides = {
        k: v for k, v in {**profile.overrides, **config}.items() if k not in reset
    }
    # an absent key inherits hooks, an empty list switches them off: both count
    if overrides.get("hooks") != profile.overrides.get("hooks"):
        if not agent_allowed(request.user, agent, "can_run_scripts"):
            raise PermissionDenied()
        if denied := stepup_denied(request, "Backup hooks run scripts on devices."):
            return denied
        from scripts.models import Script

        scripts = Script.objects.in_bulk(
            [h["script_id"] for h in overrides.get("hooks", [])]
        )
        # a kept pin stays, so a script edited after its pin stays suspended
        old = profile.hooks_pinned
        profile.hooks_pinned = {
            str(pk): old.get(str(pk)) or script_hash(script)
            for pk, script in scripts.items()
        }
        profile.hooks_approved_by = request.user
        profile.hooks_approved_at = timezone.now()
    profile.overrides = overrides
    profile.operator = request.user
    profile.save()
    audit(
        agent,
        request.user.username,
        f"Backup device settings changed: {', '.join(sorted(set(config) | set(reset)))}.",
    )
    return None


@api_view(["GET", "PUT"])
@transaction.atomic
def device(request, agent_id):
    if request.method == "GET" and "destination" in request.query_params:
        agent = _agent(request.user, agent_id, MANAGE)
        destination = request.query_params["destination"].strip()
        if not DESTINATION.fullmatch(destination):
            raise ValidationError({"destination": "Enter a valid backup folder."})
        return _no_cache(
            Response(
                {
                    "destination": destination,
                    "at_rest": storage_encryption(destination),
                    "capability": capability(agent),
                    "storage": _storage(),
                }
            )
        )
    flags = (MANAGE,) if request.method == "PUT" else (VIEW, MANAGE, RESTORE)
    agent = _agent(request.user, agent_id, *flags, lock=request.method == "PUT")
    supported = capability(agent)
    profile, state = resolver.rows(agent)
    storage = _storage(agent_allowed(request.user, agent, MANAGE))
    if request.method == "PUT":
        if not supported["supported"]:
            raise ValidationError(supported["reason"])
        profile = Profile.objects.select_for_update().get(pk=profile.pk)
        fields = resolver.effective(agent, profile, state)["fields"]
        if denied := _device_save(request, agent, supported, profile, fields):
            return denied
        profile, state = resolver.resolve_device(
            agent, cause="device", author=request.user
        )
    return Response(_device_answer(request, agent, supported, profile, state, storage))


@api_view(["GET"])
def device_effective(request, agent_id):
    agent = _agent(request.user, agent_id, VIEW, MANAGE, RESTORE)
    show_args = agent_allowed(request.user, agent, "can_run_scripts")
    return Response(masked_view(resolver.effective(agent), show_args))


@api_view(["POST"])
def device_check(request, agent_id):
    import asyncio

    agent = _agent(request.user, agent_id, MANAGE)
    _, state = resolver.rows(agent)
    if not state.protocol:
        return _problem(
            "Update the agent to run readiness checks from the dashboard.", 409
        )
    asyncio.run(agent.nats_cmd({"func": "imagingcheck"}, wait=False))
    audit(agent, request.user.username, "Backup readiness check requested.")
    return Response({}, status=202)


@api_view(["POST"])
@transaction.atomic
def hold_confirm(request, pk):
    found = get_object_or_404(PolicyChangeHold.objects.select_related("agent"), pk=pk)
    agent = _agent(request.user, found.agent.agent_id, MANAGE)
    # lock order everywhere: profile, then hold
    resolver.rows(agent)
    Profile.objects.select_for_update().filter(agent=agent).first()
    hold = PolicyChangeHold.objects.select_for_update().get(pk=pk)
    action = request.data.get("action") if isinstance(request.data, dict) else None
    if action not in ("confirm", "reject"):
        raise ValidationError({"action": ["Choose confirm or reject."]})
    if hold.status != HoldStatus.PENDING:
        return _problem("This change was already decided.", 409)
    pending = resolver.effective(agent)["hold"]
    # the live proposal: a policy edit since the last resolve needs a new review
    if not pending or request.data.get("proposed_hash") != pending["proposed_hash"]:
        return _problem("This change was updated; review it again.", 409)
    if action == "confirm" and any(c["field"] == "hooks" for c in pending["changes"]):
        # confirming changes which scripts run on the device
        if not agent_allowed(request.user, agent, "can_run_scripts"):
            raise PermissionDenied()
        if denied := stepup_denied(request, "Backup hooks run scripts on devices."):
            return denied
    hold.status = HoldStatus.CONFIRMED if action == "confirm" else HoldStatus.REJECTED
    hold.confirmed_by = request.user
    hold.confirmed_at = timezone.now()
    # a reject is remembered under the change it was shown
    hold.proposed_hash = pending["proposed_hash"]
    hold.save()
    if action == "confirm":
        resolver.resolve_device(
            agent,
            cause="device",
            author=request.user,
            members=hold.proposed_memberships,
        )
    audit(
        agent,
        request.user.username,
        f"Held backup settings change {hold.pk} {hold.status}.",
    )
    show_args = agent_allowed(request.user, agent, "can_run_scripts")
    return Response(masked_view(resolver.effective(agent), show_args))


FLEET_STATES = (
    "stale",
    "not_ready",
    "error",
    "pending",
    "legacy",
    "pending_confirmation",
)


@api_view(["GET"])
def fleet(request):
    from django.db.models import Max

    user = request.user
    if not has_flag(user, VIEW, MANAGE, RESTORE):
        raise PermissionDenied()
    agents = (
        Agent.objects.filter_by_role(user)
        .select_related("site__client", "backup_state", "profile")
        .annotate(last_verified=Max("image__verified_at"))
        .order_by("hostname", "pk")
    )
    query = request.query_params.get("q", "").strip()
    if query:
        agents = agents.filter(hostname__icontains=query)
    wanted = request.query_params.get("state", "")
    if wanted and wanted not in FLEET_STATES:
        raise ValidationError({"state": ["Unknown filter."]})
    try:
        limit = min(max(int(request.query_params.get("limit", 50)), 1), 500)
        offset = max(int(request.query_params.get("offset", 0)), 0)
    except ValueError:
        raise ValidationError("Use numbers for limit and offset.") from None
    holds = {
        h.agent_id: h
        for h in PolicyChangeHold.objects.filter(status=HoldStatus.PENDING)
    }
    runs = {
        r.image.agent_id: r
        for r in BackupRun.objects.filter(
            status__in=OPEN_RUNS, image__status__in=ACTIVE_STATUSES
        )
        .select_related("image")
        .defer("log")
    }
    tab = resolver.table()
    counts = dict.fromkeys(FLEET_STATES, 0)
    rows, seen = [], []
    for agent in agents:
        seen.append(agent.pk)
        state = getattr(agent, "backup_state", None) or DeviceBackupState(agent=agent)
        profile = getattr(agent, "profile", None)
        sync = sync_state(agent, state)["state"]
        hold = holds.get(agent.pk)
        tags = {
            "stale": "stale" in state.alerts,
            "not_ready": not state.ready,
            "error": sync == "error",
            "pending": sync == "pending",
            "legacy": sync == "legacy",
            "pending_confirmation": hold is not None,
        }
        for key, hit in tags.items():
            counts[key] += hit
        if wanted and not tags[wanted]:
            continue
        rows.append((agent, state, profile, sync, hold))
    page = []
    for agent, state, profile, sync, hold in rows[offset : offset + limit]:
        members = state.memberships or {}
        policies = [tab["global"]] + [
            tab[scope].get(members.get(scope)) for scope in ("client", "site")
        ]
        policies += resolver._shared(members, tab)
        if profile and profile.policy_id:
            policies.append(tab["policies"].get(profile.policy_id))
        run = runs.get(agent.pk)
        page.append(
            {
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "client": agent.site.client.name,
                "site": agent.site.name,
                "plat": agent.plat,
                "policies": [
                    {"id": p["id"], "name": p["name"], "level": p["scope"]}
                    for p in policies
                    if p
                ],
                "sync": sync,
                "ready": state.ready,
                "not_ready_reason": state.not_ready_reason,
                "last_verified_at": agent.last_verified,
                "next_run": profile.next_run if profile else None,
                "stored_bytes": sum(state.usage.values()),
                "alerts": sorted(state.alerts),
                "hold": (
                    {
                        "id": hold.pk,
                        "proposed_hash": resolver.live_hash(agent, profile, hold, tab),
                    }
                    if hold
                    else None
                ),
                "run": {"status": run.status, "step": run.step} if run else None,
                "can_manage": agent_allowed(user, agent, MANAGE),
            }
        )
    counts["all"] = len(seen)
    return Response(
        {
            "rows": page,
            "total": len(rows),
            "counts": counts,
            "internal": internal_available(),
        }
    )


def _target_row(target):
    return {
        "id": target.pk,
        "name": target.name,
        "kind": target.kind,
        "scope": target.scope,
        "client": target.client_id,
        "site": target.site_id,
        "quota_bytes": target.quota_bytes,
        "max_runs": target.max_runs,
        "is_default": target.is_default,
        "used_bytes": target.used_bytes,
        "unreachable_since": target.unreachable_since,
        "in_use": _target_in_use(target),
        "storage_encryption": storage_encryption(target.name),
    }


def _target_in_use(target):
    return (
        Profile.objects.filter(target=target).exists()
        or Profile.objects.filter(overrides__target=target.pk).exists()
        or Image.objects.filter(target=target).exists()
        or any(
            p.get("target") == target.pk
            for p in BackupPolicy.objects.values_list("config", flat=True)
        )
    )


@api_view(["GET", "POST", "PUT", "DELETE"])
@transaction.atomic
def targets(request, pk=None):
    user = request.user
    if request.method == "GET":
        if not (_has_perm(request, "can_view_core_settings") or has_flag(user, MANAGE)):
            raise PermissionDenied()
        rows = StorageTarget.objects.order_by("name", "pk")
        if _is_restricted(user):
            from clients.models import Client, Site

            rows = rows.filter(
                Q(scope="global")
                | Q(client__in=Client.objects.filter_by_role(user))
                | Q(site__in=Site.objects.filter_by_role(user))
            )
        return Response([_target_row(t) for t in rows])
    if not _has_perm(request, "can_edit_core_settings"):
        raise PermissionDenied()
    target = None
    if pk is not None:
        target = get_object_or_404(StorageTarget.objects.select_for_update(), pk=pk)
    elif request.method != "POST":
        return Response(status=405)
    if request.method == "DELETE":
        if target.is_default:
            return _problem("The default backup target cannot be deleted.", 409)
        if _target_in_use(target):
            return _problem("This backup target is in use.", 409)
        name = target.name
        target.delete()
        resolver.invalidate()
        audit(None, user.username, f"Backup target {name} deleted.")
        return Response(status=204)
    serializer = TargetSerializer(target, data=request.data, partial=target is not None)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    if (
        target is not None
        and _target_in_use(target)
        and data.get("name", target.name) != target.name
    ):
        raise ValidationError(
            {
                "name": [
                    "The name is the backup folder of existing points and cannot change."
                ]
            }
        )
    if target is not None and target.is_default and data.get("is_default") is False:
        raise ValidationError({"is_default": ["One target must be the default."]})
    target = target or StorageTarget()
    was_default = target.is_default
    for key, value in data.items():
        setattr(target, key, value)
    if target.is_default and not was_default:
        StorageTarget.objects.filter(is_default=True).update(is_default=False)
    target.save()
    resolver.invalidate()
    reached = (
        Agent.objects.all()
        if target.is_default != was_default
        else Agent.objects.filter(profile__target=target)
    )
    resolver.resolve_many(
        reached.values_list("pk", flat=True), cause="target", author=user
    )
    audit(None, user.username, f"Backup target {target.name} saved.")
    return Response(_target_row(target), status=201 if pk is None else 200)


@api_view(["POST"])
@transaction.atomic
def capture(request, agent_id):
    agent = _agent(request.user, agent_id, MANAGE, lock=True)
    supported = capability(agent)
    if not supported["supported"]:
        raise ValidationError(supported["reason"])
    if not _storage()["configured"]:
        return _problem("Configure private server imaging storage.", 503)
    profile, _ = resolver.rows(agent)
    profile = Profile.objects.select_for_update().get(pk=profile.pk)
    if profile.network_mode == "internal" and not internal_available():
        return _problem(NO_INTERNAL, 409)
    return Response(
        ImageSerializer(
            queue_capture(profile, request.user.username, request.user)
        ).data,
        status=202,
    )


def _root_state(path=None):
    current = imaging_root()
    problem = ""
    configured = False
    try:
        # the current store gets its marker, so a copy of it is recognised
        with directory():
            pass
        configured = True
    except StoreUnavailable:
        problem = OTHER_STORE
    except OSError:
        pass
    points = Image.objects.filter(STORED).count()
    # the newest stored data shows whether another folder is a current copy
    probes = newest_files()
    path = current if path is None else path
    return {
        "path": path,
        "current": current,
        "source": "dashboard" if get_core_settings().imaging_root else "server",
        "server_default": settings.ULRMM_IMAGING_ROOT,
        "configured": configured,
        "problem": problem,
        **check_root(
            path,
            current,
            probes,
            configured,
            bool(problem),
            get_core_settings().imaging_store_id,
        ),
        "reserve_bytes": settings.ULRMM_IMAGING_RESERVE_BYTES,
        "points": points,
        "docker": getattr(settings, "ULRMM_DOCKER", False),
    }


@api_view(["GET", "PUT"])
def storage(request):
    if not _has_perm(request, "can_edit_core_settings"):
        raise PermissionDenied()
    if request.method == "GET":
        return _no_cache(Response(_root_state(request.query_params.get("path"))))
    if denied := stepup_denied(request, "Moving the system image storage needs it."):
        return denied
    path = request.data.get("path")
    if not isinstance(path, str):
        raise ValidationError({"path": ["Enter a folder path."]})
    path = path.strip()
    # a lost disk: an empty folder replaces the store and its points fail
    start_new = request.data.get("start_new") is True
    state = _root_state(path or settings.ULRMM_IMAGING_ROOT)
    failed = next(
        (
            c["text"]
            for c in state["checks"]
            if not c["ok"] and not (start_new and c["key"] == "content")
        ),
        None,
    )
    if start_new and not failed and not state["can_start_new"]:
        failed = (
            "A new store needs an empty folder that does not hold the stored points."
        )
    if failed:
        raise ValidationError({"path": [failed]})
    message = f"System image storage moved from {state['current']} to {state['path']}."
    store = None
    if state["older_copy"] and not start_new:
        message += " It is an older copy; points without their data fail when checked."
    try:
        with transaction.atomic():
            core = CoreSettings.objects.select_for_update().get()
            core.imaging_root = path
            fields = ["imaging_root"]
            if start_new:
                now = timezone.now()
                lost = Image.objects.filter(STORED).exclude(status=ImageStatus.FAILED)
                Transfer.objects.filter(image__in=lost, expires_at__gt=now).update(
                    expires_at=now
                )
                retired = lost.update(
                    status=ImageStatus.FAILED, reason=REPLACED, updated_at=now
                )
                ImagePart.objects.all().delete()
                # the delete collector would load every block row first
                ImageBlock.objects.all()._raw_delete(ImageBlock.objects.db)
                core.imaging_store_id = store = secrets.token_hex(16)
                fields.append("imaging_store_id")
                message = (
                    f"System image storage replaced by a new store at {state['path']}, "
                    f"{retired} stored points retired."
                )
            core.save(update_fields=fields)
            try:
                claim_store(state["path"], store, core)
            except OSError as error:
                raise ValidationError(
                    {"path": [f"The folder cannot be marked: {error}"]}
                )
            AuditLog.objects.create(
                username=request.user.username,
                object_type=AuditObjType.CORE,
                action=AuditActionType.MODIFY,
                message=message[:255],
                before_value={"imaging_root": state["current"]},
                after_value={"imaging_root": state["path"]},
            )
    finally:
        # after the commit, or after a refused claim rolled back: a reader in
        # between may have cached the uncommitted or the old row
        cache.delete(CORESETTINGS_CACHE_KEY)
    return _no_cache(Response(_root_state()))


def _problem(detail, status):
    return Response({"detail": detail}, status=status)


def _check_storage(image):
    internal = image.network_mode == "internal"
    try:
        with directory(image.destination, internal=internal):
            pass
    except FileNotFoundError:
        with directory(internal=internal):
            pass


def _token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _no_cache(response):
    response["Cache-Control"] = "no-store"
    return response


def _pairing_metadata(agent, user):
    if not agent_allowed(user, agent, MANAGE):
        return None
    return (
        Pairing.objects.filter(agent=agent, expires_at__gt=timezone.now())
        .values("device_uuid", "disk_id", "expires_at", "network_mode")
        .first()
    )


@api_view(["POST", "DELETE"])
@transaction.atomic
def pair(request, agent_id):
    agent = _agent(request.user, agent_id, MANAGE, lock=True)
    if request.method == "DELETE":
        if Pairing.objects.filter(agent=agent).delete()[0]:
            audit(agent, request.user.username, "Offline imaging pairing revoked.")
        return Response(status=204)
    if agent.plat != "linux":
        raise ValidationError("Offline rescue pairing requires a Linux device.")
    if not capability(agent)["supported"]:
        raise ValidationError(capability(agent)["reason"])
    if not _storage()["configured"]:
        return _problem("Configure private server imaging storage.", 503)
    profile = Profile.objects.select_for_update().filter(agent=agent).first()
    if profile is None:
        return _problem("Save the imaging configuration before pairing recovery.", 409)
    identity = _validated(CaptureGrantSerializer, request.data)
    domain = origin(profile.network_mode)
    if not domain or (
        profile.network_mode == "internal" and not settings.ULRMM_IMAGING_INTERNAL_CIDRS
    ):
        return _problem("Configure the selected HTTPS imaging ingress.", 503)
    Pairing.objects.filter(agent=agent).delete()
    secret = secrets.token_urlsafe(32)
    pairing = Pairing.objects.create(
        agent=agent,
        user=request.user,
        network_mode=profile.network_mode,
        token_digest=_token_digest(secret),
        expires_at=timezone.now() + timedelta(days=90),
        **identity,
    )
    audit(
        agent, request.user.username, f"Offline imaging pairing {pairing.id} granted."
    )
    return _no_cache(
        Response(
            {
                "url": domain + reverse("imaging-poll", args=[pairing.id]),
                "token": secret,
                "expires_at": pairing.expires_at,
                "network_mode": pairing.network_mode,
            },
            status=201,
        )
    )


def _identity_matches(image, device_uuid, disk_id):
    return image.device_uuid is None or (
        image.device_uuid == device_uuid and image.disk_id == disk_id
    )


def _image_identity(image, device_uuid, disk_id):
    if not image.device_uuid:
        image.device_uuid = device_uuid
        image.disk_id = disk_id
        image.save(update_fields=["device_uuid", "disk_id"])


def _grant_response(grant, secret, *, status, image_id=None):
    return _no_cache(Response(_grant_data(grant, secret, image_id), status=status))


def _grant_data(grant, secret, image_id=None):
    data = {
        "url": origin(grant.image.network_mode)
        + reverse("imaging-transfer", args=[grant.id]),
        "token": secret,
        "claim": str(grant.id),
        "expires_at": grant.expires_at,
        "network_mode": grant.image.network_mode,
    }
    if image_id is not None:
        data["image_id"] = image_id
    return data


def _bearer(request, grant):
    match = BEARER.fullmatch(request.META.get("HTTP_AUTHORIZATION", ""))
    if (
        not match
        or not grant
        or not hmac.compare_digest(grant.token_digest, _token_digest(match[1]))
    ):
        raise NotAuthenticated("A valid imaging recovery credential is required.")
    return match[1]


@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
@transaction.atomic
def poll(request, pair_id):
    pairing = Pairing.objects.filter(pk=pair_id).first()
    secret = _bearer(request, pairing)
    check_path(request, pairing.network_mode)
    agent = get_object_or_404(Agent.objects.select_for_update(), pk=pairing.agent_id)
    if not agent_allowed(pairing.user, agent, MANAGE):
        raise PermissionDenied("Recovery pairing access was revoked.")
    pairing = get_object_or_404(Pairing, pk=pair_id)
    profile = Profile.objects.select_for_update().filter(agent=agent).first()
    now = timezone.now()
    if (
        pairing.expires_at <= now
        or not profile
        or profile.network_mode != pairing.network_mode
    ):
        raise PermissionDenied(
            "This recovery pairing has expired or needs to be configured again."
        )
    if not capability(agent)["supported"]:
        raise PermissionDenied("The device no longer supports offline client imaging.")
    image = (
        Image.objects.select_for_update()
        .filter(
            agent=agent,
            status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING),
        )
        .first()
    )
    if image is None:
        return _no_cache(Response(status=204))
    if image.network_mode != pairing.network_mode:
        return _problem(MODE_CHANGED, 409)
    if not _identity_matches(image, pairing.device_uuid, pairing.disk_id):
        return _problem(
            "The recovery pairing does not match the approved capture.", 409
        )
    try:
        _check_storage(image)
    except OSError as error:
        reason = (
            UNCONFIRMED_STORAGE
            if isinstance(error, UnconfirmedStorage)
            else "Imaging storage is unavailable."
        )
        Image.objects.filter(pk=image.pk).update(reason=reason)
        return _problem(reason, 503)
    grant = Transfer.objects.filter(
        image=image,
        direction=CAPTURE,
        expires_at__gt=now,
    ).first()
    if grant and grant.pairing_id != pair_id:
        return _no_cache(Response(status=204))
    if grant:
        renew(grant)
        grant.refresh_from_db(fields=["expires_at"])
    else:
        _image_identity(image, pairing.device_uuid, pairing.disk_id)
        grant = Transfer(
            image=image,
            direction=CAPTURE,
            target=agent,
            user=pairing.user,
            pairing=pairing,
            device_uuid=pairing.device_uuid,
            disk_id=pairing.disk_id,
            # A resume regenerates the stream without requests; every request
            # still re-checks the pairing, its mode and the operator role.
            expires_at=pairing.expires_at,
            renew_until=pairing.expires_at,
        )
    digest = hmac.digest(secret.encode("ascii"), grant.id.bytes, "sha256")
    ephemeral = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if grant._state.adding:
        grant.token_digest = _token_digest(ephemeral)
        grant.save()
        audit(
            agent,
            pairing.user.username,
            f"Offline pairing granted capture for image {image.id}.",
        )
    return _grant_response(grant, ephemeral, status=200, image_id=str(image.id))


@api_view(["POST"])
@transaction.atomic
def access(request, agent_id, image_id, direction):
    agent = _agent(request.user, agent_id, MANAGE if direction == CAPTURE else RESTORE)
    # a session without the two-factor step-up learns nothing about the image
    if direction == RECOVERY and (
        denied := stepup_denied(request, "This grants access to restore a device disk.")
    ):
        return denied
    image = _lock_image(get_object_or_404(Image, agent=agent, pk=image_id))
    selected = agent
    if direction == RECOVERY:
        confirmation = _validated(
            NativeRestoreSerializer if image.native else RestoreGrantSerializer,
            request.data,
        )
        selected = _agent(request.user, confirmation["target_agent_id"], RESTORE)
        if selected.plat != agent.plat or (
            not image.native and not capability(selected)["supported"]
        ):
            raise ValidationError(
                "The selected target has no compatible recovery workflow."
            )
        method = (image.native or {}).get("method")
        # Windows Recovery recreates the source partitions on the target.
        if method == WINDOWS_METHOD and (
            confirmation.get("raw_size", 0) < image.native["size"]
            or confirmation.get("sector_size") != image.native["sector_size"]
        ):
            raise ValidationError(
                "The target disk must be at least as large as the source disk and use its sector size."
            )
        # The recovery helper recreates the recorded partitions on the target.
        if method == LINUX_FILES_METHOD and (
            confirmation.get("raw_size", 0) < image.native["min_target_size"]
            or confirmation.get("sector_size") != image.native["sector_size"]
        ):
            raise ValidationError(
                "The target disk must be at least as large as the recorded partitions and use the source sector size."
            )
        if image.status != ImageStatus.VERIFIED:
            return _problem(
                "The image must pass verification before it can be restored.", 409
            )
        # The files restore writes before the whole stream is checked.
        # shortcut: one fstat per block, a point with a million blocks makes
        # this request slow; batch the lookups when such points are common.
        if method == LINUX_FILES_METHOD:
            try:
                for part in image.parts.select_related("block").iterator(
                    chunk_size=256
                ):
                    if not blocks.stored(image, part.block):
                        return _problem(
                            "A block of this point is missing from the image store. Check the point again before restoring.",
                            409,
                        )
            except StoreUnavailable:
                return _problem(OTHER_STORE, 503)
            except OSError:
                return _problem("Imaging storage is unavailable.", 503)
    else:
        if image.status not in (ImageStatus.WAITING, ImageStatus.UPLOADING):
            return _problem("This image cannot accept a capture.", 409)
        if not Profile.objects.filter(
            agent=agent, network_mode=image.network_mode
        ).exists():
            return _problem(MODE_CHANGED, 409)
        confirmation = _validated(CaptureGrantSerializer, request.data)
        if not _identity_matches(
            image, confirmation["device_uuid"], confirmation["disk_id"]
        ):
            return _problem(
                "The device or disk differs from the approved capture.", 409
            )
    if not _storage()["configured"]:
        return _problem("Configure private server imaging storage.", 503)
    domain = origin(image.network_mode)
    if not domain or (
        image.network_mode == "internal" and not settings.ULRMM_IMAGING_INTERNAL_CIDRS
    ):
        return _problem("Configure the selected HTTPS imaging ingress.", 503)
    now = timezone.now()
    Transfer.objects.filter(
        image=image,
        direction=direction,
        target=selected,
        expires_at__gt=now,
    ).update(expires_at=now)
    if direction == CAPTURE:
        _image_identity(image, confirmation["device_uuid"], confirmation["disk_id"])
    secret = secrets.token_urlsafe(32)
    grant = Transfer.objects.create(
        image=image,
        direction=direction,
        target=selected,
        user=request.user,
        device_uuid=confirmation["device_uuid"],
        disk_id=confirmation["disk_id"],
        token_digest=_token_digest(secret),
        expires_at=now + timedelta(hours=6 if direction == CAPTURE else 2),
        renew_until=now + RENEW_LIMIT,
    )
    audit(
        agent,
        request.user.username,
        f"Client imaging {direction} access granted for image {image.id}, target {selected.agent_id}, transfer {grant.id}.",
    )
    return _grant_response(grant, secret, status=201)


@api_view(["POST"])
@transaction.atomic
def cancel(request, agent_id, image_id):
    agent = _agent(request.user, agent_id, MANAGE)
    image = _lock_image(get_object_or_404(Image, agent=agent, pk=image_id))
    if image.status not in DISCARDABLE:
        return _problem(
            "Only pending, interrupted or failed captures can be discarded.", 409
        )
    return _discard(request, agent, image) or Response(status=204)


def _discard(request, agent, image):
    from .runs import finish

    try:
        remove_image_file(image)
    except OSError:
        return _problem("Imaging storage is unavailable.", 503)
    for run in image.runs.select_for_update().filter(
        status__in=(RunStatus.DEFERRED, *OPEN_RUNS)
    ):
        finish(run, RunStatus.CANCELLED, "Capture discarded.", by=request.user)
    image.parts.all().delete()
    set_status(image, ImageStatus.FAILED, "Capture discarded.")
    Transfer.objects.filter(image=image).update(expires_at=timezone.now())
    audit(agent, request.user.username, f"Client image {image.id} discarded.")
    usage_later(agent.pk)
    return None


@api_view(["GET"])
def runs(request, agent_id, run_id=None):
    agent = _agent(request.user, agent_id, VIEW, MANAGE, RESTORE)
    found = BackupRun.objects.filter(image__agent=agent).select_related("cancelled_by")
    show = agent_allowed(request.user, agent, "can_run_scripts")
    if run_id is None:
        rows = found.defer("log").order_by("-created_at")[:50]
        return Response([run_row(r, show) for r in rows])
    log_from = request.query_params.get("log_from", "0")
    if not NUMBER.fullmatch(log_from):
        raise ValidationError({"log_from": ["Enter a line number."]})
    return Response(run_row(get_object_or_404(found, pk=run_id), show, int(log_from)))


@api_view(["POST"])
@transaction.atomic
def run_cancel(request, agent_id, run_id):
    import asyncio

    agent = _agent(request.user, agent_id, MANAGE)
    run = get_object_or_404(
        BackupRun.objects.select_related("image"), pk=run_id, image__agent=agent
    )
    image = run.image
    if image.status != ImageStatus.VERIFYING:
        image = _lock_image(image)
        run = BackupRun.objects.select_for_update().get(pk=run.pk)
    if run.status not in (RunStatus.DEFERRED, *OPEN_RUNS):
        return _problem("This run has ended.", 409)
    if image.status == ImageStatus.VERIFYING:
        return _problem("The backup is sealed and being verified.", 409)
    _, state = resolver.rows(agent)
    online = state.protocol and agent.is_online and run.status in OPEN_RUNS
    if not online and image.status not in DISCARDABLE:
        return _problem(
            "Only pending, interrupted or failed captures can be discarded.", 409
        )
    audit(agent, request.user.username, f"Backup run {run.pk} cancel requested.")
    if state.protocol:
        # update() keeps updated_at, the stale clock of the run
        BackupRun.objects.filter(pk=run.pk).update(
            cancel_requested=True, cancelled_by=request.user
        )
    if online:
        message = {"func": "imagingcancel", "payload": {"run": str(run.pk)}}
        transaction.on_commit(
            lambda: asyncio.run(agent.nats_cmd(message, wait=False)), robust=True
        )
    elif denied := _discard(request, agent, image):
        return denied
    run.refresh_from_db()
    return Response(run_row(run, agent_allowed(request.user, agent, "can_run_scripts")))


@api_view(["POST"])
@transaction.atomic
def protect(request, agent_id, image_id):
    agent = _agent(request.user, agent_id, MANAGE)
    value = request.data.get("protected") if isinstance(request.data, dict) else None
    if not isinstance(value, bool):
        raise ValidationError({"protected": ["Send true or false."]})
    if not value and (
        denied := stepup_denied(request, "Retention may then delete this point.")
    ):
        return denied
    image = _lock_image(get_object_or_404(Image, agent=agent, pk=image_id))
    image.protected = value
    image.save(update_fields=["protected"])
    audit(
        agent,
        request.user.username,
        f"Image {image.id} {'protected' if value else 'unprotected'}.",
    )
    return Response(ImageSerializer(image).data)


@api_view(["POST"])
def retention_preview(request):
    from django.db.models import Exists

    from .retention import when
    from .tasks import _restoring, failed_due, retention_plan

    body = request.data if isinstance(request.data, dict) else {}
    agent = _agent(request.user, str(body.get("agent_id", ""))[:200], MANAGE)
    config = body.get("config") or {}
    if not isinstance(config, dict):
        raise ValidationError({"config": ["Send the retention settings as an object."]})
    unknown = set(config) - {"keep_last", "gfs", "timezone"}
    if unknown:
        raise ValidationError({"config": {k: ["Unknown setting."] for k in unknown}})
    serializer = ConfigSerializer(data=config)
    if not serializer.is_valid():
        raise ValidationError({"config": serializer.errors})
    profile, _ = resolver.rows(agent)
    vals = {**profile.effective, **serializer.validated_data}
    # a blank zone is the device's, as the resolver turns it
    vals["timezone"] = vals.get("timezone") or agent.timezone
    now = timezone.now()
    points = list(
        Image.objects.filter(
            agent=agent, status__in=(ImageStatus.VERIFIED, ImageStatus.FAILED)
        ).annotate(restoring=Exists(_restoring(now)))
    )
    kept, newest, zone = retention_plan(profile, vals, points)
    rows = []
    for p in sorted(points, key=lambda p: (when(p), p.created_at), reverse=True):
        if p.status == ImageStatus.VERIFIED:
            action = "keep" if kept[p.id] else "delete"
        else:
            action = "delete" if failed_due(p, newest, now) else "keep"
        rows.append(
            {
                "id": str(p.id),
                "target": p.target_id,
                "snapshot_at": p.snapshot_at,
                "at": when(p),
                "status": p.status,
                "kept_by": kept.get(p.id, []),
                "action": action,
            }
        )
    return Response({"timezone": zone, "points": rows})


@api_view(["POST"])
@transaction.atomic
def device_hooks_confirm(request, agent_id):
    from scripts.models import Script

    agent = _agent(request.user, agent_id, MANAGE, lock=True)
    if not agent_allowed(request.user, agent, "can_run_scripts"):
        raise PermissionDenied()
    if denied := stepup_denied(request, "Backup hooks run scripts on devices."):
        return denied
    data = _validated(HookConfirmSerializer, request.data)
    profile, _ = resolver.rows(agent)
    profile = Profile.objects.select_for_update().get(pk=profile.pk)
    if not any(
        h["script_id"] == data["script_id"] for h in profile.overrides.get("hooks", [])
    ):
        raise ValidationError({"script_id": ["The device settings hold no such hook."]})
    script = Script.objects.filter(pk=data["script_id"]).first()
    if script is None or script_hash(script) != data["sha256"]:
        return _problem("The script changed again; review it again.", 409)
    profile.hooks_pinned = {**profile.hooks_pinned, str(script.pk): data["sha256"]}
    profile.hooks_approved_by = request.user
    profile.hooks_approved_at = timezone.now()
    profile.save(
        update_fields=["hooks_pinned", "hooks_approved_by", "hooks_approved_at"]
    )
    audit(
        agent,
        request.user.username,
        f"Backup hook {script.name} confirmed at {data['sha256'][:12]}.",
    )
    profile, state = resolver.resolve_device(agent, cause="device", author=request.user)
    supported = capability(agent)
    return Response(
        _device_answer(request, agent, supported, profile, state, _storage(True))
    )


@api_view(["POST"])
@transaction.atomic
def recheck(request, agent_id, image_id):
    agent = _agent(request.user, agent_id, MANAGE, RESTORE)
    image = get_object_or_404(Image, agent=agent, pk=image_id)
    if image.status != ImageStatus.VERIFIED:
        return _problem("Only verified points can be checked again.", 409)
    transaction.on_commit(
        lambda: verify_image.delay(str(image.id), recheck=True), robust=True
    )
    audit(agent, request.user.username, f"Client image {image.id} check requested.")
    return Response(status=202)


@api_view(["DELETE"])
@transaction.atomic
def delete_image(request, agent_id, image_id):
    agent = _agent(request.user, agent_id, MANAGE)
    image = _lock_image(get_object_or_404(Image, agent=agent, pk=image_id))
    denied = stepup_denied(request, "This permanently deletes a restore point.")
    if denied is not None:
        return denied
    if image.status not in (ImageStatus.VERIFIED, ImageStatus.FAILED):
        return _problem("Only verified or failed images can be deleted.", 409)
    # Transfers serve data of verified images only, so a failed one has no reader.
    if (
        image.status == ImageStatus.VERIFIED
        and Transfer.objects.filter(
            image=image,
            direction=RECOVERY,
            expires_at__gt=timezone.now(),
            completed_at__isnull=True,
        ).exists()
    ):
        return _problem(
            "A restore of this image is in progress. Delete it after the restore finishes or its access expires.",
            409,
        )
    try:
        remove_image_file(image)
    except OSError:
        return _problem("Imaging storage is unavailable.", 503)
    # Parts and grants cascade; unreferenced blocks go to the orphan cleanup.
    image.delete()
    audit(agent, request.user.username, f"Client image {image_id} deleted.")
    usage_later(agent.pk)
    return Response(status=204)


def _policy_authorized(grant, image):
    # the config version is pinned at the claim and not compared again
    profile, state = resolver.rows(image.agent)
    if grant.policy_id:
        policy = resolver.table()["policies"].get(grant.policy_id)
        return bool(policy) and resolver.reaches(policy, profile, state.memberships)
    fields = resolver.effective(image.agent, profile, state)["fields"]
    return fields["schedule"]["value"]["kind"] != "none" or bool(
        fields["schedule_events"]["value"]
    )


def _authorized_transfer(request, transfer_id, *, lock):
    grant = (
        Transfer.objects.select_related("user__role", "target", "image")
        .filter(pk=transfer_id)
        .first()
    )
    _bearer(request, grant)
    # Access renewal and every transfer mutation serialize on the image row.
    image = _lock_image(grant.image) if lock else grant.image
    if lock:
        grant = get_object_or_404(Transfer, pk=transfer_id)
    if (
        grant.pairing_id
        and not Pairing.objects.filter(
            pk=grant.pairing_id,
            expires_at__gt=timezone.now(),
            agent__profile__network_mode=image.network_mode,
        ).exists()
    ):
        raise PermissionDenied(
            "This recovery pairing has expired or needs to be configured again."
        )
    if (
        grant.direction == CAPTURE
        and image.agent_id
        and not Profile.objects.filter(
            agent_id=image.agent_id, network_mode=image.network_mode
        ).exists()
    ):
        raise PermissionDenied(MODE_CHANGED)
    flag = MANAGE if grant.direction == CAPTURE else RESTORE
    if (
        grant.expires_at <= timezone.now()
        or not image.agent_id
        or not grant.target_id
        or not (
            _policy_authorized(grant, image)
            if grant.authority == Authority.POLICY
            else agent_allowed(grant.user, image.agent, flag)
            and agent_allowed(grant.user, grant.target, flag)
        )
    ):
        raise PermissionDenied(
            "This imaging transfer grant has expired or been revoked."
        )
    return grant, image


PROGRESS_MAX = 256 * 1024


def _progress(request, transfer_id):
    from .runs import progress

    length = str(request.META.get("CONTENT_LENGTH") or "0")
    if not NUMBER.fullmatch(length) or int(length) > PROGRESS_MAX:
        return _problem("A progress report is at most 256 KiB.", 413)
    # without a final only the run row is locked, so a verification never blocks it
    grant, image = _authorized_transfer(request, transfer_id, lock=False)
    try:
        check_path(request, image.network_mode)
    except PermissionDenied as error:
        return _problem(str(error.detail), 403)
    if grant.direction != CAPTURE:
        return _problem("This operation is unavailable for this transfer.", 409)
    if isinstance(request.data, dict) and request.data.get("final") is not None:
        grant, image = _authorized_transfer(request, transfer_id, lock=True)
    return progress(request, grant, image)


@api_view(["GET", "POST", "PUT", "PATCH"])
@authentication_classes([])
@permission_classes([])
@transaction.atomic
def transfer(request, transfer_id, operation=""):
    if operation == "progress":
        if request.method != "PATCH":
            return _problem("This operation is unavailable for this transfer.", 409)
        return _progress(request, transfer_id)
    if request.method == "PATCH":
        return _problem("This operation is unavailable for this transfer.", 409)
    metadata = request.method == "GET" and not operation
    # Reads take no image lock, so parallel restores and a recheck do not queue.
    grant, image = _authorized_transfer(
        request, transfer_id, lock=request.method != "GET"
    )
    try:
        check_path(request, image.network_mode)
    except PermissionDenied as error:
        if (
            image.network_mode == "internal"
            and grant.direction == CAPTURE
            and image.status in ACTIVE_STATUSES
            and image.status != ImageStatus.VERIFYING
            and image.reason != CHANGED_PATH
        ):
            Image.objects.filter(pk=image.pk, status=image.status).exclude(
                reason=CHANGED_PATH
            ).update(reason=CHANGED_PATH)
        return _problem(str(error.detail), 403)
    try:
        _check_storage(image)
    except UnconfirmedStorage:
        if grant.direction == CAPTURE:
            Image.objects.filter(pk=image.pk, status=image.status).exclude(
                reason=UNCONFIRMED_STORAGE
            ).update(reason=UNCONFIRMED_STORAGE)
        return _problem(UNCONFIRMED_STORAGE, 503)
    except OSError:
        return _problem("Imaging storage is unavailable.", 503)
    if metadata:
        return _transfer_metadata(grant, image)
    response = _operate(request, grant, image, operation)
    if operation in ("data", "part", "parts") and response.status_code in (200, 204):
        window = timedelta(hours=1)
        total = image.raw_size if image.native else image.size
        # After the last chunk the client still writes and reads back the disk
        # before it reports completion.
        if (
            grant.direction == RECOVERY
            and _offset(request) + len(response.content) >= total
        ):
            window = timedelta(hours=24)
        renew(grant, window)
    return response


def _operate(request, grant, image, operation):
    if grant.direction == CAPTURE:
        if image.native:
            return blocks.capture(request, image, operation)
        if operation == "complete" and request.method == "POST":
            return _complete_capture(request, image)
        if image.status not in (ImageStatus.WAITING, ImageStatus.UPLOADING):
            return _problem("This image cannot accept a capture.", 409)
        if operation == "manifest" and request.method == "POST":
            return _manifest(request, image)
        if operation == "data" and request.method == "PUT":
            return _upload(request, image)
    elif image.status == ImageStatus.VERIFIED:
        if operation == "complete" and request.method == "POST":
            return _complete_restore(request, grant, image)
        if (
            operation == "integrity-failed"
            and request.method == "POST"
            and not grant.completed_at
        ):
            grant.expires_at = timezone.now()
            grant.save(update_fields=["expires_at"])
            audit(
                grant.target,
                grant.user.username,
                f"Recovery reported an integrity mismatch for image {image.id}.",
            )
            transaction.on_commit(
                lambda: verify_image.delay(str(image.id), recheck=True), robust=True
            )
            return Response(status=204)
        if operation == "data" and request.method == "GET" and not grant.completed_at:
            if image.native:
                return blocks.download(image, _offset(request))
            return _download(request, image)
    return _problem("This operation is unavailable for this transfer.", 409)


def _transfer_metadata(grant, image):
    data = ImageSerializer(image).data
    if image.native and grant.direction == RECOVERY:
        data.update(compression="none", size=image.raw_size)
    if image.native and grant.direction == CAPTURE:
        data["compression_level"] = image.compression_level
    data["disk_id"] = grant.disk_id
    data["device_uuid"] = str(grant.device_uuid)
    data.update(
        image_id=str(image.id),
        agent_id=grant.target.agent_id,
        direction=grant.direction,
        completed_at=grant.completed_at,
    )
    response = Response(data)
    response["Cache-Control"] = "no-store"
    return response


def _manifest(request, image):
    data = _validated(ManifestSerializer, request.data)
    if data["disk_id"] != image.disk_id:
        return _problem("This disk differs from the approved capture.", 409)
    if image.raw_size is not None and any(
        getattr(image, key) != value for key, value in data.items()
    ):
        return _problem(
            "The capture disk or format changed since this upload began.", 409
        )
    for key, value in data.items():
        setattr(image, key, value)
    image.save(update_fields=list(data))
    set_status(image, ImageStatus.UPLOADING, RECEIVING_REASON)
    return Response(status=204)


def _offset(request):
    offset = request.query_params.get("offset", "")
    if not NUMBER.fullmatch(offset):
        raise ValidationError("Provide a valid byte offset.")
    return int(offset)


def _upload(request, image):
    if not image.raw_size:
        return _problem("Submit the disk manifest before uploading.", 409)
    offset = _offset(request)
    if offset != image.offset:
        return Response(
            {"detail": "Resume at the committed byte offset.", "offset": image.offset},
            status=409,
        )
    length = str(request.META.get("CONTENT_LENGTH", ""))
    if (
        not NUMBER.fullmatch(length)
        or not 0 < int(length) <= CHUNK_SIZE
        or request.content_type != "application/octet-stream"
    ):
        return _problem("Submit a binary chunk between 1 byte and 4 MiB.", 413)
    data = request.stream.read(int(length))
    if len(data) != int(length):
        return _problem("Incomplete binary chunk.", 400)
    end = offset + len(data)
    limit = image.raw_size
    if image.compression == "gzip":
        limit += max(65536, limit // 100)
    if end > limit:
        return _problem("The chunk exceeds the declared image size.", 413)
    try:
        with image_file(image, write=True, incoming=len(data)) as file:
            if os.fstat(file.fileno()).st_size < offset:
                set_status(
                    image, ImageStatus.FAILED, "Previously uploaded data is missing."
                )
                return _problem(image.reason, 409)
            file.truncate(offset)
            file.seek(offset)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except OSError as error:
        if error.errno in (errno.ENOSPC, errno.EDQUOT):
            set_status(image, ImageStatus.UPLOADING, NO_SPACE)
            return _problem(image.reason, 507)
        return _problem("Imaging storage is unavailable.", 503)
    image.offset = end
    image.save(update_fields=["offset"])
    set_status(image, ImageStatus.UPLOADING, RECEIVING_REASON)
    return Response(status=204)


def _complete_capture(request, image):
    data = _validated(CompleteCaptureSerializer, request.data)
    if image.status in (ImageStatus.VERIFYING, ImageStatus.VERIFIED):
        if all(getattr(image, key) == value for key, value in data.items()):
            return Response(ImageSerializer(image).data, status=202)
        return _problem("Completion metadata changed.", 409)
    if image.status != ImageStatus.UPLOADING or data["size"] != image.offset:
        return _problem("Upload the entire image before requesting verification.", 409)
    for key, value in data.items():
        setattr(image, key, value)
    image.save(update_fields=list(data))
    set_status(
        image,
        ImageStatus.VERIFYING,
        "Verifying stored and uncompressed SHA-256 and size.",
    )
    transaction.on_commit(lambda: verify_image.delay(str(image.id)), robust=True)
    return Response(ImageSerializer(image).data, status=202)


def _download(request, image):
    offset = _offset(request)
    if offset >= image.size:
        return _problem("Offset is outside the image.", 416)
    try:
        with image_file(image) as file:
            length = min(CHUNK_SIZE, image.size - offset)
            file.seek(offset)
            data = file.read(length)
            if len(data) != length or os.fstat(file.fileno()).st_size != image.size:
                set_status(
                    image, ImageStatus.FAILED, "Verified image data changed in storage."
                )
                return _problem(image.reason, 409)
    except FileNotFoundError:
        set_status(image, ImageStatus.FAILED, "Verified image is missing from storage.")
        audit(image.agent, "imaging", f"Image {image.id} disappeared from storage.")
        return _problem(image.reason, 409)
    except DamagedFile:
        set_status(
            image, ImageStatus.FAILED, "Verified image cannot be read from storage."
        )
        return _problem(image.reason, 409)
    except OSError:
        return _problem("Imaging storage is unavailable.", 503)
    result = HttpResponse(data, content_type="application/octet-stream")
    result["Cache-Control"] = "no-store"
    result["Content-Length"] = len(data)
    return result


def _complete_restore(request, grant, image):
    data = _validated(CompleteRestoreSerializer, request.data)
    if data["raw_sha256"] != image.raw_sha256:
        return _problem("Restored image SHA-256 differs from the verified source.", 409)
    if not grant.completed_at:
        grant.completed_at = timezone.now()
        grant.save(update_fields=["completed_at"])
        audit(
            grant.target,
            grant.user.username,
            (
                f"Recovery verified the retrieved artifact for image {image.id}, transfer {grant.id}."
                if image.native
                else f"Recovery reported successful read-back for image {image.id}, transfer {grant.id}."
            ),
        )
    return Response(status=204)

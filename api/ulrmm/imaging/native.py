# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import secrets
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from apiv3.views import AgentTokenView, _token_agent
from deploy import envelope
from scripts.models import Script
from ulrmm.constants import AlertSeverity, GoArch
from .models import (
    ACTIVE_STATUSES,
    LINUX_FILES_METHOD,
    LINUX_OFFLINE_METHOD,
    METHODS,
    MODE_CHANGED,
    OPEN_RUNS,
    VOLUME_KINDS,
    Authority,
    BackupRun,
    DeviceBackupState,
    NativeInventory,
    Image,
    ImageStatus,
    RunStatus,
    RunStep,
    StorageTarget,
    Transfer,
    Trigger,
)
from .resolver import (
    effective,
    pinned_hooks,
    reaches,
    rows,
    table,
    target_of,
    values,
    window,
)
from .runs import alert, drop, end_quietly
from .service import (
    agent_allowed,
    audit,
    capability,
    clear_alert,
    covers,
    not_covered,
    origin,
    queue_capture,
    raise_alert,
    script_hash,
    set_status,
)
from .storage import NO_SPACE, OTHER_STORE, StoreUnavailable
from .views import (
    RENEW_LIMIT,
    _check_storage,
    _grant_data,
    _no_cache,
    _token_digest,
)

PROTOCOL = 2
# the last millisecond of year 9999, the largest time datetime can hold
MAX_MS = 253402300799999
CONFIG_HEADER = "X-ULRMM-Imaging-Config"
NO_IDENTITY = "The agent has no active identity."
NOT_ASKED = "The agent did not ask for sealed answers."
LEGACY_HOOKS = (
    "Update the agent: this backup runs hooks, which older agents cannot run."
)
NO_AUTHORITY = (
    "The backup schedule that queued this point no longer applies to this device."
)
REPLACED_RUN = "Claimed again after the agent went quiet."
# three regular poll intervals of a legacy agent
POLL_GAP = timedelta(minutes=15)

FAILURES = {
    "network": "Waiting for the permitted imaging network.",
    "capture": "Native capture failed preflight or could not complete. Check the local agent imaging log.",
    "upload": "Upload paused. Check backup storage and network availability.",
}


class VolumeSerializer(serializers.Serializer):
    id = serializers.CharField(max_length=300, allow_blank=True)
    mount = serializers.CharField(
        max_length=255, allow_blank=True, trim_whitespace=False
    )
    fs = serializers.CharField(max_length=32, allow_blank=True)
    kind = serializers.ChoiceField(choices=VOLUME_KINDS)
    disk = serializers.CharField(max_length=255, allow_blank=True)
    size = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    used = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    consistency = serializers.ChoiceField(
        choices=("", "live", "lvm-snapshot", "btrfs-snapshot")
    )
    reason = serializers.CharField(max_length=255, allow_blank=True)


class CheckSerializer(serializers.Serializer):
    id = serializers.RegexField(r"\A[a-z0-9_.-]{1,64}\Z")
    state = serializers.ChoiceField(
        choices=("ok", "fixed", "missing", "failed", "manual")
    )
    blocking = serializers.BooleanField()
    detail = serializers.CharField(max_length=512, allow_blank=True, default="")
    fix = serializers.CharField(max_length=512, allow_blank=True, default="")
    fix_argv = serializers.ListField(
        child=serializers.CharField(max_length=512, trim_whitespace=False),
        max_length=32,
        default=list,
    )
    fixed_at = serializers.IntegerField(
        min_value=0, max_value=MAX_MS, allow_null=True, default=None
    )
    observed_at = serializers.IntegerField(min_value=0, max_value=MAX_MS)


class ConfigErrorSerializer(serializers.Serializer):
    field = serializers.CharField(max_length=64)
    message = serializers.CharField(max_length=512)


class ConfigAckSerializer(serializers.Serializer):
    version = serializers.IntegerField(min_value=0)
    checks_version = serializers.IntegerField(min_value=0, default=0)
    hash = serializers.RegexField(r"\A([0-9a-f]{64})?\Z", allow_blank=True)
    status = serializers.ChoiceField(choices=("applied", "error", "none"))
    errors = ConfigErrorSerializer(many=True, max_length=64, default=list)


class ConditionsSerializer(serializers.Serializer):
    on_ac = serializers.BooleanField(allow_null=True, default=None)
    up_since = serializers.IntegerField(min_value=0, max_value=MAX_MS, required=False)
    events = serializers.ListField(
        child=serializers.ChoiceField(choices=("agent_start", "ac_connected")),
        max_length=2,
        default=list,
    )


class CapabilitySerializer(serializers.Serializer):
    method = serializers.CharField(max_length=64, allow_blank=True)
    ready = serializers.BooleanField()
    scope = serializers.CharField(max_length=2048, allow_blank=True)
    recovery = serializers.CharField(max_length=2048, allow_blank=True)
    reason = serializers.CharField(max_length=2048, allow_blank=True)
    encryption = serializers.CharField(max_length=512, allow_blank=True)
    source_id = serializers.CharField(max_length=255, allow_blank=True)
    device_uuid = serializers.CharField(max_length=36, allow_blank=True)
    boot_mode = serializers.CharField(max_length=32, allow_blank=True)
    size = serializers.IntegerField(min_value=0, max_value=2**63 - 1)
    sector_size = serializers.IntegerField(min_value=0, max_value=65536)
    volumes = VolumeSerializer(many=True, required=False, default=list, max_length=64)
    min_target_size = serializers.IntegerField(
        min_value=0, max_value=2**63 - 1, required=False, default=0
    )

    def validate(self, data):
        if data["device_uuid"]:
            uuid = serializers.UUIDField().run_validation(data["device_uuid"])
            if uuid.int in (0, 2**128 - 1):
                raise serializers.ValidationError("The device UUID is a placeholder.")
            data["device_uuid"] = str(uuid)
        ids = [
            v["id"]
            for v in data["volumes"]
            if v["id"] and v["kind"] in ("system", "extra", "unmounted")
        ]
        if len(ids) != len(set(ids)):
            raise serializers.ValidationError("Volume IDs must be unique.")
        if data["ready"] and (
            not all(
                data[k]
                for k in (
                    "method",
                    "source_id",
                    "device_uuid",
                    "size",
                    "sector_size",
                    "scope",
                    "recovery",
                )
            )
            or (
                data["method"] == LINUX_FILES_METHOD
                and not (
                    any(v["kind"] == "system" for v in data["volumes"])
                    and 0 < data["min_target_size"] <= data["size"]
                )
            )
        ):
            raise serializers.ValidationError(
                "A ready provider must identify its source and recovery procedure."
            )
        return data


class PollSerializer(serializers.Serializer):
    protocol = serializers.IntegerField(min_value=PROTOCOL, required=False)
    capabilities = CapabilitySerializer(many=True, max_length=4, required=False)
    config = ConfigAckSerializer(required=False)
    checks = CheckSerializer(many=True, max_length=64, required=False)
    checks_at = serializers.IntegerField(min_value=0, max_value=MAX_MS, required=False)
    conditions = ConditionsSerializer(required=False)
    deferred = serializers.ChoiceField(choices=("", "on_battery"), required=False)

    def validate_checks(self, value):
        ids = [c["id"] for c in value]
        if len(ids) != len(set(ids)):
            raise serializers.ValidationError("Check ids must be unique.")
        return value

    def validate_capabilities(self, value):
        methods = [c["method"] for c in value]
        if len(methods) != len(set(methods)):
            raise serializers.ValidationError("Report each method once.")
        return value


def _fail(image, reason):
    # A point that can never be claimed would block every later scheduled run.
    drop(image, reason)
    return Response(status=204)


def _ms(value):
    return datetime.fromtimestamp(value / 1000, UTC) if value is not None else None


def sealed_or_none(agent, request, data, status=200):
    """The sealed answer, or None when the request cannot get one."""
    if (
        request.META.get("HTTP_X_ULRMM_SEAL") != "1"
        or not envelope.target(agent)["active"]
    ):
        return None
    response = envelope.seal_response(agent, request, data, status=status)
    return response if response.get("X-ULRMM-Sealed") == "1" else None


class _Unsealed(Exception):
    """Leaves the claim's atomic block when its answer cannot be sealed."""


def _check(check_id, state="ok", detail="", blocking=True):
    return {
        "id": check_id,
        "state": state,
        "blocking": blocking,
        "detail": detail,
        "fix": "",
        "fix_argv": [],
        "fixed_at": None,
        "observed_at": int(timezone.now().timestamp() * 1000),
        "source": "server",
    }


def server_checks(agent, state, fields, tab):
    """The checks of contract 6.2 that the server computes."""
    hooks = bool(fields["hooks"]["value"])
    if state.protocol:
        out = [_check("agent.config")]
    elif hooks:
        out = [
            _check(
                "agent.config",
                "missing",
                "This backup runs hooks. The agent makes no backup until it is updated.",
            )
        ]
    else:
        out = [
            _check(
                "agent.config",
                "manual",
                "Older agent: settings apply on the server only. Update the agent.",
                blocking=False,
            )
        ]
    if state.protocol:
        refused = sealing_refused(state)
        out.append(
            _check("agent.sealing", "missing", refused)
            if refused
            else (
                _check("agent.sealing")
                if state.sealed
                else _check("agent.sealing", "missing", sealing_detail(agent))
            )
        )
    supported = agent.plat in METHODS and (
        agent.plat != "linux" or agent.goarch in (GoArch.AMD64, GoArch.ARM64)
    )
    out.append(
        _check("agent.platform")
        if supported
        else _check(
            "agent.platform",
            "missing",
            f"Backups are not available on {agent.plat} {agent.goarch}.",
        )
    )
    target = target_of(tab, fields["target"]["value"])
    out.append(
        _check("target.scope")
        if covers(target, agent.site.client_id, agent.site_id)
        else _check("target.scope", "missing", not_covered(target))
    )
    out.append(
        _check("target.reachable")
        if not target.get("unreachable_since")
        else _check("target.reachable", "failed", "Imaging storage is unavailable.")
    )
    return out


def sealing_refused(state):
    """The agent's message while its last acknowledgement says it cannot open
    sealed answers; every claim is sealed, so the device cannot back up."""
    if state.ack_status != "error":
        return ""
    return next(
        (e["message"][:512] for e in state.ack_errors if e.get("field") == "sealing"),
        "",
    )


def sealing_detail(agent):
    return NOT_ASKED if envelope.target(agent)["active"] else NO_IDENTITY


def shown_checks(agent, state, fields, tab):
    agent_checks = (
        [{**c, "source": "agent"} for c in state.checks] if state.protocol else []
    )
    return server_checks(agent, state, fields, tab) + agent_checks


def readiness(agent, state, fields, tab, cap):
    """(ready, reason) of contract 6.3."""
    for check in shown_checks(agent, state, fields, tab):
        blocking = check["blocking"]
        if check["id"] == "smart.source":
            # the SMART level of the settings decides, not the device
            blocking = fields["smart"]["value"] == "abort"
        if blocking and check["state"] not in ("ok", "fixed"):
            return False, check["detail"][:255]
    if not cap.get("ready"):
        return False, (cap.get("reason") or "")[:255]
    return True, ""


def _authority(agent, image, fields, state, profile, tab):
    """(allowed, policy pk or None, audit name) of the point's authority (9.2)."""
    if image.trigger == Trigger.MANUAL:
        allowed = bool(image.operator_id) and agent_allowed(
            image.operator, agent, "can_manage_images"
        )
        return allowed, None, image.operator.username if image.operator_id else ""
    origin_ = fields["schedule"]["origin"]
    policy = (
        origin_["id"]
        if origin_["level"] not in ("default", "global", "device")
        else None
    )
    if policy is not None:
        row = tab["policies"].get(policy)
        allowed = bool(row) and reaches(row, profile, state.memberships)
        return allowed, policy, f"policy {policy}"
    live = fields["schedule"]["value"]["kind"] != "none" or bool(
        fields["schedule_events"]["value"]
    )
    return live, None, "the device schedule"


def hook_bodies(agent, fields, profile, tab):
    """Hook entries of a claim (11.4) and the skipped ones."""
    v = fields["hooks"]
    pinned = pinned_hooks(fields, profile, tab)
    scripts = Script.objects.in_bulk([h["script_id"] for h in v["value"]])
    out, skipped = [], []
    for hook in v["value"]:
        script = scripts.get(hook["script_id"])
        sha = pinned.get(str(hook["script_id"]), "")
        if (
            script
            and script.supported_platforms
            and agent.plat not in script.supported_platforms
        ):
            skipped.append(
                {
                    "phase": hook["phase"],
                    "script_id": hook["script_id"],
                    "sha256": sha,
                    "status": "skipped",
                    "script_name": script.name if script else "",
                }
            )
            continue
        suspended = not script or script_hash(script) != sha
        out.append(
            {
                "phase": hook["phase"],
                "script_id": hook["script_id"],
                "name": script.name if script else "",
                "sha256": sha,
                "shell": script.shell if script else "",
                "code": "" if suspended else script.code,
                "args": hook["args"],
                "env_vars": (
                    []
                    if suspended
                    else Script.parse_script_env_vars(
                        agent, script.shell, hook["env_vars"]
                    )
                ),
                "timeout": hook["timeout"],
                "on_fail": hook["on_fail"],
                "run_as_user": bool(script and script.run_as_user),
                "suspended": suspended,
            }
        )
    return out, skipped


def _defer(image, run, code, reason):
    if run is not None and run.status in OPEN_RUNS:
        if end_quietly(run, image, REPLACED_RUN):
            return Response(status=204)
        run = None
    if image.reason != reason[:255]:
        set_status(image, image.status, reason[:255])
    if run is None:
        run = BackupRun(image=image, trigger=image.trigger)
    run.status = RunStatus.DEFERRED
    run.deferred_reason = code
    run.save()
    return Response(status=204)


class _ImagingView(AgentTokenView):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not request.is_secure():
            raise PermissionDenied(
                "Native imaging requires an authenticated HTTPS control channel."
            )


class NativeConfig(_ImagingView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid)
        _, state = rows(agent)
        response = sealed_or_none(
            agent,
            request,
            {"version": state.config_version, "document": state.config_doc},
        )
        if response is None:
            return Response(
                {
                    "detail": "Backup settings are sent only on a sealed channel.",
                    "check": "agent.sealing",
                },
                status=403,
            )
        response[CONFIG_HEADER] = str(state.config_version)
        return _no_cache(response)


class NativePoll(_ImagingView):
    def get(self, request, agentid):
        agent = _token_agent(request, agentid)
        point = serializers.UUIDField().run_validation(
            request.query_params.get("point")
        )
        image = (
            Image.objects.filter(pk=point, agent=agent, native__isnull=False)
            .values("status")
            .first()
        )
        return Response(image, status=200 if image else 404)

    @transaction.atomic
    def post(self, request, agentid):
        agent = _token_agent(request, agentid)
        if not isinstance(request.data, dict):
            raise serializers.ValidationError("Expected an imaging capability report.")
        serializer = CapabilitySerializer(data=request.data.get("capability"))
        serializer.is_valid(raise_exception=True)
        cap = serializer.validated_data
        if cap["method"] and cap["method"] not in METHODS.get(agent.plat, ()):
            raise serializers.ValidationError(
                "The capture method belongs to a different platform."
            )
        poll = PollSerializer(data=request.data)
        poll.is_valid(raise_exception=True)
        poll = poll.validated_data
        protocol = PROTOCOL if "protocol" in poll else 0
        capabilities = poll.get("capabilities", [cap]) if protocol else []
        if any(c["method"] != cap["method"] for c in capabilities):
            raise serializers.ValidationError(
                "The capability list must name the reported method."
            )
        NativeInventory.objects.update_or_create(
            agent=agent, defaults={"capability": cap}
        )
        profile, state = rows(agent)
        state = DeviceBackupState.objects.select_for_update().get(pk=state.pk)
        response = self._process(
            request, agent, cap, poll, protocol, capabilities, profile, state
        )
        if response.status_code in (200, 204):
            response[CONFIG_HEADER] = str(state.config_version)
        return response

    def _process(
        self, request, agent, cap, poll, protocol, capabilities, profile, state
    ):
        now = timezone.now()
        previous = {c["id"]: c.get("fixed_at") or 0 for c in state.checks}
        ack = poll.get("config")
        # checks computed under an older document (an agent start) count for nothing
        stale = (
            bool(protocol)
            and (ack or {}).get("checks_version", 0) != state.config_version
        )
        state.protocol = protocol
        state.sealed = (
            request.META.get("HTTP_X_ULRMM_SEAL") == "1"
            and envelope.target(agent)["active"]
        )
        if not stale:
            state.checks = poll.get("checks", []) if protocol else []
            state.checks_at = _ms(poll.get("checks_at"))
            state.capabilities = capabilities
        conditions = poll.get("conditions", {})
        if not protocol:
            # a legacy agent sends no start time: the first poll after a gap is one
            gap = state.last_poll_at is None or state.last_poll_at < now - POLL_GAP
            up = (
                int(now.timestamp() * 1000) if gap else state.conditions.get("up_since")
            )
            conditions = {"up_since": up} if up else {}
        state.conditions = conditions
        state.last_poll_at = now
        if protocol and ack and ack["version"] == state.config_version:
            if ack["status"] == "applied" and ack["hash"] == state.config_hash:
                if (state.acked_version, state.acked_hash, state.ack_status) != (
                    state.config_version,
                    state.config_hash,
                    "applied",
                ):
                    state.acked_version = state.config_version
                    state.acked_hash = state.config_hash
                    state.acked_at = now
                    state.ack_status = "applied"
                    state.ack_errors = []
                    state.pending_since = None
                clear_alert(state, "config_error")
            elif ack["status"] == "error":
                if (state.acked_version, state.acked_hash, state.ack_status) != (
                    ack["version"],
                    ack["hash"],
                    "error",
                ):
                    state.acked_at = now
                state.acked_version = ack["version"]
                state.acked_hash = ack["hash"]
                state.ack_status = "error"
                state.ack_errors = ack["errors"]
                raise_alert(
                    agent,
                    state,
                    "config_error",
                    AlertSeverity.WARNING,
                    "The agent refused its backup settings.",
                    "; ".join(f"{e['field']}: {e['message']}" for e in ack["errors"]),
                )
        now_ms = int(now.timestamp() * 1000)
        for check in [] if stale else state.checks:
            if (
                check["state"] == "fixed"
                and check["fixed_at"]
                and previous.get(check["id"], 0) < check["fixed_at"] <= now_ms
            ):
                audit(
                    agent,
                    "imaging",
                    f"Backup readiness fix {check['id']} applied: {' '.join(check['fix_argv'])}.",
                )
        tab = table()
        view = effective(agent, profile, state)
        fields = view["fields"]
        # a sealing refusal is the server's own knowledge, also on a stale poll
        if not stale or sealing_refused(state):
            was_ready = state.ready
            state.ready, state.not_ready_reason = readiness(
                agent, state, fields, tab, cap
            )
            if was_ready and not state.ready:
                raise_alert(
                    agent,
                    state,
                    "readiness_lost",
                    AlertSeverity.WARNING,
                    "Backups are no longer ready.",
                    state.not_ready_reason,
                )
            elif state.ready:
                clear_alert(state, "readiness_lost")
        state.save()
        _events(agent, profile, fields, conditions.get("events", ()))
        return self._claim(
            request, agent, cap, poll, protocol, profile, state, fields, tab, stale
        )

    def _claim(
        self, request, agent, cap, poll, protocol, profile, state, fields, tab, stale
    ):
        image = (
            Image.objects.select_for_update()
            .filter(
                agent=agent,
                native__isnull=False,
                status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING),
            )
            .first()
        )
        if not image:
            return Response(status=204)
        run = (
            image.runs.select_for_update()
            .filter(status__in=(RunStatus.DEFERRED, *OPEN_RUNS))
            .order_by("-created_at")
            .first()
        )
        allowed, policy, authority = _authority(
            agent, image, fields, state, profile, tab
        )
        # An offline Linux point is claimed by its rescue pairing, not the operator.
        if not allowed and image.native.get("method") != LINUX_OFFLINE_METHOD:
            return _fail(
                image,
                (
                    "The backup operator no longer has imaging access. Save the imaging configuration again."
                    if image.trigger == Trigger.MANUAL
                    else NO_AUTHORITY
                ),
            )
        if profile.network_mode != image.network_mode:
            return _fail(image, MODE_CHANGED)
        failure = request.data.get("failure")
        if failure:
            if (
                request.data.get("image_id") == str(image.id)
                and isinstance(failure, str)
                and failure in FAILURES
                and Transfer.objects.filter(
                    image=image,
                    direction="capture",
                    id=serializers.UUIDField().run_validation(
                        request.data.get("claim")
                    ),
                    expires_at__gt=timezone.now(),
                ).update(expires_at=timezone.now())
            ):
                if image.reason not in (NO_SPACE, OTHER_STORE):
                    reason = FAILURES[failure]
                    if failure == "upload" and image.network_mode == "internal":
                        reason = "Upload paused. Waiting for the permitted internal network and storage."
                    set_status(image, image.status, reason)
                if run and run.status in OPEN_RUNS:
                    end_quietly(run, image, image.reason)
            return Response(status=204)
        if stale:
            refused = sealing_refused(state)
            # the agent cannot fetch the document, so all its polls are stale;
            # say why the point waits, as the not-ready deferral does
            if refused and not (run and run.status in OPEN_RUNS):
                return _defer(image, run, "not_ready", refused)
            return Response(status=204)
        # protocol 2: the stored entry of the point's method is the gate (9.2)
        if protocol:
            method = image.native.get("method")
            cap = next((c for c in state.capabilities if c["method"] == method), cap)
        if not cap["ready"] or not origin(image.network_mode):
            reason = cap["reason"] or "Waiting for the configured HTTPS imaging origin."
            if image.reason != reason[:255]:
                set_status(image, image.status, reason[:255])
            return Response(status=204)
        if any(
            image.native.get(k) != cap[k]
            for k in (
                "method",
                "device_uuid",
                "source_id",
                "size",
                "sector_size",
                "boot_mode",
                "encryption",
                "scope",
            )
        ):
            return _fail(
                image,
                "The backup source changed. Review the capability and request a new capture.",
            )
        current = {v["id"]: v for v in cap["volumes"]}
        queued = {v["id"]: v for v in image.native.get("volumes", [])}
        for vid in image.native.get("include", []):
            mount = queued.get(vid, {}).get("mount", vid)
            v = current.get(vid)
            if not v or v["kind"] not in ("system", "extra") or v["mount"] != mount:
                return _fail(image, f"Selected volume {mount} is not mounted."[:255])
        now = timezone.now()
        active = Transfer.objects.filter(
            image=image, direction="capture", expires_at__gt=now
        )
        # Native snapshots can take a long time before the first byte. After
        # upload begins, each committed block renews the claim's activity.
        idle_limit = (
            timedelta(minutes=5)
            if image.status == ImageStatus.UPLOADING
            else timedelta(hours=1)
        )
        # a protocol-2 run lives while it reports progress, blocks or not (9.5)
        reporting = (
            run is not None
            and run.status in OPEN_RUNS
            and run.agent_protocol == PROTOCOL
            and run.updated_at > now - timedelta(minutes=run.pause_max_minutes + 15)
        )
        if not allowed or (
            active.exists() and (image.updated_at > now - idle_limit or reporting)
        ):
            return Response(status=204)
        if not protocol and fields["hooks"]["value"]:
            return _defer(image, run, "legacy", LEGACY_HOOKS)
        if protocol and not state.sealed:
            return _defer(image, run, "sealing", sealing_detail(agent))
        if not state.ready:
            return _defer(image, run, "not_ready", state.not_ready_reason)
        deferral, stop_at = _deferral(agent, image, poll, state, fields, now)
        if deferral:
            return _defer(image, run, *deferral)
        prior = run and run.pk
        # atomic, not a bare savepoint: a rollback also drops its on-commit callbacks
        try:
            with transaction.atomic():
                if run and run.status in OPEN_RUNS:
                    if end_quietly(run, image, REPLACED_RUN):
                        return Response(status=204)
                    run = None
                active.update(expires_at=now)
                set_status(
                    image, image.status, "Native agent is preparing the backup source."
                )
                run = run or BackupRun(image=image, trigger=image.trigger)
                run.status = RunStatus.RUNNING
                run.step = RunStep.SNAPSHOT
                run.deferred_reason = ""
                run.policy_id = policy
                run.policy_version = state.config_version
                run.pause_max_minutes = fields["pause_max_minutes"]["value"]
                run.agent_protocol = protocol
                run.started_at = now
                hooks, skipped = (
                    hook_bodies(agent, fields, profile, tab) if protocol else ([], [])
                )
                run.hooks = skipped
                run.claimed_hooks = [
                    {
                        "phase": h["phase"],
                        "script_id": h["script_id"],
                        "sha256": h["sha256"],
                        "script_name": h["name"],
                    }
                    for h in hooks
                ]
                run.save()
                secret = secrets.token_urlsafe(32)
                grant = Transfer.objects.create(
                    image=image,
                    target=agent,
                    user=image.operator if image.trigger == Trigger.MANUAL else None,
                    authority=(
                        Authority.USER
                        if image.trigger == Trigger.MANUAL
                        else Authority.POLICY
                    ),
                    policy_id=policy,
                    config_version=state.config_version,
                    run=run,
                    direction="capture",
                    device_uuid=cap["device_uuid"],
                    disk_id=cap["source_id"],
                    token_digest=_token_digest(secret),
                    expires_at=now + timedelta(hours=24),
                    renew_until=now + RENEW_LIMIT,
                )
                data = _grant_data(grant, secret, image_id=str(image.id))
                if protocol:
                    v = {k: f["value"] for k, f in fields.items()}
                    data.update(
                        run=str(run.id),
                        config_version=state.config_version,
                        trigger=image.trigger,
                        stop_at=int(stop_at.timestamp() * 1000) if stop_at else None,
                        run_config={
                            k: v[k]
                            for k in (
                                "throttle",
                                "on_battery",
                                "pause_on_battery",
                                "pause_max_minutes",
                                "keep_awake",
                                "priority",
                                "smart",
                            )
                        },
                        hooks=hooks,
                        nushell_enable_config=settings.NUSHELL_ENABLE_CONFIG,
                        deno_default_permissions=settings.DENO_DEFAULT_PERMISSIONS,
                    )
                    response = sealed_or_none(agent, request, data)
                    if response is None:
                        raise _Unsealed
                else:
                    response = Response(data)
        except _Unsealed:
            image.refresh_from_db()
            run = BackupRun.objects.filter(pk=prior).first() if prior else None
            return _defer(image, run, "sealing", sealing_detail(agent))
        audit(
            agent,
            image.operator.username if image.operator_id else "imaging scheduler",
            f"Native agent claimed image {image.id} (authority {authority}, run {run.id}).",
        )
        return _no_cache(response)


def _events(agent, profile, fields, events):
    """Queue one event point when the settings list an event (contract 7.5)."""
    if not set(events) & set(fields["schedule_events"]["value"]):
        return
    if Image.objects.filter(agent=agent, status__in=ACTIVE_STATUSES).exists():
        return
    newest = (
        Image.objects.filter(agent=agent)
        .order_by("-created_at")
        .values_list("created_at", flat=True)
        .first()
    )
    spacing = timedelta(minutes=fields["min_spacing_minutes"]["value"])
    if newest and timezone.now() < newest + spacing:
        return
    if capability(agent)["supported"]:
        queue_capture(profile, "imaging scheduler", trigger=Trigger.EVENT)


def _wake_at(agent, start):
    """One wake of the agent when the catch-up delay ends, not one per poll."""
    from django.core.cache import cache

    from .tasks import wake_imaging_agent

    key = f"imaging:catchup:{agent.pk}:{int(start.timestamp())}"
    wait = (start - timezone.now()).total_seconds()
    if cache.add(key, 1, timeout=int(wait) + 60):
        agent_id = agent.agent_id
        transaction.on_commit(
            lambda: wake_imaging_agent.apply_async((agent_id,), eta=start),
            robust=True,
        )


def _deferral(agent, image, poll, state, fields, now):
    """((code, text) or None, stop_at) of the server deferrals of contract 9.3."""
    vals = values(fields, agent)
    if poll.get("deferred") == "on_battery":
        return ("on_battery", "Waiting for AC power."), None
    allowed, stop_at = window(vals, agent, now)
    if not allowed:
        return ("window", "Waiting for the backup window."), None
    up = _ms(state.conditions.get("up_since"))
    # a manual point is claimable at once after a reconnect
    if (
        image.trigger != Trigger.MANUAL
        and vals["catch_up"] == "run_asap"
        and up
        and image.created_at < up
    ):
        start = up + timedelta(minutes=vals["catch_up_delay_minutes"])
        if now < start:
            _wake_at(agent, start)
            return (
                "catch_up_delay",
                f"The device is back online; the missed backup starts at {start:%H:%M} UTC.",
            ), None
    target = StorageTarget.objects.filter(pk=image.target_id).first()
    used = state.usage.get(str(image.target_id), 0)
    full = None
    if vals["quota_bytes"] and used >= vals["quota_bytes"]:
        full = ("quota_device", "The backup quota of this device is used up.")
    elif target and target.quota_bytes and target.used_bytes >= target.quota_bytes:
        full = ("quota_target", f"The backup target {target.name} is full.")
        from .tasks import _notice

        _notice(
            f"backup:quota:{target.pk}",
            "error",
            f"Backup target {target.name} is full",
            f"{target.used_bytes} of {target.quota_bytes} bytes used.",
        )
    if full:
        alert(agent, state, "quota_exceeded", full[1])
        state.save(update_fields=["alerts", "updated_at"])
        return full, None
    if "quota_exceeded" in state.alerts:
        clear_alert(state, "quota_exceeded")
        state.save(update_fields=["alerts", "updated_at"])
    if target:
        # a legacy run past the idle limits of the re-claim no longer holds a slot
        idle = Q(agent_protocol=0) & (
            Q(
                image__status=ImageStatus.UPLOADING,
                image__updated_at__lt=now - timedelta(minutes=5),
            )
            | Q(
                image__status=ImageStatus.WAITING,
                image__updated_at__lt=now - timedelta(hours=1),
            )
        )
        busy = (
            BackupRun.objects.filter(
                status__in=OPEN_RUNS,
                image__target=target,
                image__status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING),
            )
            .exclude(image=image)
            .exclude(idle)
            .count()
        )
        if busy >= target.max_runs:
            return (
                "target_busy",
                f"Waiting: {busy} backups already run on target {target.name}.",
            ), None
    try:
        _check_storage(image)
    except StoreUnavailable:
        return ("store", OTHER_STORE), None
    except OSError:
        return ("store", "Imaging storage is unavailable."), None
    return None, stop_at

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.response import Response

from ulrmm.constants import AlertSeverity

from .models import (
    OPEN_RUNS,
    BackupRun,
    ImageStatus,
    RunStatus,
    RunStep,
    Transfer,
)
from .serializers import PHASES
from .service import (
    audit,
    backup_rows,
    clear_alert,
    keep_blocks,
    raise_alert,
    set_status,
    usage_later,
)

LOG_KEEP = 2000
WARNINGS_KEEP = 64
HOOKS_KEEP = 16
RUNS_KEPT = 20
STALE = "The agent stopped reporting progress."
ENDED = "This run has ended."
MESSAGES = {
    "run_failed": "A backup run failed.",
    "failures_in_row": "Backup runs failed several times in a row.",
    "interruptions_in_row": "Backup runs were interrupted three times in a row.",
    "stale": "No recent verified backup.",
    "verify_failed": "A backup point failed verification.",
    "quota_exceeded": "The backup quota is used up.",
    "quota_high": "The backup quota is over 90 % used.",
    "smart_warning": "A disk of the backup source reports a SMART warning.",
}
SEVERITY = {
    "run_failed": AlertSeverity.WARNING,
    "failures_in_row": AlertSeverity.ERROR,
    "interruptions_in_row": AlertSeverity.WARNING,
    "stale": AlertSeverity.ERROR,
    "verify_failed": AlertSeverity.ERROR,
    "quota_exceeded": AlertSeverity.ERROR,
    "quota_high": AlertSeverity.WARNING,
    "smart_warning": AlertSeverity.WARNING,
}
CLEARED_BY_SUCCESS = (
    "run_failed",
    "failures_in_row",
    "interruptions_in_row",
    "stale",
    "verify_failed",
)


def alert(agent, state, kind, body=""):
    raise_alert(agent, state, kind, SEVERITY[kind], MESSAGES[kind], body)


def _count(**kw):
    return serializers.IntegerField(
        min_value=0, max_value=2**63 - 1, required=False, **kw
    )


class CountersSerializer(serializers.Serializer):
    bytes_read = _count()
    blocks_read = _count()
    blocks_new = _count()
    bytes_sent = _count()
    rate = _count()
    eta = _count(allow_null=True)
    expected_bytes = _count(allow_null=True)
    dedup_permille = _count()
    compression_permille = _count()


class WarningSerializer(serializers.Serializer):
    code = serializers.ChoiceField(choices=("smart", "hook", "window", "other"))
    detail = serializers.CharField(max_length=512, allow_blank=True, default="")


class HookResultSerializer(serializers.Serializer):
    phase = serializers.ChoiceField(choices=PHASES)
    script_id = serializers.IntegerField(min_value=1, max_value=2**31 - 1)
    sha256 = serializers.RegexField(r"\A([0-9a-f]{64})?\Z", allow_blank=True)
    status = serializers.ChoiceField(
        choices=("ok", "failed", "timeout", "suspended", "skipped")
    )
    exit_code = serializers.IntegerField(
        min_value=-(2**31), max_value=2**32, allow_null=True, default=None
    )
    duration_ms = _count(default=0)
    stdout = serializers.CharField(
        max_length=4096, allow_blank=True, trim_whitespace=False, default=""
    )
    stderr = serializers.CharField(
        max_length=4096, allow_blank=True, trim_whitespace=False, default=""
    )


class FinalSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=("failed", "interrupted", "cancelled"))
    reason = serializers.CharField(max_length=255)


class ProgressSerializer(serializers.Serializer):
    run = serializers.UUIDField()
    state = serializers.ChoiceField(choices=("running", "paused"), required=False)
    step = serializers.ChoiceField(
        choices=("snapshot", "scan", "transfer", "verify", "cleanup"), required=False
    )
    pause_reason = serializers.ChoiceField(
        choices=("", "network", "battery"), required=False
    )
    counters = CountersSerializer(required=False)
    log = serializers.ListField(
        child=serializers.CharField(
            max_length=512, allow_blank=True, trim_whitespace=False
        ),
        max_length=64,
        required=False,
    )
    warnings = WarningSerializer(many=True, max_length=64, required=False)
    hooks = HookResultSerializer(many=True, max_length=8, required=False)
    final = FinalSerializer(allow_null=True, required=False)


def finish(run, status, reason, by=None):
    """End a run; the device counters and alerts follow after the commit."""
    run.status = status
    run.reason = reason[:255]
    run.ended_at = timezone.now()
    if by is not None:
        run.cancelled_by = by
    run.save(
        update_fields=["status", "reason", "ended_at", "cancelled_by", "updated_at"]
    )
    # a device that loops claim and interrupt keeps a bounded history per point
    old = (
        BackupRun.objects.filter(image_id=run.image_id)
        .exclude(status__in=(RunStatus.DEFERRED, *OPEN_RUNS))
        .order_by("-created_at")
        .values_list("pk", flat=True)[RUNS_KEPT:]
    )
    BackupRun.objects.filter(pk__in=list(old)).delete()
    pk = run.pk
    # the state row is locked after the image locks are gone, as the poll locks it first
    transaction.on_commit(lambda: settle(pk, ended=True), robust=True)


def expire(image):
    now = timezone.now()
    Transfer.objects.filter(
        image=image, direction="capture", expires_at__gt=now
    ).update(expires_at=now)


def interrupt(run, image, reason):
    """A run that stopped without an end: its point waits for the next claim."""
    finish(run, RunStatus.INTERRUPTED, reason)
    if image.status in (ImageStatus.WAITING, ImageStatus.UPLOADING):
        expire(image)
        set_status(image, ImageStatus.WAITING, reason[:255])


def end_quietly(run, image, reason):
    """End an open run that sent no final; a requested cancel still stands.
    True when the point was discarded."""
    if run.cancel_requested:
        finish(run, RunStatus.CANCELLED, reason)
        who = run.cancelled_by.username if run.cancelled_by else "the agent"
        drop(image, f"Backup cancelled by {who}.")
        return True
    interrupt(run, image, reason)
    return False


def drop(image, reason):
    """Fail a point after its run failed or was cancelled."""
    keep_blocks(image)
    image.parts.all().delete()
    expire(image)
    set_status(image, ImageStatus.FAILED, reason[:255])
    audit(image.agent, "imaging", f"Image {image.id} failed: {reason}"[:255])
    if image.agent_id:
        usage_later(image.agent_id)


def point_changed(image):
    """Runs follow a point that the server failed or sealed (contract 9.1)."""
    runs = image.runs.filter(status__in=OPEN_RUNS)
    if image.status == ImageStatus.FAILED:
        # a deferred row of a failed point never starts
        for run in image.runs.select_for_update().filter(
            status__in=(RunStatus.DEFERRED, *OPEN_RUNS)
        ):
            finish(run, RunStatus.FAILED, image.reason or "The backup point failed.")
    elif image.status == ImageStatus.VERIFYING:
        runs.exclude(step=RunStep.VERIFY).update(
            step=RunStep.VERIFY, updated_at=timezone.now()
        )


def settle(run_pk, *, ended):
    from .tasks import prune_device

    with transaction.atomic():
        run = BackupRun.objects.select_related("image__agent").filter(pk=run_pk).first()
        if run is None or run.image.agent is None:
            return
        image, agent = run.image, run.image.agent
        profile, state = backup_rows(agent, lock=True)
        smart = next((w["detail"] for w in run.warnings if w["code"] == "smart"), None)
        if smart is not None:
            alert(agent, state, "smart_warning", smart)
        if ended:
            if smart is None:
                clear_alert(state, "smart_warning")
            if run.status == RunStatus.FAILED:
                state.consecutive_failures += 1
                state.consecutive_interruptions = 0
                alert(agent, state, "run_failed", run.reason)
                limit = (profile.effective or {}).get("alert_failures", 3)
                if state.consecutive_failures >= limit:
                    alert(agent, state, "failures_in_row", run.reason)
            elif run.status == RunStatus.INTERRUPTED:
                state.consecutive_interruptions += 1
                if state.consecutive_interruptions >= 3:
                    alert(agent, state, "interruptions_in_row", run.reason)
            audit(
                agent,
                "imaging",
                f"Backup run {run.pk} {run.status}: {run.reason or 'verified'}.",
            )
        state.save()
        if ended and run.status == RunStatus.SUCCEEDED:
            verified(agent, profile, state, image)
            # the point just verified stays, whatever its snapshot time says
            prune_device(agent.pk, timezone.now(), keep={image.pk})


def verified(agent, profile, state, image):
    """A point passed its first verification: the success time, the next
    interval run and the usage move (contract 3.7)."""
    from .resolver import next_occurrence
    from .service import update_usage

    now = timezone.now()
    state.last_success_at = image.verified_at or now
    state.consecutive_failures = state.consecutive_interruptions = 0
    for kind in CLEARED_BY_SUCCESS:
        clear_alert(state, kind)
    state.save(
        update_fields=[
            "last_success_at",
            "consecutive_failures",
            "consecutive_interruptions",
            "alerts",
            "updated_at",
        ]
    )
    if profile.effective:
        profile.next_run = next_occurrence(profile.effective, state, now, agent)
        profile.save(update_fields=["next_run"])
    update_usage(agent, state)


def point_verified(image_pk):
    """The first verification of a point that had no run (an offline capture)."""
    from .models import Image

    with transaction.atomic():
        image = Image.objects.select_related("agent").filter(pk=image_pk).first()
        if image is None or image.agent is None:
            return
        profile, state = backup_rows(image.agent, lock=True)
        verified(image.agent, profile, state, image)


def verify_failed(agent_pk):
    from agents.models import Agent

    with transaction.atomic():
        agent = Agent.objects.filter(pk=agent_pk).first()
        if agent is None:
            return
        _, state = backup_rows(agent, lock=True)
        alert(agent, state, "verify_failed")
        state.save(update_fields=["alerts", "updated_at"])


def _hook_audits(agent, run, results, origin):
    from scripts.models import Script

    from .models import BackupPolicy

    if origin["level"] == "device":
        approver, where = agent.profile.hooks_approved_by, "device settings"
    else:
        policy = (
            BackupPolicy.objects.select_related("hooks_approved_by")
            .filter(pk=origin["id"])
            .first()
        )
        approver = policy.hooks_approved_by if policy else None
        where = policy.name if policy else origin["name"]
    names = Script.objects.in_bulk([r["script_id"] for r in results])
    for r in results:
        script = names.get(r["script_id"])
        audit(
            agent,
            "imaging",
            f"Backup hook {script.name if script else r['script_id']} "
            f"({r['sha256'][:12]}) {r['status']} in {r['phase']} for run {run.pk}; "
            f"approved by {approver.username if approver else 'unknown'} for {where}."[
                :255
            ],
        )


def progress(request, grant, image):
    """PATCH progress/ (contract 5.6.1); the caller holds the image lock for a final."""
    serializer = ProgressSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    if grant.run_id is None or data["run"] != grant.run_id:
        return Response({"detail": "This is not the run of this grant."}, status=404)
    run = BackupRun.objects.select_for_update().get(pk=grant.run_id)
    live = run.status in OPEN_RUNS and image.status in (
        ImageStatus.WAITING,
        ImageStatus.UPLOADING,
    )
    final = data.get("final")
    if final and not live:
        return Response({"detail": ENDED}, status=409)
    if data.get("log"):
        log = run.log + data["log"]
        cut = max(0, len(log) - LOG_KEEP)
        run.log, run.log_start = log[cut:], run.log_start + cut
    warnings = data.get("warnings", [])
    run.warnings = (run.warnings + warnings)[:WARNINGS_KEEP]
    fresh, agent = [], image.agent
    # results only for the hooks the claim carried, so the audit names no other script
    carried = {(h["phase"], h["script_id"]) for h in run.claimed_hooks}
    for result in data.get("hooks", []):
        # a resent result after a 409 is the same object and counts once
        if (
            (result["phase"], result["script_id"]) in carried
            and result not in run.hooks
            and len(run.hooks) < HOOKS_KEEP
        ):
            run.hooks = [*run.hooks, result]
            fresh.append(result)
    if live:
        if "state" in data:
            run.status = data["state"]
        for key in ("step", "pause_reason", "counters"):
            if key in data:
                setattr(run, key, data[key])
    run.save()
    if fresh:
        from .resolver import effective

        _hook_audits(agent, run, fresh, effective(agent)["fields"]["hooks"]["origin"])
    if final:
        reason = final["reason"]
        # a requested cancel stands, also when the agent stopped first; only it counts as one
        if final["status"] == "interrupted" or (
            final["status"] == "cancelled" and run.cancel_requested
        ):
            end_quietly(run, image, reason)
        else:
            finish(run, RunStatus.FAILED, reason)
            drop(image, reason)
    else:
        if live:
            from .views import renew

            # hooks and staging send progress but no block for a long time
            renew(grant)
        if any(w["code"] == "smart" for w in warnings):
            pk = run.pk
            transaction.on_commit(lambda: settle(pk, ended=False), robust=True)
    return Response({"cancel": run.cancel_requested})


def stale_runs(now):
    """Protocol-2 runs without a PATCH past their pause limit (contract 9.5)."""
    from datetime import timedelta

    from .models import Image

    candidates = list(
        BackupRun.objects.filter(
            status__in=OPEN_RUNS,
            agent_protocol=2,
            image__status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING),
            updated_at__lt=now - timedelta(minutes=15),
        )
        .order_by("updated_at")
        .values_list("pk", "image_id", "pause_max_minutes", "updated_at")[:100]
    )
    for pk, image_id, pause, updated in candidates:
        if updated >= now - timedelta(minutes=pause + 15):
            continue
        with transaction.atomic():
            # image, then run: the lock order of the transfer endpoints
            image = (
                Image.objects.select_for_update(skip_locked=True)
                .filter(pk=image_id)
                .first()
            )
            run = (
                BackupRun.objects.select_for_update(skip_locked=True)
                .filter(pk=pk, status__in=OPEN_RUNS, updated_at=updated)
                .first()
            )
            if image and run:
                end_quietly(run, image, STALE)

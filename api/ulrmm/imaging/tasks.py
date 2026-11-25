# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import logging
from datetime import timedelta
from itertools import groupby
from zoneinfo import ZoneInfo

from celery import shared_task
from django.core.cache import cache
from django.db import OperationalError, transaction
from django.db.models import Exists, F, OuterRef
from django.utils import timezone

from .blocks import verify_point
from .models import (
    NATIVE_RECEIVING_REASON,
    OPEN_RUNS,
    RECEIVING_REASON,
    BackupPolicy,
    BackupRun,
    DeviceBackupState,
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    Profile,
    RunStatus,
    StorageTarget,
    Transfer,
    Trigger,
)
from .retention import plan, when
from .service import (
    NO_INTERNAL,
    audit,
    backup_rows,
    capability,
    clear_alert,
    internal_available,
    next_run,
    queue_capture,
    set_status,
    suspended_hooks,
    update_usage,
    usage_later,
)
from .storage import (
    UNCONFIRMED_STORAGE,
    UnconfirmedStorage,
    directory,
    remove_image_file,
    verify,
)

logger = logging.getLogger(__name__)
DEVICE_DELETED = "Device deleted. Removed after 30 days."
SCHEDULER = "imaging scheduler"
PRUNE_LIMIT = 20


@shared_task
def wake_imaging_agent(agent_id):
    from ulrmm.nats_utils import abulk_nats_command

    asyncio.run(abulk_nats_command(items=[(agent_id, {"func": "imagingpoll"})]))


@shared_task
def verify_image(image_id, *, recheck=False, retried=False):
    status = ImageStatus.VERIFIED if recheck else ImageStatus.VERIFYING
    with transaction.atomic():
        # The row lock is the claim; a duplicate task returns at once.
        # shortcut: the lock is held for the whole verification, so deleting
        # the device or the operator waits on it; use an advisory lock when
        # verifications of large points block deletes.
        image = (
            Image.objects.select_for_update(skip_locked=True)
            .filter(pk=image_id, status=status)
            .first()
        )
        if image is None:
            # The tick retries only verifying points, and a short request lock
            # can hide the row from a recheck; try once more.
            if (
                recheck
                and not retried
                and Image.objects.filter(pk=image_id, status=status).exists()
            ):
                verify_image.apply_async(
                    (image_id,), {"recheck": True, "retried": True}, countdown=60
                )
            return
        try:
            verified = verify_point(image) if image.native else verify(image)
        except OSError as error:
            logger.warning("Imaging verification storage error for image %s", image_id)
            if recheck:
                # The tick retries only verifying points; keep the verified text.
                transaction.on_commit(
                    lambda: verify_image.apply_async(
                        (image_id,), {"recheck": True}, countdown=300
                    ),
                    robust=True,
                )
                return
            reason = (
                UNCONFIRMED_STORAGE
                if isinstance(error, UnconfirmedStorage)
                else "Waiting for imaging storage before retrying verification."
            )
            set_status(image, status, reason)
            return
        if verified:
            image.verified_at = timezone.now()
            image.save(update_fields=["verified_at"])
            set_status(image, ImageStatus.VERIFIED, "")
            if not recheck:
                from .runs import finish, point_verified

                open_runs = list(
                    image.runs.select_for_update().filter(status__in=OPEN_RUNS)
                )
                for run in open_runs:
                    finish(run, RunStatus.SUCCEEDED, "")
                # a deferred row of a verified point never starts
                for run in image.runs.select_for_update().filter(
                    status=RunStatus.DEFERRED
                ):
                    finish(run, RunStatus.CANCELLED, "The point was verified.")
                if not open_runs:
                    pk = image.pk
                    transaction.on_commit(lambda: point_verified(pk), robust=True)
        else:
            set_status(
                image, ImageStatus.FAILED, "Image size or SHA-256 verification failed."
            )
            if image.agent_id:
                from .runs import verify_failed

                agent_pk = image.agent_id
                transaction.on_commit(lambda: verify_failed(agent_pk), robust=True)
        audit(
            image.agent,
            "imaging",
            f"Image {image.id} verification status: {image.status}.",
        )


def _advance(profile_id, now):
    from .resolver import missed, next_occurrence

    with transaction.atomic():
        profile = (
            Profile.objects.select_for_update(skip_locked=True)
            .filter(
                pk=profile_id,
                next_run__lte=now,
            )
            .first()
        )
        if profile is None:
            return
        agent, vals = profile.agent, profile.effective
        state = DeviceBackupState.objects.filter(agent=agent).first()
        schedule = vals.get("schedule") or {}
        last = state.last_success_at if state else None
        queued = blocked = None
        if vals.get("catch_up") == "skip" and not agent.is_online:
            audit(
                agent,
                SCHEDULER,
                "Scheduled backup missed while the device was offline.",
            )
        elif (
            schedule.get("kind") == "interval"
            and last
            and now < last + timedelta(hours=schedule["hours"])
        ):
            # the spacing floor alone never queues an interval point
            pass
        elif profile.network_mode == "internal" and not internal_available():
            audit(
                agent,
                SCHEDULER,
                f"Client imaging capture skipped. {NO_INTERNAL}",
            )
        elif (supported := capability(agent))["supported"]:
            queued = queue_capture(profile, SCHEDULER, trigger=Trigger.SCHEDULE)
            blocked = queued is None
        else:
            audit(
                agent,
                SCHEDULER,
                f"Scheduled backup skipped: {supported['reason'].rstrip('.')}."[:255],
            )
        if vals:
            count = missed(vals, state, profile.next_run, now, agent)
            if count > 1:
                audit(
                    agent, SCHEDULER, f"{count} missed backup runs coalesced into one."
                )
            profile.next_run = next_occurrence(vals, state, now, agent)
            spacing = now + timedelta(
                minutes=max(vals.get("min_spacing_minutes", 0), 15)
            )
            if blocked:
                # an open point ends some time; the occurrence is tried again soon
                profile.next_run = spacing
            elif queued is not None and profile.next_run:
                # a queued point waits at least this long before a new one replaces it
                profile.next_run = max(profile.next_run, spacing)
            elif queued is None and profile.next_run:
                # an interval without a new point would be due again at once
                floor = max(
                    vals.get("min_spacing_minutes", 0),
                    60 * schedule.get("hours", 0),
                    15,
                )
                profile.next_run = max(profile.next_run, now + timedelta(minutes=floor))
        else:
            profile.next_run = next_run(profile, now)
        profile.save(update_fields=["next_run"])


def _expire_uploads(now):
    stale = now - timedelta(days=1)
    with transaction.atomic():
        images = Image.objects.select_for_update(skip_locked=True).filter(
            status=ImageStatus.UPLOADING,
            updated_at__lt=stale,
        )[:100]
        for image in images:
            try:
                remove_image_file(image)
            except OSError:
                logger.warning("Imaging cleanup storage error for image %s", image.pk)
                continue
            image.parts.all().delete()
            set_status(image, ImageStatus.FAILED, "Incomplete upload expired.")
            audit(image.agent, "imaging", f"Incomplete image {image.id} expired.")
            if image.agent_id:
                usage_later(image.agent_id)
    Image.objects.filter(
        status=ImageStatus.UPLOADING,
        reason__in=(RECEIVING_REASON, NATIVE_RECEIVING_REASON),
        updated_at__lt=now - timedelta(minutes=3),
    ).update(
        reason="Upload paused. Reconnect to the configured recovery ingress and resume."
    )
    # Keep expired grants briefly so recovery completion can be retried and audited.
    Transfer.objects.filter(expires_at__lt=now - timedelta(days=1)).delete()


def _remove(image, message):
    try:
        remove_image_file(image)
    except OSError:
        logger.warning("Imaging cleanup storage error for image %s", image.pk)
        return False
    agent = image.agent
    # Parts cascade; their blocks become orphans for the block sweep.
    image.delete()
    audit(agent, "imaging", message)
    return True


def _restoring(now):
    return Transfer.objects.filter(
        image=OuterRef("pk"),
        direction=Transfer.Direction.RESTORE,
        expires_at__gt=now,
        completed_at__isnull=True,
    )


def _target(point):
    return point.target_id or 0


def retention_plan(profile, vals, points, keep=()):
    """(rules by verified point, newest time by target, zone name) of one
    device; the tick and the preview share it, so both decide alike."""
    zone = vals.get("timezone") or profile.timezone or "UTC"
    rules, newest = {}, {}
    good = [p for p in points if p.status == ImageStatus.VERIFIED]
    for target, group in groupby(sorted(good, key=_target), key=_target):
        group = list(group)
        newest[target] = max(when(p) for p in group)
        opened = {p.id for p in group if p.restoring} | set(keep)
        rules.update(
            plan(
                group,
                vals.get("keep_last", profile.keep_last),
                vals.get("gfs") or {},
                ZoneInfo(zone),
                opened,
            )
        )
    return rules, newest, zone


def failed_due(point, newest, now):
    """A failed point goes after 7 days once its target holds a newer verified one."""
    return point.updated_at < now - timedelta(days=7) and newest.get(
        _target(point), point.created_at
    ) > when(point)


def prune_device(agent_pk, now, limit=PRUNE_LIMIT, keep=()):
    """Retention and the failed-point cleanup of one device (contract 8.2);
    returns the number of removed points."""
    profile = Profile.objects.filter(agent_id=agent_pk).first()
    if profile is None:
        return 0
    points = list(
        Image.objects.filter(agent_id=agent_pk, status=ImageStatus.VERIFIED).annotate(
            restoring=Exists(_restoring(now))
        )
    )
    rules, newest, _ = retention_plan(profile, profile.effective or {}, points, keep)
    doomed = [pk for pk, kept in rules.items() if not kept]
    removed = 0
    with transaction.atomic():
        for image in (
            Image.objects.select_for_update(skip_locked=True)
            .filter(pk__in=doomed, status=ImageStatus.VERIFIED, protected=False)
            .exclude(Exists(_restoring(now)))[:limit]
        ):
            # storage that refuses ends the device's turn: one failed try a tick
            if not _remove(image, f"Image {image.id} removed by retention."):
                break
            removed += 1
        else:
            for image in Image.objects.select_for_update(skip_locked=True).filter(
                agent_id=agent_pk,
                status=ImageStatus.FAILED,
                updated_at__lt=now - timedelta(days=7),
            )[: max(0, limit - removed)]:
                if failed_due(image, newest, now):
                    if not _remove(
                        image, f"Failed image {image.id} removed after 7 days."
                    ):
                        break
                    removed += 1
    if removed:
        update_usage(profile.agent, backup_rows(profile.agent)[1])
    return removed


def _batch(key, model, size):
    """The next `size` primary keys after a stored cursor, wrapping around, so
    a beat touches a bounded slice and reaches every row within a few runs."""
    cursor = cache.get(key) or 0
    rows = model.objects.order_by("pk").values_list("pk", flat=True)
    pks = list(rows.filter(pk__gt=cursor)[:size])
    if len(pks) < size:
        pks += list(rows.filter(pk__lte=cursor)[: size - len(pks)])
    cache.set(key, pks[-1] if pks else 0, None)
    return pks


def _prune(now):
    from agents.models import Agent

    budget = PRUNE_LIMIT
    for agent_pk in _batch("imaging:prune:cursor", Agent, 50):
        if budget <= 0:
            return
        try:
            budget -= prune_device(agent_pk, now, budget)
        except Exception:
            logger.exception("Backup retention of agent %s failed", agent_pk)


def _failed(profile_id, now):
    profile = Profile.objects.select_related("agent").filter(pk=profile_id).first()
    logger.exception(
        "Imaging schedule of agent %s failed",
        profile.agent.agent_id if profile else "?",
    )
    if profile is None:
        return
    Profile.objects.filter(pk=profile_id).update(next_run=now + timedelta(minutes=15))
    audit(profile.agent, SCHEDULER, "Scheduled backup failed: internal error.")


def _remove_deleted_devices(now):
    with transaction.atomic():
        marked = list(
            Image.objects.select_for_update(skip_locked=True)
            .filter(agent__isnull=True)
            .exclude(reason=DEVICE_DELETED)
            .values_list("pk", flat=True)
        )
        Image.objects.filter(pk__in=marked).update(
            reason=DEVICE_DELETED, updated_at=now
        )
    with transaction.atomic():
        for image in Image.objects.select_for_update(skip_locked=True).filter(
            agent__isnull=True,
            reason=DEVICE_DELETED,
            updated_at__lt=now - timedelta(days=30),
        )[:20]:
            _remove(image, f"Image {image.id} of a deleted device removed.")


def _sweep_blocks(now):
    # A restarted upload can leave immutable blocks without a manifest. Give
    # reconnecting clients a day to reuse them. Referenced blocks are retained.
    # shortcut: with no orphans the query still checks every block older than a
    # day each minute; move it to an hourly beat entry when blocks reach millions.
    for _ in range(20):
        removed = 0
        with transaction.atomic():
            orphaned = list(
                ImageBlock.objects.select_for_update(skip_locked=True)
                .filter(created_at__lt=now - timedelta(days=1))
                .filter(~Exists(ImagePart.objects.filter(block_id=OuterRef("pk"))))[
                    :100
                ]
            )
            for block in orphaned:
                if block.imagepart_set.exists():
                    continue
                try:
                    remove_image_file(block)
                except OSError:
                    continue
                block.delete()
                removed += 1
        if len(orphaned) < 100 or not removed:
            return


def _ensure_rows():
    from agents.models import Agent

    from .resolver import resolve_now

    missing = list(
        Agent.objects.filter(backup_state__isnull=True)
        .order_by("pk")
        .values_list("pk", flat=True)[:500]
    )
    if missing:
        DeviceBackupState.objects.bulk_create(
            [DeviceBackupState(agent_id=pk) for pk in missing], ignore_conflicts=True
        )
        resolve_now(missing, cause="enrol")


def _first_resolve():
    from .resolver import resolve_now

    pending = list(
        DeviceBackupState.objects.filter(config_version=0)
        .order_by("pk")
        .values_list("agent_id", flat=True)[:500]
    )
    if pending:
        resolve_now(pending, cause="enrol")


def _reachable(ok, now):
    from .resolver import invalidate

    targets = StorageTarget.objects.filter(kind="server")
    changed = (
        targets.exclude(unreachable_since=None).update(unreachable_since=None)
        if ok
        else targets.filter(unreachable_since=None).update(unreachable_since=now)
    )
    if changed:
        invalidate()


def _clear_logs(now):
    cutoff = now - timedelta(days=30)
    old = BackupRun.objects.filter(
        status__in=(
            RunStatus.SUCCEEDED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
            RunStatus.INTERRUPTED,
        ),
        updated_at__lt=cutoff,
        ended_at__lt=cutoff,
    ).values_list("pk", flat=True)[:500]
    # the new updated_at takes a cleared run out of the next ticks' range
    BackupRun.objects.filter(pk__in=list(old)).update(log=[], updated_at=now)


@shared_task
def imaging_resolve_all():
    from agents.models import Agent

    from .resolver import resolve_now

    resolve_now(list(Agent.objects.values_list("pk", flat=True)), cause="beat")


@shared_task
def imaging_tick():
    # enrolment must never keep the schedule, uploads and retention from running
    for name, step in (("rows", _ensure_rows), ("first resolve", _first_resolve)):
        try:
            step()
        except Exception:
            logger.exception("Imaging step %s failed", name)
    now = timezone.now()
    try:
        with directory():
            pass
    except OSError:
        _reachable(False, now)
        return
    _reachable(True, now)
    from .runs import stale_runs

    stale_runs(now)
    _clear_logs(now)
    for profile_id in Profile.objects.filter(next_run__lte=now).values_list(
        "id", flat=True
    ):
        try:
            _advance(profile_id, now)
        except OperationalError:
            # shortcut: requests lock Agent then Profile, the scheduler the
            # reverse; a deadlock victim runs next minute instead of reordering.
            logger.warning("Imaging schedule for profile %s deferred", profile_id)
        except Exception:
            # one device's data must never stop the schedule of the others
            _failed(profile_id, now)
    _expire_uploads(now)
    _prune(now)
    _remove_deleted_devices(now)
    _sweep_blocks(now)
    retry_after = now - timedelta(minutes=5)
    with transaction.atomic():
        images = Image.objects.select_for_update(skip_locked=True).filter(
            status=ImageStatus.VERIFYING,
            agent__isnull=False,
            updated_at__lt=retry_after,
        )[:100]
        for image in images:
            Image.objects.filter(pk=image.pk).update(updated_at=now)
            transaction.on_commit(
                lambda image_id=str(image.id): verify_image.delay(image_id), robust=True
            )


def _notice(key, severity, title, body=""):
    from notify.dispatch import dispatch

    dispatch(
        {
            "source": "backup",
            "severity": severity,
            "title": title,
            "body": body or title,
            "dedupe_key": key,
            "dedupe_hours": 24,
        }
    )


def _hook_notices(owner, hooks, pinned, where):
    for hook in suspended_hooks(hooks, pinned):
        _notice(
            f"backup:hook:{owner}:{hook['script_id']}:{hook['sha256']}",
            "warning",
            f"Backup hook {hook['name'] or hook['script_id']} of {where} is suspended",
            "The script changed or was deleted after its hash was approved.",
        )


def _watch_device(agent_pk, now):
    from agents.models import Agent

    from .resolver import rpo
    from .runs import alert

    agent = Agent.objects.filter(pk=agent_pk).first()
    if agent is None:
        return
    with transaction.atomic():
        profile, state = backup_rows(agent, lock=True)
        vals = profile.effective
        if not vals:
            return
        if {"quota_exceeded", "quota_high"} & set(state.alerts):
            # a delete or a discard may have freed space since the last result
            update_usage(agent, state)
        limit = rpo(vals, agent, now)
        base = state.last_success_at or state.schedule_since
        if limit and base and now - base > limit:
            alert(
                agent,
                state,
                "stale",
                f"The last verified backup is older than {limit}.",
            )
        quota = vals.get("quota_bytes", 0)
        used = state.usage.get(str(vals.get("target")), 0)
        if quota and used * 10 > quota * 9:
            alert(agent, state, "quota_high", f"{used} of {quota} bytes used.")
        else:
            clear_alert(state, "quota_high")
        if "quota_exceeded" in state.alerts:
            # the claim raises it for the target of an open point, which a move keeps
            ids = {vals.get("target")} | set(
                Image.objects.filter(
                    agent=agent, status__in=(ImageStatus.WAITING, ImageStatus.UPLOADING)
                ).values_list("target_id", flat=True)
            )
            full = StorageTarget.objects.filter(
                pk__in=ids, quota_bytes__gt=0, used_bytes__gte=F("quota_bytes")
            ).exists()
            if not full and not (
                quota and any(state.usage.get(str(t), 0) >= quota for t in ids)
            ):
                clear_alert(state, "quota_exceeded")
        state.save(update_fields=["alerts", "updated_at"])
    if profile.overrides.get("hooks"):
        _hook_notices(
            f"a{agent.pk}",
            profile.overrides["hooks"],
            profile.hooks_pinned,
            f"{agent.hostname} device settings",
        )


@shared_task
def imaging_watch():
    """Staleness, quotas, unreachable targets and suspended hooks (contract 10.3)."""
    from agents.models import Agent

    now = timezone.now()
    for agent_pk in _batch("imaging:watch:cursor", Agent, 500):
        try:
            _watch_device(agent_pk, now)
        except Exception:
            logger.exception("Backup watch of agent %s failed", agent_pk)
    for target in StorageTarget.objects.order_by("pk"):
        if target.quota_bytes and target.used_bytes * 10 > target.quota_bytes * 9:
            _notice(
                f"backup:quota90:{target.pk}",
                "warning",
                f"Backup target {target.name} is over 90 % full",
            )
        if target.unreachable_since and now - target.unreachable_since > timedelta(
            hours=6
        ):
            _notice(
                f"backup:target:{target.pk}",
                "error",
                f"Backup target {target.name} is unreachable",
                f"Unreachable since {target.unreachable_since:%Y-%m-%d %H:%M} UTC.",
            )
    for policy in BackupPolicy.objects.filter(config__has_key="hooks").order_by("pk"):
        _hook_notices(
            policy.pk,
            policy.config["hooks"],
            policy.hooks_pinned,
            f"backup policy {policy.name}",
        )

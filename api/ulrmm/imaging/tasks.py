# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import logging
from datetime import timedelta
from itertools import groupby

from celery import shared_task
from django.db import OperationalError, transaction
from django.db.models import Exists, OuterRef
from django.utils import timezone

from .blocks import verify_point
from .models import (
    NATIVE_RECEIVING_REASON,
    RECEIVING_REASON,
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    Profile,
    Transfer,
)
from .service import audit, capability, next_run, queue_capture, set_status
from .storage import (
    UNCONFIRMED_STORAGE,
    UnconfirmedStorage,
    directory,
    remove_image_file,
    verify,
)

logger = logging.getLogger(__name__)
DEVICE_DELETED = "Device deleted. Removed after 30 days."


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
        else:
            set_status(
                image, ImageStatus.FAILED, "Image size or SHA-256 verification failed."
            )
        audit(
            image.agent,
            "imaging",
            f"Image {image.id} verification status: {image.status}.",
        )


def _advance(profile_id, now):
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
        if capability(profile.agent)["supported"]:
            queue_capture(profile, "imaging scheduler")
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
        return
    agent = image.agent
    # Parts cascade; their blocks become orphans for the block sweep.
    image.delete()
    audit(agent, "imaging", message)


def _prune(now):
    rows = (
        Image.objects.filter(
            status=ImageStatus.VERIFIED, agent__profile__keep_last__gt=0
        )
        .order_by("agent_id", "-created_at")
        .values_list("pk", "agent_id", "agent__profile__keep_last")
    )
    surplus = []
    for _, points in groupby(rows, key=lambda row: row[1]):
        points = list(points)
        surplus += [pk for pk, _, _ in points[points[0][2] :]]
    if not surplus:
        return
    restoring = Transfer.objects.filter(
        image=OuterRef("pk"),
        direction=Transfer.Direction.RESTORE,
        expires_at__gt=now,
        completed_at__isnull=True,
    )
    with transaction.atomic():
        for image in (
            Image.objects.select_for_update(skip_locked=True)
            .filter(pk__in=surplus, status=ImageStatus.VERIFIED)
            .exclude(Exists(restoring))[:20]
        ):
            _remove(image, f"Image {image.id} removed by the keep-last retention.")


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


@shared_task
def imaging_tick():
    try:
        with directory():
            pass
    except OSError:
        return
    now = timezone.now()
    for profile_id in Profile.objects.filter(next_run__lte=now).values_list(
        "id", flat=True
    ):
        try:
            _advance(profile_id, now)
        except OperationalError:
            # shortcut: requests lock Agent then Profile, the scheduler the
            # reverse; a deadlock victim runs next minute instead of reordering.
            logger.warning("Imaging schedule for profile %s deferred", profile_id)
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

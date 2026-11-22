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
from django.db import DatabaseError, transaction
from django.db.models import Value
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
from core.utils import stepup_denied

from . import blocks
from .models import (
    ACTIVE_STATUSES,
    MODE_CHANGED,
    RECEIVING_REASON,
    Image,
    ImageStatus,
    Pairing,
    Profile,
    Transfer,
)
from .serializers import (
    CaptureGrantSerializer,
    CompleteCaptureSerializer,
    CompleteRestoreSerializer,
    ImageSerializer,
    ManifestSerializer,
    ProfileSerializer,
    RestoreGrantSerializer,
    NativeRestoreSerializer,
)
from .service import (
    CHANGED_PATH,
    agent_allowed,
    audit,
    capability,
    check_path,
    next_run,
    origin,
    queue_capture,
    set_status,
    storage_encryption,
)
from .storage import (
    CHUNK_SIZE,
    DESTINATION,
    UNCONFIRMED_STORAGE,
    UnconfirmedStorage,
    directory,
    image_file,
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


def _storage():
    try:
        with directory():
            pass
    except OSError:
        return {"configured": False, "location": ""}
    return {"configured": True, "location": settings.ULRMM_IMAGING_ROOT}


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
                    "storage": {"configured": _storage()["configured"]},
                }
            )
        )
    flags = (MANAGE,) if request.method == "PUT" else (VIEW, MANAGE, RESTORE)
    agent = _agent(request.user, agent_id, *flags, lock=request.method == "PUT")
    supported = capability(agent)
    profiles = Profile.objects
    if request.method == "PUT":
        profiles = profiles.select_for_update()
    profile = profiles.filter(agent=agent).first() or Profile(agent=agent)
    storage = _storage()
    can_manage = agent_allowed(request.user, agent, MANAGE)
    if not can_manage:
        storage = {"configured": storage["configured"]}
    if request.method == "PUT":
        if not supported["supported"]:
            raise ValidationError(supported["reason"])
        config = _validated(ProfileSerializer, request.data)
        for key, value in config.items():
            setattr(profile, key, value)
        profile.operator = request.user
        profile.policy_id = None
        profile.next_run = next_run(profile, timezone.now())
        profile.save()
        Pairing.objects.filter(agent=agent).exclude(
            network_mode=profile.network_mode
        ).delete()
        audit(agent, request.user.username, "Client imaging configuration changed.")
    return Response(
        {
            "capability": supported,
            "storage": storage,
            "can_manage": can_manage,
            "can_restore": agent_allowed(request.user, agent, RESTORE),
            "config": ProfileSerializer(profile).data,
            "policy": (
                {"id": profile.policy_id, "name": profile.policy.name}
                if profile.policy_id
                else None
            ),
            "at_rest": storage_encryption(profile.destination),
            "pairing": _pairing_metadata(agent, request.user),
            "images": ImageSerializer(
                Image.objects.filter(agent=agent).order_by("-created_at"), many=True
            ).data,
        }
    )


@api_view(["POST"])
@transaction.atomic
def capture(request, agent_id):
    agent = _agent(request.user, agent_id, MANAGE, lock=True)
    supported = capability(agent)
    if not supported["supported"]:
        raise ValidationError(supported["reason"])
    if not _storage()["configured"]:
        return _problem("Configure private server imaging storage.", 503)
    profile, _ = Profile.objects.get_or_create(agent=agent)
    profile = Profile.objects.select_for_update().get(pk=profile.pk)
    return Response(
        ImageSerializer(
            queue_capture(profile, request.user.username, request.user)
        ).data,
        status=202,
    )


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
    return _no_cache(Response(data, status=status))


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
    image = _lock_image(get_object_or_404(Image, agent=agent, pk=image_id))
    selected = agent
    if direction == RECOVERY:
        denied = stepup_denied(request, "This grants access to restore a device disk.")
        if denied is not None:
            return denied
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
        # Windows Recovery recreates the source partitions on the target.
        if (image.native or {}).get("method") == "windows-wbadmin-tar-v1" and (
            confirmation.get("raw_size", 0) < image.native["size"]
            or confirmation.get("sector_size") != image.native["sector_size"]
        ):
            raise ValidationError(
                "The target disk must be at least as large as the source disk and use its sector size."
            )
        if image.status != ImageStatus.VERIFIED:
            return _problem(
                "The image must pass verification before it can be restored.", 409
            )
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
    if image.status not in (
        ImageStatus.WAITING,
        ImageStatus.UPLOADING,
        ImageStatus.FAILED,
    ):
        return _problem(
            "Only pending, interrupted or failed captures can be discarded.", 409
        )
    try:
        remove_image_file(image)
    except OSError:
        return _problem("Imaging storage is unavailable.", 503)
    image.parts.all().delete()
    set_status(image, ImageStatus.FAILED, "Capture discarded.")
    Transfer.objects.filter(image=image).update(expires_at=timezone.now())
    audit(agent, request.user.username, f"Client image {image.id} discarded.")
    return Response(status=204)


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
    return Response(status=204)


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
        or not agent_allowed(grant.user, image.agent, flag)
        or not agent_allowed(grant.user, grant.target, flag)
    ):
        raise PermissionDenied(
            "This imaging transfer grant has expired or been revoked."
        )
    return grant, image


@api_view(["GET", "POST", "PUT"])
@authentication_classes([])
@permission_classes([])
@transaction.atomic
def transfer(request, transfer_id, operation=""):
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
    if operation in ("data", "part") and response.status_code in (200, 204):
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
        with image_file(image, write=True) as file:
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
            set_status(
                image,
                ImageStatus.UPLOADING,
                "Waiting for free space on the imaging server.",
            )
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

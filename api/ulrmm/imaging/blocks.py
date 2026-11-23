# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import errno
import gzip
import hashlib
import io
import os
import re
import zlib

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from .models import Image, ImageBlock, ImagePart, ImageStatus, NATIVE_RECEIVING_REASON
from .service import audit, set_status
from .storage import (
    NO_SPACE,
    OTHER_STORE,
    DamagedFile,
    StoreUnavailable,
    image_file,
    read_twice,
    remove_image_file,
)

BLOCK = 2 * 1024**2
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CorruptBlock(ValueError):
    pass


def decode(data, codec, size, digest):
    try:
        if codec == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as file:
                data = file.read(size + 1)
    except (EOFError, OSError, zlib.error) as error:
        raise CorruptBlock from error
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise CorruptBlock
    return data


def load_block(image, block):
    block.network_mode = image.network_mode

    def read():
        with image_file(block) as file:
            return file.read(block.stored_size + 1)

    try:
        data = read_twice(read)
    except DamagedFile as error:
        raise CorruptBlock from error
    if len(data) != block.stored_size:
        raise CorruptBlock
    return decode(data, image.compression, block.size, block.digest)


def stored(image, block):
    block.network_mode = image.network_mode
    try:
        with image_file(block) as file:
            return os.fstat(file.fileno()).st_size == block.stored_size
    except (FileNotFoundError, DamagedFile):
        return False


def report_corrupt_dependency(block):
    # Keep all historical manifests and blob files immutable. A future verified
    # upload gets a new file, even when the digest is identical.
    block.namespace = "corrupt/" + str(block.pk)
    ImageBlock.objects.filter(pk=block.pk).update(namespace=block.namespace)

    # Other restores may hold their own image locks. Update their status after
    # releasing this transaction rather than acquiring those locks in reverse order.
    def invalidate():
        Image.objects.filter(
            parts__block_id=block.pk, status=ImageStatus.VERIFIED
        ).update(
            status=ImageStatus.FAILED,
            reason="A required backup block is missing or corrupt.",
            updated_at=timezone.now(),
        )

    transaction.on_commit(invalidate, robust=True)


def verify_point(image):
    digest = hashlib.sha256()
    total = stored = count = 0
    for part in (
        image.parts.select_related("block").order_by("index").iterator(chunk_size=256)
    ):
        if part.index != count or total != count * BLOCK:
            return False
        try:
            data = load_block(image, part.block)
        except (CorruptBlock, FileNotFoundError):
            report_corrupt_dependency(part.block)
            return False
        digest.update(data)
        total += len(data)
        stored += part.block.stored_size
        count += 1
    return (
        count > 0
        and total == image.raw_size
        and stored == image.size
        and digest.hexdigest() == image.raw_sha256
    )


def append_part(request, image):
    index = request.query_params.get("i", "")
    size = request.query_params.get("size", "")
    digest = request.query_params.get("sha256", "")
    if not (
        re.fullmatch(r"[0-9]{1,9}", index)
        and re.fullmatch(r"[0-9]{1,8}", size)
        and DIGEST.fullmatch(digest)
    ):
        raise ValidationError("Invalid block index, length or SHA-256.")
    index, size = int(index), int(size)
    if not 0 < size <= BLOCK or index * BLOCK + size > settings.ULRMM_IMAGING_MAX_BYTES:
        raise ValidationError("Block exceeds the image size limit.")
    # Restarted maps keep new_bytes, so the second bound also holds across begin.
    approved = image.native["size"]
    if (
        image.native["method"] != "windows-wbadmin-tar-v1"
        and index * BLOCK + size > approved
    ) or image.new_bytes > 2 * approved:
        # A refused part stays refused on every retry; end the point so the
        # next scheduled run can start a fresh one.
        image.parts.all().delete()
        set_status(
            image, ImageStatus.FAILED, "Upload exceeded the approved source size."
        )
        audit(image.agent, "imaging", f"Image {image.id} failed: {image.reason}")
        return Response({"detail": image.reason}, status=400)
    if index * BLOCK != image.offset:
        return Response(
            {"detail": "Block offset differs from the active capture."}, status=409
        )
    # A namespace cannot be probed across devices, destinations, compression settings or routes.
    scope = (
        image.agent_id,
        image.destination,
        image.network_mode,
        image.compression,
        image.compression_level,
    )
    namespace = hashlib.sha256(repr(scope).encode()).hexdigest()
    block = (
        ImageBlock.objects.select_for_update()
        .filter(namespace=namespace, digest=digest)
        .first()
    )
    # A dedup hit checks presence and length only; verify_point reads every
    # block and retires a damaged one, so the next capture uploads it again.
    try:
        if block and not stored(image, block):
            report_corrupt_dependency(block)
            block = None
    except StoreUnavailable:
        set_status(image, ImageStatus.UPLOADING, OTHER_STORE)
        return Response({"detail": image.reason}, status=503)
    if block and block.size != size:
        raise ValidationError("Block length differs.")
    if not block and request.method == "POST":
        return Response(status=404)
    if not block:
        length = request.META.get("CONTENT_LENGTH", "")
        if (
            not re.fullmatch(r"[0-9]{1,8}", str(length))
            or not 0 < int(length) <= BLOCK + 65536
            or request.content_type != "application/octet-stream"
        ):
            return Response(
                {"detail": "Invalid encoded block length or content type."}, status=413
            )
        body = request.stream.read(int(length))
        if len(body) != int(length):
            raise ValidationError("Incomplete block.")
        try:
            decode(body, image.compression, size, digest)
        except CorruptBlock:
            raise ValidationError("Invalid block digest or encoding.") from None
        block = ImageBlock(
            namespace=namespace,
            destination=image.destination,
            digest=digest,
            size=size,
            stored_size=len(body),
        )
        block.network_mode = image.network_mode
        try:
            with image_file(block, write=True, incoming=len(body)) as file:
                file.write(body)
                file.flush()
                os.fsync(file.fileno())
        except StoreUnavailable:
            set_status(image, ImageStatus.UPLOADING, OTHER_STORE)
            return Response({"detail": image.reason}, status=503)
        except OSError as error:
            remove_image_file(block)
            if error.errno not in (errno.ENOSPC, errno.EDQUOT):
                raise
            set_status(image, ImageStatus.UPLOADING, NO_SPACE)
            return Response({"detail": image.reason}, status=507)
        block.save(force_insert=True)
        image.new_bytes += block.stored_size
    ImagePart.objects.create(image=image, index=index, block=block)
    image.offset += size
    image.size = (image.size or 0) + block.stored_size
    image.reason = NATIVE_RECEIVING_REASON
    image.updated_at = timezone.now()
    image.save(update_fields=["new_bytes", "offset", "size", "reason", "updated_at"])
    return Response(status=204)


def capture(request, image, operation):
    if image.status not in (ImageStatus.WAITING, ImageStatus.UPLOADING):
        return Response(status=409)
    if operation == "begin" and request.method == "POST":
        # Each fresh OS snapshot gets its own map. Already uploaded immutable
        # blocks are reused when the new snapshot contains the same bytes.
        # The dropped map's blocks get a fresh grace before the orphan sweep.
        ImageBlock.objects.filter(imagepart__image=image).update(
            created_at=timezone.now()
        )
        image.parts.all().delete()
        image.offset = image.size = 0
        image.save(update_fields=["offset", "size"])
        set_status(image, ImageStatus.UPLOADING, NATIVE_RECEIVING_REASON)
        return Response(status=204)
    if image.status == ImageStatus.UPLOADING:
        if operation == "part" and request.method in ("POST", "PUT"):
            return append_part(request, image)
        if operation == "seal" and request.method == "POST":
            size, digest = request.data.get("size"), request.data.get("sha256")
            if (
                type(size) is not int
                or size <= 0
                or size != image.offset
                or not isinstance(digest, str)
                or not DIGEST.fullmatch(digest)
            ):
                raise ValidationError("Final length or SHA-256 is invalid.")
            if (
                image.native["method"] != "windows-wbadmin-tar-v1"
                and size != image.native["size"]
            ):
                raise ValidationError("The capture does not cover the complete media.")
            image.raw_size = size
            image.sha256 = image.raw_sha256 = digest
            image.save(update_fields=["raw_size", "sha256", "raw_sha256"])
            set_status(
                image,
                ImageStatus.VERIFYING,
                "Verifying the full restore point and all block dependencies.",
            )
            from .tasks import verify_image

            transaction.on_commit(
                lambda: verify_image.delay(str(image.pk)), robust=True
            )
            return Response(status=202)
    return Response(status=409)


def download(image, offset):
    if offset >= image.raw_size:
        return Response(status=416)
    try:
        part = image.parts.select_related("block").get(index=offset // BLOCK)
        try:
            data = load_block(image, part.block)
        except (CorruptBlock, FileNotFoundError):
            report_corrupt_dependency(part.block)
            raise
    except StoreUnavailable:
        return Response({"detail": OTHER_STORE}, status=503)
    except (ImagePart.DoesNotExist, CorruptBlock, FileNotFoundError):
        set_status(
            image, ImageStatus.FAILED, "A required backup block is missing or corrupt."
        )
        return Response({"detail": image.reason}, status=409)
    response = HttpResponse(
        data[offset % BLOCK :], content_type="application/octet-stream"
    )
    response["Cache-Control"] = "no-store"
    return response

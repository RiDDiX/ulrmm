# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import gzip
import hashlib
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from re import compile
from zlib import error as ZlibError

from django.conf import settings

CHUNK_SIZE = 4 * 1024**2
LOCAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs"}
UNCONFIRMED_STORAGE = "Waiting for a confirmed local disk on the imaging server."


class UnconfirmedStorage(OSError):
    pass


def _local_disk(fd):
    if not settings.ULRMM_IMAGING_INTERNAL_STORAGE_CONFIRMED:
        raise UnconfirmedStorage(UNCONFIRMED_STORAGE)
    fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
    mount_id = next(
        (line.split()[1] for line in fdinfo if line.startswith("mnt_id:")), None
    )
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields, _, filesystem = line.partition(" - ")
        if fields.split()[0] == mount_id and filesystem.split()[0] in LOCAL_FS:
            return
    raise UnconfirmedStorage(UNCONFIRMED_STORAGE)


DESTINATION = compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


@contextmanager
def directory(destination=None, *, create=False, internal=False):
    root = Path(settings.ULRMM_IMAGING_ROOT)
    if not root.is_absolute():
        raise OSError("Imaging requires an absolute storage root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, flags)
    try:
        _private(root_fd)
        if internal:
            _local_disk(root_fd)
        if destination is None:
            yield root_fd
            return
        if not DESTINATION.fullmatch(destination):
            raise OSError("Invalid imaging destination")
        if create:
            try:
                os.mkdir(destination, mode=0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
        fd = os.open(destination, flags, dir_fd=root_fd)
        try:
            _private(fd)
            if internal:
                _local_disk(fd)
            yield fd
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def _private(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OSError("Imaging storage must be private to the backend service user")


@contextmanager
def image_file(image, *, write=False):
    with directory(
        image.destination, create=write, internal=image.network_mode == "internal"
    ) as folder:
        # shortcut: one flat folder per destination; ext4 without large_dir caps
        # it near 10-20 million blocks, fan out when a destination nears 20 TB.
        name = str(image.id)
        flags = os.O_NOFOLLOW | os.O_NONBLOCK
        if write:
            try:
                fd = os.open(
                    name,
                    flags | os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=folder,
                )
            except FileExistsError:
                fd = os.open(name, flags | os.O_RDWR, dir_fd=folder)
        else:
            fd = os.open(name, flags | os.O_RDONLY, dir_fd=folder)
        with os.fdopen(fd, "r+b" if write else "rb") as output:
            _private(fd)
            if image.network_mode == "internal":
                _local_disk(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("Imaging storage requires a private regular file")
            yield output
            if write:
                os.fsync(folder)


def remove_image_file(image):
    try:
        with directory(
            image.destination, internal=image.network_mode == "internal"
        ) as folder:
            os.unlink(str(image.id), dir_fd=folder)
    except FileNotFoundError:
        pass


def verify(image):
    try:
        with image_file(image) as file:
            if os.fstat(file.fileno()).st_size != image.size:
                return False
            if hashlib.file_digest(file, "sha256").hexdigest() != image.sha256:
                return False
            file.seek(0)
            if image.compression == "none":
                return image.size == image.raw_size and image.sha256 == image.raw_sha256
            with gzip.GzipFile(fileobj=file, mode="rb") as raw:
                remaining = image.raw_size
                digest = hashlib.sha256()
                while remaining:
                    chunk = raw.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        return False
                    remaining -= len(chunk)
                    digest.update(chunk)
                return not raw.read(1) and digest.hexdigest() == image.raw_sha256
    except (gzip.BadGzipFile, EOFError, ZlibError, FileNotFoundError):
        return False

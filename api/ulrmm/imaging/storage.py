# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import errno
import grp
import gzip
import hashlib
import os
import pwd
import secrets
import shlex
import stat
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from re import compile
from zlib import error as ZlibError

from django.conf import settings

CHUNK_SIZE = 4 * 1024**2
LOCAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs"}
UNCONFIRMED_STORAGE = "Waiting for a confirmed local disk on the imaging server."
NO_SPACE = "Waiting for free space on the imaging server."
# a usable store holds this file with the store id, so a moved or remounted
# copy is recognised and an unmounted disk is not taken for the store
MARKER = ".ulrmm-images"
OTHER_STORE = (
    "The image store is not reachable or is not this server's store. Check that "
    "its disk is mounted, or choose its folder in Global Settings > System Images."
)
SYSTEM_PATHS = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/postgresql",
    "/var/lib/redis",
    "/root",
    "/rmm",
    "/opt/ulrmm-web",
    "/opt/ulrmm-agents",
)
# mount points and shared parents: a store gets its own subfolder there
SHARED_PARENTS = ("/var", "/home", "/opt", "/srv", "/mnt", "/media")
# cleaned up by the system, so never a store
TEMP_PATHS = ("/tmp", "/var/tmp")


def _core():
    from core.utils import CoreSettingsNotFound, get_core_settings

    try:
        return get_core_settings()
    except CoreSettingsNotFound:
        return None


def imaging_root(core=None):
    core = core or _core()
    return (core and core.imaging_root) or settings.ULRMM_IMAGING_ROOT


class UnconfirmedStorage(OSError):
    pass


class StoreUnavailable(OSError):
    """The root is missing or another store: points wait instead of failing."""


class DamagedFile(OSError):
    """A stored file that cannot be read back: its point fails instead of waiting."""


def _fsid(fd):
    # ext4, btrfs and zfs derive it from the file system, xfs, f2fs and vfat
    # from the device number, NFS and FUSE report 0; an unmounted disk's mount
    # point folder lies on the parent file system and has another one
    return str(os.statvfs(fd).f_fsid)


def _read_marker(root_fd):
    try:
        fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as marker:
        return marker.read(64).decode("ascii", "replace").strip()


def _write_marker(root_fd, store):
    if _read_marker(root_fd) == store:
        return
    # readers never see a half written marker, not even after a power cut
    part = f"{MARKER}.{secrets.token_hex(8)}"
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
    try:
        with os.fdopen(fd, "w") as marker:
            marker.write(store + "\n")
            marker.flush()
            os.fsync(marker.fileno())
        os.replace(part, MARKER, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(part, dir_fd=root_fd)
    os.fsync(root_fd)


def _remember(store, fs):
    from core.models import CoreSettings
    from core.utils import CORESETTINGS_CACHE_KEY
    from django.core.cache import cache

    CoreSettings.objects.update(imaging_store_id=store, imaging_store_fs=fs)
    cache.delete(CORESETTINGS_CACHE_KEY)


# what this process last found to be the store, checked again each minute
_verified = None


def _identity(root_fd, core):
    info = os.fstat(root_fd)
    try:
        marker = os.stat(MARKER, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return (
        info.st_dev,
        info.st_ino,
        _fsid(root_fd),
        marker.st_ino,
        marker.st_ctime_ns,
        core.imaging_store_id,
        core.imaging_store_fs,
        int(time.monotonic() // 60),
    )


def _holds_each_kind(root_fd):
    held = {}
    for relative, size, exact, kind in newest_files(kinds=True):
        found = _holds(f"/proc/self/fd/{root_fd}", relative, size, exact)
        held[kind] = held.get(kind, False) or found
    return all(held.values())


def _same_store(root_fd, core):
    """The root is this server's store: its marker holds the store id and it is
    the file system the store was claimed on. Anything else waits while backup
    data is stored, so a missing mount never fails points."""
    global _verified
    if core is None:
        return
    key = _identity(root_fd, core)
    if key is not None and key == _verified:
        return
    store, fs = core.imaging_store_id, core.imaging_store_fs
    here = _fsid(root_fd)
    marker = _read_marker(root_fd)
    ours = bool(store) and marker == store
    if ours and fs in ("", here):
        if fs != here:
            _remember(store, here)
            core.imaging_store_fs = here
    elif newest_files():
        # the store's marker on another file system id is a renumbered device
        # or a copy, and a store from before the marker has none: either counts
        # when it holds the newest data of each kind, an unmounted disk does not
        if not (ours or (not store and not marker)) or not _holds_each_kind(root_fd):
            raise StoreUnavailable(OTHER_STORE)
        claim(root_fd, core)
    elif marker and not ours:
        # another server's store is never taken over without an explicit move
        raise StoreUnavailable(OTHER_STORE)
    else:
        claim(root_fd, core)
    _verified = _identity(root_fd, core)


def claim(root_fd, core, store=None):
    """Makes the open root this server's store and returns (store id, fsid)."""
    from core.models import CoreSettings

    _private(root_fd)
    if not store:
        # one id for every process that claims a new store at the same time
        CoreSettings.objects.filter(imaging_store_id="").update(
            imaging_store_id=secrets.token_hex(16)
        )
        store = CoreSettings.objects.values_list("imaging_store_id", flat=True).get()
    _write_marker(root_fd, store)
    fs = _fsid(root_fd)
    _remember(store, fs)
    core.imaging_store_id, core.imaging_store_fs = store, fs
    return store, fs


def newest_files(count=3, kinds=False):
    """(store-relative path, size, exact) of the newest stored data, newest first.

    Empty means nothing is stored. An upload holds at least its offset.
    """
    from .models import Image, ImageBlock, ImageStatus

    images = Image.objects.filter(
        native__isnull=True,
        offset__gt=0,
        status__in=(ImageStatus.UPLOADING, ImageStatus.VERIFYING, ImageStatus.VERIFIED),
    ).order_by("-created_at")[:count]
    newest = ImageBlock.objects.exclude(namespace__startswith="corrupt/").order_by(
        "-created_at"
    )[:count]
    files = [
        (
            (f"{row.destination}/{row.id}", row.offset, False, "image")
            if row.status == ImageStatus.UPLOADING
            else (f"{row.destination}/{row.id}", row.size, True, "image")
        )
        for row in images
    ] + [
        (f"{row.destination}/{row.id}", row.stored_size, True, "block")
        for row in newest
    ]
    return files if kinds else [f[:3] for f in files]


def claim_store(path, store=None, core=None):
    """Marks a folder that passed check_root as this server's store."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _private(fd)
        return claim(fd, core or _core(), store)
    finally:
        os.close(fd)


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
    core = _core()
    root = Path(imaging_root(core))
    if not root.is_absolute():
        raise OSError("Imaging requires an absolute storage root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
    except OSError as error:
        # with stored points a missing folder is a lost mount, not a new setup
        if newest_files():
            raise StoreUnavailable(OTHER_STORE) from error
        raise
    try:
        # identity first: an unmounted disk's folder is not the store even
        # before its owner or mode are looked at
        _same_store(root_fd, core)
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


def _name(lookup, number):
    try:
        return lookup(number)[0]
    except KeyError:
        return str(number)


def _system_path(path):
    repo = str(Path(settings.BASE_DIR).resolve().parent.parent)
    denied = {*SYSTEM_PATHS, *TEMP_PATHS, repo} - {"/"}
    return any(
        candidate == "/"
        or candidate in SHARED_PARENTS
        or any(candidate == d or candidate.startswith(d + "/") for d in denied)
        for candidate in (path, os.path.realpath(path))
    )


def _nested(path, current):
    # a folder inside the current store or around it would copy the store into itself
    if not os.path.isabs(current) or path == current:
        return False
    real, here = os.path.realpath(path), os.path.realpath(current)
    return real != here and (
        real.startswith(here.rstrip("/") + "/")
        or here.startswith(real.rstrip("/") + "/")
    )


def _encodable(path):
    try:
        os.fsencode(path)
    except UnicodeEncodeError:
        return False
    return "\0" not in path


def _holds(path, relative, size, exact):
    with suppress(OSError):
        info = os.lstat(os.path.join(path, relative))
        return stat.S_ISREG(info.st_mode) and (
            info.st_size == size if exact else info.st_size >= size
        )
    return False


def check_root(path, current, probes=(), current_ok=True, unreachable=False, store=""):
    """Checks a candidate storage root without changing it.

    probes are newest_files() of the stored data; another folder, or the
    current one while it cannot be used, must hold them. unreachable: the
    current store is missing or not this server's store. store: the store id.
    """
    user = _name(pwd.getpwuid, os.geteuid())
    group = _name(grp.getgrgid, os.getegid())
    absolute = (
        _encodable(path) and os.path.isabs(path) and os.path.normpath(path) == path
    )
    system = absolute and _system_path(path)
    # an unreadable store cannot be copied into itself
    nested = absolute and not system and current_ok and _nested(path, current)
    allowed = absolute and not system and not nested
    info = None
    if allowed:
        with suppress(OSError):
            info = os.lstat(path)
    folder = info is not None and stat.S_ISDIR(info.st_mode)
    owner = folder and info.st_uid == os.geteuid()
    private = folder and not info.st_mode & 0o077
    names = marker = None
    if folder:
        with suppress(OSError):
            names = set(os.listdir(path)) - {"lost+found"}
        with suppress(OSError):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                marker = _read_marker(fd)
            finally:
                os.close(fd)
    # empty, or an image folder that is not another server's store
    ours = names is not None and (
        not names or (MARKER in names and marker in ("", store))
    )
    stranded = bool(probes) and unreachable
    # with stored data another folder must hold its copy or be the same disk,
    # and so must the current folder while it cannot be used (an unmounted disk)
    needs_data = bool(probes) and (path != current or not current_ok)
    older = False
    if needs_data:
        content = all(_holds(path, *p) for p in probes)
        # while the store is lost, an older copy of it may be taken on purpose;
        # points whose data it lacks fail when they are checked
        older = not content and unreachable and bool(store) and marker == store
        content = content or older
    elif path == current:
        content = True
    else:
        content = ours
    if not needs_data:
        content_text = (
            f"The folder holds other files. Use an empty subfolder such as "
            f"{path}/rmmimages."
        )
    elif current_ok:
        content_text = (
            f"The folder must hold a copy of the current store {current} with its "
            "newest backup data, or be the same disk."
        )
    elif path == current:
        content_text = (
            "Mount the disk that holds the stored system images here, or choose "
            "the folder where it is mounted now."
        )
    else:
        content_text = (
            "The folder must be the disk that holds the stored system images. "
            f"The current folder {current or '(none)'} cannot be read."
        )
    checks = [
        (
            "absolute",
            absolute,
            "Enter an absolute path without trailing slash, . or .. parts.",
        ),
        (
            "allowed",
            allowed,
            (
                "The folder must not be inside the current store or contain it."
                if nested
                else "The path must not be / or a system, database or program folder."
            ),
        ),
        ("exists", info is not None, "The folder must exist."),
        ("directory", folder, "The path must be a folder, not a symlink or file."),
        ("owner", owner, f"The folder must belong to {user}."),
        ("mode", private, "The folder must be private to its owner (mode 0700)."),
        ("content", folder and content, content_text),
    ]
    quoted = shlex.quote(path)
    create = f"sudo install -d -m 0700 -o {user} -g {group}"
    fix = ""
    if allowed and info is None:
        # a missing store folder is an unmounted disk, not a folder to create
        if not (probes and path == current):
            fix = f"{create} {quoted}"
    elif folder and not (owner and private):
        # never take over a folder that holds other data, nor make an empty
        # mount point look like the store while the stored points are unreachable
        if not stranded or content:
            fix = (
                f"sudo chown {user}:{group} {quoted} && sudo chmod 0700 {quoted}"
                if ours or content
                else f"{create} {shlex.quote(path + '/rmmimages')}"
            )
    elif folder and not content and needs_data:
        if current_ok and current:
            fix = f"sudo rsync -a {shlex.quote(current + '/')} {quoted}/"
    elif folder and not content:
        fix = f"{create} {shlex.quote(path + '/rmmimages')}"
    # a lost disk: an empty folder may replace it and retire the stored points
    fresh = names is not None and names <= {MARKER}
    volume = None
    if folder:
        with suppress(OSError):
            volume = os.statvfs(path)
    return {
        "ok": all(ok for _, ok, _ in checks),
        "older_copy": older,
        "can_start_new": stranded
        and fresh
        and not content
        and all(ok for key, ok, _ in checks if key != "content"),
        "checks": [{"key": k, "ok": bool(ok), "text": t} for k, ok, t in checks],
        "fix": fix,
        "free_bytes": volume and volume.f_bavail * volume.f_frsize,
        "total_bytes": volume and volume.f_blocks * volume.f_frsize,
        "service_user": user,
        "service_group": group,
    }


def _answers(folder):
    # a disk that dropped off answers EIO, and one that went read-only after an
    # error answers EROFS; a full one still answers
    name = f".ulrmm-probe-{secrets.token_hex(8)}"
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=folder)
        try:
            os.write(fd, b"probe")
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as error:
        return error.errno in (errno.ENOSPC, errno.EDQUOT)
    finally:
        with suppress(OSError):
            os.unlink(name, dir_fd=folder)
    return True


def free_bytes(fd):
    info = os.statvfs(fd)
    return info.f_bavail * info.f_frsize


def _private(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OSError("Imaging storage must be private to the backend service user")


@contextmanager
def image_file(image, *, write=False, incoming=0):
    with directory(
        image.destination, create=write, internal=image.network_mode == "internal"
    ) as folder:
        # shortcut: one flat folder per destination; ext4 without large_dir caps
        # it near 10-20 million blocks, fan out when a destination nears 20 TB.
        name = str(image.id)
        flags = os.O_NOFOLLOW | os.O_NONBLOCK
        if write:
            # Keep a reserve so a full volume does not take the server down with it.
            if free_bytes(folder) - incoming < settings.ULRMM_IMAGING_RESERVE_BYTES:
                raise OSError(errno.ENOSPC, NO_SPACE)
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
                raise DamagedFile("Imaging storage requires a private regular file")
            try:
                yield output
            except OSError as error:
                # a read error inside an opened file is damage there, not a lost
                # store, unless the disk itself stopped answering
                if write or error.errno != errno.EIO:
                    raise
                if not _answers(folder):
                    raise StoreUnavailable(OTHER_STORE) from error
                raise DamagedFile(
                    errno.EIO, "Stored imaging data cannot be read"
                ) from error
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


def read_twice(read):
    """Calls read(); a read error is damage only when it repeats, so a passing
    link reset does not fail a point."""
    try:
        return read()
    except DamagedFile as error:
        if error.errno != errno.EIO:
            raise
    return read()


def verify(image):
    try:
        return read_twice(lambda: _verify(image))
    except DamagedFile:
        return False


def _verify(image):
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

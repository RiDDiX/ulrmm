#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Capture or recover a Linux system disk with a ULRMM transfer."""

import argparse
import contextlib
import decimal
import errno
import fcntl
import getpass
import gzip
import hashlib
import http.client
import json
import os
import platform
import posixpath
import re
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from pathlib import Path

CHUNK = 4 * 1024 * 1024
NATIVE_CHUNK = 2 * 1024 * 1024
NATIVE_METHOD = "linux-offline-disk-v1"
FILES_METHOD = "linux-files-v1"
RESTORE_ROOT = "/run/ulrmm-restore"
RESTORE_TOOLS = (
    "sfdisk",
    "blockdev",
    "udevadm",
    "lsblk",
    "wipefs",
    "blkid",
    "mount",
    "umount",
    "mkfs.ext4",
    "e2fsck",
    "mkfs.fat",
    "fsck.vfat",
    "mkswap",
)
APPROVED = (
    "agent_id",
    "image_id",
    "network_mode",
    "compression",
    "sha256",
    "raw_sha256",
    "size",
)
UUID_TEXT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
VOLUME_KEY = re.compile(r"root|boot|esp|[sx]-[0-9a-f-]{1,36}")
STREAM_META = (".ulrmm/layout.json", ".ulrmm/index.jsonl.gz", ".ulrmm/report.json")
REGULAR = (tarfile.REGTYPE, tarfile.AREGTYPE)
MEMBER_TYPES = (
    *REGULAR,
    tarfile.DIRTYPE,
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
    tarfile.CHRTYPE,
    tarfile.BLKTYPE,
    tarfile.FIFOTYPE,
)
GPT_ATTRS = {0: "RequiredPartition", 1: "NoBlockIOProtocol", 2: "LegacyBIOSBootable"}
ZERO_PAGE = bytes(4096)
BY_ID = Path("/dev/disk/by-id")
# Every transfer request is retried after a network error or a reply from a
# restarting server, up to 62 s in all.
RETRIES = 5
RETRY_STATUS = (502, 503, 504)


class RecoveryError(Exception):
    pass


class ImageIntegrityError(RecoveryError):
    pass


class TransportError(RecoveryError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, interface, **kwargs):
        super().__init__(*args, **kwargs)
        self.interface = interface
        self._create_connection = self.connect_bound

    def connect_bound(self, address, timeout, source_address):
        try:
            result = subprocess.run(
                ["ip", "-json", "-details", "link", "show", "dev", self.interface],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            (link,) = json.loads(result.stdout)
            index = socket.if_nametoindex(self.interface)
            if (
                link["linkinfo"]["info_kind"] != "wireguard"
                or link["ifindex"] != index
                or "UP" not in link["flags"]
            ):
                raise TransportError("Waiting for the configured WireGuard interface")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            raise TransportError(
                "Waiting for the configured WireGuard interface"
            ) from exc

        # A fresh socket for every request avoids reusing a connection from another route.
        for family, kind, protocol, _, peer in socket.getaddrinfo(
            *address, type=socket.SOCK_STREAM
        ):
            with contextlib.ExitStack() as close:
                sock = close.enter_context(socket.socket(family, kind, protocol))
                sock.settimeout(timeout)
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_BINDTODEVICE,
                        self.interface.encode() + b"\0",
                    )
                    if socket.if_nametoindex(self.interface) != index:
                        raise TransportError(
                            "WireGuard interface changed during connection setup"
                        )
                    sock.connect(peer)
                except OSError:
                    continue
                close.pop_all()
                return sock
        raise TransportError(
            "Waiting for a ULRMM connection through the configured WireGuard interface"
        )


class BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, interface, context):
        super().__init__(context=context)
        self.interface = interface

    def https_open(self, req):
        def connect(*args, **kwargs):
            return BoundHTTPSConnection(*args, interface=self.interface, **kwargs)

        return self.do_open(connect, req, context=self._context)


class Transfer:
    def __init__(self, url, token, interface=None, ca_file=None):
        self.url = url
        self.token = token
        context = ssl.create_default_context(cafile=ca_file)
        https = (
            BoundHTTPSHandler(interface, context)
            if interface
            else urllib.request.HTTPSHandler(context=context)
        )
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), https
        )

    def request(
        self, method, endpoint="", payload=None, limit=64 * 1024, committed=None
    ):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept-Encoding": "identity",
        }
        if isinstance(payload, dict):
            payload = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        elif payload is not None:
            headers["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(
            self.url + endpoint, payload, headers, method=method
        )
        for attempt in range(RETRIES + 1):
            if attempt:
                time.sleep(2**attempt)
            try:
                with self.opener.open(req, timeout=60) as response:
                    if response.status not in (200, 201, 202, 204, 206):
                        raise RecoveryError(f"{method} returned HTTP {response.status}")
                    body = response.read(limit + 1)
                    # http.client returns a body cut off by a dropped link without error.
                    size = response.headers.get("Content-Length")
                    if size and len(body) < min(int(size), limit + 1):
                        raise http.client.IncompleteRead(body)
                break
            except urllib.error.HTTPError as exc:
                # A conflict after a lost reply: the earlier attempt committed the chunk.
                if (
                    attempt
                    and exc.code == 409
                    and committed is not None
                    and json.loads(self.request("GET")).get("offset") == committed
                ):
                    return b""
                if exc.code not in RETRY_STATUS or attempt == RETRIES:
                    raise RecoveryError(
                        f"{method} returned HTTP {exc.code}. Check the transfer status in ULRMM."
                    ) from exc
            except (OSError, http.client.HTTPException, TransportError):
                if attempt == RETRIES:
                    raise
        if len(body) > limit:
            raise RecoveryError("Server response exceeds the transfer limit")
        return body


def parse_transfer_url(url):
    parts = urllib.parse.urlsplit(url)
    prefix, sep, transfer_id = parts.path.rstrip("/").rpartition("/")
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or not sep
        or not prefix.endswith("/imaging/transfers")
        or not parts.path.endswith("/")
    ):
        raise RecoveryError("Use the HTTPS transfer URL displayed in ULRMM")
    try:
        return str(uuid.UUID(transfer_id))
    except ValueError as exc:
        raise RecoveryError("Invalid transfer ID") from exc


def recovery_environment():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RecoveryError(
            "Boot a dedicated Linux recovery environment and run as root"
        )
    if "ulrmm.recovery=1" not in Path("/proc/cmdline").read_text().split():
        raise RecoveryError(
            "Boot the recovery environment with kernel parameter ulrmm.recovery=1"
        )
    architecture = platform.machine()
    if architecture != "x86_64":
        raise RecoveryError("Recovery currently supports x86_64 Linux systems")
    try:
        device_uuid = uuid.UUID(
            Path("/sys/class/dmi/id/product_uuid").read_text().strip()
        )
    except (OSError, ValueError) as exc:
        raise RecoveryError(
            "A valid local DMI product UUID is required to pair the recovery transfer"
        ) from exc
    if device_uuid.int in (0, (1 << 128) - 1):
        raise RecoveryError(
            "A valid local DMI product UUID is required to pair the recovery transfer"
        )
    mode = "uefi" if Path("/sys/firmware/efi").is_dir() else "bios"
    return {
        "architecture": architecture,
        "boot_mode": mode,
        "device_uuid": str(device_uuid),
    }


@contextlib.contextmanager
def open_disk(disk_id, writable=False):
    if not re.fullmatch(r"(?:ata|nvme|scsi|usb|virtio|wwn)-[A-Za-z0-9_.:+-]+", disk_id):
        raise RecoveryError("Select a whole disk by its stable /dev/disk/by-id name")
    disk = BY_ID / disk_id
    device = disk.resolve(strict=True)
    selected = device.stat()
    if not stat.S_ISBLK(selected.st_mode):
        raise RecoveryError("Selected path is not a block device")
    sysfs = Path(
        f"/sys/dev/block/{os.major(selected.st_rdev)}:{os.minor(selected.st_rdev)}"
    )
    if (
        not sysfs.exists()
        or (sysfs / "partition").exists()
        or any((sysfs / "slaves").iterdir())
    ):
        raise RecoveryError("Select a whole physical or virtual disk")
    flags = os.O_RDWR if writable else os.O_RDONLY
    # A Linux exclusive block open also excludes mounted/claimed partitions.
    fd = os.open(device, flags | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r+b" if writable else "rb", buffering=0) as stream:
        actual = os.fstat(fd)
        if (
            actual.st_rdev != selected.st_rdev
            or not stat.S_ISBLK(actual.st_mode)
            or disk.resolve(strict=True) != device
            or disk.stat().st_rdev != actual.st_rdev
        ):
            raise RecoveryError("Selected disk changed while opening it")
        # Determine geometry from the opened descriptor so it matches the disk used for I/O.
        size_request = 0x80001272 | struct.calcsize("@L") << 16  # BLKGETSIZE64
        size = struct.unpack("=Q", fcntl.ioctl(fd, size_request, bytes(8)))[0]
        sector = struct.unpack("=I", fcntl.ioctl(fd, 0x1268, bytes(4)))[0]  # BLKSSZGET
        if sector not in (512, 4096) or not size or size % sector:
            raise RecoveryError("Unsupported disk geometry")
        if writable and fcntl.ioctl(fd, 0x125E, bytes(4)) != bytes(4):  # BLKROGET
            raise RecoveryError("Restore target is read-only")
        yield stream, {"disk_id": disk_id, "raw_size": size, "sector_size": sector}


def inspect(*command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=True,
            env=os.environ | {"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RecoveryError(
            f"Could not inspect the offline system with {command[0]}"
        ) from exc
    return result.stdout


def verify_source(device, boot_mode, *, require_gpt=False):
    devices = json.loads(
        inspect(
            "lsblk",
            "--json",
            "--paths",
            "--output",
            "NAME,TYPE,FSTYPE,UUID,PARTUUID,PARTTYPE,PTTYPE,LABEL,PARTLABEL",
            device,
        )
    )["blockdevices"]
    if (
        len(devices) != 1
        or devices[0]["type"] != "disk"
        or devices[0]["fstype"]
        or devices[0]["pttype"] not in (("gpt",) if require_gpt else ("dos", "gpt"))
    ):
        raise RecoveryError("Recovery supports a single partitioned Linux system disk")
    partitions = devices[0].get("children", [])
    supported = (None, "ext4", "vfat", "swap")
    if any(
        p["type"] != "part" or p.get("children") or p["fstype"] not in supported
        for p in partitions
    ):
        raise RecoveryError(
            "Recovery source contains unsupported storage, encryption or volume management"
        )
    sources = {}
    candidates = []
    for part in partitions:
        for field, prefix in (
            ("uuid", "UUID="),
            ("partuuid", "PARTUUID="),
            ("label", "LABEL="),
            ("partlabel", "PARTLABEL="),
        ):
            if part.get(field):
                # Only UUIDs are case-insensitive, labels are not.
                key = prefix + (
                    part[field].lower()
                    if field in ("uuid", "partuuid")
                    else part[field]
                )
                if key in sources and field in ("uuid", "partuuid"):
                    raise RecoveryError(
                        "Recovery source has ambiguous partition identities"
                    )
                # A label several partitions share is refused only where fstab uses it.
                sources[key] = None if key in sources else part
        if part["fstype"] != "ext4":
            continue
        path = part["name"]
        header = inspect("dumpe2fs", "-h", path)
        if (
            not re.search(r"^Filesystem state:\s+clean$", header, re.MULTILINE)
            or "needs_recovery" in header
        ):
            raise RecoveryError("An ext4 partition was not shut down cleanly")
        release = inspect("debugfs", "-R", "cat /usr/lib/os-release", path)
        if not release:
            release = inspect("debugfs", "-R", "cat /etc/os-release", path)
        if re.search(r"^ID=", release, re.MULTILINE):
            candidates.append(part)
    if len(candidates) != 1:
        raise RecoveryError(
            "Could not identify exactly one Linux system partition on this disk"
        )
    root = candidates[0]
    fstab = inspect("debugfs", "-R", "cat /etc/fstab", root["name"])
    mounts = {}
    excluded = {}
    for line in fstab.splitlines():
        fields = line.partition("#")[0].split()
        if not fields:
            continue
        if len(fields) < 4:
            raise RecoveryError("Linux system has an unsupported fstab entry")
        source, mount, filesystem, options = fields[:4]
        # mount and systemd clean the path, so "/boot/" is /boot
        if mount.startswith("/"):
            mount = "/" + os.path.normpath(mount).lstrip("/")
        required = mount in ("/", "/boot", "/boot/efi", "/efi")
        if filesystem in ("proc", "sysfs", "devpts", "tmpfs") and source in (
            filesystem,
            "none",
        ):
            continue
        # Boot skips noauto entries unless systemd automounts them, and a swap file
        # lives on a file system checked here.
        opts = options.split(",")
        if ("noauto" in opts and "x-systemd.automount" not in opts) or (
            filesystem == "swap"
            and source.startswith("/")
            and not source.startswith("/dev/")
        ):
            continue
        # bind mounts and pseudo file systems hold no disk of their own, and a
        # by-* link to a partition of this disk is in the image
        if not required and (
            "bind" in opts
            or "rbind" in opts
            or not any(c in source for c in "/=")
            or (
                source.startswith("/dev/disk/by-")
                and os.path.realpath(source) in {p["name"] for p in partitions}
            )
        ):
            continue
        key = fstab_key(source)
        # Storage off this disk is not in the image and not needed to boot it.
        # Kernel names of this disk's partitions differ in recovery, so they are
        # listed here although the agent refuses them on the running system.
        if key not in sources and not required:
            point = "swap" if filesystem == "swap" else mount
            excluded.setdefault(point, fields[0])
            continue
        part = sources.get(key)
        if part is None or filesystem != part["fstype"] or mount in mounts:
            raise RecoveryError(
                "Linux fstab references storage outside the supported source disk or file systems"
            )
        if filesystem != "swap":
            mounts[mount] = part
    if mounts.get("/") != root:
        raise RecoveryError(
            "Linux fstab does not identify the selected ext4 root partition"
        )
    if "/boot" in mounts and mounts["/boot"]["fstype"] != "ext4":
        raise RecoveryError("A separate /boot must use ext4 on the selected disk")
    if boot_mode == "uefi":
        esp = mounts.get("/boot/efi") or mounts.get("/efi", {})
        if esp.get("fstype") != "vfat" or esp.get("parttype") not in (
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "0xef",
        ):
            raise RecoveryError(
                "UEFI capture requires the EFI system partition on the selected disk in fstab"
            )
    return [f"{point} ({source})" for point, source in excluded.items()]


def fstab_key(source):
    kind, sep, value = source.removeprefix("/dev/disk/by-").partition("/")
    if source.startswith("/dev/disk/by-") and sep:
        source = f"{kind.upper()}={value}"
    prefix, sep, value = source.partition("=")
    return prefix + sep + (value.lower() if prefix.endswith("UUID") else value)


def read_chunks(stream, size):
    remaining = size
    while remaining:
        try:
            block = stream.read(min(CHUNK, remaining))
        except OSError as exc:
            raise RecoveryError("Could not read the entire disk or image") from exc
        if not block:
            raise RecoveryError("Disk or image ended before the declared size")
        remaining -= len(block)
        yield block


class Upload:
    def __init__(self, transfer, resume):
        self.transfer = transfer
        self.resume = resume
        self.offset = 0
        self.pending = bytearray()
        self.digest = hashlib.sha256()
        self.failed = False

    def write(self, data):
        if self.failed:
            return len(data)
        self.digest.update(data)
        self.pending.extend(data)
        while len(self.pending) >= CHUNK:
            self.send(CHUNK)
        return len(data)

    def send(self, length):
        next_offset = self.offset + length
        # shortcut: bytes regenerated below the committed offset are dropped
        # unchecked, so a capture resumed with another zlib build fails only the
        # server's final verification; compare the committed tail first if that
        # case shows up in practice.
        if self.resume < next_offset:
            start = max(self.resume - self.offset, 0)
            offset = self.offset + start
            try:
                self.transfer.request(
                    "PUT",
                    f"data/?offset={offset}",
                    bytes(self.pending[start:length]),
                    committed=next_offset,
                )
            except (RecoveryError, OSError, http.client.HTTPException):
                self.failed = True
                raise
        del self.pending[:length]
        self.offset = next_offset

    def complete(self, raw_sha256):
        # The server refuses an empty chunk, and a stream of whole chunks has none left.
        if self.pending:
            self.send(len(self.pending))
        if self.offset < self.resume:
            raise RecoveryError(
                "The recorded upload offset exceeds the local image size"
            )
        self.transfer.request(
            "POST",
            "complete/",
            {
                "size": self.offset,
                "sha256": self.digest.hexdigest(),
                "raw_sha256": raw_sha256,
            },
        )


def capture(transfer, manifest, disk, geometry):
    transfer.request("POST", "manifest/", geometry)
    resume = manifest["offset"]
    if type(resume) is not int or resume < 0:
        raise RecoveryError("Invalid upload offset")
    upload = Upload(transfer, resume)
    raw_hash = hashlib.sha256()
    compression = manifest["compression"]
    if compression == "gzip":
        encoder = gzip.GzipFile(
            filename="",
            fileobj=upload,
            mode="wb",
            compresslevel=manifest["compression_level"],
            mtime=0,
        )
    elif compression == "none":
        encoder = contextlib.nullcontext(upload)
    else:
        raise RecoveryError("Unsupported image compression")
    with encoder as output:
        for data in read_chunks(disk, geometry["raw_size"]):
            raw_hash.update(data)
            output.write(data)
    upload.complete(raw_hash.hexdigest())


def verify_target(manifest, geometry):
    for field, value in geometry.items():
        if manifest[field] != value:
            raise RecoveryError(
                f"Restore target {field} does not match the approved image"
            )


def disk_restore_manifest(manifest):
    native = manifest.get("native")
    if not native:
        return manifest
    if (
        native["method"] != NATIVE_METHOD
        or manifest["compression"] != "none"
        or native["size"] != manifest["raw_size"]
    ):
        raise RecoveryError("The selected image is not a native Linux disk image")
    return manifest | {
        "sha256": manifest["raw_sha256"],
        "architecture": "x86_64",
        "sector_size": native["sector_size"],
        "boot_mode": native["boot_mode"],
    }


def stage_restore(transfer, manifest, raw, directory):
    total = manifest["size"]
    raw_size = manifest["raw_size"]
    if (
        type(total) is not int
        or total <= 0
        or type(raw_size) is not int
        or raw_size <= 0
    ):
        raise RecoveryError("Invalid image size")
    for key in ("sha256", "raw_sha256"):
        if not isinstance(manifest[key], str) or not re.fullmatch(
            "[a-f0-9]{64}", manifest[key]
        ):
            raise RecoveryError("Invalid image checksum")
    compression = manifest["compression"]
    if (
        compression not in ("none", "gzip")
        or compression == "none"
        and total != raw_size
    ):
        raise RecoveryError("Unsupported compression or image size")
    storage = os.fstatvfs(raw.fileno())
    required = total + raw_size if compression == "gzip" else raw_size
    if storage.f_bavail * storage.f_frsize < required:
        raise RecoveryError("Insufficient free staging space for image verification")
    with (
        tempfile.TemporaryFile(dir=directory)
        if compression == "gzip"
        else contextlib.nullcontext(raw)
    ) as stored:
        digest = hashlib.sha256()
        chunk_size = NATIVE_CHUNK if manifest.get("native") else CHUNK
        for offset in range(0, total, chunk_size):
            expected = min(chunk_size, total - offset)
            chunk = transfer.request("GET", f"data/?offset={offset}", limit=expected)
            if len(chunk) != expected:
                raise ImageIntegrityError("Server returned an incomplete image chunk")
            stored.write(chunk)
            digest.update(chunk)
        if digest.hexdigest() != manifest["sha256"]:
            raise ImageIntegrityError(
                "Stored image SHA-256 does not match the approval"
            )
        stored.seek(0)
        if compression == "gzip":
            digest = hashlib.sha256()
            with gzip.GzipFile(fileobj=stored) as decoder:
                for chunk in read_chunks(decoder, raw_size):
                    raw.write(chunk)
                    digest.update(chunk)
                if decoder.read(1):
                    raise ImageIntegrityError("Image expands beyond its declared size")
        if digest.hexdigest() != manifest["raw_sha256"]:
            raise ImageIntegrityError(
                "Raw disk image SHA-256 does not match the approval"
            )
    raw.flush()
    raw.seek(0)


def restore(transfer, manifest, args, host, verify, confirm):
    manifest = disk_restore_manifest(manifest)
    with verify(args.disk_id) as (_, geometry):
        verify_target(manifest, geometry | host)
    with tempfile.TemporaryFile(dir=args.staging_dir) as raw:
        try:
            stage_restore(transfer, manifest, raw, args.staging_dir)
        except (ImageIntegrityError, gzip.BadGzipFile, EOFError, zlib.error):
            # A client report requests an independent check of the server's copy.
            with contextlib.suppress(RecoveryError, OSError, http.client.HTTPException):
                transfer.request("POST", "integrity-failed/", {})
            raise
        if not confirm():
            raise RecoveryError("Restore confirmation does not match")
        current = disk_restore_manifest(json.loads(transfer.request("GET")))
        if any(current[field] != manifest[field] for field in APPROVED):
            raise RecoveryError("Restore approval changed during verification")
        with verify(args.disk_id, writable=True) as (disk, geometry):
            verify_target(manifest, geometry | host)
            verify_target(current, geometry | host)
            for chunk in read_chunks(raw, geometry["raw_size"]):
                if disk.write(chunk) != len(chunk):
                    raise RecoveryError("Short write while restoring the disk")
            os.fsync(disk.fileno())
            os.posix_fadvise(disk.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            disk.seek(0)
            digest = hashlib.sha256()
            for chunk in read_chunks(disk, geometry["raw_size"]):
                digest.update(chunk)
            if digest.hexdigest() != manifest["raw_sha256"]:
                raise RecoveryError(
                    "Restored disk failed SHA-256 readback verification"
                )
        try:
            transfer.request(
                "POST", "complete/", {"raw_sha256": manifest["raw_sha256"]}
            )
        except (RecoveryError, OSError, http.client.HTTPException) as exc:
            raise RecoveryError(
                f"Disk readback verified, but ULRMM could not record completion. {exc}"
            ) from exc


def run(*command, stdin=None):
    try:
        result = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            errors="replace",
            check=True,
            env=os.environ | {"LC_ALL": "C"},
        )
    except subprocess.CalledProcessError as exc:
        lines = (exc.stderr or exc.stdout or "").strip().splitlines()
        detail = lines[-1] if lines else f"exit status {exc.returncode}"
        raise RecoveryError(f"{command[0]} failed: {detail}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise RecoveryError(f"Could not run {command[0]}") from exc
    return result.stdout


class BlockReader:
    """The point stream, fetched block by block, with its block-list digest."""

    def __init__(self, transfer, size):
        self.transfer = transfer
        self.size = size
        self.offset = 0
        self.block = b""
        self.position = 0
        self.digest = hashlib.sha256()

    def fetch(self):
        expected = min(NATIVE_CHUNK, self.size - self.offset)
        try:
            block = self.transfer.request(
                "GET", f"data/?offset={self.offset}", limit=expected
            )
        except RecoveryError as exc:
            if getattr(exc.__cause__, "code", None) == 409:
                raise ImageIntegrityError("A block of this point is damaged") from exc
            raise
        if len(block) != expected:
            raise ImageIntegrityError("Server returned an incomplete image chunk")
        self.digest.update(hashlib.sha256(block).digest())
        self.offset += expected
        return block

    def read(self, size=-1):
        if self.position == len(self.block):
            if self.offset == self.size:
                return b""
            self.block, self.position = self.fetch(), 0
        end = len(self.block) if size < 0 else self.position + size
        data = self.block[self.position : end]
        self.position += len(data)
        return data

    def drain(self):
        while self.offset < self.size:
            self.fetch()


def blank_target(verify, disk_id, native):
    with verify(disk_id) as (disk, geometry):
        if geometry["sector_size"] != native["sector_size"]:
            raise RecoveryError("Restore target sector size differs from the source.")
        if geometry["raw_size"] < native["min_target_size"]:
            raise RecoveryError(
                "Restore target is smaller than the recorded partitions."
            )
        device = os.readlink(f"/proc/self/fd/{disk.fileno()}")
        (target,) = json.loads(
            run("lsblk", "--json", "--paths", "--output", "NAME", device)
        )["blockdevices"]
        probe = subprocess.run(["blkid", "-p", device], capture_output=True)
        if (
            target.get("children")
            or run("wipefs", "--no-act", device).strip()
            or probe.returncode != 2
        ):
            raise RecoveryError(
                "Restore target is not blank. Wipe it first with: "
                f"wipefs -a /dev/disk/by-id/{disk_id}"
            )
    return device, geometry


def safe_path(path):
    return isinstance(path, str) and all(
        part not in ("", ".", "..") and "\0" not in part for part in path.split("/")
    )


def check_layout(layout, native):
    def need(condition):
        if not condition:
            raise ValueError

    def number(value):
        need(type(value) is int and 0 < value < 2**63)
        return value

    disk = layout["disk"]
    need(
        disk["pttype"] == "gpt"
        and disk["sector_size"] == native["sector_size"]
        and isinstance(disk["id"], str)
        and disk["id"]
        and UUID_TEXT.fullmatch(disk["ptuuid"])
    )
    parts = {}
    for part in disk["partitions"]:
        number(part["start"])
        number(part["size"])
        need(number(part["number"]) <= 128 and part["number"] not in parts)
        need(UUID_TEXT.fullmatch(part["type"]) and UUID_TEXT.fullmatch(part["uuid"]))
        need(isinstance(part["name"], str))
        # sfdisk script syntax: no quote, backslash or control character; GPT
        # names hold 36 UTF-16 units
        name = part["name"]
        if (
            '"' in name
            or "\\" in name
            or not name.isprintable()
            or len(name.encode("utf-16-le")) > 72
        ):
            print(
                f"Partition {part['number']} is restored without its name "
                f"{part['name'][:40]!r}."
            )
            part["name"] = ""
        need(re.fullmatch(r"0x[0-9a-f]{1,16}", part["attrs"]))
        parts[part["number"]] = part
    need(parts)
    keys, used, restored = set(), set(), {}
    for item in layout["filesystems"]:
        need(VOLUME_KEY.fullmatch(item["key"]) and item["key"] not in keys)
        keys.add(item["key"])
        if item["disk"] != disk["id"]:
            continue
        need(item["partition"] in parts and item["partition"] not in used)
        need(isinstance(item["label"], str) and item["mount"].startswith("/"))
        used.add(item["partition"])
        if item["fs"] == "ext4":
            ext4 = item["ext4"]
            number(ext4["inode_count"])
            need(
                UUID_TEXT.fullmatch(item["uuid"])
                and ext4["block_size"] in (1024, 2048, 4096)
                and ext4["inode_size"] in (128, 256, 512, 1024)
                and isinstance(ext4["features"], list)
                and all(re.fullmatch("[a-z0-9_]+", f) for f in ext4["features"])
            )
        else:
            need(
                item["fs"] == "vfat"
                and isinstance(item["uuid"], str)
                and item["vfat"]["fat_bits"] in (12, 16, 32)
                and re.fullmatch("[0-9a-f]{8}", item["vfat"]["volume_id"])
            )
        restored[item["key"]] = item
    for swap in layout["swap"]:
        need(swap["partition"] in parts and swap["partition"] not in used)
        need(not swap["uuid"] or UUID_TEXT.fullmatch(swap["uuid"]))
        need(isinstance(swap["label"], str))
        used.add(swap["partition"])
    need(restored.get("root", {}).get("fs") == "ext4")
    need(restored.get("esp", {}).get("fs") == "vfat")
    for swap in layout["swap_files"]:
        need(swap["key"] in restored and restored[swap["key"]]["fs"] == "ext4")
        need(safe_path(swap["path"]) and number(swap["size"]))
        need(not swap["uuid"] or UUID_TEXT.fullmatch(swap["uuid"]))
        need(isinstance(swap["label"], str))
    return list(restored.values())


def files_layout(tar, native, host):
    first = tar.next()
    if (
        first is None
        or first.name != STREAM_META[0]
        or first.type not in REGULAR
        or first.size > 4 << 20
    ):
        raise RecoveryError("The point stream does not start with its layout")
    layout = json.loads(tar.extractfile(first).read())
    tar.members.clear()
    if (
        not isinstance(layout, dict)
        or layout.get("format") != 1
        or layout.get("method") != FILES_METHOD
    ):
        raise RecoveryError("The point layout has an unsupported format")
    if layout.get("arch") != host["architecture"]:
        raise RecoveryError(
            f"The point was captured on {str(layout.get('arch'))[:32]}. "
            "Boot recovery media for that architecture."
        )
    try:
        return layout, check_layout(layout, native)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise RecoveryError("The point layout is invalid") from exc


def ext4_options(item):
    ext4 = item["ext4"]
    return [
        "-U",
        item["uuid"],
        "-b",
        str(ext4["block_size"]),
        "-I",
        str(ext4["inode_size"]),
        "-N",
        str(ext4["inode_count"]),
        "-O",
        ",".join(["none", *ext4["features"]]),
    ]


def identity_options(item):
    return [
        *(("-U", item["uuid"]) if item["uuid"] else ()),
        *(("-L", item["label"]) if item["label"] else ()),
    ]


def gpt_attrs(value):
    bits = int(value, 16)
    return " ".join(
        GPT_ATTRS.get(bit, f"GUID:{bit}")
        for bit in (*range(3), *range(48, 64))
        if bits >> bit & 1
    )


def partition(device, layout):
    disk = layout["disk"]
    separator = "p" if device[-1].isdigit() else ""
    script = ["label: gpt", f"label-id: {disk['ptuuid']}", "unit: sectors"]
    for part in disk["partitions"]:
        line = (
            f"{device}{separator}{part['number']} : start={part['start']}, "
            f"size={part['size']}, type={part['type']}, uuid={part['uuid']}, "
            f'name="{part["name"]}"'
        )
        attrs = gpt_attrs(part["attrs"])
        script.append(line + (f', attrs="{attrs}"' if attrs else ""))
    run(
        "sfdisk",
        "--lock",
        "--no-reread",
        "--wipe",
        "never",
        device,
        stdin="\n".join(script) + "\n",
    )
    run("blockdev", "--rereadpt", device)
    run("udevadm", "settle")
    # by-partuuid may name the original disk, which carries the same ids
    (target,) = json.loads(
        run("lsblk", "--json", "--paths", "--output", "NAME,PARTN,PARTUUID", device)
    )["blockdevices"]
    nodes = {}
    for part in disk["partitions"]:
        found = [
            child["name"]
            for child in target.get("children", [])
            if str(child.get("partn")) == str(part["number"])
            and (child.get("partuuid") or "").lower() == part["uuid"]
        ]
        if len(found) != 1:
            raise RecoveryError("The new partitions did not appear on the target")
        nodes[part["number"]] = found[0]
    return nodes


def member_path(name, keys, roots):
    parts = name.split(b"/")
    if (
        b"\0" in name
        or len(parts) < 2
        or parts[0] != b"v"
        or parts[1] not in keys
        or any(part in (b"", b".", b"..") for part in parts[2:])
    ):
        raise RecoveryError(
            "The point stream holds an unsafe member name: "
            + name.decode("utf-8", "replace")[:300]
        )
    if parts[1] not in roots:
        return parts[1], None, None
    root, fs = roots[parts[1]]
    return parts[1], b"/".join([root, *parts[2:]]), fs


def metadata(member):
    try:
        mtime = decimal.Decimal(member.pax_headers.get("mtime", member.mtime))
        nanoseconds = int(mtime.scaleb(9))
    except (ArithmeticError, ValueError) as exc:
        raise RecoveryError("The point stream holds an invalid file time") from exc
    xattrs = {
        key.removeprefix("SCHILY.xattr."): value.encode("utf-8", "surrogateescape")
        for key, value in member.pax_headers.items()
        if key.startswith("SCHILY.xattr.")
    }
    return member.uid, member.gid, member.mode & 0o7777, nanoseconds, xattrs


def apply_metadata(path, fs, meta, chmod=True):
    uid, gid, mode, nanoseconds, xattrs = meta
    if fs != "vfat":
        os.chown(path, uid, gid, follow_symlinks=False)
        if chmod:
            os.chmod(path, mode)
        for name, value in xattrs.items():
            os.setxattr(path, name, value, follow_symlinks=False)
    os.utime(path, ns=(nanoseconds, nanoseconds), follow_symlinks=False)


def write_file(tar, member, path, previous):
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if not previous:
        flags |= os.O_CREAT | os.O_EXCL
    with open(os.open(path, flags, 0o600), "wb") as output:
        info = os.fstat(output.fileno())
        if previous and previous != (info.st_dev, info.st_ino):
            raise RecoveryError("A re-appended file names another restored file")
        output.truncate(0)
        source = tar.extractfile(member)
        while chunk := source.read(1 << 20):
            for start in range(0, len(chunk), len(ZERO_PAGE)):
                page = chunk[start : start + len(ZERO_PAGE)]
                if page == ZERO_PAGE[: len(page)]:
                    output.seek(len(page), os.SEEK_CUR)
                else:
                    output.write(page)
        output.truncate(member.size)
    return info.st_dev, info.st_ino


def extract(tar, keys, roots):
    # Symlinks come last, so no write below a restore root follows one.
    files, symlinks, directories = {}, [], []
    while (member := tar.next()) is not None:
        tar.members.clear()
        if member.name in STREAM_META:
            continue
        name = member.name.encode("utf-8", "surrogateescape")
        key, path, fs = member_path(name, keys, roots)
        if member.type not in MEMBER_TYPES or (
            fs == "vfat" and member.type not in (*REGULAR, tarfile.DIRTYPE)
        ):
            raise RecoveryError(
                "The point stream holds an unsupported member: "
                + name.decode("utf-8", "replace")[:300]
            )
        if path is None:
            continue
        meta = metadata(member)
        if member.isdir():
            os.makedirs(path, exist_ok=True)
            directories.append((path, fs, meta))
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if member.issym():
            target = member.linkname.encode("utf-8", "surrogateescape")
            symlinks.append((path, target, fs, meta))
        elif member.islnk():
            link = member.linkname.encode("utf-8", "surrogateescape")
            if files.get(link, (None,))[0] != key:
                raise RecoveryError(
                    "The point stream holds a hard link to a file it has not restored"
                )
            os.link(member_path(link, keys, roots)[1], path, follow_symlinks=False)
        else:
            if member.type in REGULAR:
                previous = files.get(name, (None,))[1:]
                files[name] = (key, *write_file(tar, member, path, previous))
            elif member.isfifo():
                os.mkfifo(path, 0o600)
            else:
                kind = stat.S_IFCHR if member.ischr() else stat.S_IFBLK
                device = os.makedev(member.devmajor, member.devminor)
                os.mknod(path, 0o600 | kind, device)
            apply_metadata(path, fs, meta)
    for path, target, fs, meta in symlinks:
        os.symlink(target, path)
        apply_metadata(path, fs, meta, chmod=False)
    for path, fs, meta in sorted(directories, key=lambda d: -d[0].count(b"/")):
        apply_metadata(path, fs, meta)


def open_below(root, relative, flags, makedirs=False):
    """Open a regular file below root without following any symlink on the way."""
    if not safe_path(relative):
        raise RecoveryError(f"Unsafe path on the restored disk: {relative!r}")
    *parents, name = relative.split("/")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parents:
            if makedirs:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o755, dir_fd=fd)
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        opened = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        if not stat.S_ISREG(os.fstat(opened).st_mode):
            os.close(opened)
            raise RecoveryError(
                f"{relative} on the restored disk is not a regular file"
            )
        return opened
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise RecoveryError(
                f"{relative} on the restored disk passes through a symbolic link"
            ) from exc
        raise
    finally:
        os.close(fd)


def add_nofail(text, restored):
    lines = []
    for line in text.splitlines(keepends=True):
        fields = line.split()
        if (
            len(fields) >= 3
            and not fields[0].startswith("#")
            and any(c in fields[0] for c in "/=")
            and fstab_key(fields[0]) not in restored
        ):
            options = fields[3].split(",") if len(fields) > 3 else ["defaults"]
            if "nofail" not in options:
                fields[3:4] = [",".join([*options, "nofail"])]
                line = " ".join(fields) + line[len(line.rstrip("\r\n")) :]
        lines.append(line)
    return "".join(lines)


def efi_entry(layout):
    entry = layout.get("efi_entry")
    if (
        isinstance(entry, dict)
        and all(
            isinstance(entry.get(field), str)
            and 0 < len(entry[field]) <= 255
            and entry[field].isprintable()
            for field in ("loader", "label")
        )
        and safe_path(entry["loader"].replace("\\", "/").strip("/"))
    ):
        return entry
    return None


def copy_loader(esp, source, name):
    target = open_below(
        esp, f"EFI/BOOT/{name}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, makedirs=True
    )
    with open(source, "rb") as copy_from, open(target, "wb") as copy_to:
        shutil.copyfileobj(copy_from, copy_to)


def fallback_loader(esp, layout):
    # shortcut: x64 names only, the helper runs on x86_64; add aa64 with arm64 media
    with contextlib.suppress(FileNotFoundError):
        os.close(open_below(esp, "EFI/BOOT/BOOTX64.EFI", os.O_RDONLY))
        return
    entry = efi_entry(layout)
    if entry:
        loaders = [entry["loader"].replace("\\", "/").strip("/")]
    else:
        folder = f"EFI/{layout.get('os_id')}"
        loaders = [f"{folder}/shimx64.efi", f"{folder}/grubx64.efi"]
    for loader in loaders:
        try:
            source = open_below(esp, loader, os.O_RDONLY)
        except FileNotFoundError:
            continue
        copy_loader(esp, source, "BOOTX64.EFI")
        folder, _, name = loader.rpartition("/")
        if name.lower().startswith("shim"):
            for extra in ("grubx64.efi", "mmx64.efi"):
                with contextlib.suppress(FileNotFoundError):
                    path = posixpath.join(folder, extra)
                    copy_loader(esp, open_below(esp, path, os.O_RDONLY), extra)
        return
    print("No boot loader found to copy to EFI/BOOT/BOOTX64.EFI.")


def finish_files(layout, restored):
    roots = {item["key"]: f"{RESTORE_ROOT}/{item['key']}" for item in restored}
    mounts = {item["key"]: item["mount"] for item in restored}
    parts = {part["number"]: part for part in layout["disk"]["partitions"]}
    sources = set()
    for item in [*restored, *layout["swap"]]:
        part = parts[item["partition"]]
        for kind, value in (
            ("UUID", item["uuid"].lower()),
            ("PARTUUID", part["uuid"]),
            ("LABEL", item["label"]),
            ("PARTLABEL", part["name"]),
        ):
            if value:
                sources.add(f"{kind}={value}")
    for swap in layout["swap_files"]:
        fd = open_below(
            roots[swap["key"]], swap["path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL
        )
        try:
            os.posix_fallocate(fd, 0, swap["size"])
            os.fchmod(fd, 0o600)
            run("mkswap", *identity_options(swap), f"/proc/{os.getpid()}/fd/{fd}")
        finally:
            os.close(fd)
        sources.add(posixpath.join(mounts[swap["key"]], swap["path"]))
    try:
        fd = open_below(roots["root"], "etc/fstab", os.O_RDWR)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with open(
            fd, "r+", encoding="utf-8", errors="surrogateescape", newline=""
        ) as fstab:
            text = fstab.read()
            changed = add_nofail(text, sources)
            if changed != text:
                fstab.seek(0)
                fstab.write(changed)
                fstab.truncate()
    fallback_loader(roots["esp"], layout)


def restore_files(transfer, manifest, args, host, verify, confirm):
    native = manifest["native"]
    raw_size = manifest["raw_size"]
    if (
        manifest["compression"] != "none"
        or type(raw_size) is not int
        or raw_size <= 0
        or not re.fullmatch("[a-f0-9]{64}", str(manifest["raw_sha256"]))
    ):
        raise RecoveryError("The selected point is not a live Linux file backup")
    if host["boot_mode"] != "uefi":
        raise RecoveryError("Boot the recovery media in UEFI mode.")
    for tool in RESTORE_TOOLS:
        if not shutil.which(tool):
            raise RecoveryError(f"Recovery media lacks {tool}.")
    device, geometry = blank_target(verify, args.disk_id, native)
    reader = BlockReader(transfer, raw_size)
    mounted = []
    try:
        with tarfile.open(
            fileobj=reader, mode="r|", encoding="utf-8", errors="surrogateescape"
        ) as tar:
            layout, restored = files_layout(tar, native, host)
            sector = layout["disk"]["sector_size"]
            parts = layout["disk"]["partitions"]
            end = max(part["start"] + part["size"] for part in parts) * sector
            if geometry["raw_size"] < end + 16384 + sector:
                raise RecoveryError(
                    "Restore target is smaller than the recorded partitions."
                )
            sizes = {part["number"]: part["size"] * sector for part in parts}
            for item in restored:
                if item["fs"] != "ext4":
                    continue
                size = sizes[item["partition"]]
                with tempfile.NamedTemporaryFile() as probe:
                    os.ftruncate(probe.fileno(), size)
                    result = subprocess.run(
                        ["mkfs.ext4", "-n", "-F", "-q", *ext4_options(item)]
                        + [probe.name, str(size // item["ext4"]["block_size"])],
                        capture_output=True,
                        text=True,
                        errors="replace",
                    )
                if result.returncode:
                    raise RecoveryError(
                        "This recovery media cannot create the recorded ext4 "
                        f"features: {result.stderr.strip()}"
                    )
            if not confirm():
                raise RecoveryError("Restore confirmation does not match")
            current = json.loads(transfer.request("GET"))
            if any(current[field] != manifest[field] for field in APPROVED):
                raise RecoveryError("Restore approval changed during verification")
            if blank_target(verify, args.disk_id, native) != (device, geometry):
                raise RecoveryError("Selected disk changed while opening it")
            # Nothing touches the target before this point.
            nodes = partition(device, layout)
            for item in restored:
                node = nodes[item["partition"]]
                label = item["label"]
                if item["fs"] == "ext4":
                    label = ("-L", label) if label else ()
                    run("mkfs.ext4", "-F", "-q", *label, *ext4_options(item), node)
                else:
                    label = ("-n", label) if label else ()
                    fat = item["vfat"]
                    bits = str(fat["fat_bits"])
                    run("mkfs.fat", "-F", bits, "-i", fat["volume_id"], *label, node)
            for swap in layout["swap"]:
                run("mkswap", *identity_options(swap), nodes[swap["partition"]])
            roots = {}
            for item in restored:
                path = f"{RESTORE_ROOT}/{item['key']}"
                os.makedirs(path, mode=0o700, exist_ok=True)
                node = nodes[item["partition"]]
                # nodev: a device node from the stream can be created, never opened
                run("mount", "-t", item["fs"], "-o", "nodev,nosuid,noexec", node, path)
                mounted.append(path)
                roots[item["key"].encode()] = (os.fsencode(path), item["fs"])
            keys = {item["key"].encode() for item in layout["filesystems"]}
            extract(tar, keys, roots)
        reader.drain()
        if reader.digest.hexdigest() != manifest["raw_sha256"]:
            raise ImageIntegrityError("Block-list SHA-256 does not match the approval")
        finish_files(layout, restored)
        os.sync()
        while mounted:
            run("umount", mounted[-1])
            mounted.pop()
    except ImageIntegrityError as exc:
        with contextlib.suppress(RecoveryError, OSError, http.client.HTTPException):
            transfer.request("POST", "integrity-failed/", {})
        raise RecoveryError(
            "Restore stopped: the point failed its integrity check. "
            "Only the blank target was written."
        ) from exc
    except tarfile.TarError as exc:
        raise RecoveryError(f"The point stream is not a valid backup: {exc}") from exc
    finally:
        for path in reversed(mounted):
            subprocess.run(["umount", path], capture_output=True)
    for item in restored:
        node = nodes[item["partition"]]
        if item["fs"] == "ext4":
            run("e2fsck", "-fn", node)
        else:
            run("fsck.vfat", "-n", node)
    entry = efi_entry(layout) if shutil.which("efibootmgr") else None
    if entry:
        esp = next(item for item in restored if item["key"] == "esp")
        try:
            run(
                "efibootmgr",
                "--create",
                "--disk",
                device,
                "--part",
                str(esp["partition"]),
                "--loader",
                entry["loader"],
                "--label",
                entry["label"],
            )
        except RecoveryError as exc:
            print(exc)
            entry = None
    if not entry:
        print(
            "Firmware boot entry not created; "
            "the disk boots through EFI/BOOT/BOOTX64.EFI."
        )
    try:
        transfer.request("POST", "complete/", {"raw_sha256": manifest["raw_sha256"]})
    except (RecoveryError, OSError, http.client.HTTPException) as exc:
        raise RecoveryError(
            f"The disk was restored, but ULRMM could not record completion. {exc}"
        ) from exc


def poll_capture(args, token):
    if not args.poll_url.endswith("/poll/"):
        raise RecoveryError("Use the capture pairing URL displayed in ULRMM")
    parse_transfer_url(args.poll_url.removesuffix("poll/"))
    pairing = Transfer(args.poll_url, token, args.interface, args.ca_file)
    reply = pairing.request("GET")
    if not reply:
        return None
    grant = json.loads(reply)
    parse_transfer_url(grant["url"])
    if (
        urllib.parse.urlsplit(grant["url"]).netloc
        != urllib.parse.urlsplit(args.poll_url).netloc
        or grant["network_mode"] != args.network_mode
    ):
        raise RecoveryError(
            "The grant differs from the approved pairing origin or network mode"
        )
    return grant


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--identify",
        choices=("capture", "restore"),
        help="Check the local disk and show the identity used to pair the grant",
    )
    source.add_argument("--url", help="HTTPS transfer URL from ULRMM")
    source.add_argument(
        "--check-capture-fd", action="store_true", help=argparse.SUPPRESS
    )
    source.add_argument(
        "--poll-url",
        help="Check the paired offline device for a due backup; read its token from stdin",
    )
    parser.add_argument(
        "--disk-id", required=True, help="Stable name under /dev/disk/by-id"
    )
    parser.add_argument(
        "--staging-dir", help="Private staging directory on a separate filesystem"
    )
    parser.add_argument(
        "--network-mode",
        choices=("internal", "internet"),
        help="Network mode displayed in the ULRMM transfer grant",
    )
    parser.add_argument(
        "--interface", help="WireGuard interface required for internal mode"
    )
    parser.add_argument("--ca-file", help="Custom ULRMM TLS CA certificate")
    args = parser.parse_args()
    host = recovery_environment()
    if args.check_capture_fd:
        # The recovery agent holds the exclusive read-only block handle for capture.
        fd = 3
        stable = BY_ID / args.disk_id
        if (
            not re.fullmatch(
                r"(?:ata|nvme|scsi|usb|virtio|wwn)-[A-Za-z0-9_.:+-]+", args.disk_id
            )
            or not stat.S_ISBLK(os.fstat(fd).st_mode)
            or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or stable.resolve(strict=True) != Path(os.readlink("/proc/self/fd/3"))
            or stable.stat().st_rdev != os.fstat(fd).st_rdev
        ):
            raise RecoveryError("Invalid recovery agent capture descriptor")
        verify_source(
            str(stable.resolve(strict=True)), host["boot_mode"], require_gpt=True
        )
        return
    if args.identify:
        with open_disk(args.disk_id) as (disk, geometry):
            if args.identify == "capture":
                verify_source(
                    os.readlink(f"/proc/self/fd/{disk.fileno()}"), host["boot_mode"]
                )
            print(json.dumps(geometry | host))
        return
    if not args.network_mode:
        raise RecoveryError(
            "Select the --network-mode displayed in the ULRMM transfer grant"
        )
    if args.network_mode == "internal" and not args.interface:
        raise RecoveryError(
            "Waiting for a configured WireGuard interface (--interface) in internal mode"
        )
    if args.interface and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", args.interface):
        raise RecoveryError("Invalid WireGuard interface name")
    if args.url:
        parse_transfer_url(args.url)
    if sys.stdin.isatty():
        token = getpass.getpass("ULRMM transfer token: ")
    else:
        token = sys.stdin.readline(4096).strip()
    if not re.fullmatch(r"[A-Za-z0-9._~-]{20,512}", token):
        raise RecoveryError("Invalid transfer token")
    if args.poll_url:
        grant = poll_capture(args, token)
        if grant is None:
            print("No offline capture due.")
            return
        args.url, token = grant["url"], grant["token"]
    transfer_id = parse_transfer_url(args.url)
    transfer = Transfer(args.url, token, args.interface, args.ca_file)
    manifest = json.loads(transfer.request("GET"))
    if manifest["network_mode"] != args.network_mode:
        raise RecoveryError("Network mode does not match the ULRMM transfer grant")
    verify_target(
        manifest, {"disk_id": args.disk_id, "device_uuid": host["device_uuid"]}
    )
    if manifest["direction"] == "capture":
        if manifest.get("native"):
            if manifest["native"]["method"] != NATIVE_METHOD:
                raise RecoveryError("The capture grant uses a different imaging method")
            command = [
                "/usr/bin/ulrmm-agent",
                "imaging-capture",
                "--url",
                args.url,
                "--image",
                manifest["image_id"],
                "--target",
                manifest["agent_id"],
                "--disk",
                args.disk_id,
                "--network-mode",
                args.network_mode,
            ]
            if args.interface:
                command.extend(("--interface", args.interface))
            if args.ca_file:
                command.extend(("--ca", args.ca_file))
            if subprocess.run(command, input=token + "\n", text=True).returncode:
                raise RecoveryError("Native Linux agent capture failed")
            print("Upload accepted. Check image verification in ULRMM.")
            return
        print(f"Capturing device {manifest['agent_id']!r} from disk {args.disk_id!r}.")
        with open_disk(args.disk_id) as (disk, geometry):
            excluded = verify_source(
                os.readlink(f"/proc/self/fd/{disk.fileno()}"), host["boot_mode"]
            )
            if excluded:
                print("Not included: " + ", ".join(excluded))
            capture(transfer, manifest, disk, geometry | host)
        print("Upload accepted. Check image verification in ULRMM.")
    elif manifest["direction"] == "restore" and not args.poll_url:
        files = (manifest.get("native") or {}).get("method") == FILES_METHOD
        if not files and not args.staging_dir:
            raise RecoveryError(
                "Restore requires --staging-dir on a separate filesystem"
            )
        phrase = f"RESTORE {transfer_id} {args.disk_id}"
        action = "Partition and write blank disk" if files else "Overwrite disk"

        def confirm():
            with open("/dev/tty", "w") as terminal:
                terminal.write(
                    f"{action} {args.disk_id!r} on device {manifest['agent_id']!r} "
                    f"with image {manifest['image_id']!r}? Type {phrase}: "
                )
                terminal.flush()
            with open("/dev/tty") as confirmation:
                return confirmation.readline(4096).rstrip("\n") == phrase

        if files:
            restore_files(transfer, manifest, args, host, open_disk, confirm)
            print(
                "Restore completed. Keep the original disk detached: "
                "the restored disk carries the same UUIDs."
            )
        else:
            restore(transfer, manifest, args, host, open_disk, confirm)
            print("Restore completed and disk readback verified.")
    else:
        raise RecoveryError("Unsupported transfer direction")


if __name__ == "__main__":
    try:
        main()
    except (
        RecoveryError,
        OSError,
        ValueError,
        KeyError,
        EOFError,
        TypeError,
        http.client.HTTPException,
        zlib.error,
    ) as exc:
        sys.exit(f"ULRMM recovery: {exc}")

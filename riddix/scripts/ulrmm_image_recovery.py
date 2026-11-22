#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Capture or recover a whole offline Linux system disk with a ULRMM transfer."""

import argparse
import contextlib
import fcntl
import getpass
import gzip
import hashlib
import http.client
import json
import os
import platform
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
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
    for line in fstab.splitlines():
        fields = line.partition("#")[0].split()
        if not fields:
            continue
        if len(fields) < 4:
            raise RecoveryError("Linux system has an unsupported fstab entry")
        source, mount, filesystem, options = fields[:4]
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
        kind, sep, value = source.removeprefix("/dev/disk/by-").partition("/")
        if source.startswith("/dev/disk/by-") and sep:
            source = f"{kind.upper()}={value}"
        prefix, sep, value = source.partition("=")
        part = sources.get(
            prefix + sep + (value.lower() if prefix.endswith("UUID") else value)
        )
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
        approved = (
            "agent_id",
            "image_id",
            "network_mode",
            "compression",
            "sha256",
            "raw_sha256",
            "size",
        )
        if any(current[field] != manifest[field] for field in approved):
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
            verify_source(
                os.readlink(f"/proc/self/fd/{disk.fileno()}"), host["boot_mode"]
            )
            capture(transfer, manifest, disk, geometry | host)
        print("Upload accepted. Check image verification in ULRMM.")
    elif manifest["direction"] == "restore" and not args.poll_url:
        if not args.staging_dir:
            raise RecoveryError(
                "Restore requires --staging-dir on a separate filesystem"
            )
        phrase = f"RESTORE {transfer_id} {args.disk_id}"

        def confirm():
            with open("/dev/tty", "w") as terminal:
                terminal.write(
                    f"Overwrite disk {args.disk_id!r} on device {manifest['agent_id']!r} "
                    f"with image {manifest['image_id']!r}? Type {phrase}: "
                )
                terminal.flush()
            with open("/dev/tty") as confirmation:
                return confirmation.readline(4096).rstrip("\n") == phrase

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

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import ulrmm_image_recovery as recovery
from test_ulrmm_image_recovery import LocalTransfer

DISK = "nvme-Samsung_SSD_980_1TB_S64ANS0T123456"
EXTRA = "x-5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a"
MTIME = 1763900000123456789
# blocks of the test streams, so a point spans several data/ requests
BLOCK = 4096
LAYOUT = {
    "format": 1,
    "method": "linux-files-v1",
    "arch": "x86_64",
    "boot_mode": "uefi",
    "device_uuid": "90cb53c8-01ea-444d-b1f1-23abcd127ace",
    "os_id": "debian",
    "efi_entry": {"loader": "\\EFI\\debian\\shimx64.efi", "label": "debian"},
    "disk": {
        "id": DISK,
        "size": 1000204886016,
        "sector_size": 512,
        "pttype": "gpt",
        "ptuuid": "6f0f5a7e-3c2b-4d8e-9a51-0c6d1f2e3a4b",
        "partitions": [
            {
                "number": 1,
                "start": 2048,
                "size": 1048576,
                "type": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "uuid": "1c3e5a7b-9d2f-4e61-8a0b-c4d5e6f70801",
                "name": "EFI System Partition",
                "attrs": "0x0",
            },
            {
                "number": 2,
                "start": 1050624,
                "size": 1952473088,
                "type": "0fc63daf-8483-4772-8e79-3d69d8477de4",
                "uuid": "1c3e5a7b-9d2f-4e61-8a0b-c4d5e6f70802",
                "name": "",
                "attrs": "0x0",
            },
        ],
    },
    "filesystems": [
        {
            "key": "root",
            "mount": "/",
            "fs": "ext4",
            "disk": DISK,
            "partition": 2,
            "uuid": "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f",
            "label": "",
            "consistency": "live",
            "ext4": {
                "block_size": 4096,
                "inode_size": 256,
                "inode_count": 61054976,
                "features": ["has_journal", "ext_attr", "extent", "64bit"],
            },
        },
        {
            "key": "esp",
            "mount": "/boot/efi",
            "fs": "vfat",
            "disk": DISK,
            "partition": 1,
            "uuid": "abcd-1234",
            "label": "",
            "consistency": "live",
            "vfat": {"fat_bits": 32, "volume_id": "abcd1234"},
        },
        {
            "key": EXTRA,
            "mount": "/media/frigate",
            "fs": "ext4",
            "disk": "ata-WDC_WD40PURZ-85AKKY0_WD-WX12345678",
            "partition": 1,
            "uuid": "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a",
            "label": "frigate",
            "consistency": "live",
            "ext4": {
                "block_size": 4096,
                "inode_size": 256,
                "inode_count": 1000,
                "features": ["has_journal"],
            },
        },
    ],
    "swap": [],
    "swap_files": [
        {"key": "root", "path": "swapfile", "size": 65536, "uuid": "", "label": ""}
    ],
    "missing": [],
    "fstab": "",
}
FSTAB = (
    "# /etc/fstab\n"
    "UUID=0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f / ext4 errors=remount-ro 0 1\n"
    "UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1\n"
    "UUID=5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a /media/frigate ext4 defaults 0 2\n"
    "//nas/backups /mnt/backups cifs credentials=/root/.smb 0 0\n"
    "/dev/disk/by-uuid/0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f /srv ext4 bind 0 0\n"
    "UUID=gone /mnt/gone ext4 defaults,nofail 0 2\n"
    "/swapfile none swap sw 0 0\n"
    "proc /proc proc defaults 0 0\n"
    "tmpfs /tmp tmpfs defaults 0 0\n"
)


def record(key, value):
    body = b" " + key + b"=" + value + b"\n"
    size = len(body)
    while len(str(size)) + len(body) != size:
        size += 1
    return str(size).encode() + body


def pad(data):
    return data + bytes(-len(data) % 512)


def member(name, kind=tarfile.REGTYPE, data=b"", link=b"", records=(), mode=0o644):
    """A PAX member as the agent writes it: raw path bytes in an x header."""
    info = tarfile.TarInfo("member")
    info.type, info.size, info.mode = kind, len(data), mode
    info.uid, info.gid = os.getuid(), os.getgid()
    pax = [(b"path", name), (b"mtime", b"1763900000.123456789"), *records]
    if link:
        pax.append((b"linkpath", link))
    body = b"".join(record(key, value) for key, value in pax)
    head = tarfile.TarInfo("PaxHeader")
    head.type, head.size = tarfile.XHDTYPE, len(body)
    return (
        head.tobuf(tarfile.USTAR_FORMAT)
        + pad(body)
        + info.tobuf(tarfile.USTAR_FORMAT)
        + pad(data)
    )


def directory(name):
    return member(name, tarfile.DIRTYPE, mode=0o755)


def point(*members, layout=LAYOUT):
    return (
        member(b".ulrmm/layout.json", data=json.dumps(layout).encode(), mode=0o600)
        + b"".join(members)
        + member(b".ulrmm/index.jsonl.gz", data=gzip.compress(b""), mode=0o600)
        + member(b".ulrmm/report.json", data=b"{}", mode=0o600)
        + bytes(1024)
    )


def block_digest(data):
    digest = hashlib.sha256()
    for offset in range(0, len(data), BLOCK):
        chunk = data[offset : offset + BLOCK]
        digest.update(hashlib.sha256(chunk).digest())
    return digest.hexdigest()


class Commands:
    """Stands in for every external tool and records the calls."""

    writes = ("sfdisk", "blockdev", "mkfs.fat", "mkswap", "mount")

    def __init__(self, device):
        self.device = device
        self.children, self.wipefs, self.blkid, self.mke2fs = False, "", 2, 0
        self.calls = []
        self.script = None

    def __call__(self, command, input=None, check=False, **kwargs):
        command = list(command)
        self.calls.append(command)
        name, output, code = command[0], "", 0
        if name == "lsblk":
            target = {"name": self.device}
            if "NAME,PARTN,PARTUUID" in command:
                target["children"] = [
                    {"name": f"{self.device}p{p['number']}", "partn": p["number"]}
                    | {"partuuid": p["uuid"].upper()}
                    for p in LAYOUT["disk"]["partitions"]
                ]
            elif self.children:
                target["children"] = [{"name": self.device + "p1"}]
            output = json.dumps({"blockdevices": [target]})
        elif name == "wipefs":
            output = self.wipefs
        elif name == "blkid":
            code = self.blkid
        elif name == "mkfs.ext4" and "-n" in command:
            code = self.mke2fs
        elif name == "sfdisk":
            self.script = input
        if code and check:
            raise subprocess.CalledProcessError(code, command, output, "failed")
        stderr = "Invalid filesystem option set: none,orphan_file" if code else ""
        return subprocess.CompletedProcess(command, code, output, stderr)

    def written(self):
        return [
            c
            for c in self.calls
            if c[0] in self.writes or (c[0] == "mkfs.ext4" and "-n" not in c)
        ]


class FilesRestoreTest(unittest.TestCase):
    def unpack(self, *members):
        folder = self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name in ("root", "esp", "outside"):
            (folder / name).mkdir()
        roots = {
            b"root": (os.fsencode(folder / "root"), "ext4"),
            b"esp": (os.fsencode(folder / "esp"), "vfat"),
        }
        data = b"".join(members) + bytes(1024)
        with tarfile.open(
            fileobj=io.BytesIO(data),
            mode="r|",
            encoding="utf-8",
            errors="surrogateescape",
        ) as tar:
            recovery.extract(tar, {b"root", b"esp", EXTRA.encode()}, roots)
        return folder

    def test_unsafe_names_abort(self):
        for name in (
            b"/etc/passwd",
            b"v/root/../outside/x",
            b"v/root/a//b",
            b"v/root/./x",
            b"v/other/x",
            b"etc/passwd",
            b".ulrmm/extra.json",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(recovery.RecoveryError, "unsafe member"):
                    self.unpack(member(name, data=b"x"))

    def test_symlink_then_file_never_writes_through_the_link(self):
        outside = Path(self.enterContext(tempfile.TemporaryDirectory()))
        link = member(b"v/root/a", tarfile.SYMTYPE, link=os.fsencode(outside))
        below = member(b"v/root/a/passwd", data=b"root:x:0:0")
        with self.assertRaises(FileExistsError):
            self.unpack(link, below)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.folder / "root/a").is_symlink())
        self.assertTrue((self.folder / "root/a/passwd").is_file())

    def test_hard_links_and_special_files(self):
        file = member(b"v/root/a", data=b"data")
        for members, error in [
            ([member(b"v/root/b", tarfile.LNKTYPE, link=b"v/root/a")], "hard link"),
            (
                [
                    member(b"v/esp/a", data=b"x"),
                    member(b"v/root/b", tarfile.LNKTYPE, link=b"v/esp/a"),
                ],
                "hard link",
            ),
            ([file, member(b"v/root/b", tarfile.LNKTYPE, link=b"/etc/x")], "hard"),
            ([member(b"v/other/fifo", tarfile.FIFOTYPE)], "unsafe member"),
            ([member(b"/dev/sda", tarfile.BLKTYPE)], "unsafe member"),
            ([member(b"v/esp/sda", tarfile.BLKTYPE)], "unsupported member"),
            ([member(b"v/root/s", tarfile.GNUTYPE_SPARSE)], "unsupported member"),
        ]:
            with self.subTest(error=error, members=len(members)):
                with self.assertRaisesRegex(recovery.RecoveryError, error):
                    self.unpack(*members)
        folder = self.unpack(
            file,
            member(b"v/root/b", tarfile.LNKTYPE, link=b"v/root/a"),
            member(b"v/root/fifo", tarfile.FIFOTYPE),
        )
        self.assertTrue(os.path.samefile(folder / "root/a", folder / "root/b"))
        self.assertTrue(stat.S_ISFIFO((folder / "root/fifo").lstat().st_mode))

    def test_raw_name_and_nanosecond_time_round_trip(self):
        folder = self.unpack(member(b"v/root/caf\xe9", data=b"x", mode=0o4750))
        path = os.fsencode(folder / "root") + b"/caf\xe9"
        info = os.lstat(path)
        self.assertEqual(os.listdir(os.fsencode(folder / "root")), [b"caf\xe9"])
        self.assertEqual(info.st_mtime_ns, MTIME)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o4750)

    @unittest.skipUnless(os.geteuid() == 0, "security xattrs need root")
    def test_binary_capability_xattr_round_trip(self):
        # v2 capability with every permitted bit: not valid UTF-8
        value = b"\x00\x00\x00\x02\xff\xff\xff\xff" + bytes(12)
        xattr = (b"SCHILY.xattr.security.capability", value)
        folder = self.unpack(member(b"v/root/ping", data=b"x", records=[xattr]))
        stored = os.getxattr(folder / "root/ping", "security.capability")
        self.assertEqual(stored, value)

    def test_reappend_rewrites_the_same_inode_with_holes(self):
        first = b"a" * 4096 + bytes(8192) + b"b"
        second = b"c" * 4096 + bytes(8192) + b"d"
        folder = self.unpack(
            member(b"v/root/big", data=first),
            member(b"v/root/link", tarfile.LNKTYPE, link=b"v/root/big"),
            member(b"v/" + EXTRA.encode() + b"/clip.mp4", data=b"clip"),
            member(b"v/root/big", data=second),
        )
        path = folder / "root/big"
        self.assertEqual((folder / "root/link").read_bytes(), second)
        self.assertEqual(path.stat().st_nlink, 2)
        self.assertLess(path.stat().st_blocks * 512, len(second))
        self.assertEqual(
            sorted(p.name for p in folder.iterdir()), ["esp", "outside", "root"]
        )
        self.assertFalse(any(folder.rglob("clip.mp4")))

    def test_vfat_keys_get_content_and_time_only(self):
        folder = self.unpack(
            directory(b"v/esp/EFI"),
            member(b"v/esp/EFI/grubx64.efi", data=b"grub", mode=0o4755),
        )
        info = (folder / "esp/EFI/grubx64.efi").stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_mtime_ns, MTIME)
        with self.assertRaisesRegex(recovery.RecoveryError, "unsupported member"):
            self.unpack(member(b"v/esp/EFI", tarfile.SYMTYPE, link=b"/"))

    def test_sfdisk_script_and_nodes_by_partuuid(self):
        layout = copy.deepcopy(LAYOUT)
        layout["disk"]["partitions"][1].update(number=3, attrs="0x8000000000000005")
        uuids = [p["uuid"] for p in layout["disk"]["partitions"]]
        commands = Commands("/dev/nvme0n1")
        listing = {
            "blockdevices": [
                {
                    "name": "/dev/nvme0n1",
                    "children": [
                        {"name": "/dev/nvme0n1p1", "partn": 1, "partuuid": uuids[0]},
                        {"name": "/dev/nvme0n1p3", "partn": 3, "partuuid": uuids[1]},
                    ],
                }
            ]
        }

        def tools(command, **kwargs):
            commands(command, **kwargs)
            return SimpleNamespace(stdout=json.dumps(listing))

        with mock.patch.object(recovery.subprocess, "run", side_effect=tools):
            nodes = recovery.partition("/dev/nvme0n1", layout)
        self.assertEqual(nodes, {1: "/dev/nvme0n1p1", 3: "/dev/nvme0n1p3"})
        self.assertEqual(
            commands.script,
            "label: gpt\n"
            "label-id: 6f0f5a7e-3c2b-4d8e-9a51-0c6d1f2e3a4b\n"
            "unit: sectors\n"
            "/dev/nvme0n1p1 : start=2048, size=1048576, "
            "type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b, "
            f'uuid={uuids[0]}, name="EFI System Partition"\n'
            "/dev/nvme0n1p3 : start=1050624, size=1952473088, "
            "type=0fc63daf-8483-4772-8e79-3d69d8477de4, "
            f'uuid={uuids[1]}, name="", '
            'attrs="RequiredPartition LegacyBIOSBootable GUID:63"\n',
        )
        self.assertEqual(
            [c[0] for c in commands.calls], ["sfdisk", "blockdev", "udevadm", "lsblk"]
        )
        self.assertNotIn("/dev/disk/by-partuuid", json.dumps(commands.calls))
        listing["blockdevices"][0]["children"][1]["partuuid"] = uuids[0]
        with mock.patch.object(recovery.subprocess, "run", side_effect=tools):
            with self.assertRaisesRegex(recovery.RecoveryError, "did not appear"):
                recovery.partition("/dev/nvme0n1", layout)
        with mock.patch.object(recovery.subprocess, "run", side_effect=tools):
            listing["blockdevices"][0]["children"][1]["partuuid"] = uuids[1]
            recovery.partition("/dev/sda", layout)
        self.assertTrue(commands.script.splitlines()[3].startswith("/dev/sda1 : "))

    def test_fstab_gets_nofail_only_outside_the_restored_disk(self):
        restored = {
            "UUID=0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f",
            "UUID=abcd-1234",
            "/swapfile",
        }
        lines = recovery.add_nofail(FSTAB, restored).splitlines()
        self.assertEqual(
            [line for line in lines if "nofail" in line],
            [
                "UUID=5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a /media/frigate ext4 "
                "defaults,nofail 0 2",
                "//nas/backups /mnt/backups cifs credentials=/root/.smb,nofail 0 0",
                "UUID=gone /mnt/gone ext4 defaults,nofail 0 2",
            ],
        )
        unchanged = set(FSTAB.splitlines()) & set(lines)
        self.assertEqual(len(unchanged), len(lines) - 2)

        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / "real").mkdir()
        (folder / "real/fstab").write_text(FSTAB)
        (folder / "root").mkdir()
        (folder / "root/etc").symlink_to(folder / "real")
        with self.assertRaisesRegex(recovery.RecoveryError, "symbolic link"):
            recovery.open_below(folder / "root", "etc/fstab", os.O_RDWR)
        with self.assertRaisesRegex(recovery.RecoveryError, "Unsafe path"):
            recovery.open_below(folder / "root", "../real/fstab", os.O_RDONLY)

    @contextlib.contextmanager
    def restore(self, data, geometry=None, native=None, missing=None):
        """restore_files with every tool, the disk and the restore root faked."""
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / "nvme0n1").write_bytes(b"")
        commands = Commands(os.fspath(folder / "nvme0n1"))
        digest = block_digest(data)
        transfer = LocalTransfer(
            native={"method": recovery.FILES_METHOD, "sector_size": 512}
            | {"min_target_size": 1000204157440}
            | (native or {}),
            compression="none",
            size=len(data),
            raw_size=len(data),
            sha256=digest,
            raw_sha256=digest,
            agent_id="test-agent",
            image_id="image",
            network_mode="internet",
        )
        transfer.data.extend(data)
        geometry = {"raw_size": 1000204886016, "sector_size": 512} | (geometry or {})

        @contextlib.contextmanager
        def verify(disk_id, writable=False):
            self.assertFalse(writable)
            with (folder / "nvme0n1").open("rb") as disk:
                yield disk, geometry | {"disk_id": disk_id}

        confirm = mock.Mock(return_value=True)
        run = SimpleNamespace(
            transfer=transfer,
            commands=commands,
            confirm=confirm,
            root=folder / "run",
            call=lambda: recovery.restore_files(
                transfer,
                dict(transfer.manifest),
                SimpleNamespace(disk_id=DISK),
                {"architecture": "x86_64", "boot_mode": "uefi"},
                verify,
                confirm,
            ),
        )
        with mock.patch.object(recovery, "NATIVE_CHUNK", BLOCK), mock.patch.object(
            recovery, "RESTORE_ROOT", os.fspath(folder / "run")
        ), mock.patch.object(
            recovery.subprocess, "run", side_effect=commands
        ), mock.patch.object(
            recovery.os, "sync"
        ), mock.patch.object(
            recovery.shutil,
            "which",
            side_effect=lambda tool: None if tool == missing else "/usr/sbin/" + tool,
        ):
            yield run

    def frigate_point(self, layout=LAYOUT):
        extra = EXTRA.encode()
        return point(
            directory(b"v/root"),
            directory(b"v/root/etc"),
            member(b"v/root/etc/fstab", data=FSTAB.encode()),
            directory(b"v/esp"),
            directory(b"v/esp/EFI"),
            directory(b"v/esp/EFI/debian"),
            member(b"v/esp/EFI/debian/shimx64.efi", data=b"shim"),
            member(b"v/esp/EFI/debian/grubx64.efi", data=b"grub"),
            directory(b"v/" + extra),
            member(b"v/" + extra + b"/clip.mp4", data=b"clip" * 3000),
            layout=layout,
        )

    def test_files_restore_writes_after_preflight_and_completes(self):
        with self.restore(self.frigate_point()) as run:
            device = run.commands.device

            def confirm():
                self.assertEqual(run.commands.written(), [])
                return True

            run.confirm.side_effect = confirm
            run.call()
        root, esp = run.root / "root", run.root / "esp"
        self.assertEqual(
            [c[0] for c in run.commands.calls],
            ["lsblk", "blkid", "wipefs", "mkfs.ext4", "lsblk", "blkid", "wipefs"]
            + ["sfdisk", "blockdev", "udevadm", "lsblk", "mkfs.ext4", "mkfs.fat"]
            + ["mount", "mount", "mkswap", "umount", "umount", "e2fsck", "fsck.vfat"]
            + ["efibootmgr"],
        )
        self.assertIn(
            [
                "mkfs.ext4",
                "-F",
                "-q",
                "-U",
                "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f",
                "-b",
                "4096",
                "-I",
                "256",
                "-N",
                "61054976",
                "-O",
                "none,has_journal,ext_attr,extent,64bit",
                f"{device}p2",
            ],
            run.commands.calls,
        )
        self.assertIn(
            ["mkfs.fat", "-F", "32", "-i", "abcd1234", f"{device}p1"],
            run.commands.calls,
        )
        self.assertEqual(
            run.commands.calls[-1],
            ["efibootmgr", "--create", "--disk", device, "--part", "1"]
            + ["--loader", "\\EFI\\debian\\shimx64.efi", "--label", "debian"],
        )
        self.assertEqual((esp / "EFI/BOOT/BOOTX64.EFI").read_bytes(), b"shim")
        self.assertEqual((esp / "EFI/BOOT/grubx64.efi").read_bytes(), b"grub")
        self.assertFalse((esp / "EFI/BOOT/mmx64.efi").exists())
        fstab = (root / "etc/fstab").read_text()
        self.assertIn("/media/frigate ext4 defaults,nofail 0 2", fstab)
        self.assertIn("/swapfile none swap sw 0 0\n", fstab)
        swap = root / "swapfile"
        self.assertEqual(swap.stat().st_size, 65536)
        self.assertEqual(stat.S_IMODE(swap.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in run.root.iterdir()), ["esp", "root"])
        self.assertEqual(
            run.transfer.completed, {"raw_sha256": run.transfer.manifest["raw_sha256"]}
        )
        self.assertFalse(run.transfer.reported)

    def test_unusable_partition_names_are_dropped(self):
        layout = copy.deepcopy(LAYOUT)
        for name in ('EFI"\nlabel: dos', "back\\slash", "tab\tname", "x" * 37):
            layout["disk"]["partitions"][0]["name"] = name
            output = io.StringIO()
            with self.subTest(name=name), self.restore(
                self.frigate_point(layout)
            ) as run, contextlib.redirect_stdout(output):
                run.call()
                self.assertIn(
                    f"Partition 1 is restored without its name {name!r}.",
                    output.getvalue(),
                )
                lines = run.commands.script.splitlines()
                self.assertEqual(len(lines), 5)
                self.assertTrue(lines[3].endswith(', name=""'))
                self.assertIsNotNone(run.transfer.completed)

    def test_printable_utf8_partition_names_are_kept(self):
        layout = copy.deepcopy(LAYOUT)
        for name in ("Syst\xe8me EFI", "\u7cfb\u7edf" * 18):
            layout["disk"]["partitions"][0]["name"] = name
            with self.subTest(name=name), self.restore(
                self.frigate_point(layout)
            ) as run:
                run.call()
                lines = run.commands.script.splitlines()
                self.assertTrue(lines[3].endswith(f', name="{name}"'))

    def test_special_fstab_aborts_on_mounts_that_refuse_devices(self):
        cases = [(tarfile.FIFOTYPE, recovery.RecoveryError, "fstab .* not a regular")]
        if os.geteuid() == 0:
            # opening the node fails: nodev here, no driver for 0:0 elsewhere
            cases.append((tarfile.BLKTYPE, OSError, ""))
        for kind, error, message in cases:
            data = point(
                directory(b"v/root"),
                directory(b"v/root/etc"),
                member(b"v/root/etc/fstab", kind),
            )
            with self.subTest(kind=kind), self.restore(data) as run:
                with self.assertRaisesRegex(error, message):
                    run.call()
                fstab = (run.root / "root/etc/fstab").lstat()
                self.assertFalse(stat.S_ISREG(fstab.st_mode))
                self.assertEqual(
                    [c[3:5] for c in run.commands.calls if c[0] == "mount"],
                    [["-o", "nodev,nosuid,noexec"]] * 2,
                )
                self.assertNotIn("e2fsck", [c[0] for c in run.commands.calls])
                self.assertIsNone(run.transfer.completed)

    def test_digest_mismatch_or_damaged_block_stops_before_completion(self):
        data = self.frigate_point()
        for damage in ("digest", "409"):
            with self.subTest(damage=damage), self.restore(data) as run:
                if damage == "digest":
                    run.transfer.manifest["raw_sha256"] = "0" * 64
                else:
                    request = run.transfer.request

                    def damaged(method, endpoint="", *args, **kwargs):
                        if endpoint == "data/?offset=8192":
                            url = "https://ulrmm.test/"
                            error = urllib.error.HTTPError(url, 409, "", {}, None)
                            raise recovery.RecoveryError("HTTP 409") from error
                        return request(method, endpoint, *args, **kwargs)

                    run.transfer.request = damaged
                with self.assertRaisesRegex(
                    recovery.RecoveryError,
                    "Restore stopped: the point failed its integrity check. "
                    "Only the blank target was written.",
                ):
                    run.call()
                self.assertTrue(run.transfer.reported)
                self.assertIsNone(run.transfer.completed)
                self.assertNotIn("e2fsck", [c[0] for c in run.commands.calls])
                self.assertEqual([c[0] for c in run.commands.calls].count("umount"), 2)

    def test_preflight_failures_stop_before_any_write(self):
        data = self.frigate_point()
        bad_arch = point(layout=LAYOUT | {"arch": "aarch64"})
        unnamed = copy.deepcopy(LAYOUT)
        unnamed["disk"]["partitions"][0]["name"] = None
        smaller = "smaller than the recorded partitions"
        for case, message in [
            ({"children": True}, "not blank. Wipe it first with: wipefs -a "),
            ({"wipefs": "/dev/x 0x200 gpt\n"}, "not blank"),
            ({"blkid": 0}, "not blank"),
            ({"geometry": {"raw_size": 1000204157439}}, smaller),
            ({"native": {"min_target_size": 1}, "geometry": {"raw_size": 1}}, smaller),
            ({"geometry": {"sector_size": 4096}}, "sector size differs"),
            ({"missing": "fsck.vfat"}, "Recovery media lacks fsck.vfat."),
            ({"mke2fs": 1}, "cannot create the recorded ext4 features: Invalid"),
            ({"data": bad_arch}, "captured on aarch64. Boot recovery media for"),
            ({"data": point(layout=unnamed)}, "layout is invalid"),
            ({"data": point(directory(b"v/root"))[512:]}, "not a valid backup"),
        ]:
            with self.subTest(case=case), self.restore(
                case.get("data", data),
                case.get("geometry"),
                case.get("native"),
                case.get("missing"),
            ) as run:
                for key in ("children", "wipefs", "blkid", "mke2fs"):
                    if key in case:
                        setattr(run.commands, key, case[key])
                with self.assertRaisesRegex(recovery.RecoveryError, message):
                    run.call()
                self.assertEqual(run.commands.written(), [])
                run.confirm.assert_not_called()
                self.assertIsNone(run.transfer.completed)


if __name__ == "__main__":
    unittest.main()

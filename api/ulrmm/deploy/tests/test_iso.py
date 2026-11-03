# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import io
import os
import struct
import tempfile
import time
import unittest
import zlib

import pycdlib

from deploy import iso

GRUB = b"linux /casper/vmlinuz quiet ---\n"


def _isolinux(fill):
    data = bytearray(fill * 2048)
    data[0x40:0x44] = b"\xfb\xc0\x78\x70"
    return bytes(data)


def _add(img, data, iso_path, joliet_path, udf_path=None):
    kwargs = {"iso_path": iso_path, "joliet_path": joliet_path}
    if img.has_rock_ridge():
        kwargs["rr_name"] = joliet_path.rsplit("/", 1)[1]
    if udf_path:
        kwargs["udf_path"] = udf_path
    img.add_fp(io.BytesIO(data), len(data), **kwargs)


def _mkdir(img, iso_path, joliet_path, udf_path=None):
    kwargs = {"iso_path": iso_path, "joliet_path": joliet_path}
    if img.has_rock_ridge():
        kwargs["rr_name"] = joliet_path.rsplit("/", 1)[1]
    if udf_path:
        kwargs["udf_path"] = udf_path
    img.add_directory(**kwargs)


def _read(img, **kwargs):
    buf = io.BytesIO()
    img.get_file_from_iso_fp(buf, **kwargs)
    return buf.getvalue()


def linux_fixture(path, boot_info_table=False):
    img = pycdlib.PyCdlib()
    img.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="UBUNTU_TEST")
    for iso_path, joliet_path in (
        ("/ISOLINUX", "/isolinux"),
        ("/EFI", "/EFI"),
        ("/EFI/BOOT", "/EFI/BOOT"),
        ("/BOOT", "/boot"),
        ("/BOOT/GRUB", "/boot/grub"),
        ("/_DISK", "/.disk"),
    ):
        _mkdir(img, iso_path, joliet_path)
    _add(img, _isolinux(b"\x01"), "/ISOLINUX/ISOLINUX.BIN;1", "/isolinux/isolinux.bin")
    _add(img, b"\x02" * 4096, "/EFI/BOOT/EFIBOOT.IMG;1", "/EFI/BOOT/efiboot.img")
    _add(img, GRUB, "/BOOT/GRUB/GRUB.CFG;1", "/boot/grub/grub.cfg")
    _add(img, b"Ubuntu-Server 24.04.1 LTS\n", "/_DISK/INFO.;1", "/.disk/info")
    img.add_eltorito(
        "/ISOLINUX/ISOLINUX.BIN;1",
        bootcatfile="/ISOLINUX/BOOT.CAT;1",
        rr_bootcatname="boot.cat",
        joliet_bootcatfile="/isolinux/boot.cat",
        boot_load_size=4,
        boot_info_table=boot_info_table,
    )
    img.add_eltorito("/EFI/BOOT/EFIBOOT.IMG;1", efi=True)
    img.add_isohybrid(efi=True)
    img.write(path)
    img.close()


def _fat(sectors):
    """A FAT12 image of sectors * 512 bytes with a valid boot sector."""
    data = bytearray(b"\xf1" * (sectors * 512))
    data[0:11] = b"\xeb\x3c\x90MSDOS5.0"
    data[11:13] = (512).to_bytes(2, "little")
    data[13:19] = b"\x01\x01\x00\x02\xe0\x00"
    data[19:21] = sectors.to_bytes(2, "little")
    data[21:24] = b"\xf8\x01\x00"
    data[510:512] = b"\x55\xaa"
    return bytes(data)


EFISYS = _fat(16)


def windows_fixture(path):
    """Laid out like oscdimg: BIOS image with a sector count of 8, EFI image
    with a sector count of 1 and no directory entry."""
    img = pycdlib.PyCdlib()
    img.new(interchange_level=3, joliet=3, udf="2.60", vol_ident="CCCOMA_X64FRE")
    _mkdir(img, "/SOURCES", "/sources", "/sources")
    _mkdir(img, "/BOOT", "/boot", "/boot")
    _add(img, b"wim", "/SOURCES/BOOT.WIM;1", "/sources/boot.wim", "/sources/boot.wim")
    _add(
        img,
        b"\x02" * 4096,
        "/BOOT/ETFSBOOT.COM;1",
        "/boot/etfsboot.com",
        "/boot/etfsboot.com",
    )
    _add(img, EFISYS, "/EFISYS.BIN;1", "/efisys.bin", "/efisys.bin")
    img.add_eltorito("/BOOT/ETFSBOOT.COM;1", boot_load_size=8)
    img.add_eltorito("/EFISYS.BIN;1", efi=True, boot_load_size=1)
    for kwargs in (
        {"iso_path": "/EFISYS.BIN;1"},
        {"joliet_path": "/efisys.bin"},
        {"udf_path": "/efisys.bin"},
    ):
        img.rm_hard_link(**kwargs)
    img.write(path)
    img.close()


def _crc(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
            )
    return crc


def _seal(buf, off, loc):
    """Set a UDF descriptor tag's location, CRC and checksum."""
    struct.pack_into("<I", buf, off + 12, loc)
    crclen = struct.unpack_from("<H", buf, off + 10)[0]
    struct.pack_into("<H", buf, off + 8, _crc(buf[off + 16 : off + 16 + crclen]))
    buf[off + 4] = (sum(buf[off : off + 4]) + sum(buf[off + 5 : off + 16])) & 0xFF


def _add_eas(path):
    """Give the File Entry of every root file an extended attribute header,
    as the Microsoft tool writes them."""
    img = _open(path)
    part = img.udf_main_descs.partitions[0].part_start_location
    blocks = [
        r.extent_location()
        for r in img.list_children(udf_path="/")
        if r is not None and not r.is_dir()
    ]
    img.close()
    with open(path, "r+b") as f:
        for block in blocks:
            f.seek(block * 2048)
            fe = bytearray(f.read(2048))
            lad = struct.unpack_from("<I", fe, 172)[0]
            ea = bytearray(24)
            struct.pack_into("<HHHHII", ea, 0, 262, 2, 0, 8, 24, 24)
            _seal(ea, 0, block - part)
            fe = bytearray(fe[:176] + ea + fe[176 : 176 + lad])
            fe += bytes(2048 - len(fe))
            struct.pack_into("<I", fe, 168, 24)
            struct.pack_into("<H", fe, 10, 160 + 24 + lad)
            _seal(fe, 0, block - part)
            f.seek(block * 2048)
            f.write(fe)


def _udf_check(path):
    """Walk the UDF tree byte by byte, not through pycdlib: the '..' entries
    that do not point at the parent directory, the extended attribute headers
    that do not point at their File Entry, and partition end vs image size."""
    with open(path, "rb") as f:

        def block(n):
            f.seek(n * 2048)
            return f.read(2048)

        vds_len, vds = struct.unpack_from("<II", block(256), 16)
        for n in range(vds, vds + vds_len // 2048):
            desc = block(n)
            tag = struct.unpack_from("<H", desc, 0)[0]
            if tag == 5:
                start, length = struct.unpack_from("<II", desc, 188)
            elif tag == 6:
                fsd = struct.unpack_from("<I", desc, 252)[0]
            elif tag == 8:
                break
        root = struct.unpack_from("<I", block(start + fsd), 404)[0]
        stale, bad_ea, todo = [], [], [(root, root, "/")]
        while todo:
            lbn, up, name = todo.pop()
            fe = block(start + lbn)
            lea, lad = struct.unpack_from("<II", fe, 168)
            if lea and struct.unpack_from("<I", fe, 188)[0] != lbn:
                bad_ea.append(name)
            if fe[27] != 4:
                continue
            size, pos = struct.unpack_from("<II", fe, 176 + lea)
            size &= 0x3FFFFFFF
            f.seek((start + pos) * 2048)
            data, off = f.read(size), 0
            while off < size:
                kind, lfi = data[off + 18], data[off + 19]
                icb = struct.unpack_from("<I", data, off + 24)[0]
                liu = struct.unpack_from("<H", data, off + 36)[0]
                if kind & 8:
                    if icb != up:
                        stale.append(name)
                else:
                    child = data[off + 38 + liu + 1 : off + 38 + liu + lfi]
                    todo.append((icb, lbn, name + child.decode("latin-1") + "/"))
                off += (38 + liu + lfi + 3) & ~3
        sectors = os.path.getsize(path) // 2048
    # the partition ends right before the closing anchor in the last block
    return {"stale": stale, "bad_ea": bad_ea, "end": (start + length, sectors - 1)}


def _boot_image(path, rba, size):
    with open(path, "rb") as f:
        f.seek(rba * 2048)
        return f.read(size)


def _open(path):
    img = pycdlib.PyCdlib()
    img.open(path)
    return img


class TestSeedIso(unittest.TestCase):
    def test_seed_roundtrip(self):
        files = [
            ("/nocloud/user-data", b"#cloud-config\n"),
            ("/nocloud/meta-data", b""),
            ("/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"@echo off\r\n"),
        ]
        img = pycdlib.PyCdlib()
        img.open_fp(io.BytesIO(iso.seed_iso("cidata", files)))
        try:
            self.assertEqual(img.pvd.volume_identifier.strip(), b"CIDATA")
            for path, body in files:
                self.assertEqual(_read(img, joliet_path=path), body)
                self.assertEqual(_read(img, rr_path=path), body)
            names = [
                c.rock_ridge.name()
                for c in img.list_children(rr_path="/$OEM$/$$/Setup/Scripts")
                if not (c.is_dot() or c.is_dotdot())
            ]
            self.assertEqual(names, [b"SetupComplete.cmd"])
        finally:
            img.close()

    def test_label(self):
        self.assertEqual(iso.safe_label("ci data!"), "CI_DATA_")
        self.assertEqual(len(iso.safe_label("x" * 40)), 32)
        with self.assertRaises(iso.IsoError):
            iso.safe_label("")

    def test_safe_path(self):
        self.assertEqual(iso.safe_path("/a/b/c.txt"), "/a/b/c.txt")
        self.assertEqual(iso.safe_path("/$OEM$/$$/x"), "/$OEM$/$$/x")
        bad = [
            "../x",
            "/a/../b",
            "/a/./b",
            "a//b",
            "/a\\b",
            "/a/b\x00",
            "/",
            "/a b",
            "/" + "/".join("d" * 9),
            "/" + "a" * 65,
            "/" + "/".join(["a" * 60] * 4) + "/b",
        ]
        for path in bad:
            with self.assertRaises(iso.IsoError, msg=path):
                iso.safe_path(path)

    def test_duplicate(self):
        with self.assertRaises(iso.IsoError):
            iso.seed_iso("x", [("/a/b", b"1"), ("/a/B", b"2")])

    def test_fast(self):
        start = time.monotonic()
        iso.seed_iso("big", [("/blob.bin", os.urandom(1 << 20)), ("/x", b"y")])
        self.assertLess(time.monotonic() - start, 0.5)


class TestInject(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "src.iso")
        self.out = os.path.join(self.tmp.name, "out.iso")

    def test_linux(self):
        linux_fixture(self.src)
        seen = []
        new_boot = _isolinux(b"\x07")
        with open(self.out, "w+b") as out:
            res = iso.inject(
                self.src,
                out,
                [
                    ("/autoinstall.yaml", b"version: 1\n"),
                    ("/ISOLINUX/isolinux.bin", new_boot),
                ],
                edits={
                    "/boot/grub/grub.cfg": lambda b: b.replace(
                        b"quiet", b"quiet autoinstall"
                    ),
                    "/missing.cfg": lambda b: b,
                },
                progress=lambda done, total: seen.append((done, total)),
            )
        self.assertEqual(res["added"], ["/autoinstall.yaml"])
        self.assertEqual(res["replaced"], ["/ISOLINUX/isolinux.bin"])
        self.assertEqual(res["edited"], ["/boot/grub/grub.cfg"])
        self.assertEqual(res["sha256"], iso.sha256_of(self.out))
        self.assertTrue(res["mbr_kept"])
        self.assertEqual(res["size"], os.path.getsize(self.out))
        with open(self.out, "rb") as f:
            mbr = f.read(512)
            gpt = f.read(8)
        self.assertEqual(mbr[510:], b"\x55\xaa")
        self.assertEqual(gpt, b"EFI PART")
        self.assertTrue(any(mbr[:446]))
        dones = [d for d, _ in seen]
        self.assertEqual(dones, sorted(dones))
        self.assertEqual(seen[-1][0], seen[-1][1])

        img = _open(self.out)
        try:
            cat = img.eltorito_boot_catalog
            self.assertEqual(cat.validation_entry.platform_id, 0)
            self.assertEqual([s.platform_id for s in cat.sections], [0xEF])
            self.assertIsNotNone(img.isohybrid_mbr)
            rba = cat.initial_entry.load_rba
            self.assertEqual(
                _read(img, joliet_path="/boot/grub/grub.cfg"),
                b"linux /casper/vmlinuz quiet autoinstall ---\n",
            )
            self.assertEqual(
                _read(img, joliet_path="/autoinstall.yaml"), b"version: 1\n"
            )
            self.assertEqual(_read(img, rr_path="/autoinstall.yaml"), b"version: 1\n")
            self.assertEqual(_read(img, rr_path="/isolinux/isolinux.bin"), new_boot)
        finally:
            img.close()
        with open(self.out, "rb") as f:
            f.seek(rba * 2048)
            self.assertEqual(f.read(2048), new_boot)
        self.assertIn(b"autoinstall", iso.read_file(self.out, "/Boot/Grub/GRUB.cfg"))
        self.assertIsNone(iso.read_file(self.out, "/nope"))

    def test_inspect_linux(self):
        linux_fixture(self.src)
        info = iso.inspect(self.src)
        self.assertEqual(info["os"], "ubuntu")
        self.assertEqual(info["info"], "Ubuntu-Server 24.04.1 LTS")
        self.assertEqual(info["label"], "UBUNTU_TEST")
        self.assertTrue(info["bios"])
        self.assertTrue(info["efi"])
        self.assertTrue(info["isohybrid"])
        self.assertTrue(info["rock_ridge"])
        self.assertFalse(info["udf"])
        self.assertIn("boot", info["files"])

    def test_udf(self):
        windows_fixture(self.src)
        with open(self.out, "w+b") as out:
            res = iso.inject(
                self.src,
                out,
                [
                    ("/autounattend.xml", b"<unattend/>"),
                    ("/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"rem\r\n"),
                ],
            )
        self.assertEqual(len(res["added"]), 2)
        img = _open(self.out)
        try:
            self.assertEqual(_read(img, udf_path="/autounattend.xml"), b"<unattend/>")
            self.assertEqual(
                _read(img, joliet_path="/autounattend.xml"), b"<unattend/>"
            )
            self.assertEqual(
                _read(img, udf_path="/$OEM$/$$/Setup/Scripts/SetupComplete.cmd"),
                b"rem\r\n",
            )
        finally:
            img.close()
        info = iso.inspect(self.out)
        self.assertEqual(info["os"], "windows")
        self.assertTrue(info["udf"])
        self.assertTrue(info["bios"])
        self.assertTrue(info["efi"])
        self.assertEqual(info["label"], "CCCOMA_X64FRE")

    def test_hidden_efi_image_kept_whole(self):
        windows_fixture(self.src)
        with open(self.out, "w+b") as out:
            iso.inject(self.src, out, [("/autounattend.xml", b"<unattend/>")])
        for path in (self.src, self.out):
            img = _open(path)
            try:
                cat = img.eltorito_boot_catalog
                bios = cat.initial_entry
                efi = cat.sections[0].section_entries[0]
                self.assertEqual((bios.sector_count, efi.sector_count), (8, 1))
                self.assertEqual(_boot_image(path, bios.load_rba, 4096), b"\x02" * 4096)
                self.assertEqual(_boot_image(path, efi.load_rba, len(EFISYS)), EFISYS)
            finally:
                img.close()

    def test_udf_tree_follows_the_new_layout(self):
        # pycdlib 1.22 moves the tree but kept the old '..' entries, which
        # Windows reads as files: Setup then failed at 6%
        windows_fixture(self.src)
        img = _open(self.src)
        for path in ("/sources/a", "/sources/a/b", "/sources/a/b/c"):
            _mkdir(img, path.upper(), path, path)
        img.write(self.src + ".2")
        img.close()
        os.replace(self.src + ".2", self.src)
        _add_eas(self.src)
        files = [
            ("/sources/a/b/c/x.txt", b"x"),
            ("/sources/$OEM$/$1/ulrmm/agent.exe", b"MZ" * 3000),
            # a new folder ahead of the others moves every directory
            ("/$OEM$/x.txt", b"y"),
        ]
        with open(self.out, "w+b") as out:
            iso.inject(self.src, out, files)
        check = _udf_check(self.out)
        self.assertEqual(check["stale"], [])
        self.assertEqual(check["bad_ea"], [])
        self.assertEqual(check["end"][0], check["end"][1])
        img = _open(self.out)
        try:
            self.assertEqual(_read(img, udf_path="/sources/a/b/c/x.txt"), b"x")
            self.assertEqual(_read(img, udf_path="/sources/boot.wim"), b"wim")
        finally:
            img.close()

    def test_unmovable_isohybrid_mbr_is_dropped(self):
        # SUSE and Arch keep the EFI partition in MBR slot 1; pycdlib cannot
        # move it and failed to write the image
        linux_fixture(self.src)
        with open(self.src, "r+b") as f:
            f.seek(446)
            first, second = f.read(16), f.read(16)
            f.seek(446)
            f.write(second + first)
        with open(self.out, "w+b") as out:
            res = iso.inject(self.src, out, [("/a.cfg", b"x")])
        self.assertFalse(res["mbr_kept"])
        info = iso.inspect(self.out)
        self.assertTrue(info["bios"])
        self.assertTrue(info["efi"])

    def test_boot_info_table_with_partition_offset(self):
        # xorriso names the PVD at block 48 in partition offset images (Alma
        # 10); pycdlib left such a table pointing at the old place of the
        # moved boot image and BIOS boot hung
        linux_fixture(self.src, boot_info_table=True)
        img = _open(self.src)
        rba = img.eltorito_boot_catalog.initial_entry.load_rba
        img.close()
        with open(self.src, "r+b") as f:
            f.seek(rba * 2048 + 8)
            f.write(struct.pack("<I", 48))
        with open(self.out, "w+b") as out:
            iso.inject(self.src, out, [("/aaa/" + "a" * 60, os.urandom(1 << 16))])
        img = _open(self.out)
        moved = img.eltorito_boot_catalog.initial_entry.load_rba
        img.close()
        self.assertNotEqual(moved, rba)
        with open(self.out, "rb") as f:
            f.seek(moved * 2048 + 8)
            pvd, block = struct.unpack("<II", f.read(8))
        self.assertEqual((pvd, block), (16, moved))

    def test_suse_treeinfo(self):
        tree = (
            b"[header]\nversion = 1.0\n"
            b"[general]\nfamily = openSUSE Leap\nversion = 15.6\n"
        )
        with open(self.src, "wb") as f:
            f.write(iso.seed_iso("LEAP", [("/.treeinfo", tree)]))
        info = iso.inspect(self.src)
        self.assertEqual((info["os"], info["info"]), ("suse", "openSUSE Leap 15.6"))

    def test_gpt_needs_its_partition_array(self):
        # pycdlib keeps the GPT header but leaves the partition array empty
        # or with a stale CRC; only a matching array counts as kept
        linux_fixture(self.src)
        with open(self.src, "r+b") as f:
            f.seek(512 + 72)
            lba, count, size = struct.unpack("<QII", f.read(16))
            f.seek(lba * 512)
            crc = zlib.crc32(f.read(count * size))
            f.seek(512 + 88)
            f.write(struct.pack("<I", crc))
            self.assertTrue(iso._has_gpt(f))
            f.seek(lba * 512)
            f.write(bytes(128))
            self.assertFalse(iso._has_gpt(f))

    def test_fat_size(self):
        self.assertEqual(iso._fat_size(EFISYS[:512]), len(EFISYS))
        self.assertEqual(iso._fat_size(b"\x02" * 512), 0)
        self.assertEqual(iso._fat_size(b""), 0)

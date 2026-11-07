# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""ISO images for the OS targets: small seed images built in memory and
existing install images copied with answer files added. Existing data is
streamed from the source image, never loaded into memory.
"""

import hashlib
import io
import os
import re
import struct
import zlib

import pycdlib
from pycdlib.eltorito import EltoritoBootInfoTable, EltoritoEntry
from pycdlib.pycdlibexception import PyCdlibException

_D1 = re.compile(r"[^A-Z0-9_]")
_SEGMENT = re.compile(r"[A-Za-z0-9._$-]+")
_CHUNK = 1 << 20


class IsoError(ValueError):
    pass


def safe_label(label: str) -> str:
    out = _D1.sub("_", (label or "").upper())[:32]
    if not out:
        raise IsoError("empty volume label")
    return out


def safe_path(path: str) -> str:
    if not isinstance(path, str) or "\\" in path:
        raise IsoError(f"invalid path {path!r}")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise IsoError(f"control character in path {path!r}")
    parts = (path[1:] if path.startswith("/") else path).split("/")
    if len(parts) > 8:
        raise IsoError(f"path too deep {path!r}")
    for part in parts:
        if part in ("", ".", "..") or len(part) > 64 or not _SEGMENT.fullmatch(part):
            raise IsoError(f"invalid path {path!r}")
    out = "/" + "/".join(parts)
    if len(out) > 240:
        raise IsoError(f"path too long {path!r}")
    return out


def _iso_name(segment, is_dir, level, n=0):
    """The ISO9660 identifier for a Joliet/Rock Ridge name; n > 0 numbers it
    to avoid a collision."""
    name = segment.upper()
    stem, ext = name, ""
    if is_dir:
        stem = name.replace(".", "_")
    elif "." in name:
        stem, ext = name.rsplit(".", 1)
    stem, ext = _D1.sub("_", stem), _D1.sub("_", ext)[: 3 if level == 1 else 8]
    if level == 1:
        room = 8
    else:
        room = 31 if is_dir else 30 - len(ext)
    suffix = str(n) if n else ""
    stem = stem[: room - len(suffix)] + suffix
    if is_dir:
        return stem
    return f"{stem}.{ext};1" if ext else f"{stem};1"


def _base(ident):
    return ident.split(";")[0].rstrip(".").upper()


def _name(iso, ns, rec):
    if ns == "udf_path":
        return rec.file_identifier().decode(rec.file_ident.encoding)
    if ns == "joliet_path":
        return rec.file_identifier().decode("utf-16_be").split(";")[0]
    if rec.rock_ridge is not None:
        return rec.rock_ridge.name().decode("utf-8")
    return rec.file_identifier().decode("ascii", "replace").split(";")[0].rstrip(".")


def _children(iso, ns, parent):
    for rec in iso.list_children(**{ns: parent}):
        if rec is None:
            continue
        if ns != "udf_path" and (rec.is_dot() or rec.is_dotdot()):
            continue
        yield rec


def _child(iso, ns, parent, segment):
    """The record named segment (case-insensitive) in parent, or None."""
    want = {segment.lower()}
    if ns == "iso_path" and not iso.has_rock_ridge():
        want.add(_base(_iso_name(segment, False, iso.interchange_level)).lower())
        want.add(_iso_name(segment, True, iso.interchange_level).lower())
    for rec in _children(iso, ns, parent):
        if _name(iso, ns, rec).lower() in want:
            return rec
    return None


def _order(iso):
    """Namespaces to search, the one with the most faithful names first."""
    order = ["iso_path"] if iso.has_rock_ridge() else []
    if iso.has_udf():
        order.append("udf_path")
    if iso.has_joliet():
        order.append("joliet_path")
    if "iso_path" not in order:
        order.append("iso_path")
    return order


def _find(iso, path):
    """(namespace, actual path, record) of path on the image, or None."""
    parts = path.strip("/").split("/")
    for ns in _order(iso):
        cur, rec = "/", None
        for part in parts:
            if rec is not None and not rec.is_dir():
                rec = None
            else:
                rec = _child(iso, ns, cur, part)
            if rec is None:
                break
            cur = iso.full_path_from_dirrecord(rec)
        else:
            return ns, cur, rec
    return None


def _read(iso, path):
    found = _find(iso, path)
    if found is None or found[2].is_dir():
        return None
    buf = io.BytesIO()
    iso.get_file_from_iso_fp(buf, **{found[0]: found[1]})
    return buf.getvalue()


def _join(parent, name):
    return parent.rstrip("/") + "/" + name


def _target(iso, namespaces, parent, segment, is_dir):
    """add_directory/add_fp arguments for segment under parent in every
    namespace where it does not exist yet, and the existing ones."""
    args, have = {}, {}
    for ns in namespaces:
        rec = _child(iso, ns, parent[ns], segment)
        if rec is not None:
            have[ns] = iso.full_path_from_dirrecord(rec)
        elif ns == "iso_path":
            level = iso.interchange_level
            used = {
                _base(r.file_identifier().decode("ascii", "replace"))
                for r in _children(iso, ns, parent[ns])
            }
            n = 0
            while _base(_iso_name(segment, is_dir, level, n)) in used:
                n += 1
            args[ns] = _join(parent[ns], _iso_name(segment, is_dir, level, n))
            if iso.has_rock_ridge():
                args["rr_name"] = segment
        else:
            args[ns] = _join(parent[ns], segment)
    return args, have


def _put(iso, files, edits):
    namespaces = ["iso_path"]
    if iso.has_joliet():
        namespaces.append("joliet_path")
    if iso.has_udf():
        namespaces.append("udf_path")
    dirs = {"/": {ns: "/" for ns in namespaces}}
    keep = []

    def directory(path):
        key = path.lower()
        if key not in dirs:
            parent, _, segment = path.rpartition("/")
            pdirs = directory(parent or "/")
            args, have = _target(iso, namespaces, pdirs, segment, True)
            if args:
                iso.add_directory(**args)
            have.update((ns, args[ns]) for ns in namespaces if ns in args)
            dirs[key] = have
        return dirs[key]

    def update(found, data):
        fp = io.BytesIO(data)
        keep.append(fp)
        iso.update_file_contents_fp(fp, len(data), **{found[0]: found[1]})

    report = {"added": [], "replaced": [], "edited": []}
    seen = set()
    for path, data in files:
        path = safe_path(path)
        if path.lower() in seen:
            raise IsoError(f"duplicate path {path}")
        seen.add(path.lower())
        found = _find(iso, path)
        if found is not None and not found[2].is_dir():
            update(found, data)
            report["replaced"].append(path)
            continue
        parent, _, segment = path.rpartition("/")
        args, _ = _target(iso, namespaces, directory(parent or "/"), segment, False)
        fp = io.BytesIO(data)
        keep.append(fp)
        iso.add_fp(fp, len(data), **args)
        report["added"].append(path)
    for path, fn in (edits or {}).items():
        path = safe_path(path)
        found = _find(iso, path)
        if found is None or found[2].is_dir():
            continue
        update(found, fn(_read(iso, path)))
        report["edited"].append(path)
    return report, keep


def _open(src):
    iso = pycdlib.PyCdlib()
    try:
        iso.open(src)
    except PyCdlibException as e:
        raise IsoError(f"cannot read ISO: {e}") from e
    return iso


def _boot_entries(iso):
    cat = iso.eltorito_boot_catalog
    if cat is None:
        return []
    out = [cat.initial_entry]
    for sec in cat.sections:
        out.extend(sec.section_entries)
    return out + list(cat.standalone_entries)


def _fat_size(head: bytes) -> int:
    """Byte size of the FAT image whose boot sector is head, or 0."""
    if len(head) < 512 or head[0] not in (0xEB, 0xE9) or head[510:] != b"\x55\xaa":
        return 0
    bps = int.from_bytes(head[11:13], "little")
    total = int.from_bytes(head[19:21], "little") or int.from_bytes(
        head[32:36], "little"
    )
    if bps not in (512, 1024, 2048, 4096):
        return 0
    return bps * total


def _grow_boot_images(iso, src: str) -> None:
    """Windows media (oscdimg) list the EFI boot image with a sector count of
    1 and no directory entry; the firmware reads on to the end of the FAT
    image, but pycdlib would copy only those 512 bytes. Widen such entries to
    the size the FAT boot sector declares."""
    size = os.path.getsize(src)
    with open(src, "rb") as fp:
        for entry in _boot_entries(iso):
            ino = entry.inode
            if ino is None or not all(
                isinstance(rec, EltoritoEntry) for rec, _ in ino.linked_records
            ):
                continue
            fp.seek(ino.fp_offset)
            want = _fat_size(fp.read(512))
            if ino.data_length < want <= size - ino.fp_offset:
                ino.data_length = want


def _keep_boot_info_tables(iso, src: str) -> None:
    """pycdlib updates a boot info table only when it names the PVD at block
    16. xorriso writes 48 into images with a partition offset (Alma 10), so
    the table kept the boot image's old place and BIOS boot hung. Take over
    every table whose file block and checksum match."""
    with open(src, "rb") as fp:
        for entry in _boot_entries(iso):
            ino = entry.inode
            if ino is None or ino.boot_info_table is not None:
                continue
            fp.seek(ino.fp_offset + 8)
            head = fp.read(16)
            if len(head) < 16:
                continue
            _pvd, block, length, csum = struct.unpack("<IIII", head)
            if block != ino.extent_location():
                continue
            fp.seek(ino.fp_offset)
            if (
                iso._calculate_eltorito_boot_info_table_csum(fp, ino.data_length)
                != csum
            ):
                continue
            table = EltoritoBootInfoTable()
            table.new(iso.pvd, ino, length, csum)
            ino.add_boot_info_table(table)


def _drop_unmovable_mbr(iso) -> None:
    """pycdlib only finds the EFI partition of an isohybrid MBR in slot 2
    with the CHS values it writes itself (SUSE and Arch differ) and then fails
    to write the image; drop such an MBR, the image boots as CD then."""
    mbr, cat = iso.isohybrid_mbr, iso.eltorito_boot_catalog
    if mbr is None or mbr.efi or cat is None:
        return
    platforms = {cat.validation_entry.platform_id}
    platforms.update(s.platform_id for s in cat.sections)
    if 0xEF in platforms:
        iso.isohybrid_mbr = None


def _fix_ea(fe) -> None:
    """Point an extended attribute header at the File Entry's new block."""
    ea = bytearray(fe.extended_attrs or b"")
    if len(ea) < 16 or int.from_bytes(ea[:2], "little") != 262:
        return
    ea[12:16] = fe.desc_tag.tag_location.to_bytes(4, "little")
    ea[4] = (sum(ea[:4]) + sum(ea[5:16])) & 0xFF
    fe.extended_attrs = bytes(ea)


def _fix_udf(iso) -> None:
    """pycdlib 1.22 moves the UDF tree when it writes an image but leaves the
    '..' entry of each directory, the extended attribute headers and the
    partition length at their old values. Windows then reads '..' as a file
    and Setup stops copying the media at 6% (0x8007007E). Lay the image out
    now and set the three to the new layout."""
    if not iso.has_udf():
        return
    iso._reshuffle_extents()
    start = iso.udf_main_descs.partitions[0].part_start_location
    todo = [iso.udf_root]
    while todo:
        fe = todo.pop()
        _fix_ea(fe)
        up = (fe.parent or fe).extent_location()
        for d in fe.fi_descs.values():
            if d.is_parent():
                d.set_icb(up, up - start)
            elif d.file_entry is not None:
                if d.is_dir():
                    todo.append(d.file_entry)
                else:
                    _fix_ea(d.file_entry)
    # up to the closing anchor in the last block, as pycdlib's new images
    length = iso.pvd.space_size - 1 - start
    for descs in (iso.udf_main_descs, iso.udf_reserve_descs):
        descs.partitions[0].part_length = length
    lvid = iso.udf_logical_volume_integrity
    if lvid is not None and lvid.size_tables:
        lvid.size_tables[0] = length


def seed_iso(label: str, files: list[tuple[str, bytes]]) -> bytes:
    iso = pycdlib.PyCdlib()
    iso.new(
        interchange_level=4, joliet=3, rock_ridge="1.09", vol_ident=safe_label(label)
    )
    out = io.BytesIO()
    try:
        _report, _keep = _put(iso, files, None)
        iso.write_fp(out)
    except PyCdlibException as e:
        raise IsoError(str(e)) from e
    finally:
        iso.close()
    return out.getvalue()


def inject(src: str, out, files, *, edits=None, progress=None) -> dict:
    """Copy src to out with files added or replaced in every namespace the
    image has; edits rewrite files already on the image. Boot catalog and
    hybrid MBR are carried over as they are."""
    iso = _open(src)
    try:
        _drop_unmovable_mbr(iso)
        _keep_boot_info_tables(iso, src)
        _grow_boot_images(iso, src)
        report, _keep = _put(iso, files, edits)
        _fix_udf(iso)
        cb = None if progress is None else (lambda done, total: progress(done, total))
        iso.write_fp(out, blocksize=_CHUNK, progress_cb=cb)
    except PyCdlibException as e:
        raise IsoError(str(e)) from e
    finally:
        iso.close()
    out.flush()
    out.seek(0)
    h, size = hashlib.sha256(), 0
    while chunk := out.read(_CHUNK):
        h.update(chunk)
        size += len(chunk)
    return {
        "sha256": h.hexdigest(),
        "size": size,
        "mbr_kept": _kept(_has_mbr_fp, src, out) and _kept(_has_gpt, src, out),
        **report,
    }


def _kept(check, src: str, out) -> bool:
    with open(src, "rb") as fp:
        return not check(fp) or check(out)


def _has_mbr_fp(fp) -> bool:
    fp.seek(0)
    head = fp.read(512)
    return len(head) == 512 and head[510:] == b"\x55\xaa" and any(head[:446])


def _has_gpt(fp) -> bool:
    """A GPT header whose partition array matches its CRC; pycdlib can keep
    the header and leave the array empty."""
    fp.seek(512)
    head = fp.read(92)
    if len(head) < 92 or head[:8] != b"EFI PART":
        return False
    lba, count, size, crc = struct.unpack_from("<QIII", head, 72)
    if not 0 < count * size <= 1 << 20:
        return False
    fp.seek(lba * 512)
    return zlib.crc32(fp.read(count * size)) == crc


def _has_mbr(path: str) -> bool:
    with open(path, "rb") as fp:
        return _has_mbr_fp(fp)


def _detect(iso, label):
    for p in ("/sources/boot.wim", "/sources/install.wim", "/sources/install.esd"):
        if _find(iso, p) is not None:
            return "windows", label
    info = _read(iso, "/.disk/info")
    if info:
        line = info.decode("utf-8", "replace").strip().splitlines()[0].strip()
        if "Ubuntu" in line:
            return "ubuntu", line
        if "Debian" in line:
            return "debian", line
    tree = _read(iso, "/.treeinfo")
    if tree is not None:
        # [general] wins: Leap's [header] carries a format version first
        values, section = {}, ""
        for line in tree.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line.strip("[]").lower()
                continue
            key, sep, value = line.partition("=")
            key = key.strip().lower()
            if sep and (section == "general" or key not in values):
                values[key] = value.strip()
        family = values.get("family", "")
        info = f"{family} {values.get('version', '')}".strip() or label
        if "suse" in family.lower():
            return "suse", info
        return ("fedora" if "Fedora" in family else "rhel"), info
    if _find(iso, "/boot/x86_64/loader") is not None or label.upper().startswith(
        ("OPENSUSE", "SLE")
    ):
        return "suse", label
    if _find(iso, "/arch/boot") is not None:
        return "arch", label
    return "unknown", label


def inspect(src: str) -> dict:
    iso = _open(src)
    try:
        label = iso.pvd.volume_identifier.decode("ascii", "replace").strip(" \x00")
        platforms = set()
        cat = iso.eltorito_boot_catalog
        if cat is not None:
            platforms.add(cat.validation_entry.platform_id)
            platforms.update(s.platform_id for s in cat.sections)
        os_name, info = _detect(iso, label)
        ns = _order(iso)[0]
        return {
            "label": label,
            "size": os.path.getsize(src),
            "bios": 0 in platforms,
            "efi": 0xEF in platforms,
            "udf": bool(iso.has_udf()),
            "joliet": bool(iso.has_joliet()),
            "rock_ridge": bool(iso.has_rock_ridge()),
            "isohybrid": iso.isohybrid_mbr is not None,
            "mbr": _has_mbr(src),
            "os": os_name,
            "info": info,
            "files": [_name(iso, ns, r) for r in _children(iso, ns, "/")],
        }
    finally:
        iso.close()


def sha256_of(path: str, progress=None) -> str:
    total = os.path.getsize(path)
    h, done = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            done += len(chunk)
            if progress is not None:
                progress(done, total)
    return h.hexdigest()

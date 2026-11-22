#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Stage one verified Windows Backup archive on dedicated recovery media."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


BACKUP_DIR = "WindowsImageBackup"
INVALID_COMPONENT = re.compile(r'[<>:"\\|?*\x00-\x1f]|[. ]$')
RESERVED_COMPONENT = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)",
    re.IGNORECASE,
)


def backup_members(archive):
    seen = {}
    members = []
    for member in archive:
        if len(members) >= 20000:
            raise ValueError("Windows Backup archive contains too many entries")
        parts = member.name.split("/")
        if (
            parts[0] != BACKUP_DIR
            or any(
                part in ("", ".", "..")
                or INVALID_COMPONENT.search(part)
                or RESERVED_COMPONENT.match(part)
                for part in parts
            )
            or not (member.isdir() or member.isfile())
            or member.issparse()
            or member.size < 0
        ):
            raise ValueError(f"Unsafe Windows Backup archive entry: {member.name!r}")

        key = tuple(part.casefold() for part in parts)
        if key in seen:
            raise ValueError(f"Duplicate Windows Backup archive entry: {member.name!r}")
        if len(parts) == 1:
            if not member.isdir():
                raise ValueError("Windows Backup archive root must be a directory")
        elif seen.get(key[:-1]) != parts[:-1]:
            raise ValueError(
                f"Missing or inconsistent Windows Backup parent: {member.name!r}"
            )
        seen[key] = parts if member.isdir() else None
        members.append((parts, member))

    if not any(member.isfile() for _, member in members):
        raise ValueError("Windows Backup archive contains no files")
    return members


def ntfs_volume_root(staging_root):
    if not os.path.ismount(staging_root):
        return False
    if os.name == "nt":
        import ctypes

        if (
            staging_root.drive.casefold()
            == os.environ.get("SystemDrive", "").casefold()
        ):
            return False
        filesystem = ctypes.create_unicode_buffer(32)
        result = ctypes.windll.kernel32.GetVolumeInformationW(
            str(staging_root), None, 0, None, None, None, filesystem, len(filesystem)
        )
        return bool(result) and filesystem.value == "NTFS"
    if sys.platform.startswith("linux"):
        result = subprocess.run(
            [
                "findmnt",
                "--noheadings",
                "--output",
                "FSTYPE",
                "--mountpoint",
                str(staging_root),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() in ("ntfs", "ntfs3")
    return False


def stage(archive_path, expected_hash, staging_root):
    staging_root = staging_root.resolve(strict=True)
    if not ntfs_volume_root(staging_root):
        raise ValueError("Staging path must be the root of the dedicated NTFS volume")
    backup_root = staging_root / BACKUP_DIR
    with archive_path.open("rb") as source:
        first_stat = os.fstat(source.fileno())
        if hashlib.file_digest(source, "sha256").hexdigest() != expected_hash.lower():
            raise ValueError("Archive SHA-256 differs from the verified image")
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:") as archive:
            members = backup_members(archive)
            required = sum(member.size for _, member in members)
            if required > shutil.disk_usage(staging_root).free:
                raise ValueError(
                    "The dedicated staging volume has insufficient free space"
                )
            backup_root.mkdir(mode=0o700)
            try:
                for parts, member in members:
                    if len(parts) == 1:
                        continue
                    dest = staging_root.joinpath(*parts)
                    if member.isdir():
                        dest.mkdir(mode=0o700)
                    else:
                        with (
                            archive.extractfile(member) as item,
                            dest.open("xb") as output,
                        ):
                            shutil.copyfileobj(item, output)
                            output.flush()
                            os.fsync(output.fileno())
                last_stat = os.fstat(source.fileno())
                if (first_stat.st_size, first_stat.st_mtime_ns) != (
                    last_stat.st_size,
                    last_stat.st_mtime_ns,
                ):
                    raise ValueError("Archive changed during staging")
            except BaseException:
                shutil.rmtree(backup_root)
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="Verified uncompressed SHA-256")
    parser.add_argument(
        "--staging-root", type=Path, required=True, help="Dedicated NTFS volume root"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", args.sha256):
        parser.error(
            "provide the verified uncompressed SHA-256 as 64 hexadecimal characters"
        )
    try:
        stage(args.archive, args.sha256, args.staging_root)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"Windows recovery staging failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Staged {args.staging_root / BACKUP_DIR} from the verified archive. Safely dismount the staging volume before WinRE."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

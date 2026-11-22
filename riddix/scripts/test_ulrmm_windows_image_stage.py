# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ulrmm_windows_image_stage import BACKUP_DIR, stage


class WindowsImageStageTest(unittest.TestCase):
    def stage_fixture(self, entries, error=None, corrupt_hash=False):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            media = root / "media"
            media.mkdir()
            path = root / "image.tar"
            with tarfile.open(path, "w") as archive:
                directory = tarfile.TarInfo(BACKUP_DIR)
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                for name, kind in entries:
                    member = tarfile.TarInfo(f"{BACKUP_DIR}/{name}")
                    member.type = kind
                    if member.isfile():
                        member.size = 7
                        archive.addfile(member, io.BytesIO(b"catalog"))
                    else:
                        member.linkname = "../outside"
                        archive.addfile(member)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch("ulrmm_windows_image_stage.ntfs_volume_root", return_value=True):
                if error is None:
                    stage(path, sha, media)
                    self.assertEqual(
                        (media / BACKUP_DIR / "catalog").read_bytes(), b"catalog"
                    )
                    with self.assertRaises(FileExistsError):
                        stage(path, sha, media)
                    self.assertEqual(
                        (media / BACKUP_DIR / "catalog").read_bytes(), b"catalog"
                    )
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        stage(path, "0" * 64 if corrupt_hash else sha, media)
                    self.assertEqual(list(media.iterdir()), [])

    def test_uses_verified_archive_without_overwriting(self):
        valid = [("catalog", tarfile.REGTYPE)]
        self.stage_fixture(valid)
        self.stage_fixture(valid, "SHA-256", corrupt_hash=True)

    def test_rejects_unsafe_windows_names_and_links(self):
        for name, kind in [
            ("../escape", tarfile.REGTYPE),
            ("catalog:alternate-stream", tarfile.REGTYPE),
            ("dir\\escape", tarfile.REGTYPE),
            ("NUL.txt", tarfile.REGTYPE),
            ("catalog.", tarfile.REGTYPE),
            ("link", tarfile.SYMTYPE),
            ("hardlink", tarfile.LNKTYPE),
        ]:
            with self.subTest(name=name):
                self.stage_fixture([(name, kind)], "Unsafe")

    def test_rejects_case_collision(self):
        self.stage_fixture(
            [("catalog", tarfile.REGTYPE), ("CATALOG", tarfile.REGTYPE)], "Duplicate"
        )


if __name__ == "__main__":
    unittest.main()

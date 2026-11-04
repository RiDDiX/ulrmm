# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The ISO image parts of backup.sh and restore.sh, run on their own."""

import os
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHA = "a" * 64


def function(path: Path, name: str) -> str:
    return re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", path.read_text(), re.S | re.M
    ).group(0)


class TestBackupIso(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.iso, self.out = root / "iso", root / "iso.tar"
        for d in ("jobs", ".uploads"):
            (self.iso / d).mkdir(parents=True)
        (self.iso / "Win 11.iso").write_bytes(b"x" * 5)
        (self.iso / "ubuntu.iso").write_bytes(b"x" * 3)
        (self.iso / "debian.iso.part").write_bytes(b"partial")
        (self.iso / "jobs" / "job1.iso").write_bytes(b"building")
        (self.iso / ".uploads" / "7.part").write_bytes(b"partial")

    def bash(self, script, *args, **env):
        r = subprocess.run(
            ["bash", "-c", script, "bash", *args],
            env=dict(os.environ, **env),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def backup(self, with_large):
        backup = REPO / "backup.sh"
        script = (
            function(backup, "pack_isos")
            + function(backup, "iso_lines")
            # stands in for the database: sha256 and file name of the images
            + f'psql() {{ printf "%s Win 11.iso\\n" "{SHA}"; }}\n'
            + 'isos=()\npack_isos "$1" >/dev/null || exit 9\niso_lines\n'
        )
        out = self.bash(script, str(self.out), ISO_DIR=str(self.iso), with_large=with_large)
        return sorted(out.splitlines())

    def test_backup_lists_every_image_and_packs_them_only_when_asked(self):
        lines = ["ISO_IMAGE=- 3 ubuntu.iso", f"ISO_IMAGE={SHA} 5 Win 11.iso"]
        self.assertEqual(self.backup("false"), lines)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.backup("true"), lines)
        with tarfile.open(self.out) as tar:
            self.assertEqual(sorted(tar.getnames()), ["./Win 11.iso", "./ubuntu.iso"])

    def test_restore_lists_the_images_it_did_not_get(self):
        manifest = self.iso / "MANIFEST"
        manifest.write_text(
            "FORMAT=1\n"
            f"ISO_IMAGE={SHA} 5 Win 11.iso\n"
            "ISO_IMAGE=- 7 gone image.iso\n"
            f"LARGE_PACKAGE={SHA} 1 not an image\n"
        )
        restore = REPO / "restore.sh"
        out = self.bash(
            function(restore, "missing_isos") + 'missing_isos "$@"',
            str(manifest),
            str(self.iso),
        )
        self.assertEqual(out, "gone image.iso (7 bytes, sha256 -)\n")


if __name__ == "__main__":
    unittest.main()

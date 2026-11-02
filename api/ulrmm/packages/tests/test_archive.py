# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from collections import namedtuple
from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from model_bakery import baker

from ulrmm.constants import AgentPlat
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from ..models import PackageKind, SoftwarePackage
from ..utils import (
    CHUNK_SIZE,
    SCRIPTS,
    UPLOAD_TTL,
    remove_stale_uploads,
    upload_paths,
)
from .test_api import PackagesDirMixin, make_package

base_url = "/packages"
ZIP, SEVEN, GZIP = b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b\x08\x00"
Usage = namedtuple("Usage", "total used free")


@override_settings(CACHES=LOCMEM_CACHE)
class TestArchiveUpload(PackagesDirMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.use_packages_dir()
        self.login_with_stepup(self.john)

    def test_kinds(self):
        for filename, head, fields, plat in (
            ("tools.7z", SEVEN, {"plat": "windows", "command": "setup/x.exe"}, "w"),
            ("tools.tar.gz", GZIP, {"plat": "linux", "command": "install.sh"}, "l"),
            (
                "tools.tgz",
                GZIP,
                {"plat": "darwin", "command": "bash", "default_args": "go.sh -q"},
                "d",
            ),
            (
                "office.zip",
                ZIP,
                {
                    "kind": "archive",
                    "plat": "windows",
                    "command": "msiexec.exe",
                    "default_args": '/i "office.msi" /qn',
                },
                "w",
            ),
        ):
            with self.subTest(filename=filename):
                data = head + filename.encode()
                r = self.upload(filename, data, **fields)
                self.assertEqual(r.status_code, 200, r.data)
                package = SoftwarePackage.objects.get(pk=r.data["id"])
                self.assertEqual(package.kind, PackageKind.ARCHIVE)
                self.assertTrue(package.plat.startswith(plat))
                self.assertEqual(package.command, fields["command"])
                self.assertEqual(package.success_codes, [0])
                self.assertEqual(package.reboot_codes, [3010, 1641])

        # without the kind a zip stays a driver package
        r = self.upload("drivers.zip", ZIP + b"inf")
        self.assertEqual((r.status_code, r.data["kind"]), (200, "driver"))

    def test_refusals(self):
        win = {"plat": "windows", "command": "setup.exe"}
        for filename, head, fields, error in (
            ("tools.7z", SEVEN, {"command": "setup.exe"}, "platform"),
            ("tools.7z", SEVEN, {**win, "plat": "freebsd"}, "platform"),
            ("tools.7z", ZIP, win, "not a valid archive"),
            ("tools.tgz", SEVEN, win, "not a valid archive"),
            ("tools.7z", SEVEN, {"plat": "windows"}, "command"),
            ("tools.7z", SEVEN, {**win, "command": "../setup.exe"}, "command"),
            ("tools.7z", SEVEN, {**win, "command": "C:\\setup.exe"}, "command"),
            ("tools.7z", SEVEN, {**win, "command": "a/./setup.exe"}, "command"),
            ("tools.tgz", GZIP, {"plat": "linux", "command": "/bin/sh"}, "command"),
            ("tools.tgz", GZIP, {"plat": "linux", "command": "bin/"}, "command"),
            (
                "tools.tgz",
                GZIP,
                {"plat": "linux", "command": "sh", "default_args": "'open"},
                "open quote",
            ),
            ("tools.7z", SEVEN, {**win, "timeout": 14401}, "timeout"),
            ("setup.exe", b"MZ\x90", {"kind": "archive"}, "cannot be uploaded"),
            ("setup.exe", b"MZ\x90", {"command": "x.exe"}, "Only archives"),
        ):
            with self.subTest(filename=filename, fields=fields):
                fields = {"name": f"n-{filename}-{len(fields)}-{error}", **fields}
                r = self.upload(filename, head + os.urandom(8), **fields)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, str(r.data))
        self.assertEqual(SoftwarePackage.objects.count(), 0)

        # four hours for an archive, two for the rest
        r = self.upload("tools.7z", SEVEN + b"a", **win, timeout=14400, name="long")
        self.assertEqual(r.status_code, 200, r.data)
        r = self.upload("setup.exe", b"MZ\x90b", timeout=7201, name="exe")
        self.assertEqual(r.status_code, 400)

    def test_list_marks_missing_files(self):
        present, gone = make_package(), make_package()
        os.makedirs(self.dir, exist_ok=True)
        open(present.file_path, "wb").close()
        r = self.client.get(f"{base_url}/")
        self.assertEqual(r.status_code, 200)
        flags = {row["id"]: row["file_missing"] for row in r.data}
        self.assertEqual(flags, {present.pk: False, gone.pk: True})


@override_settings(CACHES=LOCMEM_CACHE)
class TestChunkedUpload(PackagesDirMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.use_packages_dir()
        self.login_with_stepup(self.john)
        self.data = SEVEN + os.urandom(30)

    def start(self, filename="Big Setup.7z", size=None):
        size = len(self.data) if size is None else size
        return self.client.post(
            f"{base_url}/uploads/", {"filename": filename, "size": size}, format="json"
        )

    def chunk(self, uid, start, end, total=None, body=None):
        total = len(self.data) if total is None else total
        body = self.data[start : end + 1] if body is None else body
        return self.client.put(
            f"{base_url}/uploads/{uid}/",
            body,
            content_type="application/octet-stream",
            HTTP_CONTENT_RANGE=f"bytes {start}-{end}/{total}",
        )

    def finish(self, uid, **fields):
        body = {"name": "Big Setup", "kind": "archive", "plat": "windows"}
        body["command"] = "setup/setup.exe"
        body.update(fields)
        return self.client.post(
            f"{base_url}/uploads/{uid}/finish/", body, format="json"
        )

    def test_flow(self):
        r = self.start()
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["chunk_size"], CHUNK_SIZE)
        self.assertEqual(r.data["received"], 0)
        uid = r.data["id"]
        part, meta = upload_paths(uid)
        self.assertTrue(os.path.isfile(part) and os.path.isfile(meta))

        self.assertEqual(self.chunk(uid, 0, 9).data, {"received": 10})
        # out of order or repeated: 409 with the offset to go on from
        r = self.chunk(uid, 20, 35)
        self.assertEqual((r.status_code, r.data), (409, {"received": 10}))
        r = self.chunk(uid, 0, 9)
        self.assertEqual((r.status_code, r.data), (409, {"received": 10}))
        for bad in (
            {"total": 99},
            {"start": 10, "end": 9},
            {"body": b"x"},
        ):
            with self.subTest(bad=bad):
                start, end = bad.get("start", 10), bad.get("end", 19)
                r = self.chunk(uid, start, end, bad.get("total"), bad.get("body"))
                self.assertEqual(r.status_code, 400)
        r = self.client.put(f"{base_url}/uploads/{uid}/", b"x", content_type="a/b")
        self.assertEqual(r.status_code, 400)

        # resume: the status says where to go on
        r = self.client.get(f"{base_url}/uploads/{uid}/")
        self.assertEqual((r.data["received"], r.data["size"]), (10, len(self.data)))
        r = self.finish(uid)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not complete", r.data)
        self.assertEqual(self.chunk(uid, 10, len(self.data) - 1).status_code, 200)

        r = self.finish(
            uid,
            success_codes=[0, 1],
            reboot_codes=[3010],
            detection={"type": "inventory", "name": "Big Setup", "version_min": "2"},
            vendor="Vendor",
            version="2.0",
            timeout=14400,
        )
        self.assertEqual(r.status_code, 200, r.data)
        package = SoftwarePackage.objects.get(pk=r.data["id"])
        sha = hashlib.sha256(self.data).hexdigest()
        self.assertEqual((package.sha256, package.size), (sha, len(self.data)))
        self.assertEqual(package.filename, "Big Setup.7z")
        self.assertEqual(package.kind, PackageKind.ARCHIVE)
        self.assertEqual(
            (package.success_codes, package.reboot_codes), ([0, 1], [3010])
        )
        self.assertEqual(package.detection["version_min"], "2")
        self.assertEqual(self.files(), [".uploads", sha])
        self.assertEqual(os.listdir(os.path.join(self.dir, ".uploads")), [])

    def test_finish_checks(self):
        uid = self.start().data["id"]
        self.chunk(uid, 0, len(self.data) - 1)
        for fields, error in (
            ({"success_codes": [0], "reboot_codes": [0]}, "reboot_codes"),
            ({"success_codes": ["0"]}, "success_codes"),
            ({"detection": {"type": "registry", "key": "HKCU\\x"}}, "detection"),
            ({"command": ""}, "command"),
        ):
            with self.subTest(fields=fields):
                r = self.finish(uid, **fields)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, r.data)
        # nothing was taken, the upload is still there
        self.assertEqual(self.client.get(f"{base_url}/uploads/{uid}/").status_code, 200)

        cache.clear()
        r = self.finish(uid)
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))

        self.login_with_stepup(self.john)
        baker.make(
            "packages.SoftwarePackage",
            name="twin",
            kind="archive",
            plat="windows",
            sha256=hashlib.sha256(self.data).hexdigest(),
            size=len(self.data),
        )
        r = self.finish(uid)
        self.assertEqual(r.status_code, 400)
        self.assertIn("uploaded already, as twin", r.data)

    def test_start_checks(self):
        cache.clear()
        self.assertEqual(self.start().status_code, 403)
        self.login_with_stepup(self.john)
        for filename, size, error in (
            ("x.ps1", 10, "can be uploaded"),
            ("x.7z", "10", "size"),
            ("x.7z", 0, "size"),
            ("x.7z", True, "size"),
        ):
            with self.subTest(filename=filename, size=size):
                r = self.start(filename, size)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, r.data)
        with patch("packages.views.shutil.disk_usage") as usage:
            usage.return_value = Usage(10 << 30, 0, 2 << 30)
            r = self.start(size=(1 << 30) + 1)
            self.assertEqual(r.status_code, 400)
            self.assertIn("Not enough free space", r.data)
            self.assertEqual(self.start(size=1 << 30).status_code, 201)

    def test_owner_and_abort(self):
        uid = self.start().data["id"]
        other = baker.make("accounts.User", is_superuser=True)
        self.login_with_stepup(other)
        for method in ("get", "delete"):
            self.assertEqual(
                getattr(self.client, method)(f"{base_url}/uploads/{uid}/").status_code,
                404,
            )
        self.assertEqual(self.chunk(uid, 0, 9).status_code, 404)
        self.assertEqual(self.finish(uid).status_code, 404)
        r = self.client.get(f"{base_url}/uploads/{'0' * 31}x/")
        self.assertEqual(r.status_code, 404)

        self.login_with_stepup(self.john)
        r = self.client.delete(f"{base_url}/uploads/{uid}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(os.listdir(os.path.join(self.dir, ".uploads")), [])

    def test_permissions(self):
        user = self.create_user_with_roles(["can_install_packages"])
        self.login_with_stepup(user)
        self.assertEqual(self.start().status_code, 403)

    def test_stale_uploads(self):
        old, fresh = self.start().data["id"], self.start().data["id"]
        past = time.time() - UPLOAD_TTL - 60
        for path in upload_paths(old):
            os.utime(path, (past, past))
        self.assertEqual(remove_stale_uploads(), 2)
        left = sorted(os.listdir(os.path.join(self.dir, ".uploads")))
        self.assertEqual(left, sorted(os.path.basename(p) for p in upload_paths(fresh)))


class TestScripts(SimpleTestCase):
    """The install scripts take a file the agent downloaded (PKG_FILE)."""

    def run_linux(self, **env):
        base = {"PATH": "/usr/bin:/bin", "PKG_KIND": "deb", "PKG_MODE": "system"}
        p = subprocess.run(
            ["bash", str(SCRIPTS[AgentPlat.LINUX])],
            env={**base, **env},
            capture_output=True,
            text=True,
            timeout=60,
        )
        return p.stdout.strip().splitlines()[-1]

    def test_syntax(self):
        for script in (SCRIPTS[AgentPlat.LINUX], SCRIPTS[AgentPlat.DARWIN]):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)

    @unittest.skipUnless(os.geteuid() == 0 and shutil.which("sha256sum"), "root")
    def test_linux_pkg_file(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "tool.deb")
        with open(path, "wb") as fh:
            fh.write(b"!<arch>\ndebian-binary")
        wrong = hashlib.sha256(b"other").hexdigest()

        # no link at all: the file is checked instead of a download
        line = self.run_linux(PKG_FILE=path, PKG_SHA256=wrong)
        self.assertIn('"result":"refused"', line)
        self.assertIn("sha256 mismatch", line)

        link = os.path.join(tmp, "link.deb")
        os.symlink(path, link)
        for bad in (link, "tool.deb", os.path.join(tmp, "missing.deb")):
            with self.subTest(bad=bad):
                line = self.run_linux(PKG_FILE=bad, PKG_SHA256=wrong)
                self.assertIn("not a regular file owned by root", line)

        line = self.run_linux(PKG_URL="http://x/y/", PKG_SHA256=wrong)
        self.assertIn("not https", line)

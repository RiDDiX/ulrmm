# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from unittest.mock import patch

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey
from accounts.serializers import RoleSerializer
from accounts.utils import grant_console_stepup
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from ..models import InstallState, PackageInstall, SoftwarePackage
from ..serializers import SoftwarePackageSerializer
from ..utils import batch_key, clean_filename, download_key

base_url = "/packages"

HEADS = {
    "setup.exe": b"MZ\x90\x00",
    "setup.msi": bytes.fromhex("d0cf11e0a1b11ae1"),
    "app.msix": b"PK\x03\x04",
    "app.msixbundle": b"PK\x03\x04",
    "app.appx": b"PK\x03\x04",
    "app.appxbundle": b"PK\x03\x04",
    "tool.pkg": b"xar!\x00\x1c",
    "tool.deb": b"!<arch>\ndebian-binary   1234",
    "tool.rpm": b"\xed\xab\xee\xdb\x03\x00",
    "drivers.zip": b"PK\x03\x04",
    "drivers.cab": b"MSCF\x00\x00",
}
KINDS = {
    "exe": ("exe", AgentPlat.WINDOWS),
    "msi": ("msi", AgentPlat.WINDOWS),
    "msix": ("msix", AgentPlat.WINDOWS),
    "msixbundle": ("msix", AgentPlat.WINDOWS),
    "appx": ("appx", AgentPlat.WINDOWS),
    "appxbundle": ("appx", AgentPlat.WINDOWS),
    "pkg": ("pkg", AgentPlat.DARWIN),
    "deb": ("deb", AgentPlat.LINUX),
    "rpm": ("rpm", AgentPlat.LINUX),
    "zip": ("driver", AgentPlat.WINDOWS),
    "cab": ("driver", AgentPlat.WINDOWS),
}


def content(filename: str, body: bytes = b"payload") -> bytes:
    return HEADS[filename] + body


def make_package(kind="exe", plat=AgentPlat.WINDOWS, **kwargs):
    body = uuid.uuid4().bytes
    kwargs.setdefault("name", f"pkg {body.hex()[:8]}")
    return baker.make(
        "packages.SoftwarePackage",
        kind=kind,
        plat=plat,
        filename=f"setup.{kind}",
        sha256=hashlib.sha256(body).hexdigest(),
        size=len(body),
        **kwargs,
    )


class PackagesDirMixin:
    def use_packages_dir(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        # created on the first upload
        self.dir = os.path.join(root, "packages")
        self.enterContext(override_settings(PACKAGES_DIR=self.dir))

    def files(self) -> list[str]:
        return sorted(os.listdir(self.dir)) if os.path.isdir(self.dir) else []

    def login_with_stepup(self, user):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        grant_console_stepup(user)

    def upload(self, filename="setup.exe", data=None, **fields):
        if data is None:
            data = content(filename)
        fields.setdefault("name", filename)
        fields["file"] = SimpleUploadedFile(filename, data)
        return self.client.post(f"{base_url}/", fields, format="multipart")


@override_settings(CACHES=LOCMEM_CACHE)
class TestUpload(PackagesDirMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.use_packages_dir()
        self.login_with_stepup(self.john)

    def test_each_kind(self):
        for filename in HEADS:
            with self.subTest(filename=filename):
                data = content(filename, filename.encode())
                r = self.upload(filename, data, default_args="", timeout=600)
                self.assertEqual(r.status_code, 200, r.data)

                sha = hashlib.sha256(data).hexdigest()
                package = SoftwarePackage.objects.get(sha256=sha)
                kind, plat = KINDS[filename.rsplit(".", 1)[1]]
                self.assertEqual((package.kind, package.plat), (kind, plat))
                self.assertEqual(package.filename, filename)
                self.assertEqual(package.size, len(data))
                self.assertEqual(package.timeout, 600)
                self.assertFalse(package.allow_unsigned)
                self.assertEqual(package.created_by, "john")
                self.assertEqual(r.data["sha256"], sha)

                path = os.path.join(self.dir, sha)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), data)
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)

        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o755)
        # nothing half written left behind
        self.assertEqual(len(self.files()), len(HEADS))
        self.assertFalse([f for f in self.files() if f.startswith(".")])
        self.assertTrue(
            AuditLog.objects.filter(
                object_type=AuditObjType.SOFTWARE_PACKAGE,
                action=AuditActionType.ADD,
            ).exists()
        )

    def test_rejected(self):
        self.assertEqual(self.upload(name="first").status_code, 200)
        other = content("setup.exe", b"other")
        cases = (
            ("script.bat", b"MZ", {}, "can be uploaded"),
            ("setup.exe.txt", b"MZ", {}, "can be uploaded"),
            ("setup", b"MZ", {}, "can be uploaded"),
            ("setup.msi", b"MZ\x90\x00", {}, "not a valid msi"),
            ("setup.exe", b"PK\x03\x04", {}, "not a valid exe"),
            ("tool.deb", b"!<arch>\ncontrol.tar.gz", {}, "not a valid deb"),
            ("tool.pkg", b"xa", {}, "not a valid pkg"),
            ("drivers.zip", b"MZ\x90\x00", {}, "not a valid driver"),
            ("drivers.cab", b"ISc(", {}, "not a valid driver"),
            (
                "drivers.zip",
                content("drivers.zip"),
                {"default_args": "/q"},
                "arguments",
            ),
            ("setup.exe", b"", {}, "is empty"),
            ("setup.exe", content("setup.exe"), {"name": "again"}, "as first"),
            ("setup.exe", other, {"name": "first"}, "name"),
            ("tool.deb", content("tool.deb"), {"default_args": "-y"}, "arguments"),
            ("app.msix", content("app.msix"), {"default_args": "/q"}, "arguments"),
            ("setup.exe", other, {"timeout": 30}, "timeout"),
            ("setup.exe", other, {"timeout": 7201}, "timeout"),
            ("setup.exe", other, {"name": "a\nb"}, "control characters"),
            ("setup.exe", other, {"default_args": "/S\t/Q"}, "control"),
        )
        for filename, data, fields, error in cases:
            with self.subTest(filename=filename, fields=fields):
                fields.setdefault("name", f"n-{uuid.uuid4().hex}")
                r = self.upload(filename, data, **fields)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, str(r.data))

        r = self.client.post(f"{base_url}/", {"name": "x"}, format="multipart")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Choose a file to upload.")
        r = self.client.post(f"{base_url}/", {"name": "x"}, format="json")
        self.assertEqual(r.status_code, 400)

        self.assertEqual(SoftwarePackage.objects.count(), 1)
        self.assertEqual(len(self.files()), 1)

    def test_concurrent_duplicate(self):
        # another upload commits between our checks and our insert
        real = SoftwarePackageSerializer.is_valid
        data = content("setup.exe")
        sha = hashlib.sha256(data).hexdigest()
        for other, error in (
            ({"name": "Other", "sha256": sha}, "uploaded already, as Other."),
            ({"name": "Tool", "sha256": "0" * 64}, "named Tool exists already."),
        ):

            def is_valid(serializer, other=other, **kwargs):
                ok = real(serializer, **kwargs)
                baker.make("packages.SoftwarePackage", **other)
                return ok

            with self.subTest(other=other):
                SoftwarePackage.objects.all().delete()
                with patch.object(SoftwarePackageSerializer, "is_valid", is_valid):
                    r = self.upload("setup.exe", data, name="Tool")
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, r.data)
                self.assertEqual(SoftwarePackage.objects.get().name, other["name"])
                self.assertEqual(self.files(), [])

    def test_one_file_only(self):
        first, second = content("setup.exe", b"1"), content("setup.exe", b"2")
        r = self.client.post(
            f"{base_url}/",
            {
                "name": "x",
                "file": [
                    SimpleUploadedFile("a.exe", first),
                    SimpleUploadedFile("b.exe", second),
                ],
                "other": SimpleUploadedFile("c.exe", second),
            },
            format="multipart",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["filename"], "a.exe")
        self.assertEqual(self.files(), [hashlib.sha256(first).hexdigest()])

    def test_filename(self):
        for raw, expected in (
            ("setup.exe", "setup.exe"),
            ("Setup.EXE", "Setup.exe"),
            ("../../etc/x.msi", "x.msi"),
            ("C:\\Users\\me\\x.msi", "x.msi"),
            ("--help.deb", "help.deb"),
            ("..hidden.rpm", "hidden.rpm"),
            (".exe", "package.exe"),
            ("we!rd näme$(id);`x`.pkg", "we_rd n_me_(id)_x_.pkg"),
            ("App 1.0 (x64)+.msixbundle", "App 1.0 (x64)+.msixbundle"),
            ("a" * 300 + ".appxbundle", "a" * 109 + ".appxbundle"),
        ):
            with self.subTest(raw=raw):
                filename, _ = clean_filename(raw)
                self.assertEqual(filename, expected)
                self.assertLessEqual(len(filename), 120)
        # .7z is an archive now, .rar never was
        for raw in ("x.exe.", "x.ps1", "x.msi.exe.rar", "x"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                clean_filename(raw)

        r = self.upload("../-x y;z.exe", content("setup.exe"), name="odd")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["filename"], "x y_z.exe")

    def test_needs_stepup_and_a_dashboard_token(self):
        self.client.force_authenticate(user=self.john)
        r = self.upload()
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        # step-up without a dashboard token
        grant_console_stepup(self.john)
        APIKey.objects.create(name="key", key="johnskey", user=self.john)
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_X_API_KEY="johnskey")
        r = self.upload()
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.client.credentials()

        # dashboard token without step-up
        cache.clear()
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        self.assertEqual(self.upload().status_code, 403)

        self.assertFalse(SoftwarePackage.objects.exists())
        self.assertEqual(self.files(), [])

    def test_permissions(self):
        package = make_package()
        user = self.create_user_with_roles([])
        self.login_with_stepup(user)
        self.check_not_authorized("get", f"{base_url}/")
        self.assertEqual(self.upload().status_code, 403)
        self.check_not_authorized("put", f"{base_url}/{package.pk}/", {"name": "x"})
        self.check_not_authorized("delete", f"{base_url}/{package.pk}/")

        user.role.can_install_packages = True
        user.role.save()
        r = self.client.get(f"{base_url}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([p["id"] for p in r.data], [package.pk])
        self.assertEqual(self.upload().status_code, 403)
        self.check_not_authorized("put", f"{base_url}/{package.pk}/", {"name": "x"})
        self.check_not_authorized("delete", f"{base_url}/{package.pk}/")

        user.role.can_install_packages = False
        user.role.can_manage_packages = True
        user.role.save()
        self.assertEqual(self.client.get(f"{base_url}/").status_code, 200)
        self.assertEqual(self.upload().status_code, 200)

        role = RoleSerializer(user.role).data
        self.assertIn("can_manage_packages", role)
        self.assertIn("can_install_packages", role)


@override_settings(CACHES=LOCMEM_CACHE)
class TestEditDelete(PackagesDirMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.use_packages_dir()
        self.login_with_stepup(self.john)
        self.assertEqual(self.upload("setup.msi", name="Tool").status_code, 200)
        self.package = SoftwarePackage.objects.get()
        self.agent = baker.make_recipe("agents.online_agent")

    def test_edit(self):
        url = f"{base_url}/{self.package.pk}/"
        data = {
            "name": "Tool 2",
            "default_args": "ALLUSERS=1 /l*v x.log",
            "timeout": 3600,
            "allow_unsigned": True,
            "sha256": "0" * 64,
            "kind": "exe",
            "filename": "evil.exe",
        }
        cache.clear()
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        grant_console_stepup(self.john)
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        before = self.package.sha256
        self.package.refresh_from_db()
        self.assertEqual(self.package.name, "Tool 2")
        self.assertEqual(self.package.default_args, "ALLUSERS=1 /l*v x.log")
        self.assertEqual(self.package.timeout, 3600)
        self.assertTrue(self.package.allow_unsigned)
        # set by the upload only
        self.assertEqual(self.package.sha256, before)
        self.assertEqual(self.package.kind, "msi")
        self.assertEqual(self.package.filename, "setup.msi")
        self.assertTrue(
            AuditLog.objects.filter(
                object_type=AuditObjType.SOFTWARE_PACKAGE,
                action=AuditActionType.MODIFY,
            ).exists()
        )

        for bad in ({"timeout": 59}, {"default_args": "a\tb"}, {"name": ""}):
            with self.subTest(bad=bad):
                self.assertEqual(
                    self.client.put(url, bad, format="json").status_code, 400
                )

        msix = make_package(kind="msix")
        r = self.client.put(
            f"{base_url}/{msix.pk}/", {"default_args": "/q"}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.put(
            f"{base_url}/{msix.pk}/", {"default_args": ""}, format="json"
        )
        self.assertEqual(r.status_code, 200)

    def test_delete(self):
        path = self.package.file_path
        install = baker.make(
            "packages.PackageInstall",
            package=self.package,
            package_name=self.package.name,
            agent=self.agent,
            batch=uuid.uuid4(),
            run_as="system",
            state=InstallState.RUNNING,
        )
        url = f"{base_url}/{self.package.pk}/"
        for state in (InstallState.RUNNING, InstallState.QUEUED):
            PackageInstall.objects.filter(pk=install.pk).update(state=state)
            r = self.client.delete(url)
            self.assertEqual(r.status_code, 400)
            self.assertTrue(os.path.exists(path))

        PackageInstall.objects.filter(pk=install.pk).update(state=InstallState.FAILED)
        # delete needs no step-up
        cache.clear()
        r = self.client.delete(url)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(SoftwarePackage.objects.exists())
        self.assertFalse(os.path.exists(path))
        install.refresh_from_db()
        self.assertIsNone(install.package)
        self.assertEqual(install.package_name, "Tool")

    def test_stale_installs_do_not_block(self):
        install = baker.make(
            "packages.PackageInstall",
            package=self.package,
            package_name=self.package.name,
            agent=self.agent,
            batch=uuid.uuid4(),
            run_as="system",
            state=InstallState.RUNNING,
        )
        PackageInstall.objects.filter(pk=install.pk).update(
            created=djangotime.now() - dt.timedelta(hours=3)
        )
        # its batch task still runs
        cache.set(batch_key(install.batch), 1, 60)
        r = self.client.delete(f"{base_url}/{self.package.pk}/")
        self.assertEqual(r.status_code, 400)

        cache.delete(batch_key(install.batch))
        r = self.client.delete(f"{base_url}/{self.package.pk}/")
        self.assertEqual(r.status_code, 200)
        install.refresh_from_db()
        self.assertEqual(install.state, InstallState.FAILED)
        self.assertIsNotNone(install.finished)


@override_settings(CACHES=LOCMEM_CACHE)
@patch("packages.services.install_batch_task.delay")
class TestInstall(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.other_site = baker.make("clients.Site")
        self.exe = make_package(name="Tool", default_args="/S")
        self.deb = make_package(kind="deb", plat=AgentPlat.LINUX)
        self.win = self.agent(logged_in_username="alice")
        self.nobody = self.agent(logged_in_username="None")
        self.offline = self.agent(online=False)
        self.linux = self.agent(plat=AgentPlat.LINUX)
        self.elsewhere = self.agent(site=self.other_site, logged_in_username="bob")

    def agent(self, online=True, **kwargs):
        kwargs.setdefault("site", self.site)
        kwargs.setdefault("plat", AgentPlat.WINDOWS)
        ago = 0 if online else 60
        return baker.make_recipe(
            "agents.agent",
            last_seen=djangotime.now() - dt.timedelta(minutes=ago),
            **kwargs,
        )

    def install(self, package, agent, run_as="system"):
        return self.client.post(
            f"{base_url}/{package.pk}/install/",
            {"agent_id": agent.agent_id, "run_as": run_as},
            format="json",
        )

    def bulk(self, pkg, run_as="system", **data):
        data = {
            "mode": "package",
            "target": "all",
            "monType": "all",
            "osType": "all",
            "package": pkg.pk,
            "run_as": run_as,
            **data,
        }
        return self.client.post("/agents/actions/bulk/", data, format="json")

    def test_single(self, delay):
        r = self.install(self.exe, self.win, "user")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.data), {"batch", "queued", "skipped", "refused"})
        self.assertEqual(
            (r.data["queued"], r.data["skipped"], r.data["refused"]), (1, 0, 0)
        )

        row = PackageInstall.objects.get(batch=r.data["batch"])
        self.assertEqual(row.state, InstallState.QUEUED)
        self.assertEqual(row.run_as, "user")
        self.assertEqual(row.package_name, "Tool")
        self.assertEqual(row.requested_by, "john")
        self.assertIsNone(row.finished)
        delay.assert_called_once_with(r.data["batch"])
        # the batch task keeps it alive from here
        self.assertEqual(cache.get(batch_key(r.data["batch"])), 1)

        audit = AuditLog.objects.get(action=AuditActionType.EXEC_COMMAND)
        self.assertEqual(audit.agent_id, self.win.agent_id)
        self.assertEqual(audit.object_type, AuditObjType.AGENT)
        self.assertIn("Tool", audit.message)
        self.assertIn("as user", audit.message)
        self.assertIn(r.data["batch"], audit.message)
        self.assertEqual(
            audit.after_value,
            {
                "batch": r.data["batch"],
                "package": "Tool",
                "sha256": self.exe.sha256,
                "run_as": "user",
                "queued": [self.win.hostname],
                "skipped": [],
                "refused": [],
            },
        )

    def test_single_not_started(self, delay):
        r = self.install(self.exe, self.nobody, "user")
        self.assertEqual((r.data["queued"], r.data["refused"]), (0, 1))
        row = PackageInstall.objects.get(batch=r.data["batch"])
        self.assertEqual(
            (row.state, row.detail), (InstallState.REFUSED, "nobody is logged in")
        )
        self.assertIsNotNone(row.finished)

        # system needs nobody logged in
        r = self.install(self.exe, self.nobody)
        self.assertEqual(r.data["queued"], 1)

        r = self.install(self.exe, self.offline)
        self.assertEqual((r.data["queued"], r.data["skipped"]), (0, 1))
        row = PackageInstall.objects.get(batch=r.data["batch"])
        self.assertEqual((row.state, row.detail), (InstallState.SKIPPED, "offline"))
        # nothing to run, no task to wait for
        self.assertIsNone(cache.get(batch_key(r.data["batch"])))

        self.assertEqual(delay.call_count, 1)

    def test_single_rejected(self, delay):
        for package, agent, run_as, error in (
            (self.deb, self.linux, "user", "always install as root"),
            (self.exe, self.win, "admin", "Choose System"),
            (self.exe, self.win, None, "Choose System"),
            (self.exe, self.linux, "system", "Windows package"),
            (self.deb, self.win, "system", "Linux package"),
        ):
            with self.subTest(agent=agent.plat, run_as=run_as):
                r = self.install(package, agent, run_as)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, r.data)
        r = self.client.post(
            f"{base_url}/{self.exe.pk}/install/", {"run_as": "system"}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            f"{base_url}/{self.exe.pk}/install/",
            {"agent_id": "nope" * 10, "run_as": "system"},
            format="json",
        )
        self.assertEqual(r.status_code, 404)
        self.assertFalse(PackageInstall.objects.exists())
        delay.assert_not_called()

    def test_single_permissions(self, delay):
        user = self.create_user_with_roles(["can_manage_packages"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.install(self.exe, self.win).status_code, 403)

        user.role.can_install_packages = True
        user.role.save()
        user.role.can_view_sites.set([self.site])
        self.assertEqual(self.install(self.exe, self.elsewhere).status_code, 403)
        self.assertEqual(self.install(self.exe, self.win).status_code, 200)
        self.assertEqual(delay.call_count, 1)

    def test_bulk(self, delay):
        user = self.create_user_with_roles(["can_run_bulk"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.bulk(self.exe).status_code, 403)

        user.role.can_install_packages = True
        user.role.save()
        r = self.bulk(self.exe, "user")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {"batch": r.data["batch"], "queued": 1, "skipped": 1, "refused": 1},
        )
        rows = PackageInstall.objects.filter(batch=r.data["batch"])
        # windows agents of the user's sites only
        self.assertCountEqual(
            [row.agent_id for row in rows],
            [self.win.pk, self.nobody.pk, self.offline.pk],
        )
        delay.assert_called_once_with(r.data["batch"])
        audit = AuditLog.objects.get(action=AuditActionType.EXEC_COMMAND)
        self.assertEqual(audit.object_type, AuditObjType.BULK)
        self.assertIsNone(audit.agent_id)
        # the message can be cut short, this cannot
        after = audit.after_value
        self.assertEqual(
            {k: after[k] for k in ("batch", "package", "run_as", "target")},
            {
                "batch": r.data["batch"],
                "package": "Tool",
                "run_as": "user",
                "target": "all",
            },
        )
        self.assertEqual(
            (after["queued"], after["skipped"], after["refused"]),
            ([self.win.hostname], [self.offline.hostname], [self.nobody.hostname]),
        )

        r = self.bulk(self.deb, target="site", site=self.site.pk)
        self.assertEqual((r.data["queued"], r.data["skipped"]), (1, 0))
        self.assertEqual(
            PackageInstall.objects.get(batch=r.data["batch"]).agent, self.linux
        )

        r = self.bulk(
            self.exe, target="agents", agents=[self.linux.agent_id, self.win.agent_id]
        )
        self.assertEqual(r.data["queued"], 1)
        after = AuditLog.objects.filter(action=AuditActionType.EXEC_COMMAND).last()
        self.assertEqual(after.after_value["target"], "agents")
        self.assertEqual(after.after_value["queued"], [self.win.hostname])

        # the os filter and the package disagree
        r = self.bulk(self.exe, osType=AgentPlat.LINUX)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.bulk(self.deb, "user").status_code, 400)
        self.assertEqual(self.bulk(self.exe, package="x").status_code, 400)
        self.assertEqual(self.bulk(self.exe, package=99999).status_code, 404)

    def test_installs_list(self, delay):
        r = self.install(self.exe, self.win)
        batch = r.data["batch"]
        self.install(self.exe, self.elsewhere)
        self.install(self.deb, self.linux)

        r = self.client.get(f"{base_url}/installs/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 3)
        self.assertEqual(r.data[0]["agent_id"], self.linux.agent_id)
        self.assertEqual(r.data[0]["hostname"], self.linux.hostname)
        self.assertEqual(r.data[-1]["agent_id"], self.win.agent_id)
        self.assertNotIn("agent", r.data[0])

        r = self.client.get(f"{base_url}/installs/", {"batch": batch})
        self.assertEqual([i["agent_id"] for i in r.data], [self.win.agent_id])
        r = self.client.get(f"{base_url}/installs/", {"agent": self.linux.agent_id})
        self.assertEqual(len(r.data), 1)
        r = self.client.get(f"{base_url}/installs/", {"package": self.exe.pk})
        self.assertEqual(len(r.data), 2)
        for bad in ({"batch": "x"}, {"package": "1 OR 1=1"}):
            with self.subTest(bad=bad):
                r = self.client.get(f"{base_url}/installs/", bad)
                self.assertEqual(r.status_code, 400)

        user = self.create_user_with_roles(["can_manage_packages"])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("get", f"{base_url}/installs/")
        user.role.can_install_packages = True
        user.role.save()
        user.role.can_view_sites.set([self.other_site])
        r = self.client.get(f"{base_url}/installs/")
        self.assertEqual([i["agent_id"] for i in r.data], [self.elsewhere.agent_id])

    def test_batch_list_is_not_capped(self, delay):
        batch = uuid.uuid4()
        baker.make(
            "packages.PackageInstall",
            package=self.exe,
            package_name="Tool",
            agent=self.win,
            batch=batch,
            run_as="system",
            _quantity=3,
        )
        self.install(self.exe, self.win)
        with patch("packages.views.MAX_INSTALLS", 2):
            r = self.client.get(f"{base_url}/installs/", {"batch": str(batch)})
            self.assertEqual(len(r.data), 3)
            r = self.client.get(f"{base_url}/installs/")
            self.assertEqual(len(r.data), 2)


@override_settings(CACHES=LOCMEM_CACHE)
class TestDownload(PackagesDirMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.use_packages_dir()
        self.login_with_stepup(self.john)
        self.assertEqual(self.upload("tool.deb").status_code, 200)
        self.package = SoftwarePackage.objects.get()
        self.install = baker.make(
            "packages.PackageInstall",
            package=self.package,
            package_name=self.package.name,
            agent=baker.make_recipe("agents.online_agent"),
            batch=uuid.uuid4(),
            run_as="system",
            state=InstallState.RUNNING,
        )
        self.token = "t" * 43
        cache.set(download_key(self.token), self.install.pk, 60)
        self.client.logout()
        self.client.force_authenticate(user=None)

    def get(self, token):
        return self.client.get(f"{base_url}/download/{token}/")

    def test_running_install_gets_the_file(self):
        r = self.get(self.token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r["X-Accel-Redirect"], f"/private/packages/{self.package.sha256}"
        )
        self.assertEqual(r["Content-Type"], "application/octet-stream")
        self.assertEqual(r["Content-Disposition"], 'attachment; filename="tool.deb"')
        self.assertEqual(r.content, b"")

        with override_settings(DEBUG=True):
            r = self.get(self.token)
        self.assertEqual(b"".join(r.streaming_content), content("tool.deb"))

    def test_anything_else_is_a_bare_404(self):
        for token in ("x" * 43, self.token[:-1], self.token + "t", "t" * 42 + "!"):
            with self.subTest(token=token):
                r = self.get(token)
                self.assertEqual(r.status_code, 404)
                self.assertEqual(r.content, b"")

        for state in (InstallState.QUEUED, InstallState.SUCCEEDED, InstallState.FAILED):
            with self.subTest(state=state):
                PackageInstall.objects.filter(pk=self.install.pk).update(state=state)
                r = self.get(self.token)
                self.assertEqual(r.status_code, 404)
                self.assertEqual(r.content, b"")

        PackageInstall.objects.filter(pk=self.install.pk).update(
            state=InstallState.RUNNING, package=None
        )
        self.assertEqual(self.get(self.token).status_code, 404)

        cache.clear()
        PackageInstall.objects.filter(pk=self.install.pk).update(package=self.package)
        self.assertEqual(self.get(self.token).status_code, 404)

        # nothing about the requests in the audit log
        self.assertFalse(AuditLog.objects.filter(message__contains="download").exists())

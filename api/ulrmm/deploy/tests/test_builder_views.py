# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
import zipfile
from io import BytesIO
from types import SimpleNamespace
from unittest import mock

from django.test.utils import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from deploy import installers, matrix, signing, views, windows
from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

AGENT_STUB = "# agent install\nWrite-Output 'enroll'\n"


@override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
class TestBuilderViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_base_instance()
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site1,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": False},
        )
        self.patcher = mock.patch.object(
            windows, "_agent_install_ps1", return_value=AGENT_STUB
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        dist = mock.patch.object(signing, "dist_pubkey_ok", return_value=True)
        dist.start()
        self.addCleanup(dist.stop)

    # -- matrix ----------------------------------------------------------

    def test_matrix_requires_authentication(self):
        self.check_not_authenticated("get", "/deploy/matrix/")

    def test_matrix_needs_the_list_flag(self):
        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get("/deploy/matrix/").status_code, 403)
        user.role.can_list_deployments = True
        user.role.save()
        r = self.client.get("/deploy/matrix/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("targets", r.data)
        self.assertIn("installers", r.data)

    # -- render ----------------------------------------------------------

    def test_render_needs_the_manage_flag(self):
        user = self.create_user_with_roles(["can_list_deployments"])
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        body = {"deployment": self.deployment.pk, "target": "win11-pro", "profile": {}}
        self.assertEqual(
            self.client.post("/deploy/render/", body, format="json").status_code, 403
        )

    def test_render_masks_secrets_and_returns_generated(self):
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {},
        }
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 200)
        pw = r.data["generated"]["admin_password"]
        self.assertTrue(pw)
        blob = "".join(f["content"] for f in r.data["files"])
        self.assertNotIn(pw, blob)
        self.assertIn("********", blob)
        # the xml preview hides the embedded payload entirely
        xml = next(f for f in r.data["files"] if f["name"] == "autounattend.xml")
        self.assertIn("hidden in preview", xml["content"])
        self.assertNotIn("Extensions>", xml["content"])
        self.assertNotIn("<ulrmm:File", xml["content"])

    def test_render_masks_the_escaped_form_of_a_secret(self):
        pw = 'Pw&<x>"9\\!'
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {"admin": {"password": pw}},
        }
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 200)
        xml = next(f for f in r.data["files"] if f["name"] == "autounattend.xml")
        self.assertNotIn("Pw&amp;&lt;x&gt;", xml["content"])
        self.assertIn("<Value>********</Value>", xml["content"])

    def test_mask_covers_json_and_yaml_quoting(self):
        secret = 'a"b\\c\u00e9'
        files = [
            {
                "name": "a.json",
                "language": "json",
                "content": json.dumps({"p": secret}),
            },
            {
                "name": "b.json",
                "language": "json",
                "content": json.dumps({"p": secret}, ensure_ascii=False),
            },
            {
                "name": "c.yaml",
                "language": "yaml",
                "content": 'p: "a\\"b\\\\c\u00e9"\n',
            },
        ]
        for f in views._mask(files, [secret]):
            self.assertEqual(f["content"].count("********"), 1, f["name"])
            self.assertNotIn("b\\", f["content"], f["name"])

    def test_render_returns_generated_for_the_linux_family(self):
        # the Linux module reports generated values the same way
        def render(target_id, deployment, profile):
            profile["_generated"] = {"admin_password": "Gen-Pw-1"}
            content = "password: Gen-Pw-1\n"
            return [{"name": "x.yaml", "language": "yaml", "content": content}], [
                "Gen-Pw-1"
            ]

        fake = SimpleNamespace(validate_profile=lambda t, p: dict(p), render=render)
        body = {"deployment": self.deployment.pk, "target": "fake-linux", "profile": {}}
        with mock.patch.object(matrix, "module_for", return_value=fake):
            r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["generated"], {"admin_password": "Gen-Pw-1"})
        self.assertEqual(r.data["files"][0]["content"], "password: ********\n")

    def test_stale_agent_build_refuses_answer_files(self):
        body = {"deployment": self.deployment.pk, "target": "win11-pro", "profile": {}}
        with mock.patch.object(signing, "dist_pubkey_ok", return_value=False):
            for url in ("/deploy/render/", "/deploy/download/"):
                r = self.client.post(url, body, format="json")
                self.assertEqual(r.status_code, 503, url)
                self.assertIn("agent build needed", r.data)

    def test_missing_build_is_503_and_a_bad_arch_is_400(self):
        body = {"deployment": self.deployment.pk, "target": "win11-pro", "profile": {}}
        missing = installers.Unavailable("agent build needed: run update.sh")
        with mock.patch.object(windows, "_agent_install_ps1", side_effect=missing):
            for url in ("/deploy/render/", "/deploy/download/"):
                r = self.client.post(url, body, format="json")
                self.assertEqual(r.status_code, 503, url)
        with mock.patch.object(
            windows, "_agent_install_ps1", side_effect=ValueError("no build for x")
        ):
            r = self.client.post("/deploy/download/", body, format="json")
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "no build for x")
        self.deployment.goarch = "arm64"
        self.deployment.save()
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("deployment", r.data)

    def test_render_given_password_is_masked_not_generated(self):
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {"admin": {"password": "Known-Pw-9!"}},
        }
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("admin_password", r.data["generated"])
        blob = "".join(f["content"] for f in r.data["files"])
        self.assertNotIn("Known-Pw-9!", blob)

    def test_render_validation_error_is_fielded(self):
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-home",
            "profile": {"uwf": {"enabled": True}},
        }
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("uwf", r.data)

    def test_render_unknown_target(self):
        body = {"deployment": self.deployment.pk, "target": "nope", "profile": {}}
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertEqual(r.status_code, 400)

    def test_render_out_of_scope_deployment(self):
        other = baker.make(
            "clients.Deployment",
            site=self.site3,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": False, "ping": False, "rdp": False},
        )
        user = self.create_user_with_roles(
            ["can_list_deployments", "can_manage_deployments"]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        body = {"deployment": other.pk, "target": "win11-pro", "profile": {}}
        r = self.client.post("/deploy/render/", body, format="json")
        self.assertIn(r.status_code, (400, 403, 404))

    # -- download --------------------------------------------------------

    def test_download_single_file_has_the_real_secret(self):
        before = AuditLog.objects.count()
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {"admin": {"password": "Real-Pw-7!"}},
        }
        r = self.client.post("/deploy/download/", body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertIn("attachment", r["Content-Disposition"])
        self.assertIn(b"Real-Pw-7!", b"".join(r.streaming_content))
        self.assertEqual(AuditLog.objects.count(), before + 1)
        # the audit message names what was built, never the password
        self.assertNotIn("Real-Pw-7!", AuditLog.objects.latest("id").message)

    def test_download_streams_in_chunks_with_a_length(self):
        blob = bytes(range(256)) * 1000
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {},
            "bundle": True,
        }
        with mock.patch.object(
            views.bundle, "build_bundle", return_value=("x.zip", blob)
        ):
            r = self.client.post("/deploy/download/", body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.streaming)
        chunks = list(r.streaming_content)
        self.assertEqual(len(chunks), 4)
        self.assertTrue(all(len(c) <= views.CHUNK for c in chunks))
        self.assertEqual(b"".join(chunks), blob)
        self.assertEqual(r["Content-Length"], str(len(blob)))
        self.assertEqual(r["Content-Type"], "application/zip")
        self.assertEqual(r["Cache-Control"], "no-store")

    def test_download_bundle_is_a_zip(self):
        body = {
            "deployment": self.deployment.pk,
            "target": "win11-pro",
            "profile": {},
            "bundle": True,
        }
        r = self.client.post("/deploy/download/", body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/zip")
        self.assertTrue(r["Content-Disposition"].endswith('.zip"'))
        with zipfile.ZipFile(BytesIO(b"".join(r.streaming_content))) as zf:
            members = set(zf.namelist())
        self.assertIn("autounattend.xml", members)
        self.assertIn("README.txt", members)
        self.assertIn("inject-xorriso.sh", members)
        self.assertIn("inject-oscdimg.ps1", members)

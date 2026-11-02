# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test.utils import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from deploy import installers, matrix, signing
from ulrmm.agent_ident import agent_artifact
from ulrmm.test import ULRMMTestCase


@override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
class TestEveryTargetRenders(ULRMMTestCase):
    """Every matrix target renders and downloads with its own defaults."""

    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.setup_base_instance()
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site1,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": False, "ping": True, "rdp": False},
        )
        self.dist = tempfile.TemporaryDirectory()
        self.addCleanup(self.dist.cleanup)
        ver = settings.LATEST_AGENT_VER
        for plat, arches in (
            ("windows", ("amd64", "386")),
            ("linux", ("amd64", "386", "arm64", "arm")),
        ):
            for arch in arches:
                Path(self.dist.name, agent_artifact(ver, plat, arch)).write_bytes(
                    b"x" * 64
                )
        Path(self.dist.name, signing.DIST_PUBKEY_FILE).write_text(
            signing.public_key_b64()
        )
        for p in (
            override_settings(AGENTS_DIST_DIR=self.dist.name),
            mock.patch.object(
                installers,
                "_mesh_builds",
                lambda arches: {
                    a: (f"https://mesh.example.com/{a}", "") for a in arches
                },
            ),
        ):
            p.start() if hasattr(p, "start") else p.enable()
            self.addCleanup(p.stop if hasattr(p, "stop") else p.disable)

    def _profile(self, target):
        profile = json.loads(json.dumps(target["defaults"]))
        if target["capabilities"].get("device_required"):
            profile["disk"]["device"] = "/dev/sda"
        return profile

    def test_matrix_shows_only_public_keys(self):
        r = self.client.get("/deploy/matrix/")
        self.assertEqual(r.status_code, 200)
        keys = {"id", "family", "group", "label", "formats", "capabilities"}
        for target in r.data["targets"]:
            self.assertEqual(
                set(target) - {"notes", "defaults", "fields", *matrix._OPTIONAL_KEYS},
                keys,
                target["id"],
            )
        home = next(t for t in r.data["targets"] if t["id"] == "win11-home")
        self.assertNotIn("domain", home["defaults"])
        self.assertNotIn("uwf", home["defaults"])
        self.assertEqual(home["defaults"]["general"]["image_name"], "Windows 11 Home")
        arch = next(t for t in r.data["targets"] if t["id"] == "arch")
        self.assertNotIn("luks", arch["defaults"])

    def test_matrix_sends_long_lists_once(self):
        data = self.client.get("/deploy/matrix/").data
        sets = data["choice_sets"]
        refs = set()
        for target in data["targets"]:
            for path, meta in target["fields"].items():
                if "choices_ref" in meta:
                    refs.add(meta["choices_ref"])
                    values = [c["value"] for c in sets[meta["choices_ref"]]]
                    leaf = target["defaults"]
                    for part in path.split("."):
                        leaf = leaf[part]
                    self.assertIn(leaf, values, (target["id"], path))
        self.assertTrue({"win_timezones", "win_keyboards"} <= refs)

    def test_hidden_windows_fields_do_not_block_the_render(self):
        target = next(
            t
            for t in self.client.get("/deploy/matrix/").data["targets"]
            if t["id"] == "win11-pro"
        )
        profile = self._profile(target)
        profile["ssh"] = {
            "enable": True,
            "auth": "password",
            "authorized_keys": "ssh-ed25519 truncat",
        }
        r = self.client.post(
            "/deploy/render/",
            {
                "deployment": self.deployment.pk,
                "target": "win11-pro",
                "profile": profile,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)

    def test_every_target_renders_and_downloads_its_defaults(self):
        targets = self.client.get("/deploy/matrix/").data["targets"]
        self.assertGreaterEqual(len(targets), 38)
        for target in targets:
            body = {
                "deployment": self.deployment.pk,
                "target": target["id"],
                "profile": self._profile(target),
            }
            with self.subTest(target=target["id"]):
                r = self.client.post("/deploy/render/", body, format="json")
                self.assertEqual(r.status_code, 200, r.data)
                files = r.data["files"]
                self.assertTrue(files and all(f["content"] for f in files))
                r = self.client.post(
                    "/deploy/download/", {**body, "bundle": True}, format="json"
                )
                self.assertEqual(r.status_code, 200)
                names = zipfile.ZipFile(BytesIO(b"".join(r))).namelist()
                self.assertIn(files[0]["name"], names)

    def test_domain_section_left_empty_means_workgroup(self):
        target = next(
            t
            for t in self.client.get("/deploy/matrix/").data["targets"]
            if t["id"] == "win11-pro"
        )
        profile = self._profile(target)
        self.assertEqual(profile["domain"]["domain"], "")
        r = self.client.post(
            "/deploy/render/",
            {
                "deployment": self.deployment.pk,
                "target": "win11-pro",
                "profile": profile,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        xml = next(f for f in r.data["files"] if f["name"] == "autounattend.xml")
        self.assertNotIn("UnattendedJoin", xml["content"])

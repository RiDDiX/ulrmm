# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from types import SimpleNamespace
from unittest import mock

from django.test.utils import override_settings

from deploy import matrix, signing, windows
from ulrmm.test import ULRMMTestCase


class TestMatrix(ULRMMTestCase):
    def test_every_windows_edition_is_present(self):
        ids = {t["id"] for t in windows.TARGETS}
        for want in (
            "win10-home",
            "win11-home",
            "win11-pro",
            "win11-pro-iot",
            "win11-enterprise",
            "win11-iot-enterprise",
            "server2019-standard-core",
            "server2022-datacenter-desktop",
            "server2025-datacenter-core",
        ):
            self.assertIn(want, ids)
        # 2 client groups x 5 editions + 3 server years x 2 skus x 2 forms
        self.assertEqual(len(windows.TARGETS), 10 + 12)

    def test_capabilities_follow_the_edition(self):
        by_id = {t["id"]: t for t in windows.TARGETS}
        home = by_id["win11-home"]["capabilities"]
        self.assertFalse(home["domain_join"])
        self.assertFalse(home["bitlocker"])
        self.assertFalse(home["consumer_policy"])
        self.assertFalse(home["telemetry_off"])
        self.assertFalse(home["uwf"])
        self.assertTrue(home["appx_debloat"])

        ent = by_id["win11-enterprise"]["capabilities"]
        self.assertTrue(ent["domain_join"])
        self.assertTrue(ent["consumer_policy"])
        self.assertTrue(ent["telemetry_off"])
        self.assertTrue(ent["uwf"])

        pro = by_id["win11-pro"]["capabilities"]
        self.assertTrue(pro["domain_join"])
        self.assertTrue(pro["bitlocker"])
        self.assertFalse(pro["uwf"])
        self.assertFalse(pro["consumer_policy"])

        pro_iot = by_id["win11-pro-iot"]
        self.assertTrue(pro_iot["capabilities"]["domain_join"])
        self.assertTrue(any("installs as Windows Pro" in n for n in pro_iot["notes"]))

        core = by_id["server2022-standard-core"]["capabilities"]
        desktop = by_id["server2022-standard-desktop"]["capabilities"]
        self.assertFalse(core["desktop"])
        self.assertTrue(desktop["desktop"])
        self.assertTrue(core["telemetry_off"])

    def test_merge_with_a_patched_linux_module(self):
        fake_target = {
            "id": "ubuntu-24.04",
            "family": "linux",
            "group": "ubuntu",
            "label": "Ubuntu 24.04",
            "formats": ["autoinstall.yaml"],
            "capabilities": {},
            "defaults": {},
            "notes": [],
        }
        fake = SimpleNamespace(TARGETS=[fake_target])
        with mock.patch.object(matrix, "_linux", return_value=fake):
            ids = {t["id"] for t in matrix.all_targets()}
            self.assertIn("ubuntu-24.04", ids)
            self.assertIn("win11-home", ids)
            self.assertIs(matrix.module_for("ubuntu-24.04"), fake)
            self.assertIs(matrix.module_for("win11-home"), windows)
            self.assertIsNone(matrix.module_for("nope"))

    def test_merge_tolerates_a_missing_linux_module(self):
        with mock.patch.object(matrix, "_linux", return_value=None):
            ids = {t["id"] for t in matrix.all_targets()}
            self.assertIn("win11-home", ids)
            self.assertIsNone(matrix.module_for("ubuntu-24.04"))

    @override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
    def test_build_matrix_payload(self):
        payload = matrix.build_matrix()
        self.assertEqual(payload["kid"], signing.key_id())
        self.assertEqual(payload["pubkey_b64"], signing.public_key_b64())
        self.assertTrue(payload["pubkey_pem"].startswith("-----BEGIN PUBLIC KEY"))
        self.assertIn("agent_version", payload)
        self.assertFalse(payload["win_signed"])
        fmts = {i["fmt"] for i in payload["installers"]}
        self.assertEqual(fmts, {"exe", "ps1", "deb", "rpm", "tgz", "sh"})

    @override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
    def test_fields_cover_the_defaults_and_defaults_are_choices(self):
        def leaf(defaults, path):
            value = defaults
            for part in path.split("."):
                value = value[part]
            return value

        payload = matrix.build_matrix()
        sets = payload["choice_sets"]
        targets = payload["targets"]
        self.assertTrue(all("fields" in t for t in targets))
        for tgt in targets:
            with self.subTest(target=tgt["id"]):
                for path, meta in tgt["fields"].items():
                    self.assertTrue(meta["label"])
                    # a ref names a set the matrix carries
                    choices = meta.get("choices") or sets.get(meta.get("choices_ref"))
                    if "choices_ref" in meta:
                        self.assertIn(meta["choices_ref"], sets, path)
                    if choices is not None:
                        values = [c["value"] for c in choices]
                        self.assertEqual(len(values), len(set(values)))
                        if meta["kind"] == "checkgroup":
                            self.assertLessEqual(
                                set(leaf(tgt["defaults"], path)), set(values)
                            )
                            continue
                        self.assertIn(leaf(tgt["defaults"], path), values, path)
                if tgt["family"] != "windows":
                    continue
                paths = {
                    f"{section}.{key}"
                    for section, values in tgt["defaults"].items()
                    for key in values
                }
                self.assertEqual(set(tgt["fields"]), paths)
                for path in (
                    "general.version",
                    "general.ui_language",
                    "general.locale",
                    "general.keyboard",
                    "general.timezone",
                    "privacy.level",
                    "ssh.auth",
                    "telemetry.level",
                ):
                    self.assertEqual(tgt["fields"][path]["kind"], "select", path)
                self.assertEqual(
                    tgt["fields"]["ssh.authorized_keys"]["kind"], "multiline"
                )

    def test_fields_follow_the_edition(self):
        home = windows.profile_fields("win11-home")
        ent = windows.profile_fields("win11-enterprise")
        self.assertNotIn("domain.domain", home)
        self.assertNotIn("uwf.enabled", home)
        self.assertIn("uwf.enabled", ent)

        def levels(fields):
            return [c["value"] for c in fields["telemetry.level"]["choices"]]

        self.assertEqual(levels(home), [1, 3])
        self.assertEqual(levels(ent), [0, 1, 3])
        self.assertEqual(levels(windows.profile_fields("win10-pro")), [1, 2, 3])
        # Server 2022 is on the Windows 10 code base, Server 2025 is not
        for tid, want in (
            ("server2019-standard-core", [0, 1, 2, 3]),
            ("server2022-standard-core", [0, 1, 2, 3]),
            ("server2022-datacenter-desktop", [0, 1, 2, 3]),
            ("server2025-standard-core", [0, 1, 3]),
        ):
            self.assertEqual(levels(windows.profile_fields(tid)), want, tid)
        clean = windows.validate_profile(
            "server2022-standard-core", {"telemetry": {"level": 2}}
        )
        self.assertEqual(clean["telemetry"]["level"], 2)
        # edition limits sit in the capability reasons, not in the help
        self.assertEqual(home["privacy.level"]["help"], ent["privacy.level"]["help"])
        self.assertEqual(home["privacy.spotlight"]["capability"], "consumer_policy")

    def test_missing_profile_fields_gives_empty_fields(self):
        fake_target = {
            "id": "ubuntu-24.04",
            "family": "linux",
            "group": "ubuntu",
            "label": "Ubuntu 24.04",
            "formats": ["autoinstall.yaml"],
            "capabilities": {},
            "defaults": {},
            "notes": [],
        }
        fake = SimpleNamespace(
            TARGETS=[fake_target], profile_defaults=lambda _t: {"general": {}}
        )
        with mock.patch.object(matrix, "_linux", return_value=fake):
            out = matrix._public(fake_target)
        self.assertEqual(out["fields"], {})
        self.assertEqual(out["defaults"], {"general": {}})

    @override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
    def test_long_lists_go_once_into_choice_sets(self):
        payload = matrix.build_matrix()
        sets = payload["choice_sets"]
        for name, choices in windows.CHOICE_SETS.items():
            self.assertEqual(sets[name], choices)
        self.assertEqual(len(sets["win_timezones"]), 139)
        for tgt in payload["targets"]:
            if tgt["family"] != "windows":
                continue
            fields = tgt["fields"]
            for path, ref in (
                ("general.ui_language", "win_ui_languages"),
                ("general.locale", "win_locales"),
                ("general.keyboard", "win_keyboards"),
                ("general.timezone", "win_timezones"),
            ):
                self.assertEqual(fields[path]["choices_ref"], ref)
                self.assertNotIn("choices", fields[path])
            # the per-target lists stay inline and short
            for path, meta in fields.items():
                self.assertLessEqual(len(meta.get("choices", [])), 10, path)
        size = len(
            json.dumps([t for t in payload["targets"] if t["family"] == "windows"])
        )
        # the privacy switches and presets ride along per edition
        self.assertLess(size, 300_000)

    def test_choice_sets_take_a_module_with_or_without_sets(self):
        utc = [{"value": "UTC", "label": "UTC"}]
        fake = SimpleNamespace(TARGETS=[], choice_sets=lambda: {"lx_tz": utc})
        with mock.patch.object(matrix, "_linux", return_value=fake):
            sets = matrix.choice_sets()
        self.assertEqual(sets["lx_tz"], utc)
        self.assertIn("win_timezones", sets)
        # a module with inline choices only, or none at all, adds nothing
        for linux in (SimpleNamespace(TARGETS=[]), None):
            with mock.patch.object(matrix, "_linux", return_value=linux):
                self.assertEqual(matrix.choice_sets(), windows.choice_sets())

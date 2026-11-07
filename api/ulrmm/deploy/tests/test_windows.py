# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import os
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from unittest import mock

from django.test.utils import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework.serializers import ValidationError

from deploy import windows
from ulrmm.test import ULRMMTestCase

NS = windows.NS
AGENT_STUB = "# agent install\nWrite-Output 'enroll'\n$env:PKG='x'\n"


def _pubkey(comment="ops@example"):
    name = b"ssh-ed25519"
    blob = len(name).to_bytes(4, "big") + name + (32).to_bytes(4, "big") + b"k" * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


KEY = _pubkey()


def _components(xml: str):
    root = ET.fromstring(xml)
    found = {}
    for s in root.findall(f"{{{NS}}}settings"):
        for c in s.findall(f"{{{NS}}}component"):
            found.setdefault(c.get("name"), set()).add(s.get("pass"))
    return found, root


@override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
class TestWindowsRender(ULRMMTestCase):
    def setUp(self):
        self.site = baker.make("clients.Site")
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": True},
        )
        self.patcher = mock.patch.object(
            windows, "_agent_install_ps1", return_value=AGENT_STUB
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _render(self, target_id, profile):
        return windows.render(target_id, self.deployment, profile)

    # -- validation ------------------------------------------------------

    def test_domain_rejected_on_home(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-home",
                {"domain": {"domain": "x.lan", "username": "a", "password": "b"}},
            )
        self.assertIn("domain", cm.exception.detail)

    def test_join_details_need_a_domain(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-pro", {"domain": {"domain": "", "username": "svc"}}
            )
        self.assertIn("domain", cm.exception.detail["domain"])
        # an untouched section stays a workgroup
        windows.validate_profile("win11-pro", {"domain": {"domain": "", "ou": ""}})

    def test_uwf_rejected_on_pro(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile("win11-pro", {"uwf": {"enabled": True}})
        self.assertIn("uwf", cm.exception.detail)

    def test_telemetry_floor_on_pro(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile("win11-pro", {"telemetry": {"level": 0}})
        self.assertIn("telemetry", cm.exception.detail)
        # level 1 is fine on Pro
        windows.validate_profile("win11-pro", {"telemetry": {"level": 1}})

    def test_consumer_policy_rejected_on_pro(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-pro", {"debloat": {"consumer_policy": True}}
            )
        self.assertIn("debloat", cm.exception.detail)

    def test_unknown_section_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile("win11-pro", {"bogus": {}})
        self.assertIn("bogus", cm.exception.detail)

    def test_enterprise_accepts_the_restricted_fields(self):
        clean = windows.validate_profile(
            "win11-enterprise",
            {
                "uwf": {"enabled": True},
                "telemetry": {"level": 0},
                "debloat": {"consumer_policy": True},
                "domain": {"domain": "corp.lan", "username": "svc", "password": "pw"},
            },
        )
        self.assertTrue(clean["uwf"]["enabled"])
        self.assertEqual(clean["telemetry"]["level"], 0)

    def test_bad_hostname_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-pro", {"general": {"hostname": "way-too-long-a-name-here"}}
            )
        self.assertIn("general", cm.exception.detail)

    # -- render ----------------------------------------------------------

    def test_home_has_no_join_and_a_local_account(self):
        files, secrets = self._render("win11-home", {})
        xml = files[0]["content"]
        comps, root = _components(xml)
        self.assertNotIn("Microsoft-Windows-UnattendedJoin", comps)
        self.assertIn("Microsoft-Windows-Shell-Setup", comps)
        self.assertIn("oobeSystem", comps["Microsoft-Windows-Shell-Setup"])
        self.assertIn("LocalAccounts", xml)
        self.assertNotIn("AdministratorPassword", xml)
        # a generated admin password is a secret
        self.assertTrue(secrets)

    def test_control_characters_rejected_in_credentials(self):
        self.assertFalse(
            windows._AdminSerializer(data={"password": "p\x01w"}).is_valid()
        )
        general = windows._GeneralSerializer(data={"image_name": "a\x01b"})
        self.assertFalse(general.is_valid())
        self.assertIn("image_name", general.errors)
        good = {"domain": "x.lan", "username": "a", "password": "b", "ou": "OU=x"}
        self.assertTrue(windows._DomainSerializer(data=good).is_valid())
        for field in ("username", "password", "ou"):
            bad = windows._DomainSerializer(data={**good, field: "a\nb"})
            self.assertFalse(bad.is_valid())
            self.assertIn(field, bad.errors)

    def test_server_has_administrator_password(self):
        files, secrets = self._render(
            "server2022-standard-desktop", {"admin": {"password": "Srv-Pass-123!"}}
        )
        xml = files[0]["content"]
        self.assertIn("AdministratorPassword", xml)
        self.assertNotIn("LocalAccounts", xml)
        self.assertIn("Srv-Pass-123!", secrets)

    def test_domain_join_renders_on_enterprise(self):
        files, _ = self._render(
            "win11-enterprise",
            {"domain": {"domain": "corp.lan", "username": "svc", "password": "jp"}},
        )
        xml = files[0]["content"]
        comps, _ = _components(xml)
        self.assertIn("Microsoft-Windows-UnattendedJoin", comps)
        self.assertIn("specialize", comps["Microsoft-Windows-UnattendedJoin"])
        self.assertIn("corp.lan", xml)

    def test_image_name_default_and_override(self):
        files, _ = self._render("win11-pro", {})
        self.assertIn("Windows 11 Pro", files[0]["content"])
        files, _ = self._render(
            "win11-pro", {"general": {"image_name": "Windows 11 Pro N"}}
        )
        self.assertIn("Windows 11 Pro N", files[0]["content"])

    def test_bootstrap_only_has_honored_steps(self):
        files, _ = self._render(
            "win11-enterprise",
            {
                "uwf": {"enabled": True},
                "telemetry": {"level": 0},
                "debloat": {"consumer_policy": True, "appx": ["Microsoft.XboxApp"]},
                "remote": {"rdp": True},
            },
        )
        boot = next(f for f in files if f["name"].endswith("-bootstrap.ps1"))["content"]
        self.assertIn("DisableWindowsConsumerFeatures", boot)
        self.assertIn("AllowTelemetry", boot)
        self.assertIn("uwfmgr filter enable", boot)
        self.assertIn("Microsoft.XboxApp", boot)
        self.assertIn("fDenyTSConnections", boot)

    def test_bootstrap_skips_unhonored_steps_on_home(self):
        files, _ = self._render(
            "win11-home", {"debloat": {"appx": ["Microsoft.XboxApp"]}}
        )
        boot = next(f for f in files if f["name"].endswith("-bootstrap.ps1"))["content"]
        self.assertNotIn("DisableWindowsConsumerFeatures", boot)
        self.assertNotIn("uwfmgr", boot)
        # an allowed appx removal still runs on Home
        self.assertIn("Microsoft.XboxApp", boot)

    def test_server_bitlocker_installs_the_feature_first(self):
        files, _ = self._render(
            "server2022-standard-desktop",
            {"admin": {"password": "P!"}, "encryption": {"bitlocker": True}},
        )
        boot = next(f for f in files if f["name"].endswith("-bootstrap.ps1"))["content"]
        self.assertIn("Install-WindowsFeature BitLocker", boot)
        self.assertIn("Enable-BitLocker", boot)

    def test_token_is_in_the_secrets(self):
        from deploy import signing

        files, secrets = self._render("win11-pro", {"admin": {"password": "Known-1!"}})
        token = signing.mint_for_deployment(self.deployment)
        self.assertIn(token, secrets)
        self.assertIn("Known-1!", secrets)

    def test_bundle_extras_have_inject_scripts_and_a_readme(self):
        files, _ = self._render("win11-pro", {})
        extras = dict(windows.bundle_extras("win11-pro", files))
        self.assertEqual(
            set(extras), {"README.txt", "inject-xorriso.sh", "inject-oscdimg.ps1"}
        )
        xorriso = extras["inject-xorriso.sh"].decode()
        self.assertTrue(xorriso.startswith("#!/bin/sh\n"))
        self.assertIn("xorriso -as mkisofs", xorriso)
        self.assertIn("autounattend.xml", xorriso)
        oscdimg = extras["inject-oscdimg.ps1"].decode()
        self.assertIn("-bootdata:", oscdimg)
        self.assertIn("etfsboot.com", oscdimg)
        self.assertIn("efisys.bin", oscdimg)
        readme = extras["README.txt"].decode()
        self.assertIn("inject-xorriso.sh", readme)
        self.assertIn("inject-oscdimg.ps1", readme)
        self.assertNotIn("\n", readme.replace("\r\n", ""))

    def test_arm64_deployment_is_refused(self):
        # there is no Windows arm64 agent build
        self.deployment.goarch = "arm64"
        self.deployment.save()
        with self.assertRaises(ValidationError) as cm:
            self._render("win11-pro", {})
        self.assertIn("deployment", cm.exception.detail)

    # -- first boot ------------------------------------------------------

    def _payload(self, xml):
        root = ET.fromstring(xml)
        ext = root.find(f"{{{windows.XNS}}}Extensions")
        self.assertIsNotNone(ext)
        script = ext.find(f"{{{windows.XNS}}}ExtractScript").text
        embedded = {
            el.get("name"): base64.b64decode(el.text).decode()
            for el in ext.findall(f"{{{windows.XNS}}}File")
        }
        return root, script, embedded

    def test_specialize_command_fits_the_path_limit_on_every_target(self):
        for tgt in windows.TARGETS:
            with self.subTest(target=tgt["id"]):
                files, _ = self._render(tgt["id"], {})
                root, script, embedded = self._payload(files[0]["content"])
                paths = [
                    el.text
                    for s in root.findall(f"{{{NS}}}settings")
                    if s.get("pass") == "specialize"
                    for el in s.iter(f"{{{NS}}}Path")
                ]
                self.assertEqual(paths, [windows.SPECIALIZE_CMD])
                self.assertLessEqual(len(paths[0]), windows.PATH_MAX)
                self.assertIn("Extensions.ExtractScript", paths[0])
                self.assertIn("Extensions.File", script)
                by_suffix = {n.split("-")[-1]: body for n, body in embedded.items()}
                self.assertEqual(by_suffix["bootstrap.ps1"], files[1]["content"])
                self.assertEqual(by_suffix["agent.ps1"], AGENT_STUB)
                self.assertEqual(by_suffix["SetupComplete.cmd"], files[3]["content"])
                self.assertEqual(by_suffix["enroll.jws"].count("."), 2)

    def test_extractor_locks_down_by_sid_and_leaves_the_first_run_to_boot(self):
        files, _ = self._render("win11-pro", {})
        _, script, _ = self._payload(files[0]["content"])
        self.assertIn("'*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'", script)
        self.assertNotIn("Administrators:", script)
        # the ACL is in place before any file is written
        self.assertLess(script.index("icacls"), script.index("WriteAllBytes"))
        self.assertEqual(script.count("if($LASTEXITCODE){throw"), 2)
        self.assertNotIn("schtasks /Run", script)
        # boot trigger as SYSTEM by SID, on battery too, without a time limit
        xml = script.split("@'\n", 1)[1].split("\n'@", 1)[0]
        self.assertTrue(xml.startswith('<?xml version="1.0" encoding="UTF-16"?>'))
        task = ET.fromstring(xml.split("?>", 1)[1])
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertIsNotNone(task.find("t:Triggers/t:BootTrigger", ns))
        self.assertEqual(
            task.findtext("t:Principals/t:Principal/t:UserId", None, ns), "S-1-5-18"
        )
        settings_el = task.find("t:Settings", ns)
        for tag, value in (
            ("DisallowStartIfOnBatteries", "false"),
            ("StopIfGoingOnBatteries", "false"),
            ("ExecutionTimeLimit", "PT0S"),
        ):
            self.assertEqual(settings_el.findtext(f"t:{tag}", None, ns), value, tag)
        self.assertIn(
            "-bootstrap.ps1", task.findtext("t:Actions/t:Exec/t:Arguments", "", ns)
        )
        # Setup runs SetupComplete.cmd only from Setup\Scripts itself
        self.assertIn(
            "Move-Item -Force (Join-Path $dir 'SetupComplete.cmd') (Split-Path $dir)",
            script,
        )
        # the agent setup Setup copied from $OEM$\$1 carries the token
        self.assertIn(
            "if(Test-Path $a){icacls $a /inheritance:r /grant:r "
            "'*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'",
            script,
        )

    def test_bootstrap_retries_until_enrolled_and_cleans_up_after(self):
        files, _ = self._render("win11-pro", {"firewall": {"allow": ["3389/tcp"]}})
        boot = files[1]["content"]
        self.assertNotIn("catch{Log ('agent install failed", boot)
        # double quotes, so PowerShell expands the log path
        self.assertIn('$log="$env:SystemRoot\\Temp\\', boot)
        loop = boot.index("while(-not (Enrolled)){")
        self.assertIn("-Name AgentPK", boot)
        self.assertIn("Start-Sleep -Seconds 900", boot[loop:])
        self.assertIn("-enroll", boot[loop:])
        wait = boot.index("Resolve-DnsName -Name $u.Host", loop)
        self.assertLess(wait, boot.index("Log 'install agent'", loop))
        self.assertIn("$c.Connect($u.Host,$u.Port)", boot[loop:])
        # policies run once, before the agent; cleanup only after the loop
        self.assertLess(boot.index("if(-not (Test-Path $done)){"), loop)
        self.assertLess(boot.index("New-NetFirewallRule"), loop)
        self.assertLess(loop, boot.index("schtasks /Delete"))
        self.assertLess(loop, boot.index("Remove-Item -Recurse -Force $dir"))
        self.assertLess(
            loop, boot.index("Remove-Item -Recurse -Force (Join-Path $env:SystemDrive")
        )
        # the payload leaves the processed answer file too
        self.assertLess(loop, boot.index("RemoveChild($e)"))

    def test_firewall_allow_entries_are_port_scoped(self):
        clean = windows.validate_profile(
            "win11-pro", {"firewall": {"allow": ["3389/tcp", "5353/udp"]}}
        )
        files, _ = self._render("win11-pro", clean)
        boot = files[1]["content"]
        self.assertIn("-Protocol TCP -LocalPort 3389", boot)
        self.assertIn("-Protocol UDP -LocalPort 5353", boot)
        self.assertNotIn("netsh advfirewall firewall add rule", boot)
        for bad in ("3389", "rdp", "70000/tcp", "0/tcp", "22/icmp", "3389/tcp any"):
            with self.subTest(entry=bad):
                with self.assertRaises(ValidationError) as cm:
                    windows.validate_profile(
                        "win11-pro", {"firewall": {"allow": [bad]}}
                    )
                self.assertIn("firewall", cm.exception.detail)

    def test_locale_and_keyboard_reach_the_installed_system_and_oobe(self):
        files, _ = self._render(
            "win11-pro",
            windows.validate_profile(
                "win11-pro",
                {
                    "general": {
                        "ui_language": "de-DE",
                        "locale": "de-DE",
                        "keyboard": "0407:00000407",
                    }
                },
            ),
        )
        root = ET.fromstring(files[0]["content"])
        found = {}
        for s in root.findall(f"{{{NS}}}settings"):
            for c in s.findall(f"{{{NS}}}component"):
                if c.get("name").startswith("Microsoft-Windows-International-Core"):
                    found[s.get("pass")] = c
        self.assertEqual(set(found), {"windowsPE", "specialize", "oobeSystem"})
        for pass_name in ("specialize", "oobeSystem"):
            comp = found[pass_name]
            self.assertEqual(comp.get("name"), "Microsoft-Windows-International-Core")
            values = {el.tag.split("}")[1]: el.text for el in comp}
            self.assertEqual(
                values,
                {
                    "InputLocale": "0407:00000407",
                    "SystemLocale": "de-DE",
                    "UILanguage": "de-DE",
                    "UserLocale": "de-DE",
                },
            )

    def test_ui_language_and_formats_are_separate(self):
        clean = windows.validate_profile(
            "win11-pro",
            {"general": {"ui_language": "en-GB", "locale": "de-CH"}},
        )
        files, _ = self._render("win11-pro", clean)
        root = ET.fromstring(files[0]["content"])
        for s in root.findall(f"{{{NS}}}settings"):
            for c in s.findall(f"{{{NS}}}component"):
                if c.get("name").startswith("Microsoft-Windows-International-Core"):
                    self.assertEqual(c.findtext(f"{{{NS}}}UILanguage"), "en-GB")
                    self.assertEqual(c.findtext(f"{{{NS}}}UserLocale"), "de-CH")
                    self.assertEqual(c.findtext(f"{{{NS}}}SystemLocale"), "de-CH")
        setup_ui = root.find(f".//{{{NS}}}SetupUILanguage/{{{NS}}}UILanguage")
        self.assertEqual(setup_ui.text, "en-GB")

    def test_ui_language_follows_the_formats_when_not_given(self):
        def ui(general):
            clean = windows.validate_profile("win11-pro", {"general": general})
            files, _ = self._render("win11-pro", clean)
            root = ET.fromstring(files[0]["content"])
            setup = root.find(f".//{{{NS}}}SetupUILanguage/{{{NS}}}UILanguage").text
            langs = {e.text for e in root.iter(f"{{{NS}}}UILanguage")}
            return clean["general"]["ui_language"], setup, langs

        # a profile of the old shape has one language field
        self.assertEqual(ui({"locale": "de-DE"}), ("de-DE", "de-DE", {"de-DE"}))
        self.assertEqual(
            ui({"locale": "fr-FR", "ui_language": ""}), ("fr-FR", "fr-FR", {"fr-FR"})
        )
        # formats without own media stay on the default display language
        self.assertEqual(ui({"locale": "de-CH"})[0], "en-US")
        # a display language given stays
        self.assertEqual(ui({"locale": "de-DE", "ui_language": "en-US"})[0], "en-US")

    def test_timezone_takes_windows_ids_and_maps_iana_names(self):
        for given, want in (
            ("W. Europe Standard Time", "W. Europe Standard Time"),
            ("Europe/Berlin", "W. Europe Standard Time"),
            ("Etc/UTC", "UTC"),
            ("Tokyo Standard Time", "Tokyo Standard Time"),
        ):
            with self.subTest(timezone=given):
                clean = windows.validate_profile(
                    "win11-pro", {"general": {"timezone": given}}
                )
                self.assertEqual(clean["general"]["timezone"], want)
                files, _ = self._render("win11-pro", clean)
                self.assertIn(f"<TimeZone>{want}</TimeZone>", files[0]["content"])
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-pro", {"general": {"timezone": "Mars/Base"}}
            )
        self.assertIn("timezone", cm.exception.detail["general"])
        self.assertEqual(len({z for z, _ in windows.TIMEZONES}), 139)

    def test_version_choices_per_target(self):
        def versions(target_id):
            meta = windows.profile_fields(target_id)["general.version"]
            return [c["value"] for c in meta["choices"]]

        self.assertEqual(versions("win11-pro"), ["23H2", "24H2", "25H2", "26H2"])
        self.assertEqual(versions("win10-pro"), ["22H2"])
        self.assertEqual(
            versions("win11-iot-enterprise"),
            ["23H2", "24H2", "25H2", "26H2", "ltsc2024"],
        )
        self.assertEqual(versions("win10-iot-enterprise"), ["22H2", "ltsc2021"])
        self.assertEqual(versions("server2019-standard-core"), ["1809"])
        self.assertEqual(versions("server2022-datacenter-desktop"), ["21H2"])
        self.assertEqual(versions("server2025-standard-desktop"), ["24H2"])
        for tgt in windows.TARGETS:
            with self.subTest(target=tgt["id"]):
                default = windows.profile_defaults(tgt["id"])["general"]["version"]
                self.assertIn(default, versions(tgt["id"]))
        # LTSC is IoT Enterprise only
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-enterprise", {"general": {"version": "ltsc2024"}}
            )
        self.assertIn("version", cm.exception.detail["general"])

    def test_version_picks_the_image_name(self):
        def image(target_id, general):
            clean = windows.validate_profile(target_id, {"general": general})
            files, _ = self._render(target_id, clean)
            root = ET.fromstring(files[0]["content"])
            return root.find(f".//{{{NS}}}MetaData/{{{NS}}}Value").text, clean

        name, clean = image("win11-iot-enterprise", {"version": "ltsc2024"})
        self.assertEqual(name, "Windows 11 IoT Enterprise LTSC 2024")
        self.assertTrue(any("LTSC has no Store" in n for n in clean["_warnings"]))
        # the form sends the default image name back; it follows the release
        name, _ = image(
            "win10-iot-enterprise",
            {"version": "ltsc2021", "image_name": "Windows 10 IoT Enterprise"},
        )
        self.assertEqual(name, "Windows 10 IoT Enterprise LTSC 2021")
        name, _ = image("win11-iot-enterprise", {"version": "24H2"})
        self.assertEqual(name, "Windows 11 IoT Enterprise")
        # a name typed by hand stays
        name, _ = image(
            "win11-iot-enterprise",
            {"version": "ltsc2024", "image_name": "Windows 11 IoT Enterprise N"},
        )
        self.assertEqual(name, "Windows 11 IoT Enterprise N")
        _, clean = image("win11-pro", {"version": "23H2"})
        self.assertTrue(any("November 2025" in n for n in clean["_warnings"]))

    def test_every_select_refuses_an_unknown_value(self):
        for target_id in ("win11-home", "win11-enterprise", "server2025-standard-core"):
            for path, meta in windows.profile_fields(target_id).items():
                if windows.field_choices(meta) is None:
                    continue
                section, key = path.split(".")
                # the values that show the field in the form
                shown = {
                    k.split(".")[1]: v[0] if isinstance(v, list) else v
                    for k, v in meta.get("show_if", {}).items()
                }
                for bad in ("nope", 99):
                    with self.subTest(target=target_id, path=path, value=bad):
                        with self.assertRaises(ValidationError) as cm:
                            windows.validate_profile(
                                target_id, {section: {**shown, key: bad}}
                            )
                        self.assertIn(key, cm.exception.detail[section])

    def test_every_choice_is_accepted(self):
        for path, meta in windows.profile_fields("win11-enterprise").items():
            section, key = path.split(".")
            for choice in windows.field_choices(meta) or []:
                value = choice["value"]
                with self.subTest(path=path, value=value):
                    windows.validate_profile(
                        "win11-enterprise", {section: {key: value}}
                    )

    # -- privacy ---------------------------------------------------------

    def _boot(self, target_id, profile):
        clean = windows.validate_profile(target_id, profile)
        files, _ = self._render(target_id, clean)
        return files[1]["content"], clean

    def test_privacy_maximum_on_home(self):
        boot, clean = self._boot(
            "win11-home", {"privacy": {"level": "maximum"}, "telemetry": {"level": 3}}
        )
        # one diagnostic data value, the lowest Home honours
        self.assertEqual(boot.count("AllowTelemetry"), 1)
        self.assertIn("DataCollection' 'AllowTelemetry' 1", boot)
        self.assertIn("foreach($s in 'DiagTrack','dmwappushservice')", boot)
        self.assertIn("Set-Service $s -StartupType Disabled", boot)
        for name in (
            "Microsoft Compatibility Appraiser",
            "Consolidator",
            "UsbCeip",
            "DmClient",
        ):
            self.assertIn(f"-TaskName '{name}'", boot)
        for value in (
            "AdvertisingInfo' 'DisabledByGroupPolicy' 1",
            "System' 'EnableActivityFeed' 0",
            "InputPersonalization' 'AllowInputPersonalization' 0",
            "InputPersonalization' 'RestrictImplicitInkCollection' 1",
            "Windows Error Reporting' 'Disabled' 1",
            "DataCollection' 'DoNotShowFeedbackNotifications' 1",
            "Windows Search' 'DisableWebSearch' 1",
            "DeliveryOptimization' 'DODownloadMode' 0",
            "WindowsAI' 'AllowRecallEnablement' 0",
            "WindowsAI' 'DisableAIDataAnalysis' 1",
        ):
            self.assertIn(value, boot)
        # per-user switches go to the default user profile
        hive = boot.index("reg.exe load $hive")
        self.assertIn("Users\\Default\\NTUSER.DAT", boot)
        self.assertLess(
            hive, boot.index("ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 0")
        )
        self.assertLess(hive, boot.index("Explorer' 'DisableSearchBoxSuggestions' 1"))
        self.assertLess(
            hive, boot.index("DisableTailoredExperiencesWithDiagnosticData' 1")
        )
        self.assertLess(
            boot.index("SubscribedContent-338388Enabled"), boot.index("reg.exe unload")
        )
        # a failed hive load is retried, then logged instead of written blind
        retry = boot.index("foreach($i in 1..20){reg.exe load $hive $ntu|Out-Null;")
        failed = boot.index("if($LASTEXITCODE){Log ('default user hive not loaded")
        self.assertLess(retry, failed)
        self.assertLess(
            failed, boot.index("ContentDeliveryManager' 'ContentDeliveryAllowed' 0")
        )
        self.assertIn(
            "reg.exe unload $hive|Out-Null; "
            "if($LASTEXITCODE){Log 'default user hive not unloaded'}}",
            boot,
        )
        self.assertLess(failed, boot.index("New-Item -ItemType File $done"))
        # Home cannot use the policies of Enterprise
        self.assertNotIn("DisableWindowsConsumerFeatures", boot)
        self.assertNotIn("DisableWindowsSpotlightFeatures", boot)
        self.assertIn(f"remove appx {windows._CP_APP}", boot)
        joined = " ".join(clean["_warnings"])
        self.assertIn("stays at Required", joined)
        self.assertIn("Spotlight policies work only on", joined)
        # the policies run once, before the agent
        self.assertLess(boot.index("DiagTrack"), boot.index("while(-not (Enrolled)){"))

    def test_privacy_home_mirrors_policies_in_user_and_service_switches(self):
        boot, clean = self._boot("win11-home", {"privacy": {"level": "maximum"}})
        self.assertIn("Search' 'CortanaConsent' 0", boot)
        self.assertIn("Siuf\\Rules' 'PeriodInNanoSeconds' 0", boot)
        self.assertIn("Set-Service WerSvc -StartupType Disabled", boot)
        self.assertIn(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' 'Disabled' 1",
            boot,
        )
        self.assertIn("DeliveryOptimization\\Config' 'DODownloadMode' 0", boot)
        self.assertIn("TrainedDataStore' 'HarvestContacts' 0", boot)
        self.assertIn("Input\\TIPC' 'Enabled' 0", boot)
        self.assertIn("DeliveryOptimization\\Settings' 'DownloadMode' 0", boot)
        # the policy lines stay
        self.assertIn("Windows Error Reporting' 'Disabled' 1", boot)
        self.assertIn("Home honours no machine policies", " ".join(clean["_warnings"]))

        boot, clean = self._boot("win10-home", {"privacy": {"level": "reduced"}})
        self.assertIn("CortanaConsent", boot)
        # Home turns tailored experiences off in Settings too (Reduced since
        # the switches; Maximum always did)
        tailored = "Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0"
        self.assertIn(tailored, boot)
        boot_tasks, _ = self._boot(
            "win11-home", {"privacy": {"level": "custom", "telemetry_tasks": True}}
        )
        self.assertNotIn(tailored, boot_tasks)
        self.assertNotIn("WerSvc", boot)
        self.assertNotIn("HarvestContacts", boot)

        boot, clean = self._boot("win11-pro", {"privacy": {"level": "maximum"}})
        self.assertNotIn("WerSvc", boot)
        self.assertNotIn("CortanaConsent", boot)
        self.assertNotIn("Home honours", " ".join(clean["_warnings"]))

    def test_privacy_maximum_on_enterprise_and_server(self):
        boot, clean = self._boot(
            "win11-enterprise",
            {"privacy": {"level": "maximum"}, "telemetry": {"level": 1}},
        )
        self.assertEqual(boot.count("AllowTelemetry"), 1)
        self.assertIn("DataCollection' 'AllowTelemetry' 0", boot)
        self.assertEqual(boot.count("DisableWindowsConsumerFeatures"), 1)
        self.assertIn("CloudContent' 'DisableWindowsSpotlightFeatures' 1", boot)
        self.assertEqual(clean["_warnings"], [])

        boot, _ = self._boot(
            "server2022-standard-core",
            {"privacy": {"level": "maximum"}, "admin": {"password": "Srv-1!"}},
        )
        self.assertIn("DataCollection' 'AllowTelemetry' 0", boot)
        self.assertIn("DiagTrack", boot)
        self.assertNotIn("WindowsAI", boot)
        self.assertNotIn(windows._CP, boot)

    def test_privacy_per_release(self):
        boot, _ = self._boot(
            "win11-pro",
            {"privacy": {"level": "maximum"}, "general": {"version": "23H2"}},
        )
        self.assertIn(f"Windows{windows._CP}' 'TurnOffWindows{windows._CP}' 1", boot)
        self.assertNotIn("remove appx", boot)
        self.assertNotIn("WindowsAI", boot)
        boot, _ = self._boot(
            "win11-iot-enterprise",
            {"privacy": {"level": "maximum"}, "general": {"version": "ltsc2024"}},
        )
        self.assertIn("AllowRecallEnablement", boot)
        self.assertNotIn(windows._CP, boot)
        boot, _ = self._boot("win10-pro", {"privacy": {"level": "maximum"}})
        self.assertIn(f"TurnOffWindows{windows._CP}", boot)
        self.assertNotIn("WindowsAI", boot)

    def test_privacy_reduced_and_default(self):
        boot, clean = self._boot(
            "win11-pro", {"privacy": {"level": "reduced"}, "telemetry": {"level": 3}}
        )
        self.assertIn("DataCollection' 'AllowTelemetry' 1", boot)
        self.assertIn("AdvertisingInfo' 'DisabledByGroupPolicy' 1", boot)
        self.assertIn("ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 0", boot)
        self.assertIn("Windows Search' 'DisableWebSearch' 1", boot)
        self.assertNotIn("DiagTrack", boot)
        self.assertNotIn("EnableActivityFeed", boot)
        self.assertNotIn("WindowsAI", boot)
        self.assertNotIn("stays at Required", " ".join(clean["_warnings"]))

        boot, clean = self._boot("win11-pro", {"telemetry": {"level": 3}})
        self.assertIn("DataCollection' 'AllowTelemetry' 3", boot)
        self.assertNotIn("Log 'privacy", boot)
        self.assertNotIn("reg.exe load", boot)
        self.assertEqual(clean["_warnings"], [])

    # one registry write (or step) per switch, on Enterprise 26H2 unless named
    SWITCH_WRITES = {
        "advertising_id": "AdvertisingInfo' 'DisabledByGroupPolicy' 1",
        "tailored_experiences": "DisableTailoredExperiencesWithDiagnosticData' 1",
        "activity_history": "System' 'EnableActivityFeed' 0",
        "location": "AppPrivacy' 'LetAppsAccessLocation' 2",
        "copilot": f"remove appx {windows._CP_APP}",
        "recall": "WindowsAI' 'AllowRecallEnablement' 0",
        "spotlight": "CloudContent' 'DisableWindowsSpotlightFeatures' 1",
        "consumer_content": "CloudContent' 'DisableWindowsConsumerFeatures' 1",
        "web_search": "Windows Search' 'DisableWebSearch' 1",
        "widgets": "Dsh' 'AllowNewsAndInterests' 0",
        "feedback": "DataCollection' 'DoNotShowFeedbackNotifications' 1",
        "onedrive": "OneDrive' 'DisableFileSyncNGSC' 1",
        "edge_telemetry": "Edge' 'DiagnosticData' 0",
        "input_personalization": "TextInput' 'AllowLinguisticDataCollection' 0",
        "speech": "InputPersonalization' 'AllowInputPersonalization' 0",
        "settings_suggestions": "ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 0",
        "error_reporting": "Windows Error Reporting' 'Disabled' 1",
        "cortana": "Windows Search' 'AllowCortana' 0",
        "find_my_device": "FindMyDevice' 'AllowFindMyDevice' 0",
        "tips": "CloudContent' 'DisableSoftLanding' 1",
        "telemetry_tasks": "foreach($s in 'DiagTrack','dmwappushservice')",
        "delivery_optimization": "DeliveryOptimization' 'DODownloadMode' 0",
    }

    def test_every_privacy_switch_writes_only_its_own_values(self):
        self.assertEqual(set(self.SWITCH_WRITES), set(windows._SWITCHES))
        for key, want in self.SWITCH_WRITES.items():
            version = "23H2" if key == "cortana" else "26H2"
            with self.subTest(switch=key):
                boot, clean = self._boot(
                    "win11-enterprise",
                    {
                        "privacy": {"level": "custom", key: True},
                        "general": {"version": version},
                    },
                )
                self.assertTrue(clean["privacy"][key])
                self.assertIn(want, boot)
                for other, value in self.SWITCH_WRITES.items():
                    if other != key:
                        self.assertNotIn(value, boot, other)
        boot, clean = self._boot("win11-enterprise", {"privacy": {"level": "custom"}})
        self.assertNotIn("Log 'privacy", boot)
        for value in self.SWITCH_WRITES.values():
            self.assertNotIn(value, boot)
        self.assertEqual(clean["_warnings"], [])

    def test_privacy_presets_render_as_the_level(self):
        # the form applies a preset's values; the result renders exactly like
        # a stored profile that names only the level
        for tgt in windows.TARGETS:
            presets = tgt["presets"]["privacy.level"]
            fields = windows.profile_fields(tgt["id"])
            self.assertEqual(set(presets), {"default", "reduced", "maximum"})
            admin = {"password": "Srv-1!"} if tgt["defaults"]["server"] else {}
            for level, values in presets.items():
                self.assertTrue(set(values) <= set(fields), tgt["id"])
                for version in tgt["versions"]:
                    with self.subTest(target=tgt["id"], level=level, version=version):
                        old = {
                            "admin": admin,
                            "general": {"version": version},
                            "privacy": {"level": level},
                            "telemetry": {"level": tgt["defaults"]["telemetry"]},
                        }
                        form = {
                            "admin": admin,
                            "general": {"version": version},
                            "privacy": {"level": level},
                            "telemetry": {},
                        }
                        for path, value in values.items():
                            section, key = path.split(".")
                            form[section][key] = value
                        self.assertEqual(
                            self._boot(tgt["id"], old)[0],
                            self._boot(tgt["id"], form)[0],
                        )
        # Pro gets no Enterprise-only switch from a preset
        pro = windows.target("win11-pro")["presets"]["privacy.level"]["maximum"]
        self.assertFalse(pro["privacy.spotlight"])
        self.assertFalse(pro["privacy.consumer_content"])
        self.assertTrue(pro["privacy.recall"])
        self.assertEqual(pro["telemetry.level"], 1)
        srv = windows.target("server2022-standard-core")["presets"]["privacy.level"]
        self.assertFalse(srv["maximum"]["privacy.copilot"])
        self.assertEqual(srv["reduced"]["telemetry.level"], 0)

    def test_privacy_switches_beat_the_level(self):
        boot, clean = self._boot(
            "win11-pro",
            {
                "privacy": {
                    "level": "reduced",
                    "advertising_id": False,
                    "location": True,
                }
            },
        )
        self.assertFalse(clean["privacy"]["advertising_id"])
        # the switches not given follow the level
        self.assertTrue(clean["privacy"]["web_search"])
        self.assertFalse(clean["privacy"]["activity_history"])
        self.assertNotIn("DisabledByGroupPolicy", boot)
        self.assertIn("Windows Search' 'DisableWebSearch' 1", boot)
        self.assertIn("LocationAndSensors' 'DisableLocation' 1", boot)

    def test_privacy_switches_follow_the_release(self):
        # hidden by the release: not checked, back to off
        clean = windows.validate_profile(
            "win11-pro",
            {
                "privacy": {"level": "custom", "recall": True, "cortana": True},
                "general": {"version": "23H2"},
            },
        )
        self.assertFalse(clean["privacy"]["recall"])
        self.assertTrue(clean["privacy"]["cortana"])
        clean = windows.validate_profile(
            "win11-pro",
            {"privacy": {"level": "custom", "recall": True, "cortana": True}},
        )
        self.assertTrue(clean["privacy"]["recall"])
        self.assertFalse(clean["privacy"]["cortana"])
        fields = windows.profile_fields("win11-pro")
        self.assertEqual(
            fields["privacy.recall"]["show_if"],
            {"general.version": ["24H2", "25H2", "26H2"]},
        )
        self.assertEqual(
            fields["privacy.copilot"]["show_if"],
            {"general.version": ["23H2", "24H2", "25H2", "26H2"]},
        )
        self.assertEqual(
            fields["privacy.cortana"]["show_if"], {"general.version": ["23H2"]}
        )
        ltsc = windows.profile_fields("win11-iot-enterprise")
        self.assertIn("ltsc2024", ltsc["privacy.recall"]["show_if"]["general.version"])
        self.assertNotIn(
            "ltsc2024", ltsc["privacy.copilot"]["show_if"]["general.version"]
        )

    def test_privacy_switches_the_edition_lacks_are_refused(self):
        for target_id, key, cap in (
            ("win11-pro", "spotlight", "consumer_policy"),
            ("win11-home", "consumer_content", "consumer_policy"),
            ("win11-pro", "tips", "consumer_policy"),
            ("server2025-standard-desktop", "copilot", "assistant_recall"),
            ("server2025-standard-desktop", "recall", "assistant_recall"),
            ("server2022-standard-core", "widgets", "client_apps"),
            ("server2019-standard-core", "cortana", "client_apps"),
        ):
            with self.subTest(target=target_id, switch=key):
                self.assertEqual(
                    windows.profile_fields(target_id)[f"privacy.{key}"]["capability"],
                    cap,
                )
                self.assertFalse(windows.target(target_id)["capabilities"][cap])
                with self.assertRaises(ValidationError) as cm:
                    windows.validate_profile(
                        target_id, {"privacy": {"level": "custom", key: True}}
                    )
                self.assertEqual(
                    str(cm.exception.detail["privacy"][key]),
                    windows._EDITION_REASON[cap],
                )
        # an unknown level is refused, Custom is accepted
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile("win11-pro", {"privacy": {"level": "strict"}})
        self.assertIn("level", cm.exception.detail["privacy"])
        with self.assertRaises(ValidationError):
            windows.validate_profile("win11-pro", {"privacy": {"level": ["maximum"]}})
        clean = windows.validate_profile("win11-pro", {"privacy": {"level": "custom"}})
        self.assertFalse(any(clean["privacy"][k] for k in windows._SWITCHES))

    def test_consumer_policy_alias(self):
        # older profiles name the switch under debloat
        boot, clean = self._boot(
            "win11-enterprise",
            {"debloat": {"consumer_policy": True, "appx": ["Microsoft.XboxApp"]}},
        )
        self.assertTrue(clean["privacy"]["consumer_content"])
        self.assertEqual(clean["privacy"]["level"], "default")
        self.assertEqual(clean["debloat"], {"appx": ["Microsoft.XboxApp"]})
        self.assertEqual(boot.count("DisableWindowsConsumerFeatures"), 1)
        self.assertNotIn("Log 'privacy", boot)
        self.assertNotIn(
            "debloat.consumer_policy", windows.profile_fields("win11-enterprise")
        )
        boot, clean = self._boot(
            "win11-enterprise", {"debloat": {"consumer_policy": False}}
        )
        self.assertNotIn("privacy", clean)
        self.assertNotIn("DisableWindowsConsumerFeatures", boot)
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-pro", {"debloat": {"consumer_policy": True}}
            )
        self.assertEqual(
            str(cm.exception.detail["debloat"]["consumer_policy"]),
            windows._EDITION_REASON["consumer_policy"],
        )
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile(
                "win11-enterprise", {"debloat": {"consumer_policy": "maybe"}}
            )
        self.assertIn("consumer_policy", cm.exception.detail["debloat"])

    def test_privacy_fields_metadata(self):
        for tgt in windows.TARGETS:
            fields = windows.profile_fields(tgt["id"])
            with self.subTest(target=tgt["id"]):
                self.assertTrue(fields["privacy.level"]["preset"])
                self.assertEqual(fields["privacy.level"]["order"], 0)
                self.assertEqual(fields["telemetry.level"]["group"], "privacy")
                self.assertEqual(fields["telemetry.level"]["order"], 1)
                orders = [fields[f"privacy.{k}"]["order"] for k in windows._SWITCHES]
                self.assertEqual(orders, sorted(set(orders)))
                for path, meta in fields.items():
                    self.assertLessEqual(len(meta["label"]), 28, path)
                    self.assertLessEqual(len(meta.get("help", "")), 120, path)
                    if not path.startswith(("privacy.", "telemetry.")):
                        continue
                    self.assertEqual(meta["group"], "privacy")
                    self.assertEqual(meta["help"].count(". "), 0, path)
                    for choice in meta.get("choices", []):
                        self.assertLessEqual(len(choice["label"]), 40, path)
                        self.assertLessEqual(len(choice["help"]), 120, path)
        for reason in windows._EDITION_REASON.values():
            self.assertLessEqual(len(reason), 120, reason)

    def test_oobe_privacy_questions(self):
        files, _ = self._render("win11-pro", windows.validate_profile("win11-pro", {}))
        self.assertIn("<ProtectYourPC>3</ProtectYourPC>", files[0]["content"])
        clean = windows.validate_profile(
            "win11-pro", {"oobe": {"skip_privacy_questions": False}}
        )
        files, _ = self._render("win11-pro", clean)
        self.assertNotIn("ProtectYourPC", files[0]["content"])
        self.assertIn("HideEULAPage", files[0]["content"])

    # -- ssh -------------------------------------------------------------

    def test_ssh_key_auth_writes_the_admin_key_file_with_its_acl(self):
        other = _pubkey("second")
        boot, _ = self._boot(
            "win11-pro",
            {
                "ssh": {
                    "enable": True,
                    "auth": "key",
                    "authorized_keys": f"{KEY}\n\n{other}\n",
                }
            },
        )
        loop = boot.index("while(-not (Enrolled)){")
        start = boot.index("Log 'ssh server'")
        self.assertLess(loop, start)
        self.assertLess(start, boot.index("schtasks /Delete"))
        self.assertIn(
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0", boot
        )
        self.assertIn("Set-Service sshd -StartupType Automatic", boot)
        self.assertIn("'administrators_authorized_keys'", boot)
        self.assertIn(f"(@'\n{KEY}\n{other}\n'@)", boot)
        self.assertIn(
            "icacls $ak /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'", boot
        )
        self.assertLess(boot.index("WriteAllText($ak"), boot.index("icacls $ak"))
        self.assertIn("'PubkeyAuthentication yes','PasswordAuthentication no'", boot)
        self.assertIn("New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'", boot)
        self.assertIn("-LocalPort 22", boot)
        self.assertLess(boot.index("sshd_config"), boot.index("Restart-Service sshd"))

    def test_ssh_password_and_both(self):
        boot, _ = self._boot(
            "server2025-standard-core",
            {
                "admin": {"password": "Srv-1!"},
                "ssh": {"enable": True, "auth": "password", "authorized_keys": KEY},
            },
        )
        self.assertIn("'PubkeyAuthentication no','PasswordAuthentication yes'", boot)
        self.assertNotIn("administrators_authorized_keys", boot)
        boot, _ = self._boot(
            "win11-home",
            {"ssh": {"enable": True, "auth": "both", "authorized_keys": KEY}},
        )
        self.assertIn("'PubkeyAuthentication yes','PasswordAuthentication yes'", boot)
        self.assertIn(KEY, boot)
        boot, _ = self._boot(
            "win11-home", {"ssh": {"enable": False, "authorized_keys": KEY}}
        )
        self.assertNotIn("sshd", boot)

    def test_ssh_validation(self):
        on = {"enable": True, "auth": "key"}
        for ssh, field in (
            (on, "authorized_keys"),
            ({**on, "authorized_keys": " \n"}, "authorized_keys"),
            ({**on, "authorized_keys": "ssh-ed25519 AAAA"}, "authorized_keys"),
            (
                {"enable": True, "auth": "both", "authorized_keys": f"{KEY}\nbad"},
                "authorized_keys",
            ),
            (
                {**on, "authorized_keys": KEY.replace("ssh-ed25519", "ssh-rsa", 1)},
                "authorized_keys",
            ),
            ({"enable": True, "auth": "telnet", "authorized_keys": KEY}, "auth"),
        ):
            with self.subTest(ssh=ssh):
                with self.assertRaises(ValidationError) as cm:
                    windows.validate_profile("win11-pro", {"ssh": ssh})
                self.assertIn(field, cm.exception.detail["ssh"])
        # the message names the choice, as on Linux
        with self.assertRaises(ValidationError) as cm:
            windows.validate_profile("win11-pro", {"ssh": {"enable": True}})
        self.assertIn(
            "Key only needs at least one key",
            str(cm.exception.detail["ssh"]["authorized_keys"]),
        )
        clean = windows.validate_profile(
            "win11-pro", {"ssh": {"enable": True, "auth": "password"}}
        )
        self.assertEqual(clean["ssh"]["auth"], "password")

    def test_ssh_both_without_a_key_signs_in_with_the_password(self):
        boot, clean = self._boot("win11-pro", {"ssh": {"enable": True, "auth": "both"}})
        self.assertEqual(clean["ssh"]["authorized_keys"], "")
        self.assertIn("'PubkeyAuthentication yes','PasswordAuthentication yes'", boot)
        self.assertNotIn("administrators_authorized_keys", boot)

    def test_fields_the_form_hides_are_not_validated(self):
        for ssh in (
            # keys hidden by password sign-in
            {"enable": True, "auth": "password", "authorized_keys": "garbage"},
            # the whole SSH card switched off
            {"enable": False, "auth": "telnet", "authorized_keys": "garbage"},
            {"enable": False, "auth": "key"},
        ):
            with self.subTest(ssh=ssh):
                boot, clean = self._boot("win11-pro", {"ssh": ssh})
                # what the form hides goes back to its default
                self.assertEqual(clean["ssh"]["authorized_keys"], "")
                self.assertNotIn("garbage", boot)
                if not ssh["enable"]:
                    self.assertEqual(clean["ssh"]["auth"], "key")
                    self.assertNotIn("sshd", boot)
        clean = windows.validate_profile(
            "win11-pro", {"remote": {"rdp": False, "nla": False}}
        )
        self.assertTrue(clean["remote"]["nla"])

    def test_dump_artifacts(self):
        out = os.environ.get("ULRMM_DUMP_ART")
        if not out:
            self.skipTest("set ULRMM_DUMP_ART to write artifacts for validators")
        os.makedirs(out, exist_ok=True)
        profiles = {
            "win11-home": {"debloat": {"appx": ["Microsoft.XboxApp"]}},
            "win11-pro": {"remote": {"rdp": True}, "encryption": {"bitlocker": True}},
            "win11-enterprise": {
                "uwf": {"enabled": True},
                "telemetry": {"level": 0},
                "debloat": {"consumer_policy": True},
                "domain": {"domain": "corp.lan", "username": "svc", "password": "jp"},
            },
            "win11-iot-enterprise": {"uwf": {"enabled": True}},
            "server2022-standard-core": {
                "admin": {"password": "Srv-1!"},
                "encryption": {"bitlocker": True},
            },
            "server2025-datacenter-desktop": {"admin": {"password": "Srv-2!"}},
        }
        rich = {
            "privacy": {"level": "maximum"},
            "ssh": {"enable": True, "auth": "both", "authorized_keys": KEY},
            "remote": {"rdp": True},
            "firewall": {"allow": ["443/tcp"]},
        }
        for tgt in windows.TARGETS:
            admin = {"password": "Srv-3!"} if tgt["defaults"]["server"] else {}
            profiles.setdefault(f"{tgt['id']}", {**rich, "admin": admin})
        profiles["win11-pro-23h2"] = {**rich, "general": {"version": "23H2"}}
        profiles["win11-iot-enterprise-ltsc"] = {
            **rich,
            "general": {"version": "ltsc2024"},
        }
        for name, profile in profiles.items():
            target_id = name.replace("-23h2", "").replace("-ltsc", "")
            profile = windows.validate_profile(target_id, profile)
            files, _ = self._render(target_id, profile)
            target_id = name
            for f in files:
                ext = {"xml": "xml", "powershell": "ps1"}.get(f["language"], "txt")
                safe = f["name"].replace("/", "_")
                path = os.path.join(out, f"{target_id}__{safe}")
                if not path.endswith((".xml", ".ps1", ".cmd", ".txt")):
                    path += f".{ext}"
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(f["content"])


@override_settings(CERT_FILE="/nonexistent", KEY_FILE="/nonexistent")
class TestBundleZip(ULRMMTestCase):
    def test_bundle_members(self):
        from deploy import bundle

        site = baker.make("clients.Site")
        deployment = baker.make(
            "clients.Deployment",
            site=site,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": False, "ping": False, "rdp": False},
        )
        with mock.patch.object(windows, "_agent_install_ps1", return_value=AGENT_STUB):
            files, _ = windows.render("win11-pro", deployment, {})
            name, blob = bundle.build_bundle(windows, "win11-pro", deployment, files)
        self.assertTrue(name.endswith(".zip"))
        with zipfile.ZipFile(BytesIO(blob)) as zf:
            members = set(zf.namelist())
        self.assertIn("autounattend.xml", members)
        self.assertIn("README.txt", members)
        self.assertIn("inject-xorriso.sh", members)
        self.assertIn("inject-oscdimg.ps1", members)
        self.assertTrue(any(m.endswith("-bootstrap.ps1") for m in members))

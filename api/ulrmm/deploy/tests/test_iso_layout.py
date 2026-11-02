# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import re
import subprocess
from pathlib import Path
from unittest import mock

import yaml
from django.conf import settings
from django.utils import timezone as djangotime
from model_bakery import baker

from deploy import installers, iso_layout, linux, signing, windows
from deploy.signing import EnrollmentError
from ulrmm.test import ULRMMTestCase

ORIGINAL_AGENT_PS1 = windows._agent_install_ps1
BOOT = "#!/usr/bin/env bash\necho enroll\n"
AGENT_STUB = "# agent install\nWrite-Output 'enroll'\n"
GRUB = "menuentry x {\n\tlinux /casper/vmlinuz ---\n\tinitrd /casper/initrd\n}\n"
ISOLINUX = (
    "default harddisk\ntimeout 0\nlabel linux\n  append initrd=/boot/initrd splash\n"
)


def _layout_paths(layout):
    return [path for path, _ in layout.files]


class Base(ULRMMTestCase):
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
        for patcher in (
            mock.patch.object(windows, "_agent_install_ps1", return_value=AGENT_STUB),
            mock.patch.object(linux, "_bootstrap", return_value=BOOT),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def win_files(self, target_id="win11-pro"):
        return windows.render(target_id, self.deployment, {})[0]

    def linux_files(self, target_id):
        form = linux.profile_defaults(target_id)
        form["disk"]["device"] = "/dev/sda"
        clean = linux.validate_profile(target_id, form)
        return linux.render(target_id, self.deployment, clean)[0]


class TestConfig(Base):
    def test_signed_document(self):
        jws = iso_layout.config_jws(self.deployment)
        claims = signing.verify(jws, typ=iso_layout.CONFIG_TYP)
        for key in ("cli", "site", "pol", "pins", "tok"):
            self.assertIn(key, claims)
        self.assertEqual(claims["site"], self.site.pk)
        self.assertEqual(signing.verify(claims["tok"])["dep"], claims["dep"])

    def test_not_an_enrollment_token(self):
        jws = iso_layout.config_jws(self.deployment)
        with self.assertRaises(EnrollmentError):
            signing.verify(jws)

    def test_paths_are_checked(self):
        for bad in ("/a/../b", "/a/./b", "a/b", "/a//b", "/a\\b", "/"):
            with self.assertRaises(ValueError, msg=bad):
                iso_layout.Layout(None, [(bad, b"")])
        iso_layout.Layout(None, [("/$OEM$/$$/Setup/Scripts/a-b_c.cmd", b"")])


class TestWindows(Base):
    def test_seed(self):
        layout = iso_layout.seed("win11-pro", self.deployment, self.win_files(), None)
        paths = _layout_paths(layout)
        self.assertEqual(layout.label, "AUTOUNATTEND")
        self.assertEqual(paths.count("/autounattend.xml"), 1)
        for path in (
            "/ulrmm/config.jws",
            "/ulrmm/config.pub",
            "/README.txt",
        ):
            self.assertIn(path, paths)
        files = dict(layout.files)
        self.assertTrue(files["/autounattend.xml"].startswith(b"<?xml"))
        self.assertIn(b"BEGIN PUBLIC KEY", files["/ulrmm/config.pub"])
        self.assertEqual(layout.edits, {})
        # the scripts hold the token and travel only inside the answer file
        self.assertFalse([p for p in paths if "/$$/" in p])
        self.assertIn(b"SetupComplete.cmd", files["/autounattend.xml"])

    def test_seed_leaves_the_agent_to_the_download(self):
        # Setup ignores $OEM$ on a second drive (live run, up to 12%)
        agent = ("agent-amd64.exe", b"MZ")
        layout = iso_layout.seed("win11-pro", self.deployment, self.win_files(), agent)
        self.assertFalse([p for p in _layout_paths(layout) if "$OEM$" in p])
        self.assertTrue(layout.notes)
        readme = dict(layout.files)["/README.txt"]
        self.assertNotIn(b"$OEM$", readme)

    def test_home_edition(self):
        files = self.win_files("win11-home")
        self.assertNotIn("UnattendedJoin", files[0]["content"])
        layout = iso_layout.seed("win11-home", self.deployment, files, None)
        paths = _layout_paths(layout)
        self.assertEqual(layout.label, "AUTOUNATTEND")
        self.assertIn("/autounattend.xml", paths)
        self.assertIn("/ulrmm/config.jws", paths)

    def test_full(self):
        files = self.win_files()
        agent = ("agent-amd64.exe", b"MZ")
        base = {"label": "CCCOMA_X64FRE", "os": "windows"}
        layout = iso_layout.full("win11-pro", self.deployment, files, agent, base)
        self.assertIsNone(layout.label)
        self.assertEqual(layout.notes, [])
        paths = _layout_paths(layout)
        self.assertIn("/autounattend.xml", paths)
        # Setup stages $OEM$ only from sources\ of the install media
        self.assertIn("/sources/$OEM$/$1/ulrmm/agent-amd64.exe", paths)
        self.assertFalse([p for p in paths if p.startswith("/$OEM$")])
        self.assertFalse([p for p in paths if "/$$/" in p])
        other = iso_layout.full(
            "win11-pro", self.deployment, files, agent, {"os": "ubuntu"}
        )
        self.assertEqual(len(other.notes), 1)

    def test_dotdot_in_a_file_name(self):
        with self.assertRaises(ValueError):
            iso_layout.full(
                "win11-pro",
                self.deployment,
                self.win_files(),
                ("../a.exe", b"MZ"),
                {"os": "windows"},
            )

    def test_bootstrap_prefers_the_local_exe(self):
        template = Path(settings.BASE_DIR, "core", "installer.ps1").read_text()
        with mock.patch.object(installers, "bootstrap_ps1", return_value=template):
            text = ORIGINAL_AGENT_PS1(self.deployment, "amd64")
        self.assertIn("'ulrmm\\*.exe'", text)
        self.assertIn("Copy-Item -LiteralPath $local.FullName", text)
        # the download and its sha256 check stay for the other branch
        self.assertEqual(text.count("Invoke-WebRequest"), 1)
        self.assertEqual(text.count("Get-FileHash"), 1)


class TestLinux(Base):
    def test_kickstart_seed(self):
        files = self.linux_files("rhel-9")
        layout = iso_layout.seed("rhel-9", self.deployment, files, None)
        self.assertEqual(layout.label, "OEMDRV")
        self.assertEqual(
            sorted(_layout_paths(layout)),
            ["/ks.cfg", "/ulrmm/config.jws", "/ulrmm/config.pub"],
        )

    def test_agent_package_on_the_seed(self):
        files = self.linux_files("rhel-9")
        layout = iso_layout.seed("rhel-9", self.deployment, files, ("a.rpm", b"x"))
        self.assertEqual(dict(layout.files)["/ulrmm/a.rpm"], b"x")

    def test_ubuntu_seed(self):
        for target in ("ubuntu-22.04", "ubuntu-24.04"):
            files = self.linux_files(target)
            layout = iso_layout.seed(target, self.deployment, files, None)
            self.assertEqual(layout.label, "CIDATA")
            data = dict(layout.files)
            self.assertIn("/meta-data", data)
            text = data["/user-data"].decode()
            self.assertTrue(text.startswith("#cloud-config\n"))
            self.assertEqual(list(yaml.safe_load(text)), ["autoinstall"], target)
            self.assertEqual(yaml.safe_load(text)["autoinstall"]["version"], 1)
            self.assertTrue(layout.notes)

    def test_other_seeds(self):
        cases = {
            "debian-12": ("PRESEED", "/preseed.cfg"),
            "sles-15": ("OEMDRV", "/autoinst.xml"),
            "sles-16": ("OEMDRV", "/agama-profile.json"),
            "arch": ("ARCHINSTALL", "/run-archinstall.sh"),
        }
        for target, (label, path) in cases.items():
            layout = iso_layout.seed(
                target, self.deployment, self.linux_files(target), None
            )
            self.assertEqual(layout.label, label, target)
            self.assertIn(path, _layout_paths(layout), target)

    def test_full_ubuntu_menus(self):
        files = self.linux_files("ubuntu-24.04")
        base = {"label": "Ubuntu-Server 24.04 amd64", "os": "ubuntu"}
        layout = iso_layout.full("ubuntu-24.04", self.deployment, files, None, base)
        self.assertIsNone(layout.label)
        self.assertIn("/autoinstall.yaml", _layout_paths(layout))
        self.assertIn("/boot/grub/grub.cfg", layout.edits)
        self.assertEqual(
            len(layout.edits), len(linux._ISO_MENUS.split()), "every menu has an edit"
        )
        out = layout.edits["/boot/grub/grub.cfg"](GRUB.encode()).decode()
        self.assertIn("\tlinux /casper/vmlinuz autoinstall ---\n", out)
        self.assertTrue(out.endswith("\nset timeout=5\n"))
        out = layout.edits["/isolinux/txt.cfg"](ISOLINUX.encode()).decode()
        self.assertEqual(
            out,
            "default linux\ntimeout 50\nlabel linux\n"
            "  append autoinstall initrd=/boot/initrd splash\n",
        )

    def test_full_debian_speech_menu(self):
        files = self.linux_files("debian-13")
        base = {"label": "Debian 13.7.0 amd64 n", "os": "debian"}
        layout = iso_layout.full("debian-13", self.deployment, files, None, base)
        spk = (
            "default installspk\ntimeout 300\n"
            "ontimeout /install.amd/vmlinuz vga=788 speakup.synth=soft\n"
            "label installspk\n  append initrd=/install.amd/initrd.gz quiet\n"
        )
        out = layout.edits["/isolinux/spkgtk.cfg"](spk.encode()).decode()
        self.assertNotIn("ontimeout", out)
        self.assertIn("append auto=true priority=critical preseed/file=", out)

    def test_full_rhel_skips_the_media_check(self):
        files = self.linux_files("rocky-10")
        base = {"label": "Rocky-10-2-x86_64-dvd", "os": "rhel"}
        layout = iso_layout.full("rocky-10", self.deployment, files, None, base)
        grub = (
            'set default="1"\nmenuentry "Test this media" {\n'
            "\tlinuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=R"
            " rd.live.check quiet\n}\n"
        )
        out = layout.edits["/EFI/BOOT/grub.cfg"](grub.encode()).decode()
        self.assertNotIn("rd.live.check", out)
        self.assertIn("vmlinuz inst.ks=hd:LABEL=Rocky-10-2-x86_64-dvd:/ks.cfg", out)
        isolinux = (
            "label check\n  menu default\n"
            "  append initrd=initrd.img inst.stage2=hd:LABEL=R rd.live.check quiet\n"
        )
        out = layout.edits["/isolinux/isolinux.cfg"](isolinux.encode()).decode()
        self.assertNotIn("rd.live.check", out)

    def test_full_leap_label(self):
        files = self.linux_files("leap-15")
        base = {"label": "openSUSE-Leap-15.6-NET-x86_64", "os": "suse"}
        layout = iso_layout.full("leap-15", self.deployment, files, None, base)
        out = layout.edits["/EFI/BOOT/grub.cfg"](GRUB.encode()).decode()
        self.assertIn(
            "vmlinuz autoyast=label://openSUSE-Leap-15.6-NET-x86_64/autoinst.xml",
            out,
        )

    def test_full_ubuntu_2204_nocloud(self):
        files = self.linux_files("ubuntu-22.04")
        layout = iso_layout.full(
            "ubuntu-22.04", self.deployment, files, None, {"label": "U", "os": "ubuntu"}
        )
        paths = _layout_paths(layout)
        self.assertIn("/nocloud/user-data", paths)
        self.assertIn("/nocloud/meta-data", paths)
        out = layout.edits["/boot/grub/grub.cfg"](GRUB.encode()).decode()
        self.assertIn('autoinstall "ds=nocloud;s=/cdrom/nocloud/" ---', out)

    def test_full_kickstart_label(self):
        files = self.linux_files("rhel-9")
        base = {"label": "RHEL-9-0-BaseOS-x86_64", "os": "rhel"}
        layout = iso_layout.full("rhel-9", self.deployment, files, None, base)
        self.assertIn("/ks.cfg", _layout_paths(layout))
        out = layout.edits["/EFI/BOOT/grub.cfg"](GRUB.encode()).decode()
        self.assertIn(
            "vmlinuz inst.ks=hd:LABEL=RHEL-9-0-BaseOS-x86_64:/ks.cfg ---", out
        )
        with self.assertRaises(ValueError):
            iso_layout.full("rhel-9", self.deployment, files, None, {"os": "rhel"})

    def test_full_notes_a_foreign_base(self):
        files = self.linux_files("debian-12")
        layout = iso_layout.full(
            "debian-12",
            self.deployment,
            files,
            ("a.deb", b"x"),
            {"label": "D", "os": "ubuntu"},
        )
        self.assertEqual(len(layout.notes), 2)
        self.assertIn("does not match", layout.notes[0])
        # a full image left attached would install again on the next boot
        self.assertIn("installs again", layout.notes[1])
        self.assertIn("/preseed.cfg", _layout_paths(layout))

    def test_full_arch(self):
        files = self.linux_files("arch")
        layout = iso_layout.full(
            "arch", self.deployment, files, None, {"label": "ARCH", "os": "arch"}
        )
        self.assertEqual(layout.edits, {})
        self.assertIn("/run-archinstall.sh", _layout_paths(layout))

    def test_unknown_target(self):
        with self.assertRaises(ValueError):
            iso_layout.seed("nope", self.deployment, [], None)


class TestAgentPayload(Base):
    def test_windows(self):
        with mock.patch.object(
            installers, "setup_exe", return_value=([b"MZ", b"ab"], 4, False)
        ) as exe:
            name, body = iso_layout.agent_payload(
                self.deployment, "windows", "win11-pro"
            )
        exe.assert_called_once_with(self.deployment, "amd64")
        self.assertEqual(name, "agent-amd64.exe")
        self.assertEqual(body, b"MZab")

    def test_long_client_and_site_names(self):
        # the download name ran past Joliet's 64 characters and the build
        # failed with "invalid path"
        self.site.client.name = "Mustermann Steuerberatung GmbH und Partner"
        self.site.client.save()
        self.site.name = "Berlin Charlottenburg Hauptstelle"
        self.site.save()
        with mock.patch.object(installers, "build_deb", return_value=b"p"):
            agent = iso_layout.agent_payload(self.deployment, "linux", "debian-13")
        files = self.linux_files("debian-13")
        base = {"label": "Debian 13.7.0 amd64 n", "os": "debian"}
        layout = iso_layout.full("debian-13", self.deployment, files, agent, base)
        self.assertIn("/ulrmm/agent-amd64.deb", _layout_paths(layout))

    def test_linux_formats(self):
        for target, fmt in (
            ("ubuntu-24.04", "deb"),
            ("debian-12", "deb"),
            ("rhel-9", "rpm"),
            ("sles-15", "rpm"),
            ("arch", "tgz"),
        ):
            with mock.patch.object(installers, f"build_{fmt}", return_value=b"p") as b:
                name, body = iso_layout.agent_payload(self.deployment, "linux", target)
            b.assert_called_once_with(self.deployment, "amd64")
            self.assertEqual(body, b"p")
            self.assertTrue(re.fullmatch(r"agent-amd64\.(deb|rpm|tar\.gz)", name), name)

    def test_unavailable(self):
        with mock.patch.object(
            installers, "setup_exe", side_effect=installers.Unavailable("no build")
        ):
            self.assertIsNone(
                iso_layout.agent_payload(self.deployment, "windows", "win11-pro")
            )
        with mock.patch.object(
            installers, "build_deb", side_effect=installers.Unavailable("no build")
        ):
            self.assertIsNone(
                iso_layout.agent_payload(self.deployment, "linux", "ubuntu-24.04")
            )

    def test_arch_without_a_build(self):
        self.deployment.goarch = "mips"
        with mock.patch.object(installers, "build_deb") as build:
            self.assertIsNone(
                iso_layout.agent_payload(self.deployment, "linux", "ubuntu-24.04")
            )
        build.assert_not_called()


class TestLocalAgent(Base):
    def _decoded(self, cmds):
        out = []
        for cmd in cmds:
            m = re.match(r"printf %s (\S+) \| base64 -d > (\S+)$", cmd)
            if m:
                out.append((m.group(2), base64.b64decode(m.group(1)).decode()))
        return dict(out)

    def test_first_boot_looks_at_the_seed(self):
        _, _, script_path, unit_path = linux._ident_paths()
        written = self._decoded(linux._inject_cmds(self.deployment))
        local = script_path.rsplit("/", 1)[0] + "/local.sh"
        self.assertIn("/var/lib/ulrmm-seed", written[local])
        self.assertIn("/run/install/repo/ulrmm", written[local])
        self.assertIn(
            f"ExecStartPre=-/bin/bash {local} {script_path}", written[unit_path]
        )
        self.assertEqual(written[script_path], BOOT)
        r = subprocess.run(
            ["bash", "-n"], input=written[local], capture_output=True, text=True
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_without_a_package_the_script_fails_over(self):
        local = linux._LOCAL_PKG.replace(
            "/var/lib/ulrmm-seed /cdrom/ulrmm", "/nonexistent"
        )
        r = subprocess.run(["bash", "-c", local, "x", "/dev/null"], capture_output=True)
        self.assertEqual(r.returncode, 1)

    def test_copy_from_the_media(self):
        ks = self.linux_files("rhel-9")[0]["content"]
        self.assertIn("%post --nochroot", ks)
        self.assertIn(
            "cp -a /run/install/repo/ulrmm /mnt/sysimage/var/lib/ulrmm-seed", ks
        )
        auto = self.linux_files("ubuntu-24.04")[0]["content"]
        self.assertIn("cp -a /cdrom/ulrmm /target/var/lib/ulrmm-seed", auto)
        pre = self.linux_files("debian-12")[0]["content"]
        self.assertIn("cp -a /cdrom/ulrmm /target/var/lib/ulrmm-seed", pre)
        yast = self.linux_files("sles-15")[0]["content"]
        self.assertIn("cp -a /var/adm/mount/ulrmm /mnt/var/lib/ulrmm-seed", yast)

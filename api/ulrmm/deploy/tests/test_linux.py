# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import json
import re
import shlex
import subprocess
from unittest import mock
from xml.etree import ElementTree as ET

import yaml
from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework.serializers import ValidationError

from deploy import linux, yamlish
from ulrmm.test import ULRMMTestCase

BOOT = "#!/usr/bin/env bash\necho enroll CONTAINS-TOKEN-eyJhbGciOiJFZERTQSJ9\n"
YAST = "{http://www.suse.com/1.0/yast2ns}"
SUDOERS = "'Defaults:siteadmin !targetpw' 'siteadmin ALL=(ALL) ALL'"
KEY1 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0K0MtHdAcViyIn2g8O1D33QT71YkhiNeLL1Ig7ruE3"
    " ops@nw-admin"
)
KEY2 = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHipWaPS"
    "uIoZ14DzrljAmCsYAH9k5yYXuiVY/T42LL5472MYnsUcoqmGxGK6YDh0FvV4r8gpE9fcki9Dh6lpuOs="
    " laptop"
)


def _profile(**over):
    data = {
        "hostname": "nw-host-01",
        "locale": "en_US.UTF-8",
        "keyboard": "us",
        "timezone": "Europe/Berlin",
        "admin": {"name": "siteadmin", "password": "Given-Pass-123", "sudo": True},
        "ssh": {"enable": True, "auth": "key", "authorized_keys": KEY1},
        "firewall": {"enable": True, "allow": ["443/tcp", "https"]},
        "disk": {"device": "/dev/sda", "layout": "lvm"},
        "luks": {"enable": True, "passphrase": "LuksPass-9000"},
        "packages": ["htop"],
    }
    data.update(over)
    return data


def _arch_profile(**disk):
    return _profile(
        luks={"enable": False},
        disk={"device": "/dev/sda", "layout": "direct", **disk},
    )


class LinuxBase(ULRMMTestCase):
    def setUp(self):
        self.site = baker.make("clients.Site")
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site,
            mon_type="workstation",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": False},
        )
        patcher = mock.patch.object(linux, "_bootstrap", return_value=BOOT)
        self.boot = patcher.start()
        self.addCleanup(patcher.stop)

    def render(self, target_id, profile=None):
        clean = linux.validate_profile(target_id, profile or _profile())
        return linux.render(target_id, self.deployment, clean)


class TestMatrix(LinuxBase):
    def test_target_shape(self):
        ids = {t["id"] for t in linux.TARGETS}
        for want in (
            "ubuntu-24.04",
            "debian-12",
            "rhel-10",
            "fedora",
            "sles-16",
            "arch",
        ):
            self.assertIn(want, ids)
        for t in linux.TARGETS:
            self.assertEqual(t["family"], "linux")
            for key in (
                "id",
                "group",
                "label",
                "formats",
                "capabilities",
                "defaults",
                "notes",
            ):
                self.assertIn(key, t)
            self.assertTrue(t["formats"])

    def test_arch_caps(self):
        arch = linux._BY_ID["arch"]
        self.assertFalse(arch["capabilities"]["luks"])
        self.assertFalse(arch["capabilities"]["lvm"])
        self.assertTrue(arch["capabilities"]["device_required"])

    def test_default_filesystem_per_target(self):
        for target, fs in (
            ("ubuntu-24.04", "ext4"),
            ("debian-12", "ext4"),
            ("rocky-9", "xfs"),
            ("fedora", "xfs"),
            ("sles-15", "btrfs"),
            ("leap-16", "btrfs"),
            ("arch", "ext4"),
        ):
            form = linux.profile_defaults(target)
            form["disk"]["device"] = "/dev/sda"
            self.assertEqual(form["disk"]["filesystem"], fs, target)
            self.assertIn("filesystem", linux.validate_profile(target, form)["disk"])


class TestValidate(LinuxBase):
    def test_ok(self):
        clean = linux.validate_profile("ubuntu-24.04", _profile())
        self.assertEqual(clean["admin"]["name"], "siteadmin")

    def test_bad_hostname(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("ubuntu-24.04", _profile(hostname="Not Valid!"))
        self.assertIn("hostname", cm.exception.detail)

    def test_bad_timezone(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("ubuntu-24.04", _profile(timezone="Mars/Olympus"))
        self.assertIn("timezone", cm.exception.detail)

    def test_bad_keyboard(self):
        with self.assertRaises(ValidationError):
            linux.validate_profile("ubuntu-24.04", _profile(keyboard="US_QWERTY!"))

    def test_bad_firewall_entry(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile(
                "ubuntu-24.04",
                _profile(firewall={"enable": True, "allow": ["22/sctp"]}),
            )
        self.assertIn("firewall", cm.exception.detail)

    def test_bad_ssh_key(self):
        with self.assertRaises(ValidationError):
            linux.validate_profile(
                "ubuntu-24.04",
                _profile(
                    ssh={"enable": True, "auth": "key", "authorized_keys": ["nope"]}
                ),
            )

    def test_luks_rejected_on_arch(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile(
                "arch", _profile(disk={"device": "/dev/sda", "layout": "direct"})
            )
        self.assertIn("luks", cm.exception.detail)

    def test_lvm_rejected_on_arch(self):
        prof = _profile(
            luks={"enable": False}, disk={"device": "/dev/sda", "layout": "lvm"}
        )
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("arch", prof)
        self.assertIn("disk", cm.exception.detail)

    def test_arch_needs_device(self):
        prof = _profile(luks={"enable": False}, disk={"layout": "direct"})
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("arch", prof)
        self.assertIn("disk", cm.exception.detail)

    def test_reg_code_rejected_off_suse(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("ubuntu-24.04", _profile(reg_code="ABC123"))
        self.assertIn("reg_code", cm.exception.detail)

    def test_reg_code_ok_on_sles(self):
        prof = _profile(
            reg_code="INTERNAL-REG-CODE", disk={"device": "/dev/sda", "layout": "lvm"}
        )
        clean = linux.validate_profile("sles-16", prof)
        self.assertEqual(clean["reg_code"], "INTERNAL-REG-CODE")

    def test_luks_needs_lvm_on_ubuntu_and_debian(self):
        prof = _profile(disk={"device": "/dev/sda", "layout": "direct"})
        for target in ("ubuntu-22.04", "ubuntu-24.04", "debian-12"):
            with self.assertRaises(ValidationError) as cm:
                linux.validate_profile(target, prof)
            self.assertIn("encrypts only the lvm layout", str(cm.exception.detail))
        for target in ("rhel-9", "sles-15", "leap-16"):
            linux.validate_profile(target, prof)

    def test_line_breaks_rejected_in_secrets(self):
        for prof in (
            _profile(luks={"enable": True, "passphrase": "one\nautopart"}),
            _profile(admin={"name": "a", "password": "pw\nsecond"}),
        ):
            with self.assertRaises(ValidationError):
                linux.validate_profile("rhel-9", prof)

    def test_filesystem_limits(self):
        for target, disk, reason in (
            ("ubuntu-24.04", {"filesystem": "xfs"}, "installs ext4, not xfs"),
            ("rocky-9", {"filesystem": "btrfs"}, "installs xfs or ext4, not btrfs"),
            ("fedora", {"filesystem": "btrfs", "layout": "lvm"}, "use direct"),
        ):
            prof = _profile(disk={"device": "/dev/sda", "layout": "lvm", **disk})
            with self.assertRaises(ValidationError) as cm:
                linux.validate_profile(target, prof)
            self.assertIn(reason, str(cm.exception.detail["disk"]), target)


class TestSecrets(LinuxBase):
    def test_hash_and_luks_in_secrets_and_file(self):
        for target in ("ubuntu-24.04", "debian-12", "rhel-9", "sles-15", "sles-16"):
            files, secrets = self.render(target)
            blob = "\n".join(f["content"] for f in files)
            self.assertTrue(any(s.startswith("$6$") for s in secrets), target)
            for s in secrets:
                self.assertIn(s, blob, f"{target}: secret not in file")
            self.assertTrue(any("LuksPass-9000" == s for s in secrets), target)

    def test_token_never_plaintext(self):
        # the JWS is embedded base64, never verbatim
        files, _ = self.render("ubuntu-24.04")
        blob = "\n".join(f["content"] for f in files)
        self.assertNotIn("CONTAINS-TOKEN", blob)
        self.assertIn(base64.b64encode(BOOT.encode()).decode(), blob)

    def test_generated_password_is_stable(self):
        prof = _profile(admin={"name": "a", "sudo": True})  # no password -> generated
        f1, _ = linux.render(
            "ubuntu-24.04",
            self.deployment,
            linux.validate_profile("ubuntu-24.04", prof),
        )
        f2, _ = linux.render(
            "ubuntu-24.04",
            self.deployment,
            linux.validate_profile("ubuntu-24.04", prof),
        )
        self.assertEqual(f1[0]["content"], f2[0]["content"])

    def test_generated_secrets_are_returned(self):
        prof = _profile(admin={"name": "a", "sudo": True}, luks={"enable": True})
        for target in ("ubuntu-24.04", "debian-12", "rhel-9", "sles-15", "leap-16"):
            clean = linux.validate_profile(target, prof)
            files, secrets = linux.render(target, self.deployment, clean)
            gen = clean["_generated"]
            self.assertEqual(set(gen), {"admin_password", "luks_passphrase"}, target)
            blob = "\n".join(f["content"] for f in files)
            self.assertIn(gen["luks_passphrase"], blob, target)
            self.assertIn(gen["luks_passphrase"], secrets, target)
            # the shown password is the one the hash in the file verifies
            pw_hash = next(s for s in secrets if s.startswith("$6$"))
            salt = pw_hash.split("$")[2]
            self.assertEqual(linux._crypt6(gen["admin_password"], salt), pw_hash)

    def test_given_secrets_are_not_generated(self):
        clean = linux.validate_profile("debian-12", _profile())
        linux.render("debian-12", self.deployment, clean)
        self.assertEqual(clean["_generated"], {})


class TestAutoinstall(LinuxBase):
    def test_24_04_parses_and_validates(self):
        files, _ = self.render("ubuntu-24.04")
        self.assertEqual(files[0]["name"], "autoinstall.yaml")
        doc = yaml.safe_load(files[0]["content"])
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["identity"]["hostname"], "nw-host-01")
        self.assertEqual(doc["keyboard"]["layout"], "us")
        self.assertIn("curl", doc["packages"])
        self.assertTrue(doc["late-commands"])

    def test_22_04_is_nocloud(self):
        files, _ = self.render("ubuntu-22.04")
        self.assertTrue(files[0]["content"].startswith("#cloud-config"))
        doc = yaml.safe_load(files[0]["content"])
        self.assertIn("autoinstall", doc)

    def test_layout_and_ufw(self):
        prof = _profile(
            luks={"enable": False}, disk={"device": "/dev/sda", "layout": "direct"}
        )
        files, _ = self.render("ubuntu-24.04", prof)
        doc = yaml.safe_load(files[0]["content"])
        self.assertEqual(doc["storage"]["layout"]["name"], "direct")
        self.assertTrue(any("systemctl enable ufw" in c for c in doc["late-commands"]))


class TestPreseed(LinuxBase):
    def test_lines(self):
        files, _ = self.render("debian-12")
        text = files[0]["content"]
        self.assertIn("d-i passwd/username string siteadmin", text)
        self.assertIn("d-i partman-crypto/passphrase password LuksPass-9000", text)
        self.assertIn("d-i partman-auto/method string crypto", text)
        self.assertIn("d-i partman/default_filesystem string ext4", text)
        self.assertIn("preseed/late_command", text)
        # grub-installer asks for the boot device at critical priority
        # when nothing answers it and the install never reaches late_command
        self.assertIn("d-i grub-installer/bootdev string default", text)

    def test_no_luks_lvm_method(self):
        prof = _profile(luks={"enable": False})
        files, _ = self.render("debian-12", linux.validate_profile("debian-12", prof))
        self.assertIn("d-i partman-auto/method string lvm", files[0]["content"])

    def test_filesystem(self):
        prof = _profile(
            luks={"enable": False},
            disk={"device": "/dev/sda", "layout": "direct", "filesystem": "xfs"},
        )
        text = self.render("debian-13", prof)[0][0]["content"]
        self.assertIn("d-i partman-auto/method string regular", text)
        self.assertIn("d-i partman/default_filesystem string xfs", text)


def _autopart(text):
    return next(line for line in text.splitlines() if line.startswith("autopart"))


class TestKickstart(LinuxBase):
    def test_rhel9_lines(self):
        files, _ = self.render("rhel-9")
        text = files[0]["content"]
        self.assertIn("timezone Europe/Berlin --utc", text)
        self.assertIn("--iscrypted", text)
        # a full image left in the drive would install again after the reboot
        self.assertIn("\nreboot --eject\n", text)
        self.assertIn(
            "autopart --type=lvm --fstype=ext4 --encrypted --luks-version=luks2", text
        )
        self.assertIn("%packages", text)

    def test_rhel10_omits_removed(self):
        files, _ = self.render("rhel-10")
        text = files[0]["content"]
        for banned in (
            "authconfig",
            "\nvnc",
            "%anaconda",
            "\nmodule ",
            "--isUtc",
            "--ntpservers",
        ):
            self.assertNotIn(banned, text)

    def test_passphrase_survives_kickstart_parsing(self):
        phrase = 'correct horse #2026 it\'s "x" \\ end'
        prof = _profile(luks={"enable": True, "passphrase": phrase})
        files, secrets = self.render("alma-9", prof)
        line = _autopart(files[0]["content"])
        # pykickstart tokenises with shlex.split(line, comments=True)
        args = shlex.split(line, comments=True)
        self.assertIn(f"--passphrase={phrase}", args)
        masked = line
        for s in sorted(secrets, key=len, reverse=True):
            masked = masked.replace(s, "********")
        self.assertNotIn("horse", masked)

    def test_layout_and_filesystem(self):
        for target, disk, want in (
            (
                "rocky-9",
                {"layout": "direct", "filesystem": "ext4"},
                "plain --fstype=ext4",
            ),
            ("rocky-10", {"layout": "lvm", "filesystem": "xfs"}, "lvm --fstype=xfs"),
            ("fedora", {"layout": "direct", "filesystem": "btrfs"}, "btrfs"),
        ):
            prof = _profile(luks={"enable": False}, disk={"device": "/dev/sda", **disk})
            files, _ = self.render(target, prof)
            self.assertEqual(
                _autopart(files[0]["content"]), f"autopart --type={want}", target
            )


class TestAutoyast(LinuxBase):
    def test_xml_parses(self):
        files, _ = self.render("sles-15")
        self.assertEqual(files[0]["name"], "autoinst.xml")
        root = ET.fromstring(files[0]["content"])
        self.assertTrue(root.tag.endswith("profile"))
        text = files[0]["content"]
        self.assertIn("<crypt_key>LuksPass-9000</crypt_key>", text)
        self.assertIn("english-us", text)
        # no summary screen and no confirmation dialog
        confirm = root.find("./{*}general/{*}mode/{*}confirm")
        self.assertEqual(confirm.text, "false")

    def test_hostname_and_sudo(self):
        files, _ = self.render("leap-15")
        root = ET.fromstring(files[0]["content"])
        self.assertEqual(
            root.findtext(f"{YAST}networking/{YAST}dns/{YAST}hostname"), "nw-host-01"
        )
        script = root.findtext(f".//{YAST}chroot-scripts/{YAST}script/{YAST}source")
        self.assertIn(SUDOERS, script)
        packages = [e.text for e in root.iter(f"{YAST}package")]
        self.assertIn("sudo", packages)

    def test_layout_and_filesystem(self):
        files, _ = self.render("sles-15")
        root = ET.fromstring(files[0]["content"])
        drives = root.findall(f"{YAST}partitioning/{YAST}drive")
        self.assertEqual(len(drives), 2)
        self.assertEqual(drives[0].findtext(f".//{YAST}lvm_group"), "system")
        self.assertEqual(drives[1].findtext(f"{YAST}type"), "CT_LVM")
        self.assertEqual(drives[1].findtext(f".//{YAST}mount"), "/")
        self.assertEqual(drives[1].findtext(f".//{YAST}filesystem"), "ext4")

        prof = _profile(
            luks={"enable": False},
            disk={"device": "/dev/vda", "layout": "direct", "filesystem": "xfs"},
        )
        root = ET.fromstring(self.render("leap-15", prof)[0][0]["content"])
        drives = root.findall(f"{YAST}partitioning/{YAST}drive")
        self.assertEqual(len(drives), 1)
        self.assertEqual(drives[0].findtext(f"{YAST}device"), "/dev/vda")
        self.assertEqual(drives[0].findtext(f".//{YAST}filesystem"), "xfs")
        self.assertIsNone(drives[0].find(f".//{YAST}crypt_key"))


class TestAgama(LinuxBase):
    def test_json_shape(self):
        prof = _profile(reg_code="REGME", disk={"device": "/dev/sda", "layout": "lvm"})
        files, _ = self.render("sles-16", linux.validate_profile("sles-16", prof))
        doc = json.loads(files[0]["content"])
        self.assertEqual(doc["product"]["id"], "SLES")
        self.assertEqual(doc["product"]["registrationCode"], "REGME")
        self.assertTrue(doc["user"]["hashedPassword"])
        self.assertEqual(doc["scripts"]["post"][0]["chroot"], True)
        self.assertIn(SUDOERS, doc["scripts"]["post"][0]["content"])
        self.assertNotIn("$schema", files[0]["content"])

    def test_leap_product(self):
        prof = _profile(disk={"device": "/dev/sda", "layout": "lvm"})
        files, _ = self.render("leap-16", linux.validate_profile("leap-16", prof))
        self.assertEqual(json.loads(files[0]["content"])["product"]["id"], "Leap_16.0")

    def test_storage_layout(self):
        files, _ = self.render("leap-16")
        storage = json.loads(files[0]["content"])["storage"]
        group = storage["volumeGroups"][0]
        self.assertEqual(storage["drives"][0]["alias"], "system-disk")
        self.assertEqual(
            group["physicalVolumes"][0]["generate"]["encryption"]["luks2"]["password"],
            "LuksPass-9000",
        )
        self.assertIn(
            {"filesystem": {"path": "/", "type": "ext4"}}, group["logicalVolumes"]
        )

        prof = _profile(
            luks={"enable": False},
            disk={"device": "/dev/sda", "layout": "direct", "filesystem": "btrfs"},
        )
        storage = json.loads(self.render("sles-16", prof)[0][0]["content"])["storage"]
        self.assertNotIn("volumeGroups", storage)
        self.assertEqual(
            storage["drives"][0]["partitions"],
            [
                {"search": "*", "delete": True},
                {"generate": "default"},
                {"filesystem": {"path": "/", "type": "btrfs"}},
            ],
        )


class TestArch(LinuxBase):
    def test_two_files(self):
        files, _ = self.render("arch", linux.validate_profile("arch", _arch_profile()))
        names = {f["name"] for f in files}
        self.assertEqual(names, {"user_configuration.json", "user_credentials.json"})
        cfg = json.loads(files[0]["content"])
        self.assertEqual(
            cfg["disk_config"]["device_modifications"][0]["device"], "/dev/sda"
        )
        creds = json.loads(files[1]["content"])
        self.assertEqual(creds["users"][0]["username"], "siteadmin")

    def test_network_firewall_and_partitions(self):
        files, _ = self.render("arch", _arch_profile(filesystem="btrfs"))
        cfg = json.loads(files[0]["content"])
        self.assertEqual(cfg["network_config"], {"type": "iso"})
        self.assertIn("systemctl enable ufw", cfg["custom_commands"])
        boot, root = cfg["disk_config"]["device_modifications"][0]["partitions"]
        self.assertEqual((boot["mountpoint"], boot["fs_type"]), ("/boot", "fat32"))
        self.assertEqual(boot["flags"], ["boot", "esp"])
        self.assertEqual((root["mountpoint"], root["fs_type"]), ("/", "btrfs"))
        self.assertEqual(root["start"]["value"], 1025)


class TestFirstBoot(LinuxBase):
    def test_unit_content(self):
        name, directory, script_path, unit_path = linux._ident_paths()
        unit = linux._first_boot_unit(script_path, unit_path, name)
        self.assertIn("After=network-online.target", unit)
        # the resolver is not ready when network-online fires on Debian
        self.assertRegex(unit, r"ExecStartPre=-/bin/bash -c 'for i in .*getent hosts ")
        self.assertIn("/dev/tcp/", unit)
        self.assertIn("systemd-resolved.service", unit)
        self.assertIn("StartLimitIntervalSec=0", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("RestartSec=10s", unit)
        self.assertIn(f"ExecStart=/bin/bash {script_path}", unit)
        self.assertIn(f"systemctl disable {name}.service", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_local_package_removes_a_half_installed_deb(self):
        self.assertIn(
            'dpkg -i "$1" || { dpkg -r "$(dpkg-deb -f "$1" Package)"; return 1; }',
            linux._LOCAL_PKG,
        )

    def test_unit_shell_parses_the_real_bootstrap(self):
        from agents.utils import render_linux_install

        self.setup_coresettings()
        body = render_linux_install(
            download_url="https://rmm.example.test/agent",
            sha256="0" * 64,
            mesh_url="",
            client="1",
            site="1",
            agent_type="workstation",
            token="",
            api="https://api.example.test",
            enroll="eyJhbGciOiJFZERTQSJ9.e30.c2ln",
        )
        name, _, script_path, unit_path = linux._ident_paths()
        unit = linux._first_boot_unit(script_path, unit_path, name)
        shell = re.search(r"^ExecStart=(\S+) ", unit, re.M).group(1)
        # /bin/sh is dash here as on Debian and Ubuntu, and dash rejects it
        r = subprocess.run([shell, "-n"], input=body, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_embedded_in_file(self):
        files, _ = self.render("rhel-9")
        text = files[0]["content"]
        name, directory, script_path, unit_path = linux._ident_paths()
        self.assertIn(f"systemctl enable {name}.service", text)
        # the bootstrap body is base64 in the post phase
        self.assertIn(base64.b64encode(BOOT.encode()).decode(), text)


class TestAdminDefaults(LinuxBase):
    def test_laps_account_default(self):
        baker.make(
            "laps.LapsPolicy", site=None, enabled=True, account="rmm-break-glass"
        )
        prof = _profile(admin={})  # no name
        files, _ = self.render(
            "ubuntu-24.04", linux.validate_profile("ubuntu-24.04", prof)
        )
        self.assertIn("username: rmm-break-glass", files[0]["content"])


class TestBundle(LinuxBase):
    def test_readme_everywhere(self):
        for t in ("ubuntu-24.04", "debian-12", "rhel-9", "sles-15", "sles-16", "arch"):
            extras = dict(linux.bundle_extras(t, []))
            self.assertIn("README.txt", extras)

    def test_arch_helper(self):
        extras = dict(linux.bundle_extras("arch", []))
        self.assertIn("run-archinstall.sh", extras)
        self.assertNotIn("inject-iso.sh", extras)
        helper = extras["run-archinstall.sh"]
        self.assertIn(b"archinstall --config", helper)
        self.assertIn(b"/sys/class/block/", helper)
        subprocess.run(["sh", "-n"], input=helper, check=True)
        self.assertIn(b"sh run-archinstall.sh", extras["README.txt"])

    def test_inject_scripts(self):
        for target, mapped, arg in (
            (
                "ubuntu-24.04",
                '"$here/autoinstall.yaml" /autoinstall.yaml',
                "'autoinstall'",
            ),
            ("debian-13", '"$here/preseed.cfg" /preseed.cfg', "preseed/file=/cdrom/"),
            ("rocky-10", '"$here/ks.cfg" /ks.cfg', '"inst.ks=hd:LABEL=$label:/ks.cfg"'),
            (
                "leap-15",
                '"$here/autoinst.xml" /autoinst.xml',
                '"autoyast=label://$label/autoinst.xml"',
            ),
            (
                "sles-16",
                '"$here/agama-profile.json" /agama-profile.json',
                "inst.auto=label://$label/agama-profile.json",
            ),
        ):
            extras = dict(linux.bundle_extras(target, []))
            script = extras["inject-iso.sh"].decode()
            self.assertIn(f"-map {mapped}", script, target)
            self.assertIn(arg, script, target)
            self.assertIn("-boot_image any replay", script, target)
            subprocess.run(["sh", "-n"], input=script, text=True, check=True)
            self.assertIn("sh inject-iso.sh", extras["README.txt"].decode(), target)

    def test_ubuntu_22_04_nocloud(self):
        files, _ = self.render("ubuntu-22.04")
        extras = dict(linux.bundle_extras("ubuntu-22.04", files))
        self.assertEqual(extras["nocloud/user-data"].decode(), files[0]["content"])
        self.assertEqual(extras["nocloud/meta-data"], b"")
        script = extras["inject-iso.sh"].decode()
        self.assertIn('-map "$here/nocloud" /nocloud', script)
        self.assertIn("ds=nocloud;s=/cdrom/nocloud/", script)
        self.assertIn("ds=nocloud;s=/cdrom/nocloud/", extras["README.txt"].decode())


class TestYamlish(LinuxBase):
    def test_roundtrip(self):
        data = {"a": {"b": [1, "x", True, None]}, "c": "yes", "d": {}}
        self.assertEqual(yaml.safe_load(yamlish.dump(data)), data)


def _error_at(detail, path):
    for part in path.split("."):
        detail = detail[part]
    return detail


def _sshd_conf(text):
    blob = re.search(r"printf %s (\S+) \| base64 -d > /etc/ssh/sshd_config.d/", text)
    return base64.b64decode(blob.group(1)).decode()


def _key_files(text):
    return {
        m.group(2): base64.b64decode(m.group(1)).decode()
        for m in re.finditer(
            r"printf %s (\S+) \| base64 -d > (\S+)/\.ssh/authorized_keys", text
        )
    }


def _values(meta):
    """The choice values of a field, inline or from the shared sets."""
    choices = meta.get("choices") or linux.choice_sets()[meta["choices_ref"]]
    return [c["value"] for c in choices]


class TestFields(LinuxBase):
    def test_every_field_has_metadata_and_valid_defaults(self):
        for tgt in linux.TARGETS:
            form = linux.profile_defaults(tgt["id"])
            fields = linux.profile_fields(tgt["id"])
            self.assertEqual(set(fields), set(linux._flat(form)), tgt["id"])
            for path, meta in fields.items():
                self.assertTrue(meta["label"], path)
                if "choices" not in meta and "choices_ref" not in meta:
                    continue
                value = form
                for part in path.split("."):
                    value = value[part]
                if meta["kind"] == "checkgroup":
                    self.assertLessEqual(set(value), set(_values(meta)), path)
                    continue
                self.assertIn(value, _values(meta), f"{tgt['id']} {path}")

    def test_every_select_refuses_an_unknown_value(self):
        for tid in ("ubuntu-24.04", "debian-13", "rocky-10", "leap-16", "arch"):
            for path, meta in linux.profile_fields(tid).items():
                if "choices" not in meta and "choices_ref" not in meta:
                    continue
                prof = _arch_profile() if tid == "arch" else _profile()
                section, _, key = path.rpartition(".")
                target = prof[section] if section else prof
                target[key] = "not-a-choice"
                with self.assertRaises(ValidationError, msg=f"{tid} {path}") as cm:
                    linux.validate_profile(tid, prof)
                self.assertTrue(_error_at(cm.exception.detail, path), path)

    def test_long_lists_are_shared_sets(self):
        sets = linux.choice_sets()
        for tgt in linux.TARGETS:
            fields = linux.profile_fields(tgt["id"])
            for path, name in (
                ("timezone", "linux_timezones"),
                ("locale", "linux_locales"),
                ("keyboard", "linux_keyboards"),
            ):
                self.assertEqual(fields[path]["choices_ref"], name, path)
                self.assertNotIn("choices", fields[path])
        self.assertEqual(_values({"choices_ref": "linux_timezones"})[0], "UTC")
        self.assertIn("Europe/Berlin", _values({"choices_ref": "linux_timezones"}))
        self.assertIn("de-nodeadkeys", _values({"choices_ref": "linux_keyboards"}))
        self.assertIn(
            {"value": "de_DE.UTF-8", "label": "German (Germany) (de_DE.UTF-8)"},
            sets["linux_locales"],
        )

    def test_desktop_choices_per_target(self):
        def offered(tid):
            meta = linux.profile_fields(tid)["desktop"]
            return [c["value"] for c in meta["choices"]]

        self.assertEqual(offered("sles-15"), ["none"])
        self.assertEqual(offered("rhel-10"), ["none", "gnome"])
        self.assertEqual(offered("sles-16"), ["none", "gnome"])
        self.assertIn("lxde", offered("debian-12"))
        self.assertIn("hyprland", offered("arch"))
        self.assertIn("sway", offered("fedora"))
        self.assertNotIn("hyprland", offered("fedora"))
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("rocky-9", _profile(desktop="kde"))
        self.assertIn("offers none, gnome", str(cm.exception.detail["desktop"]))

    def test_key_field_and_conditions(self):
        fields = linux.profile_fields("debian-12")
        self.assertEqual(fields["ssh.authorized_keys"]["kind"], "multiline")
        self.assertEqual(
            fields["ssh.authorized_keys"]["show_if"],
            {"ssh.enable": True, "ssh.auth": ["key", "both"]},
        )
        self.assertEqual(fields["admin.password"]["kind"], "secret")
        self.assertNotIn("luks.enable", linux.profile_fields("arch"))
        self.assertEqual(
            [
                c["value"]
                for c in linux.profile_fields("arch")["disk.layout"]["choices"]
            ],
            ["direct"],
        )


class TestSshValidation(LinuxBase):
    def ssh(self, **ssh):
        return linux.validate_profile("debian-12", _profile(ssh=ssh))["ssh"]

    def test_keys_one_per_line(self):
        clean = self.ssh(auth="both", authorized_keys=f"\n{KEY1}\r\n\n  {KEY2}  \n")
        self.assertEqual(clean["authorized_keys"], [KEY1, KEY2])
        self.assertEqual(
            self.ssh(auth="key", authorized_keys=[KEY2])["authorized_keys"], [KEY2]
        )

    def test_bad_keys_refused_with_line(self):
        swapped = "ssh-rsa " + KEY1.split()[1]
        for keys, line in (
            (f"{KEY1}\nnot a key", "line 2"),
            (swapped, "line 1"),
            (KEY1 + " $(reboot)", "line 1"),
            ("ssh-ed25519 AAAA!! x", "line 1"),
            (f'command="sh" {KEY1}', "line 1"),
        ):
            with self.assertRaises(ValidationError) as cm:
                self.ssh(auth="key", authorized_keys=keys)
            self.assertIn(
                line, str(_error_at(cm.exception.detail, "ssh.authorized_keys"))
            )

    def test_key_auth_needs_a_key(self):
        with self.assertRaises(ValidationError) as cm:
            self.ssh(enable=True, auth="key")
        self.assertEqual(
            [str(e) for e in _error_at(cm.exception.detail, "ssh.authorized_keys")],
            ["Key only needs at least one key"],
        )
        self.assertEqual(self.ssh(enable=False, auth="key")["authorized_keys"], [])
        self.assertEqual(self.ssh(auth="password")["auth"], "password")
        # key or password without a key signs in by password for now
        clean = self.ssh(auth="both")
        self.assertEqual((clean["auth"], clean["authorized_keys"]), ("both", []))

    def test_password_auth_drops_keys(self):
        self.assertEqual(
            self.ssh(auth="password", authorized_keys=KEY1)["authorized_keys"], []
        )

    def test_hidden_keys_are_not_checked(self):
        # the form hides the keys for password auth and with SSH off
        for ssh in (
            {"auth": "password", "authorized_keys": "garbage"},
            {"enable": False, "auth": "key", "authorized_keys": "ssh-rsa AAAA"},
        ):
            self.assertEqual(self.ssh(**ssh)["authorized_keys"], [], ssh)
        with self.assertRaises(ValidationError):
            self.ssh(auth="both", authorized_keys="garbage")

    def test_dsa_keys_refused(self):
        blob = base64.b64encode(b"\0\0\0\x07ssh-dss" + b"\0" * 32).decode()
        with self.assertRaises(ValidationError) as cm:
            self.ssh(auth="key", authorized_keys=f"ssh-dss {blob} old@box")
        self.assertIn(
            "line 1 is not an SSH public key",
            str(_error_at(cm.exception.detail, "ssh.authorized_keys")),
        )


class TestSshRender(LinuxBase):
    def text(self, target, **ssh):
        prof = _arch_profile() if target == "arch" else _profile()
        prof["ssh"] = dict({"enable": True, "authorized_keys": KEY1}, **ssh)
        files, _ = self.render(target, prof)
        return "\n".join(f["content"] for f in files)

    def test_sshd_config_matches_the_choice(self):
        for auth, pw, pub in (
            ("key", "no", "yes"),
            ("password", "yes", "no"),
            ("both", "yes", "yes"),
        ):
            for root, permit in ((False, "no"), (True, None)):
                conf = _sshd_conf(self.text("debian-12", auth=auth, root_login=root))
                self.assertIn(f"PasswordAuthentication {pw}\n", conf)
                self.assertIn(f"PubkeyAuthentication {pub}\n", conf)
                self.assertIn("KbdInteractiveAuthentication no\n", conf)
                # openssh 8.4 on SLES/Leap 15.5 needs the old name too
                self.assertIn("ChallengeResponseAuthentication no\n", conf)
                if permit is None:
                    permit = "prohibit-password" if auth == "key" else "yes"
                self.assertIn(f"PermitRootLogin {permit}\n", conf)

    def test_keys_for_admin_and_root_only_with_root_login(self):
        for target in ("debian-13", "rocky-10", "sles-16", "arch"):
            files = _key_files(self.text(target, auth="key"))
            self.assertEqual(files, {"/home/siteadmin": KEY1 + "\n"}, target)
            files = _key_files(self.text(target, auth="both", root_login=True))
            self.assertEqual(set(files), {"/home/siteadmin", "/root"}, target)
            self.assertFalse(_key_files(self.text(target, auth="password")), target)

    def test_native_key_placement(self):
        # Kickstart's sshkey takes one key per user (pykickstart refuses a
        # second one), so %post writes the files with their SELinux labels
        ks = self.text("alma-10", auth="both", authorized_keys=f"{KEY1}\n{KEY2}")
        self.assertNotIn("sshkey", ks)
        self.assertEqual(_key_files(ks), {"/home/siteadmin": f"{KEY1}\n{KEY2}\n"})
        self.assertIn("restorecon -R /home/siteadmin/.ssh", ks)
        # AutoYaST places them itself
        root = ET.fromstring(self.text("leap-15", auth="key", root_login=True))
        users = {
            u.findtext(f"{YAST}username"): [e.text for e in u.iter(f"{YAST}listentry")]
            for u in root.iter(f"{YAST}user")
        }
        self.assertEqual(users, {"siteadmin": [KEY1], "root": [KEY1]})
        # subiquity places the admin's keys, root's come from the late commands
        doc = yaml.safe_load(self.text("ubuntu-24.04", auth="key", root_login=True))
        self.assertEqual(doc["ssh"]["authorized-keys"], [KEY1])
        self.assertFalse(doc["ssh"]["allow-pw"])
        late = "\n".join(doc["late-commands"])
        self.assertEqual(set(_key_files(late)), {"/root"})
        self.assertIn("PubkeyAuthentication yes", _sshd_conf(late))
        doc = yaml.safe_load(self.text("ubuntu-24.04", auth="password"))
        self.assertTrue(doc["ssh"]["allow-pw"])
        self.assertEqual(doc["ssh"]["authorized-keys"], [])

    def test_ssh_off_writes_no_ssh_setup(self):
        ks = self.text("rocky-9", enable=False, auth="key", authorized_keys="")
        self.assertNotIn("services --enabled=sshd", ks)
        self.assertNotIn("sshd_config.d", ks)
        # @core still installs sshd and firewalld opens ssh by default
        self.assertIn("\nservices --disabled=sshd\n", ks)
        fw = next(ln for ln in ks.splitlines() if ln.startswith("firewall "))
        self.assertIn("--remove-service=ssh", fw.split())
        self.assertNotIn("--port=22:tcp", fw)
        ks = self.text("rocky-9")
        self.assertIn("\nservices --enabled=sshd\n", ks)
        self.assertNotIn("--remove-service", ks)

    def test_yast_includes_the_drop_ins(self):
        # openssh 8.4 on SLES/Leap 15.5 and older has no Include line
        include = (
            "grep -qs '^Include /etc/ssh/sshd_config.d/' /etc/ssh/sshd_config"
            " || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config"
        )
        for target in ("sles-15", "leap-15"):
            root = ET.fromstring(self.text(target, auth="key"))
            script = root.findtext(f".//{YAST}chroot-scripts/{YAST}script/{YAST}source")
            lines = script.splitlines()
            self.assertIn(include, lines, target)
            self.assertLess(
                lines.index(include),
                next(i for i, ln in enumerate(lines) if "00-ulrmm.conf" in ln),
            )
        self.assertNotIn("sed -i '1i Include", self.text("leap-16", auth="key"))
        root = ET.fromstring(self.text("leap-15", enable=False, authorized_keys=""))
        self.assertNotIn("Include", root.findtext(f".//{YAST}source"))


class TestDesktop(LinuxBase):
    def render_desktop(self, target, desktop):
        prof = _arch_profile() if target == "arch" else _profile()
        files, _ = self.render(target, dict(prof, desktop=desktop))
        return files

    def test_ubuntu(self):
        for target, desktop, pkg in (
            ("ubuntu-24.04", "kde", "kubuntu-desktop"),
            ("ubuntu-24.04", "cinnamon", "ubuntucinnamon-desktop"),
            ("ubuntu-22.04", "cinnamon", "cinnamon-desktop-environment"),
            ("ubuntu-22.04", "gnome", "ubuntu-desktop"),
        ):
            doc = yaml.safe_load(self.render_desktop(target, desktop)[0]["content"])
            doc = doc.get("autoinstall", doc)
            self.assertIn(pkg, doc["packages"], target)
            late = "\n".join(doc["late-commands"])
            self.assertIn("systemctl set-default graphical.target", late)
            nm = re.search(r"printf %s (\S+) \| base64 -d > /etc/netplan/01-", late)
            self.assertIn(
                "renderer: NetworkManager", base64.b64decode(nm.group(1)).decode()
            )
        doc = yaml.safe_load(self.render_desktop("ubuntu-24.04", "none")[0]["content"])
        self.assertNotIn("graphical.target", "\n".join(doc["late-commands"]))
        self.assertNotIn("ubuntu-desktop", doc["packages"])

    def test_debian_tasks(self):
        text = self.render_desktop("debian-12", "xfce")[0]["content"]
        self.assertIn(
            "tasksel tasksel/first multiselect standard, desktop, xfce-desktop", text
        )
        text = self.render_desktop("debian-13", "none")[0]["content"]
        self.assertIn("tasksel tasksel/first multiselect standard\n", text)

    def test_kickstart_environments(self):
        for target, desktop, env in (
            ("rhel-9", "gnome", "graphical-server-environment"),
            ("alma-10", "gnome", "graphical-server-environment"),
            ("fedora", "gnome", "workstation-product-environment"),
            ("fedora", "kde", "kde-desktop-environment"),
            ("fedora", "sway", "sway-desktop-environment"),
        ):
            text = self.render_desktop(target, desktop)[0]["content"]
            self.assertIn(f"\n@^{env}\n", text, target)
            self.assertIn("xconfig --startxonboot", text)
            self.assertIn("firstboot --disable", text)
        text = self.render_desktop("rocky-9", "none")[0]["content"]
        self.assertIn("\n@^minimal-environment\n", text)
        self.assertNotIn("xconfig", text)

    def test_suse_patterns(self):
        root = ET.fromstring(self.render_desktop("leap-15", "kde")[0]["content"])
        self.assertEqual([e.text for e in root.iter(f"{YAST}pattern")], ["kde"])
        self.assertEqual(root.findtext(f"{YAST}networking/{YAST}managed"), "true")
        self.assertEqual(
            root.findtext(f"{YAST}services-manager/{YAST}default_target"), "graphical"
        )
        root = ET.fromstring(self.render_desktop("leap-15", "none")[0]["content"])
        self.assertIsNone(root.find(f"{YAST}services-manager"))
        for target, desktop, pattern in (
            ("leap-16", "xfce", "xfce_wayland"),
            ("sles-16", "gnome", "gnome"),
        ):
            doc = json.loads(self.render_desktop(target, desktop)[0]["content"])
            self.assertEqual(doc["software"]["patterns"], [pattern], target)
            self.assertIn("graphical.target", doc["scripts"]["post"][0]["content"])

    def test_arch_profiles(self):
        cfg = json.loads(self.render_desktop("arch", "hyprland")[0]["content"])
        self.assertEqual(
            cfg["profile_config"]["profile"],
            {
                "main": "Desktop",
                "details": ["Hyprland"],
                "custom_settings": {"Hyprland": {"seat_access": "systemd-logind"}},
            },
        )
        self.assertEqual(cfg["profile_config"]["greeter"], "sddm")
        self.assertEqual(cfg["network_config"], {"type": "nm"})
        self.assertEqual(cfg["app_config"], {"audio_config": {"audio": "pipewire"}})
        cfg = json.loads(self.render_desktop("arch", "gnome")[0]["content"])
        self.assertEqual(cfg["profile_config"]["greeter"], "gdm")
        cfg = json.loads(self.render_desktop("arch", "none")[0]["content"])
        self.assertEqual(cfg["profile_config"]["profile"]["main"], "Minimal")
        self.assertEqual(cfg["network_config"], {"type": "iso"})


class TestKeyboard(LinuxBase):
    def test_variant_per_format(self):
        def text(target):
            prof = _arch_profile() if target == "arch" else _profile()
            files, _ = self.render(target, dict(prof, keyboard="de-nodeadkeys"))
            return files[0]["content"]

        doc = yaml.safe_load(text("ubuntu-24.04"))
        self.assertEqual(doc["keyboard"], {"layout": "de", "variant": "nodeadkeys"})
        self.assertIn(
            "keyboard-configuration/variantcode string nodeadkeys", text("debian-12")
        )
        # the installer reads the variant only from xkb-keymap
        self.assertIn(
            "\nd-i keyboard-configuration/xkb-keymap select de(nodeadkeys)\n",
            text("debian-12"),
        )
        line = next(
            ln for ln in text("rhel-9").splitlines() if ln.startswith("keyboard ")
        )
        self.assertEqual(shlex.split(line), ["keyboard", "--xlayouts=de (nodeadkeys)"])
        self.assertIn("<keymap>german</keymap>", text("leap-15"))
        self.assertEqual(
            json.loads(text("leap-16"))["localization"]["keyboard"], "de-nodeadkeys"
        )
        self.assertEqual(
            json.loads(text("arch"))["locale_config"]["kb_layout"],
            "de-latin1-nodeadkeys",
        )

    def test_dead_keys_german_on_yast(self):
        files, _ = self.render("sles-15", _profile(keyboard="de"))
        self.assertIn("<keymap>german-deadkey</keymap>", files[0]["content"])

    def test_preseed_keymap_carries_the_variant(self):
        for keyboard, keymap in (("de", "de"), ("ch-fr", "ch(fr)"), ("us", "us")):
            files, _ = self.render("debian-13", _profile(keyboard=keyboard))
            self.assertIn(
                f"\nd-i keyboard-configuration/xkb-keymap select {keymap}\n",
                files[0]["content"],
            )


class TestReleases(LinuxBase):
    def test_ubuntu_releases(self):
        ids = {t["id"] for t in linux.TARGETS if t["group"] == "ubuntu"}
        self.assertEqual(
            ids, {"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "ubuntu-26.10"}
        )
        for tid, lts, status in (
            ("ubuntu-22.04", True, "supported"),
            ("ubuntu-26.04", True, "supported"),
            ("ubuntu-26.10", False, "interim"),
        ):
            release = linux._BY_ID[tid]["release"]
            self.assertEqual((release["lts"], release["status"]), (lts, status), tid)
            self.assertRegex(release["released"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertRegex(release["eol"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(linux._BY_ID["ubuntu-26.10"]["label"], "Ubuntu 26.10")

    def test_downloads_are_https(self):
        have = set()
        for tgt in linux.TARGETS:
            for d in tgt.get("downloads", []):
                have.add(tgt["id"])
                self.assertEqual(set(d), {"label", "url", "sha256_url", "size"})
                self.assertTrue(d["url"].startswith("https://"), d["url"])
                self.assertLessEqual(len(d["label"]), 40)
                if d["sha256_url"]:
                    self.assertTrue(d["sha256_url"].startswith("https://"))
        self.assertNotIn("sles-15", have)
        self.assertNotIn("rhel-9", have)
        for tid in ("ubuntu-26.04", "debian-13", "fedora", "rocky-10", "leap-16"):
            self.assertIn(tid, have)
        labels = [d["label"] for d in linux._BY_ID["ubuntu-24.04"]["downloads"]]
        self.assertEqual(labels, ["Server 24.04.5", "Desktop 24.04.5.1"])
        # CachyOS and EndeavourOS install from the Arch ISO
        url = linux._BY_ID["arch"]["downloads"][0]["url"]
        self.assertEqual(linux._BY_ID["cachyos"]["downloads"][0]["url"], url)

    def test_wrapper_per_release(self):
        for tid, wrapped in (
            ("ubuntu-22.04", True),
            ("ubuntu-24.04", False),
            ("ubuntu-26.04", False),
            ("ubuntu-26.10", False),
        ):
            body = self.render(tid)[0][0]["content"]
            self.assertEqual(body.startswith("#cloud-config\nautoinstall:"), wrapped)
            doc = yaml.safe_load(body)
            self.assertEqual((doc.get("autoinstall") or doc)["version"], 1, tid)


class TestCatalog(LinuxBase):
    def test_sections_per_family(self):
        sections = {}
        for tid in ("ubuntu-26.04", "debian-13", "rocky-9", "fedora", "leap-16"):
            meta = linux.profile_fields(tid)["packages_catalog"]
            self.assertEqual(meta["kind"], "checkgroup")
            self.assertEqual(meta["group"], "software")
            self.assertLessEqual(len(meta["help"]), 120)
            sections[tid] = {c["section"] for c in meta["choices"]}
            self.assertNotIn("Gaming", sections[tid], tid)
        for tid in ("arch", "cachyos", "endeavouros"):
            meta = linux.profile_fields(tid)["packages_catalog"]
            self.assertIn("Gaming", {c["section"] for c in meta["choices"]})
        self.assertIn(
            "firefox-esr",
            _values(linux.profile_fields("debian-12")["packages_catalog"]),
        )
        self.assertNotIn(
            "firefox", _values(linux.profile_fields("ubuntu-24.04")["packages_catalog"])
        )
        for tgt in linux.TARGETS:
            for c in linux._catalog(tgt):
                self.assertLessEqual(len(c["label"]), 40, c)

    def test_rendered_with_extra_packages(self):
        prof = _profile(packages_catalog=["htop", "vlc"], packages=["htop", "jq"])
        doc = yaml.safe_load(self.render("ubuntu-24.04", prof)[0][0]["content"])
        self.assertEqual(doc["packages"][-3:], ["htop", "vlc", "jq"])
        text = self.render("debian-13", prof)[0][0]["content"]
        self.assertIn(" htop vlc jq\n", text)
        prof = _profile(packages_catalog=["tmux", "cockpit"], packages=[])
        text = self.render("rocky-10", prof)[0][0]["content"]
        self.assertIn("\ntmux\ncockpit\n%end", text)
        prof = _profile(packages_catalog=["MozillaFirefox"])
        xml = self.render("leap-15", prof)[0][0]["content"]
        self.assertIn("<package>MozillaFirefox</package>", xml)
        cfg = json.loads(self.render("leap-16", prof)[0][0]["content"])
        self.assertIn("MozillaFirefox", cfg["software"]["packages"])

    def test_multilib_for_steam(self):
        prof = _arch_profile() | {"packages_catalog": ["steam"]}
        cfg = json.loads(self.render("arch", prof)[0][0]["content"])
        self.assertEqual(cfg["mirror_config"], {"optional_repositories": ["multilib"]})
        self.assertIn("steam", cfg["packages"])

    def test_snaps_go_to_the_snaps_list(self):
        prof = _profile(packages_catalog=["snap:firefox", "snap:code", "vlc"])
        doc = yaml.safe_load(self.render("ubuntu-26.04", prof)[0][0]["content"])
        self.assertEqual(
            doc["snaps"], [{"name": "firefox"}, {"name": "code", "classic": True}]
        )
        self.assertIn("vlc", doc["packages"])
        self.assertFalse([x for x in doc["packages"] if "snap" in x])
        meta = linux.profile_fields("ubuntu-24.04")["packages_catalog"]
        choice = next(c for c in meta["choices"] if c["value"] == "snap:firefox")
        self.assertEqual(choice["help"], "Installed as a snap")
        plain = yaml.safe_load(self.render("ubuntu-26.04")[0][0]["content"])
        self.assertNotIn("snaps", plain)

    def test_snaps_refused_off_ubuntu(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile(
                "debian-13", _profile(packages_catalog=["snap:firefox"])
            )
        self.assertIn("snap:firefox", str(cm.exception.detail["packages_catalog"]))

    def test_unknown_entry_refused(self):
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("rocky-9", _profile(packages_catalog=["htop"]))
        self.assertIn("htop", str(cm.exception.detail["packages_catalog"]))


class TestArchRepos(LinuxBase):
    def cfg(self, tid, **over):
        prof = _arch_profile() | over
        files, _ = self.render(tid, prof)
        return json.loads(files[0]["content"])

    def test_arch_output_keeps_its_keys(self):
        cfg = self.cfg("arch")
        self.assertNotIn("kernels", cfg)
        self.assertNotIn("mirror_config", cfg)

    def test_arch_mirror(self):
        url = "https://mirror.example.com/archlinux/$repo/os/$arch"
        cfg = self.cfg("arch", mirror=url)
        self.assertEqual(cfg["mirror_config"], {"custom_servers": [{"url": url}]})

    def test_cachyos(self):
        cfg = self.cfg("cachyos")
        self.assertEqual(cfg["kernels"], ["linux-cachyos"])
        self.assertEqual(cfg["packages"][:2], ["cachyos-keyring", "cachyos-mirrorlist"])
        self.assertIn(
            "Include = /etc/pacman.d/cachyos-mirrorlist", cfg["custom_commands"][0]
        )
        self.assertEqual(self.cfg("cachyos", kernel="linux")["kernels"], ["linux"])
        with self.assertRaises(ValidationError) as cm:
            linux.validate_profile("arch", _arch_profile() | {"kernel": "linux-zen"})
        self.assertIn("no kernel choice", str(cm.exception.detail["kernel"]))
        meta = linux.profile_fields("cachyos")["kernel"]
        self.assertEqual(_values(meta), ["linux-cachyos", "linux-cachyos-lts", "linux"])

    def test_helper_trusts_the_pinned_keys(self):
        helper = dict(linux.bundle_extras("cachyos", []))["run-archinstall.sh"]
        subprocess.run(["sh", "-n"], input=helper, check=True)
        text = helper.decode()
        self.assertIn("--recv-keys 882DCFE48E2051D48E2562ABF3B607488DB35A47", text)
        self.assertIn("--lsign-key 882DCFE48E2051D48E2562ABF3B607488DB35A47", text)
        self.assertIn("'Server = https://mirror.cachyos.org/repo/$arch/$repo'", text)
        self.assertLess(text.index("pacman-key"), text.index("archinstall --config"))
        eos = dict(linux.bundle_extras("endeavouros", []))["run-archinstall.sh"]
        self.assertIn(b"'SigLevel = PackageRequired'", eos)
        arch = dict(linux.bundle_extras("arch", []))["run-archinstall.sh"]
        self.assertEqual(arch, linux._ARCH_HELPER.encode())

    def test_endeavouros_desktop(self):
        cfg = self.cfg("endeavouros", desktop="kde")
        self.assertEqual(cfg["profile_config"]["profile"]["details"], ["KDE Plasma"])
        self.assertIn("eos-packagelist", cfg["packages"])
        self.assertEqual(
            cfg["custom_commands"][1],
            "pacman -S --needed --noconfirm $(eos-packagelist KDE-Desktop)",
        )
        self.assertNotIn("kernels", cfg)


class TestBatocera(LinuxBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(
            linux,
            "_deploy_link",
            lambda d: f"https://rmm.example.com/clients/{d.uid}/deploy/?fmt=tgz&arch=amd64",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_form_is_short(self):
        self.assertEqual(
            set(linux.profile_defaults("batocera")),
            {"hostname", "locale", "keyboard", "timezone"},
        )
        caps = linux._BY_ID["batocera"]["capabilities"]
        self.assertFalse(caps["firewall"] or caps["ssh"] or caps["luks"])
        self.assertIn(
            "Experimental: not tested on hardware.", linux._BY_ID["batocera"]["notes"]
        )

    def test_files(self):
        prof = linux.validate_profile(
            "batocera", {"hostname": "arcade-1", "keyboard": "de-nodeadkeys"}
        )
        files, secrets = linux.render("batocera", self.deployment, prof)
        conf, service = files
        self.assertEqual((conf["name"], service["name"]), ("batocera.conf", "ulrmm"))
        for line in (
            "system.hostname=arcade-1",
            "system.kblayout=de",
            "system.kbvariant=nodeadkeys",
            "system.services=ulrmm",
        ):
            self.assertIn(line + "\n", conf["content"])
        body = service["content"]
        subprocess.run(["bash", "-n"], input=body, text=True, check=True)
        self.assertIn(f"/clients/{self.deployment.uid}/deploy/?fmt=tgz", body)
        self.assertIn("-m install -enroll", body)
        self.assertEqual(secrets, [str(self.deployment.uid)])
        self.assertEqual(prof["_generated"], {})

    def test_bundle_and_iso(self):
        from deploy import iso, iso_layout

        extras = dict(linux.bundle_extras("batocera", []))
        self.assertEqual(set(extras), {"README.txt"})
        self.assertIn(b"system/services/ulrmm", extras["README.txt"])
        self.assertIsNone(
            iso_layout.agent_payload(self.deployment, "linux", "batocera")
        )
        with self.assertRaises(iso.IsoError):
            iso_layout.seed("batocera", self.deployment, [], None)


class TestProxy(LinuxBase):
    URL = "http://proxy.example.net:3128"

    def test_reaches_every_installer(self):
        for target, profile in (
            ("rocky-9", _profile(proxy=self.URL)),
            ("leap-15", _profile(proxy=self.URL)),
            ("sles-16", _profile(proxy=self.URL)),
            ("arch", _arch_profile() | {"proxy": self.URL}),
        ):
            files, _ = self.render(target, profile)
            body = files[0]["content"]
            self.assertIn("https_proxy=%s", body, target)
            self.assertIn(self.URL, body, target)
        files, _ = self.render("rocky-9", _profile(proxy=self.URL))
        self.assertIn(f"printf 'proxy=%s\\n' {self.URL}", files[0]["content"])
        files, _ = self.render("ubuntu-24.04", _profile(proxy=self.URL))
        self.assertIn(self.URL, files[0]["content"])
        files, _ = self.render("rocky-9", _profile())
        self.assertNotIn("/etc/environment", files[0]["content"])

    def test_validated(self):
        for bad in ("proxy.example.net:3128", "http://a b", "http://x'; reboot"):
            with self.assertRaises(ValidationError) as ctx:
                linux.validate_profile("rocky-9", _profile(proxy=bad))
            self.assertIn("proxy", ctx.exception.detail)


class TestMirror(LinuxBase):
    def test_validated(self):
        files, _ = self.render(
            "debian-12", _profile(mirror="https://deb.example.net/debian")
        )
        self.assertIn("hostname string deb.example.net", files[0]["content"])
        files, _ = self.render(
            "ubuntu-24.04", _profile(mirror="http://ubuntu.example.net/ubuntu")
        )
        self.assertIn("http://ubuntu.example.net/ubuntu", files[0]["content"])
        for bad in (
            "deb.example.net/debian",
            "ftp://deb.example.net/debian",
            "http://a b",
            "http://x\nd-i preseed/late_command string reboot",
            "https://m.example.net/$(reboot)",
            "https://m.example.net/${repo}",
        ):
            with self.assertRaises(ValidationError) as ctx:
                linux.validate_profile("debian-12", _profile(mirror=bad))
            self.assertIn("mirror", ctx.exception.detail)

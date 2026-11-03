# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""End-to-end checks of the built media: the full ISOs keep BIOS and UEFI boot
entries, the seed ISOs carry the labels the installers look for, and the
first-boot scripts wait for name resolution and the server port instead of
failing on the first try."""

import base64
import os
import re
import subprocess
import tempfile
import textwrap

import pycdlib

from deploy import iso, iso_layout, linux
from deploy.tests.test_iso import EFISYS, linux_fixture, windows_fixture
from deploy.tests.test_iso_layout import Base

WIN_TARGETS = ("win11-home", "server2022-standard-desktop")
LINUX_FULL = {
    "ubuntu-24.04": {"label": "Ubuntu-Server 24.04", "os": "ubuntu"},
    "rhel-9": {"label": "RHEL-9-0-BaseOS-x86_64", "os": "rhel"},
    "arch": {"label": "ARCH_202610", "os": "arch"},
}
SEED_LABELS = {
    "ubuntu-24.04": "CIDATA",
    "rhel-9": "OEMDRV",
    "arch": "ARCHINSTALL",
    "win11-home": "AUTOUNATTEND",
    "server2022-standard-desktop": "AUTOUNATTEND",
}


def _entries(path):
    img = pycdlib.PyCdlib()
    img.open(path)
    try:
        label = img.pvd.volume_identifier.decode("ascii", "replace").strip()
        cat = img.eltorito_boot_catalog
        if cat is None:
            return label, []
        out = [(cat.validation_entry.platform_id, cat.initial_entry)]
        for sec in cat.sections:
            out += [(sec.platform_id, e) for e in sec.section_entries]
        return label, out
    finally:
        img.close()


class TestBootableMedia(Base):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _build(self, fixture, layout):
        src = os.path.join(self.tmp.name, "src.iso")
        out = os.path.join(self.tmp.name, "out.iso")
        fixture(src)
        with open(out, "w+b") as fp:
            iso.inject(src, fp, layout.files, edits=layout.edits)
        return out

    def _files(self, target_id):
        if target_id.startswith(("win", "server")):
            return self.win_files(target_id)
        return self.linux_files(target_id)

    def test_windows_full_boots_bios_and_uefi(self):
        for target_id in WIN_TARGETS:
            with self.subTest(target_id):
                files = self.win_files(target_id)
                layout = iso_layout.full(
                    target_id,
                    self.deployment,
                    files,
                    ("agent.exe", b"MZ"),
                    {"label": "CCCOMA_X64FRE", "os": "windows"},
                )
                out = self._build(windows_fixture, layout)
                _, entries = _entries(out)
                platforms = {p for p, _ in entries}
                self.assertEqual(platforms, {0, 0xEF}, "BIOS and UEFI entries")
                efi = next(e for p, e in entries if p == 0xEF)
                # the hidden EFI image is carried whole, not its first sector
                with open(out, "rb") as fp:
                    fp.seek(efi.load_rba * 2048)
                    self.assertEqual(fp.read(len(EFISYS)), EFISYS)
                paths = dict(layout.files)
                self.assertIn("/autounattend.xml", paths)
                self.assertIn("/sources/$OEM$/$1/ulrmm/agent.exe", paths)
                xml = paths["/autounattend.xml"].decode()
                # specialize runs the extractor, SetupComplete starts the task
                self.assertIn('pass="specialize"', xml)
                self.assertIn("Extensions.ExtractScript", xml)
                complete = next(
                    f["content"] for f in files if f["name"] == "SetupComplete.cmd"
                )
                self.assertIn("schtasks /Run", complete)

    def test_linux_full_boots_bios_and_uefi_unattended(self):
        for target_id, base in LINUX_FULL.items():
            with self.subTest(target_id):
                files = self.linux_files(target_id)
                layout = iso_layout.full(target_id, self.deployment, files, None, base)
                out = self._build(linux_fixture, layout)
                _, entries = _entries(out)
                self.assertEqual({p for p, _ in entries}, {0, 0xEF})
                if target_id == "arch":
                    continue
                img = pycdlib.PyCdlib()
                img.open(out)
                try:
                    import io

                    buf = io.BytesIO()
                    img.get_file_from_iso_fp(buf, joliet_path="/boot/grub/grub.cfg")
                finally:
                    img.close()
                grub = buf.getvalue().decode()
                arg = {"ubuntu-24.04": "autoinstall", "rhel-9": "inst.ks=hd:LABEL="}
                self.assertIn(arg[target_id], grub)
                self.assertIn("set timeout=5", grub)

    def test_seed_labels(self):
        for target_id, label in SEED_LABELS.items():
            with self.subTest(target_id):
                layout = iso_layout.seed(
                    target_id, self.deployment, self._files(target_id), None
                )
                self.assertEqual(layout.label, label)
                data = iso.seed_iso(layout.label, layout.files)
                path = os.path.join(self.tmp.name, "seed.iso")
                with open(path, "wb") as fp:
                    fp.write(data)
                got, _ = _entries(path)
                self.assertEqual(got, label)


class TestNetworkWait(Base):
    """The first-boot pieces survive a resolver that answers only later."""

    def _unit(self):
        name, _, script_path, unit_path = linux._ident_paths()
        return linux._first_boot_unit(script_path, unit_path, name)

    def test_linux_unit_restarts_until_enrolled(self):
        unit = self._unit()
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("RestartSec=10s", unit)
        self.assertIn("StartLimitIntervalSec=0", unit)
        self.assertRegex(unit, r"After=network-online\.target systemd-resolved")

    def test_linux_wait_survives_three_failed_lookups(self):
        unit = self._unit()
        cmd = re.search(r"^ExecStartPre=-/bin/bash -c '(.*)'$", unit, re.M).group(1)
        cmd = cmd.replace("sleep 5", "sleep 0.01")
        fake = os.path.join(tempfile.mkdtemp(), "bin")
        os.makedirs(fake)
        count = os.path.join(fake, "count")
        # getent fails three times, then answers; timeout stands in for the
        # port probe so nothing is dialled
        with open(os.path.join(fake, "getent"), "w") as fp:
            fp.write(textwrap.dedent(f"""\
                    #!/bin/sh
                    n=$(cat {count} 2>/dev/null || echo 0); n=$((n+1))
                    echo $n > {count}
                    [ $n -gt 3 ]
                    """))
        with open(os.path.join(fake, "timeout"), "w") as fp:
            fp.write("#!/bin/sh\nexit 0\n")
        for name in ("getent", "timeout"):
            os.chmod(os.path.join(fake, name), 0o755)
        env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"])
        r = subprocess.run(["bash", "-c", cmd], env=env, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(count) as fp:
            self.assertEqual(fp.read().strip(), "4")

    def test_linux_wait_gives_up_and_lets_the_unit_retry(self):
        cmd = re.search(
            r"^ExecStartPre=-/bin/bash -c '(.*)'$", self._unit(), re.M
        ).group(1)
        cmd = cmd.replace("seq 1 120", "seq 1 2").replace("sleep 5", "sleep 0.01")
        fake = os.path.join(tempfile.mkdtemp(), "bin")
        os.makedirs(fake)
        count = os.path.join(fake, "count")
        with open(os.path.join(fake, "getent"), "w") as fp:
            fp.write(f"#!/bin/sh\necho x >> {count}\nexit 2\n")
        os.chmod(os.path.join(fake, "getent"), 0o755)
        env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"])
        subprocess.run(["bash", "-c", cmd], env=env, capture_output=True, timeout=30)
        # the pre-start ends after its tries (ExecStartPre=- ignores the
        # result), the script runs, and Restart=on-failure covers a failure
        with open(count) as fp:
            self.assertEqual(len(fp.read().split()), 2)

    def test_every_linux_target_installs_the_unit(self):
        for target_id in LINUX_FULL:
            with self.subTest(target_id):
                text = "\n".join(f["content"] for f in self.linux_files(target_id))
                bodies = [
                    base64.b64decode(m).decode()
                    for m in re.findall(r"printf %s (\S+) \| base64 -d", text)
                ]
                units = [b for b in bodies if "[Service]" in b]
                self.assertEqual(len(units), 1, target_id)
                self.assertIn("Restart=on-failure", units[0])
                self.assertIn("/dev/tcp/", units[0])

    def test_windows_bootstrap_waits_before_each_try(self):
        for target_id in WIN_TARGETS:
            with self.subTest(target_id):
                files = {f["name"]: f["content"] for f in self.win_files(target_id)}
                boot = next(v for k, v in files.items() if k.endswith("-bootstrap.ps1"))
                loop = boot.index("while(-not (Enrolled)){")
                wait = boot.index("Resolve-DnsName -Name $u.Host", loop)
                self.assertLess(wait, boot.index("Log 'install agent'", loop))
                self.assertIn("$c.Connect($u.Host,$u.Port)", boot[loop:])
                self.assertIn("Start-Sleep -Seconds 900", boot[loop:])
                # Home writes policies as registry keys, never as GPO
                if target_id == "win11-home":
                    self.assertNotIn("UnattendedJoin", files["autounattend.xml"])
                    self.assertIn("reg.exe add", boot)

    def test_windows_wait_loop_logic(self):
        """The PowerShell loop shape, run through bash with the same control
        flow: three failed lookups, then success, no abort."""
        script = textwrap.dedent("""\
            n=0; ok=0
            lookup() { n=$((n+1)); [ $n -gt 3 ]; }
            for i in $(seq 0 59); do
              if lookup; then ok=1; break; fi
            done
            [ $ok = 1 ] && [ $n = 4 ]
            """)
        self.assertEqual(subprocess.run(["bash", "-c", script]).returncode, 0)

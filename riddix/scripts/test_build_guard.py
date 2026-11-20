# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Parts of riddix/agents/build_agents.sh, run on their own: the republish
guard and the Windows setup."""

import os
import shutil
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "agents" / "build_agents.sh"
START = "# A version is published once."
END = "# The server hands out installers only if"


def part(start: str, end: str) -> str:
    text = SCRIPT.read_text()
    i = text.index(start)
    return text[i : text.index(end, i)]


def guard() -> str:
    return part(START, END)


class TestBuildGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.src, self.new, self.dist = root / "src", root / "new", root / "dist"
        for d in (self.src / "agent", self.src / "build", self.new, self.dist):
            d.mkdir(parents=True)
        (self.src / "agent" / "brand.go").write_text("brand A")
        (self.src / "build" / "brand.env").write_text("env A")

    def run_guard(self, **env):
        script = (
            "set -euo pipefail\n"
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            'warn() { echo "WARNING: $*" >&2; }\n' + guard() + "echo PUBLISH\n"
        )
        base = {k: v for k, v in os.environ.items() if k != "ULRMM_AGENT_REPLACE"}
        e = dict(
            base,
            SRC=str(self.src),
            TMP=str(self.new),
            DIST=str(self.dist),
            ARTIFACT="ulrmm-agent",
            AGENT_VER="1.0",
            expected="linux/amd64 windows/amd64.exe windows/amd64.exe.agent.sha256",
            **dict({"WIN_ARCHS": "amd64"}, **env),
        )
        r = subprocess.run(
            ["bash", "-c", script], env=e, capture_output=True, text=True
        )
        return "PUBLISH" in r.stdout, r.stderr

    def build(self, linux: bytes, exe_sum: str, presign=None, posix="linux-amd64"):
        (self.new / f"ulrmm-agent-v1.0-{posix}").write_bytes(linux)
        (self.new / "ulrmm-agent-v1.0-windows-amd64.exe").write_bytes(os.urandom(8))
        (self.new / "ulrmm-agent-v1.0-windows-amd64.exe.agent.sha256").write_text(
            exe_sum
        )
        if presign:
            (self.new / f"ulrmm-agent-v1.0-{posix}.presign.sha256").write_text(
                presign[0]
            )
            (
                self.new / "ulrmm-agent-v1.0-windows-amd64.exe.agent.presign.sha256"
            ).write_text(presign[1])

    def test_first_and_identical_builds_publish(self):
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])
        # same code: only the setup bytes differ
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])

    def test_changed_code_same_version_keeps_the_published_builds(self):
        self.build(b"linux", "aa")
        self.run_guard()
        self.build(b"linux v2", "aa")
        published, err = self.run_guard()
        self.assertFalse(published)
        self.assertIn("ulrmm-agent-v1.0-linux-amd64", err)
        self.build(b"linux", "bb")
        published, err = self.run_guard()
        self.assertFalse(published)
        self.assertIn("windows-amd64.exe.agent.sha256", err)

    def test_branding_change_or_override_replaces(self):
        self.build(b"linux", "aa")
        self.run_guard()
        self.build(b"linux v2", "aa")
        self.assertTrue(self.run_guard(ULRMM_AGENT_REPLACE="1")[0])
        self.build(b"linux v3", "bb")
        (self.src / "agent" / "brand.go").write_text("brand B")
        self.assertTrue(self.run_guard()[0])

    def test_icon_change_publishes(self):
        self.build(b"linux", "aa")
        self.run_guard()
        self.build(b"linux v2", "bb")
        (self.src / "build" / "brand.ico").write_bytes(b"ico")
        self.assertTrue(self.run_guard()[0])
        self.build(b"linux v3", "cc")
        self.assertFalse(self.run_guard()[0])

    def test_legacy_stamp_keeps_protecting_builds_until_verified(self):
        (self.src / "build" / "brand.ico").write_bytes(b"ico")
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])
        stamp = self.dist / ".inputs-v1.0"
        current = stamp.read_text()
        legacy = sha256(b"brand Aenv A").hexdigest() + "\n"
        self.assertNotEqual(current, legacy)
        stamp.write_text(legacy)

        self.build(b"changed", "bb")
        self.assertFalse(self.run_guard()[0])
        self.assertEqual(stamp.read_text(), legacy)

        self.build(b"linux", "aa")
        for f in self.new.glob("*-windows-*"):
            f.unlink()
        self.assertTrue(self.run_guard(WIN_ARCHS="")[0])
        self.assertEqual(stamp.read_text(), legacy)

        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])
        self.assertEqual(stamp.read_text(), current)

    def test_signed_builds_keep_the_published_artifacts_on_resigning(self):
        mac = "darwin-arm64"
        self.build(b"signed 1", "aa", ("l1", "w1"), mac)
        self.assertTrue(self.run_guard()[0])
        original = {f.name: f.read_bytes() for f in self.dist.iterdir()}
        self.assertEqual(len(original), 6)
        # signed again: other bytes, same build
        self.build(b"signed 2", "bb", ("l1", "w1"), mac)
        published, err = self.run_guard()
        self.assertTrue(published)
        self.assertIn("ulrmm-agent-v1.0-darwin-arm64\n", err)
        self.assertIn("ulrmm-agent-v1.0-windows-amd64.exe\n", err)
        self.assertIn("ULRMM_AGENT_REPLACE=1 replaces them", err)
        self.assertEqual(
            {f.name: f.read_bytes() for f in self.dist.iterdir()}, original
        )
        # a new target can still be published alongside the preserved artifacts
        self.build(b"signed 2", "bb", ("l1", "w1"), mac)
        name = "ulrmm-agent-v1.0-linux-arm64"
        (self.new / name).write_bytes(b"arm64")
        self.assertTrue(self.run_guard()[0])
        self.assertEqual(
            {f.name: f.read_bytes() for f in self.dist.iterdir()},
            {**original, name: b"arm64"},
        )
        for presign, name in (
            (("l2", "w1"), "ulrmm-agent-v1.0-darwin-arm64\n"),
            (("l1", "w2"), "windows-amd64.exe.agent.sha256\n"),
        ):
            with self.subTest(presign=presign):
                self.build(b"signed 3", "cc", presign, mac)
                published, err = self.run_guard()
                self.assertFalse(published)
                self.assertIn(name, err)

    def test_icon_change_keeps_resigned_mac_builds(self):
        mac = "ulrmm-agent-v1.0-darwin-arm64"
        self.build(b"signed 1", "aa", ("m1", "w1"), "darwin-arm64")
        self.assertTrue(self.run_guard()[0])
        (self.src / "build" / "brand.ico").write_bytes(b"ico")
        self.build(b"signed 2", "bb", ("m1", "w2"), "darwin-arm64")
        published, err = self.run_guard()
        self.assertTrue(published)
        self.assertIn(mac + "\n", err)
        self.assertEqual((self.dist / mac).read_bytes(), b"signed 1")
        sums = self.dist / "ulrmm-agent-v1.0-windows-amd64.exe.agent.sha256"
        self.assertEqual(sums.read_text(), "bb")

    def test_unsigned_builds_are_compared_byte_for_byte(self):
        self.build(b"linux 1", "aa", ("l1", "w1"))
        self.assertTrue(self.run_guard()[0])
        self.build(b"linux 2", "aa", ("l1", "w1"))
        published, err = self.run_guard()
        self.assertFalse(published)
        self.assertIn("ulrmm-agent-v1.0-linux-amd64\n", err)

    def test_replace_without_windows_keeps_nothing_half_replaced(self):
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])
        for f in self.new.glob("*-windows-*"):
            f.unlink()
        (self.new / "ulrmm-agent-v1.0-linux-amd64").write_bytes(b"linux v2")
        published, err = self.run_guard(WIN_ARCHS="", ULRMM_AGENT_REPLACE="1")
        self.assertFalse(published)
        self.assertIn("Install nsis (makensis) and run again", err)
        self.assertIn("ulrmm-agent-v1.0-windows-amd64.exe ", err)
        self.assertEqual(
            (self.dist / "ulrmm-agent-v1.0-linux-amd64").read_bytes(), b"linux"
        )

    def test_missing_setup_still_protects_the_installed_exe_checksum(self):
        self.build(b"linux", "aa", ("l1", "w1"))
        self.assertTrue(self.run_guard()[0])
        (self.dist / "ulrmm-agent-v1.0-windows-amd64.exe").unlink()
        self.build(b"linux", "bb", ("l1", "w1"))
        published, err = self.run_guard()
        self.assertFalse(published)
        self.assertIn("windows-amd64.exe.agent.sha256", err)

    def test_run_without_windows_keeps_other_windows_setups(self):
        self.build(b"linux", "aa")
        self.run_guard()
        for f in self.new.glob("*-windows-*"):
            f.unlink()
        stamp = self.dist / ".inputs-v1.0"
        original = stamp.read_text()
        (self.src / "agent" / "brand.go").write_text("brand B")
        published, err = self.run_guard(WIN_ARCHS="")
        self.assertFalse(published)
        self.assertIn("ERROR: v1.0 has Windows setups in", err)
        self.assertEqual(stamp.read_text(), original)
        for env in ({"ULRMM_AGENT_REPLACE": "1"}, {}):
            stamp.unlink(missing_ok=True)
            self.assertFalse(self.run_guard(WIN_ARCHS="", **env)[0])
        # same branding, or no Windows setup of this version: publish
        stamp.write_text(original)
        (self.src / "agent" / "brand.go").write_text("brand A")
        self.assertTrue(self.run_guard(WIN_ARCHS="")[0])
        for f in self.dist.glob("*-windows-*"):
            f.unlink()
        (self.src / "agent" / "brand.go").write_text("brand C")
        self.assertTrue(self.run_guard(WIN_ARCHS="")[0])


DEFINES = (
    "MyAppName",
    "MyAppPublisher",
    "MyAppURL",
    "MyAppVersion",
    "MyAppNumVersion",
    "MyAppId",
    "MyAppExeName",
    "MyAppSvcName",
    "MyAppProgDir",
    "MyAppRegKey",
)


class TestWindowsPacker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_part(self, start, end, tail, stubs="", **env):
        script = (
            'die() { echo "ERROR: $*" >&2; exit 1; }\n'
            'warn() { echo "WARNING: $*" >&2; }\n' + stubs + part(start, end) + tail
        )
        base = {k: v for k, v in os.environ.items() if not k.startswith("ULRMM_")}
        return subprocess.run(
            [shutil.which("bash"), "-c", script],
            env=dict(base, **env),
            capture_output=True,
            text=True,
        )

    def test_packer_setting_only_warns(self):
        for env in ({"ULRMM_WIN_PACKER": "inno"}, {"LS_PACKER": "wix"}, {}):
            with self.subTest(**env):
                r = self.run_part(
                    "WIN_PACKER=${ULRMM_WIN_PACKER",
                    'echo "=== Configuration ==="',
                    "echo GO\n",
                    'py_setting() { printf %s "$LS_PACKER"; }\n',
                    **env,
                )
                self.assertEqual((r.returncode, r.stdout), (0, "GO\n"), r.stderr)
                if env:
                    self.assertEqual(r.stderr.count("WARNING"), 1, r.stderr)
                    self.assertIn(
                        "is ignored, the Windows setup is built with makensis", r.stderr
                    )
                else:
                    self.assertEqual(r.stderr, "")

    def runtime(self, version, package, makensis=True, **env):
        stubs = 'dpkg-query() { [ -n "$NSIS_PKG" ] && printf %s "$NSIS_PKG"; }\n'
        if makensis:
            stubs += (
                'makensis() { [ "$1" = -VERSION ] && [ -n "$NSIS_VER" ]'
                ' && echo "$NSIS_VER"; }\n'
            )
        return self.run_part(
            'echo "=== Windows ==="',
            "# shellcheck disable=SC1091",
            'echo "ARCHS=$WIN_ARCHS"\n',
            stubs,
            WIN_ARCHS="amd64 386",
            NSIS_VER=version,
            NSIS_PKG=package,
            **env,
        )

    @unittest.skipUnless(shutil.which("dpkg"), "needs dpkg --compare-versions")
    def test_runtime_warning(self):
        for version, package, warns in (
            ("v3.09", "", False),
            ("v3.10", "3.10-1", False),
            ("v3.11", "3.11-1", False),
            # makensis -VERSION of the Debian 12 and Ubuntu 22.04 packages
            ("v3.08-3+deb12u1", "3.08-3+deb12u1", False),
            ("v3.08-2", "3.08-2", True),
            ("v3.08", "3.08-3+deb12u1", False),
            ("v3.08", "3.08-2", True),
            ("v3.08", "", True),
            ("", "", True),
        ):
            with self.subTest(version=version, package=package):
                r = self.runtime(version, package)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("ARCHS=amd64 386", r.stdout)
                if warns:
                    self.assertEqual(r.stderr.count("WARNING"), 1, r.stderr)
                    self.assertIn("lacks the fix for CVE-2023-37378", r.stderr)
                    self.assertIn(f"package {package or 'none'}", r.stderr)
                else:
                    self.assertEqual(r.stderr, "")

    def test_missing_packer_builds_no_windows_agents(self):
        r = self.runtime("v3.09", "", makensis=False, PATH=str(self.root))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ARCHS=\n", r.stdout)
        self.assertIn("no makensis found", r.stderr)
        self.assertIn("(apt-get install nsis)", r.stderr)

    def path_check(
        self,
        prog_dir,
        exe="ulrmm-agent.exe",
        archs="amd64 386",
        svc="ulrmm-agent",
        reg_key="UniversalLocalRMM",
    ):
        return self.run_part(
            "# setup.nsi builds one path element below Program Files",
            "# The .syso holds version strings",
            'echo "ARCHS=$WIN_ARCHS"\n',
            WIN_ARCHS=archs,
            ISCC_PROG_DIR=prog_dir,
            ISCC_EXE_NAME=exe,
            ISCC_SVC_NAME=svc,
            ISCC_REG_KEY=reg_key,
        )

    def test_path_the_setup_refuses_skips_windows_only(self):
        for name in ("Acme Inc.", " Acme", "Acme..Inc", "a$b", "Grüße", "a[b]"):
            for prog_dir, exe in ((name, "ulrmm-agent.exe"), ("ULRMM Agent", name)):
                with self.subTest(prog_dir=prog_dir, exe=exe):
                    r = self.path_check(prog_dir, exe)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual((r.stdout, r.stderr), ("ARCHS=amd64 386\n", ""))
        for bad in ("a\\b", "a/b", "a:b", "a*b", "a?b", "a<b", "a>b", "a|b"):
            for setting, prog_dir, exe in (
                ("AGENT_WIN_PROG_DIR", bad, "ulrmm-agent.exe"),
                ("AGENT_WIN_EXE", "ULRMM Agent", bad),
            ):
                with self.subTest(prog_dir=prog_dir, exe=exe):
                    r = self.path_check(prog_dir, exe)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout, "ARCHS=\n")
                    self.assertIn(f"WARNING: {setting} '{bad}' holds one of", r.stderr)
                    self.assertIn("are NOT built with makensis", r.stderr)
                    self.assertNotIn("inno", r.stderr.lower())
                    # without Windows targets nothing changes
                    r = self.path_check(prog_dir, exe, "")
                    self.assertEqual((r.stdout, r.stderr), ("ARCHS=\n", ""))

    def test_identity_makensis_would_change_skips_windows_only(self):
        # a backtick, or a backslash after "$", in any of the four values
        for bad in ("Ac`me", "`", "a$\\b", "Cash$\\Agent", "$$\\x"):
            for setting, key in (
                ("AGENT_WIN_PROG_DIR", "prog_dir"),
                ("AGENT_WIN_EXE", "exe"),
                ("AGENT_SVC_NAME", "svc"),
                ("AGENT_WIN_REG_KEY", "reg_key"),
            ):
                vals = {"prog_dir": "ULRMM Agent", key: bad}
                with self.subTest(setting=setting, bad=bad):
                    r = self.path_check(**vals)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout, "ARCHS=\n")
                    # one warning block
                    self.assertEqual(r.stderr.count("WARNING"), 7, r.stderr)
                    self.assertIn(
                        f"WARNING: {setting} '{bad}' holds a ` or a \\ after a $",
                        r.stderr,
                    )
                    self.assertNotIn("inno", r.stderr.lower())
                    r = self.path_check(archs="", **vals)
                    self.assertEqual((r.stdout, r.stderr), ("ARCHS=\n", ""))
        # "$" alone and a backslash elsewhere stay: a nested registry key
        for key, ok in (
            ("svc", "s$ x$"),
            ("reg_key", "Acme\\Agent"),
            ("reg_key", "Ca$h\\Agent$"),
        ):
            with self.subTest(key=key, ok=ok):
                r = self.path_check("ULRMM Agent", **{key: ok})
                self.assertEqual((r.stdout, r.stderr), ("ARCHS=amd64 386\n", ""))

    def pack(self, fail=False):
        src, tmp = self.root / "src", self.root / "o$1ut"
        (src / "build").mkdir(parents=True, exist_ok=True)
        tmp.mkdir(exist_ok=True)
        stubs = (
            'makensis() { echo "LC=$LC_ALL PWD=$PWD"; printf "ARG %s\\n" "$@";'
            ' [ "$FAIL" != 1 ]; }\n'
        )
        # brand values as brand.env carries them: "$" may appear anywhere
        brand = {
            "ISCC_APP_NAME": "A$b Agent",
            "ISCC_PUBLISHER": "P$0",
            "ISCC_URL": "https://x.example/$INSTDIR",
            "ISCC_APP_ID": "{{61D095D9-C6CE-4D60-B192-4C6699822C40}",
            "ISCC_EXE_NAME": "e$$x.exe",
            "ISCC_SVC_NAME": "s$",
            "ISCC_PROG_DIR": "D$ir",
            "ISCC_REG_KEY": "K${R}",
        }
        call = part(
            "  # -WX: a warning",
            "  printf '  %-46s %s (self-built)",
        )
        r = self.run_part(
            '# makensis reads "$" in a define as a variable',
            "for a in $WIN_ARCHS; do",
            'a=amd64\nf="ulrmm-agent-v1.13.11.2026-windows-$a.exe"\n'
            + call
            + 'echo "DONE"\n',
            stubs,
            SRC=str(src),
            TMP=str(tmp),
            AGENT_VER="1.13.11.2026",
            AGENT_NUMVER="2026.11.13.1",
            FAIL="1" if fail else "0",
            **brand,
        )
        return r, src, tmp

    def test_makensis_gets_every_define_with_dollar_doubled(self):
        r, src, tmp = self.pack()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"LC=C.UTF-8 PWD={src}\n", r.stdout)
        args = [ln[4:] for ln in r.stdout.splitlines() if ln.startswith("ARG ")]
        out = str(tmp / "ulrmm-agent-v1.13.11.2026-windows-amd64.exe")
        self.assertEqual(
            args[:5],
            [
                "-V2",
                "-WX",
                "-INPUTCHARSET",
                "UTF8",
                "-DOutFile=" + out.replace("$", "$$"),
            ],
        )
        self.assertEqual(args[-1], "build/setup.nsi")
        defs = args[5:-1]
        self.assertEqual([d[2:].split("=", 1)[0] for d in defs], list(DEFINES))
        self.assertEqual(
            defs,
            [
                "-DMyAppName=A$$b Agent",
                "-DMyAppPublisher=P$$0",
                "-DMyAppURL=https://x.example/$$INSTDIR",
                "-DMyAppVersion=1.13.11.2026",
                "-DMyAppNumVersion=2026.11.13.1",
                "-DMyAppId={{61D095D9-C6CE-4D60-B192-4C6699822C40}",
                "-DMyAppExeName=e$$$$x.exe",
                "-DMyAppSvcName=s$$",
                "-DMyAppProgDir=D$$ir",
                "-DMyAppRegKey=K$${R}",
            ],
        )
        self.assertIn("DONE", r.stdout)

    def test_failed_makensis_stops_the_build(self):
        r, _, _ = self.pack(fail=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR: makensis (amd64) failed", r.stderr)
        self.assertNotIn("DONE", r.stdout)

    def test_failed_goversioninfo_stops_the_build(self):
        r = self.run_part(
            '  ( cd "$SRC" && goversioninfo',
            '  ( cd "$SRC" && env GOOS=windows',
            "echo DONE\n",
            "goversioninfo() { return 1; }\n",
            SRC=str(self.root),
            a="amd64",
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR: goversioninfo amd64 failed - no Windows agent", r.stderr)
        self.assertNotIn("DONE", r.stdout)


if __name__ == "__main__":
    unittest.main()

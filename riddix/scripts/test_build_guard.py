# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Parts of riddix/agents/build_agents.sh, run on their own: the republish
guard and the Windows packer."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "agents" / "build_agents.sh"
START = "# A version is published once."
END = 'echo "=== Publish to $DIST ==="'


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
            'warn() { echo "WARNING: $*" >&2; }\n'
            + guard()
            + 'echo PUBLISH\nprintf "%s\\n" "$inputs" >"$stamp"\n'
        )
        base = {k: v for k, v in os.environ.items() if k != "ULRMM_AGENT_REPLACE"}
        e = dict(
            base,
            SRC=str(self.src),
            TMP=str(self.new),
            DIST=str(self.dist),
            ARTIFACT="ulrmm-agent",
            AGENT_VER="1.0",
            **env,
        )
        r = subprocess.run(
            ["bash", "-c", script], env=e, capture_output=True, text=True
        )
        return "PUBLISH" in r.stdout, r.stderr

    def build(self, linux: bytes, exe_sum: str):
        (self.new / "ulrmm-agent-v1.0-linux-amd64").write_bytes(linux)
        (self.new / "ulrmm-agent-v1.0-windows-amd64.exe").write_bytes(os.urandom(8))
        (self.new / "ulrmm-agent-v1.0-windows-amd64.exe.agent.sha256").write_text(
            exe_sum
        )

    def publish(self):
        for f in self.new.iterdir():
            (self.dist / f.name).write_bytes(f.read_bytes())

    def test_first_and_identical_builds_publish(self):
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])
        self.publish()
        # same code: only the setup bytes differ
        self.build(b"linux", "aa")
        self.assertTrue(self.run_guard()[0])

    def test_changed_code_same_version_keeps_the_published_builds(self):
        self.build(b"linux", "aa")
        self.run_guard()
        self.publish()
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
        self.publish()
        self.build(b"linux v2", "aa")
        self.assertTrue(self.run_guard(ULRMM_AGENT_REPLACE="1")[0])
        (self.src / "agent" / "brand.go").write_text("brand B")
        self.assertTrue(self.run_guard()[0])


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
            ["bash", "-c", script],
            env=dict(base, **env),
            capture_output=True,
            text=True,
        )

    def packer(self, **env):
        return self.run_part(
            "# Windows setup: makensis with build/setup.nsi",
            'echo "=== Configuration ==="',
            'echo "PACKER $WIN_PACKER $WIN_PACKER_BIN"\n',
            'py_setting() { printf %s "$LS_PACKER"; }\n',
            **env,
        )

    def test_packer_choice(self):
        for env, want in (
            ({}, "PACKER nsis makensis"),
            ({"LS_PACKER": "inno"}, "PACKER inno iscc"),
            ({"ULRMM_WIN_PACKER": "nsis", "LS_PACKER": "inno"}, "PACKER nsis makensis"),
            ({"ULRMM_WIN_PACKER": "inno"}, "PACKER inno iscc"),
        ):
            with self.subTest(**env):
                r = self.packer(**env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), want)
        for bad in ("NSIS", "wix", "inno "):
            with self.subTest(bad=bad):
                r = self.packer(ULRMM_WIN_PACKER=bad)
                self.assertEqual(r.returncode, 1)
                self.assertIn("is neither nsis nor inno", r.stderr)
                self.assertNotIn("PACKER", r.stdout)

    def runtime(self, version, package, packer_bin="makensis"):
        stubs = (
            'makensis() { [ "$1" = -VERSION ] && [ -n "$NSIS_VER" ] && echo "$NSIS_VER"; }\n'
            'dpkg-query() { [ -n "$NSIS_PKG" ] && printf %s "$NSIS_PKG"; }\n'
        )
        return self.run_part(
            'echo "=== Windows ==="',
            "# shellcheck disable=SC1091",
            'echo "ARCHS=$WIN_ARCHS"\n',
            stubs,
            WIN_PACKER="nsis",
            WIN_PACKER_BIN=packer_bin,
            WIN_ARCHS="amd64 386",
            NSIS_VER=version,
            NSIS_PKG=package,
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
        r = self.runtime("v3.09", "", packer_bin="no-such-packer")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ARCHS=\n", r.stdout)
        self.assertIn("no no-such-packer found", r.stderr)
        self.assertIn("(apt-get install nsis)", r.stderr)
        self.assertNotIn("x86_64", r.stderr)

    def path_check(
        self,
        packer,
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
            WIN_PACKER=packer,
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
                    r = self.path_check("nsis", prog_dir, exe)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual((r.stdout, r.stderr), ("ARCHS=amd64 386\n", ""))
        for bad in ("a\\b", "a/b", "a:b", "a*b", "a?b", "a<b", "a>b", "a|b"):
            for setting, prog_dir, exe in (
                ("AGENT_WIN_PROG_DIR", bad, "ulrmm-agent.exe"),
                ("AGENT_WIN_EXE", "ULRMM Agent", bad),
            ):
                with self.subTest(prog_dir=prog_dir, exe=exe):
                    r = self.path_check("nsis", prog_dir, exe)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout, "ARCHS=\n")
                    self.assertIn(f"WARNING: {setting} '{bad}' holds one of", r.stderr)
                    self.assertIn("are NOT built with makensis", r.stderr)
                    self.assertIn("ULRMM_WIN_PACKER=inno succeeds; that", r.stderr)
                    # with Inno and without Windows targets nothing changes
                    for packer, archs in (("inno", "amd64 386"), ("nsis", "")):
                        r = self.path_check(packer, prog_dir, exe, archs)
                        self.assertEqual((r.stdout, r.stderr), (f"ARCHS={archs}\n", ""))

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
                    r = self.path_check("nsis", **vals)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout, "ARCHS=\n")
                    # one warning block
                    self.assertEqual(r.stderr.count("WARNING"), 8, r.stderr)
                    self.assertIn(
                        f"WARNING: {setting} '{bad}' holds a ` or a \\ after a $",
                        r.stderr,
                    )
                    self.assertIn("ULRMM_WIN_PACKER=inno succeeds; that", r.stderr)
                    for packer, archs in (("inno", "amd64 386"), ("nsis", "")):
                        r = self.path_check(packer, archs=archs, **vals)
                        self.assertEqual((r.stdout, r.stderr), (f"ARCHS={archs}\n", ""))
        # "$" alone and a backslash elsewhere stay: a nested registry key
        for key, ok in (
            ("svc", "s$ x$"),
            ("reg_key", "Acme\\Agent"),
            ("reg_key", "Ca$h\\Agent$"),
        ):
            with self.subTest(key=key, ok=ok):
                r = self.path_check("nsis", "ULRMM Agent", **{key: ok})
                self.assertEqual((r.stdout, r.stderr), ("ARCHS=amd64 386\n", ""))

    def pack(self, packer, fail=False):
        src, tmp = self.root / "src", self.root / "o$1ut"
        (src / "build").mkdir(parents=True, exist_ok=True)
        tmp.mkdir(exist_ok=True)
        stubs = (
            'makensis() { echo "LC=$LC_ALL PWD=$PWD"; printf "ARG %s\\n" "$@";'
            ' [ "$FAIL" != 1 ]; }\n'
            # the script sends iscc's stdout to /dev/null
            'iscc() { printf "ARG %s\\n" "$@" >&2; mkdir -p build/Output;'
            ' echo setup >"build/Output/win-$a.exe"; }\n'
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
            'if [ "$WIN_PACKER" = nsis ]; then\n    # -WX',
            "  printf '  %-46s %s (self-built)",
        )
        r = self.run_part(
            '# makensis reads "$" in a define as a variable',
            "for a in $WIN_ARCHS; do",
            'a=amd64\nf="ulrmm-agent-v1.13.11.2026-windows-$a.exe"\n'
            + call
            + 'echo "DONE"\n',
            stubs,
            WIN_PACKER=packer,
            SRC=str(src),
            TMP=str(tmp),
            AGENT_VER="1.13.11.2026",
            AGENT_NUMVER="2026.11.13.1",
            FAIL="1" if fail else "0",
            **brand,
        )
        return r, src, tmp

    def test_makensis_gets_every_define_with_dollar_doubled(self):
        r, src, tmp = self.pack("nsis")
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
        r, _, _ = self.pack("nsis", fail=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR: makensis (amd64) failed", r.stderr)
        self.assertNotIn("DONE", r.stdout)

    def test_inno_fallback_runs_iscc_unchanged(self):
        r, _, tmp = self.pack("inno")
        self.assertEqual(r.returncode, 0, r.stderr)
        args = [ln[4:] for ln in r.stderr.splitlines() if ln.startswith("ARG ")]
        self.assertEqual(args[:2], ["build/setup.iss", "/Fwin-amd64"])
        self.assertIn("/DMyAppName=A$b Agent", args)
        self.assertEqual([a[2:].split("=", 1)[0] for a in args[2:]], list(DEFINES))
        self.assertEqual(
            (tmp / "ulrmm-agent-v1.13.11.2026-windows-amd64.exe").read_text(), "setup\n"
        )


if __name__ == "__main__":
    unittest.main()

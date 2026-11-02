# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The republish guard in riddix/agents/build_agents.sh, run on its own."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "agents" / "build_agents.sh"
START = "# A version is published once."
END = 'echo "=== Publish to $DIST ==="'


def guard() -> str:
    text = SCRIPT.read_text()
    return text[text.index(START) : text.index(END)]


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
        # same code: only the Inno setup bytes differ
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


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""python3 -m unittest riddix/scripts/test_check_versions.py (or run this file)."""

import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_versions  # noqa: E402

SETTINGS = """\
BASE_DIR = Path(__file__).resolve().parent.parent
VERSION_FILE = BASE_DIR.parent.parent / "VERSION"
ULRMM_VERSION = VERSION_FILE.read_text().strip()
LATEST_AGENT_VER = "1.22.09.2026"
MESH_VER = "1.2.4"
NATS_SERVER_VER = "2.14.4"
"""


def tree(root, version="1.23.09.2026", settings=SETTINGS):
    (root / "VERSION").write_text(version + "\n")
    api = root / "api" / "ulrmm" / "ulrmm"
    api.mkdir(parents=True)
    (api / "settings.py").write_text(settings)
    (root / "docker" / "mesh").mkdir(parents=True)
    (root / "docker" / "mesh" / "Dockerfile").write_text(
        "FROM node:24\nARG MESH_VER=1.2.4\n"
    )
    (root / "docker" / "compose.yml").write_text(
        "services:\n  nats:\n    image: nats:2.14.4-alpine\n"
    )

    web = root / "web"
    web.mkdir()
    (web / "package.json").write_text(json.dumps({"version": version}))

    agent = root / "agent"
    (agent / "build").mkdir(parents=True)
    (agent / "main.go").write_text('var (\n\tversion = "1.22.09.2026"\n)\n')
    (agent / "build" / "setup.iss").write_text('#define MyAppVersion "1.22.09.2026"\n')
    (agent / "build" / "setup.nsi").write_text(
        '!ifndef MyAppVersion\n  !define MyAppVersion "1.22.09.2026"\n!endif\n'
    )
    return web, agent


class TestCheckVersions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def run_check(self, **kw):
        return check_versions.check(self.root, **kw)[0]

    def test_consistent_tree_passes(self):
        web, agent = tree(self.root)
        self.assertEqual(self.run_check(web=web, agent=agent), [])

    def test_web_out_of_step(self):
        web, agent = tree(self.root)
        (web / "package.json").write_text(json.dumps({"version": "1.22.09.2026"}))
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["web package.json"])

    def test_hardcoded_version_is_a_mismatch(self):
        # the whole point of the VERSION file: a literal here is a second source
        web, agent = tree(
            self.root,
            settings=SETTINGS.replace(
                "VERSION_FILE.read_text().strip()", '"1.23.09.2026"'
            ),
        )
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["ULRMM_VERSION"])

    def test_agent_out_of_step(self):
        web, agent = tree(self.root)
        (agent / "main.go").write_text('var (\n\tversion = "2.12.0"\n)\n')
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["agent main.go"])

    def test_installer_out_of_step(self):
        web, agent = tree(self.root)
        (agent / "build" / "setup.iss").write_text('#define MyAppVersion "2.12.0"\n')
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["setup.iss MyAppVersion"])

    def test_nsis_installer_out_of_step(self):
        web, agent = tree(self.root)
        (agent / "build" / "setup.nsi").write_text('  !define MyAppVersion "2.12.0"\n')
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["setup.nsi MyAppVersion"])

    def test_nsis_installer_is_required(self):
        web, agent = tree(self.root)
        (agent / "build" / "setup.nsi").unlink()
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual(
            [r[:2] for r in rows],
            [("setup.nsi", "unreadable (No such file or directory)")],
        )

    def test_fallback_script_may_be_gone(self):
        # setup.iss stays for one release only
        web, agent = tree(self.root)
        (agent / "build" / "setup.iss").unlink()
        self.assertEqual(self.run_check(web=web, agent=agent), [])

    def test_second_assignment_wins_and_is_reported(self):
        # the last module level assignment is what the import actually ends up with
        web, agent = tree(
            self.root, settings=SETTINGS + 'ULRMM_VERSION = "1.23.09.2026"\n'
        )
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["ULRMM_VERSION"])

    def test_mesh_dockerfile_out_of_step(self):
        web, agent = tree(self.root)
        dockerfile = self.root / "docker" / "mesh" / "Dockerfile"
        dockerfile.write_text("ARG MESH_VER=1.2.3\n")
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual(
            [r[:3] for r in rows], [("mesh Dockerfile", "1.2.3", "MESH_VER 1.2.4")]
        )

    def test_compose_nats_out_of_step(self):
        web, agent = tree(self.root)
        (self.root / "docker" / "compose.yml").write_text(
            "    image: nats:2.12.0-alpine\n"
        )
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["compose.yml nats"])

    def test_server_files_only(self):
        # CI has no web or agent checkout
        tree(self.root)
        self.assertEqual(self.run_check(web=None, agent=None), [])

    def test_unparseable_settings_is_a_row_not_a_traceback(self):
        web, agent = tree(self.root, settings="ULRMM_VERSION = (\n")
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["settings.py"])

    def test_version_format(self):
        web, agent = tree(self.root, version="1.5.3")
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["VERSION"])

        valid = check_versions.valid_version
        self.assertTrue(valid("12.29.02.2028"))
        for bad in (
            "1.5.9.2026",
            "v1.23.09.2026",
            "0.23.09.2026",
            "1.31.09.2026",
            "1.29.02.2027",
            None,
        ):
            self.assertFalse(valid(bad), bad)

    def test_agent_version_format(self):
        web, agent = tree(
            self.root, settings=SETTINGS.replace("1.22.09.2026", "2.12.0")
        )
        rows = self.run_check(web=web, agent=agent)
        self.assertEqual([r[0] for r in rows], ["LATEST_AGENT_VER"])

    def test_next_version(self):
        day = datetime.date(2026, 9, 23)
        nxt = check_versions.next_version
        self.assertEqual(nxt("1.23.09.2026", day), "2.23.09.2026")
        self.assertEqual(nxt("9.23.09.2026", day), "10.23.09.2026")
        self.assertEqual(nxt("3.22.09.2026", day), "1.23.09.2026")
        self.assertEqual(nxt("1.23.09.2025", day), "1.23.09.2026")
        self.assertEqual(nxt("2.12.0", day), "1.23.09.2026")
        oct1 = datetime.date(2026, 10, 1)
        self.assertEqual(nxt("1.30.09.2026", oct1), "1.01.10.2026")


if __name__ == "__main__":
    unittest.main()

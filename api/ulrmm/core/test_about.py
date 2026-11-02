# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.test import override_settings

from core.about import MAX_RELEASES, parse_changelog, read_changelog
from ulrmm.test import ULRMMTestCase

SAMPLE = """# Server changelog

## Unreleased

- Not released yet

## 2.09.10.2026 (2026-10-09)

- Audit save for singletons
- Second item

## 2026-10-06

- Library sync
"""


class TestParseChangelog(ULRMMTestCase):
    def test_versions_dates_and_items(self):
        r = parse_changelog(SAMPLE)
        self.assertEqual(
            [x["version"] for x in r], ["Unreleased", "2.09.10.2026", "2026-10-06"]
        )
        self.assertIsNone(r[0]["date"])
        self.assertEqual(r[1]["date"], "2026-10-09")
        self.assertEqual(r[1]["items"], ["Audit save for singletons", "Second item"])
        self.assertEqual(r[2]["items"], ["Library sync"])

    def test_items_before_the_first_heading_are_ignored(self):
        self.assertEqual(parse_changelog("- stray\n# title\n"), [])

    def test_release_count_is_capped(self):
        text = "".join(f"## 1.{i:02d}.10.2026\n- x\n" for i in range(MAX_RELEASES + 5))
        self.assertEqual(len(parse_changelog(text)), MAX_RELEASES)

    def test_missing_file_reads_as_empty(self):
        self.assertEqual(read_changelog(Path("/nonexistent/CHANGELOG.md")), [])


class TestAboutView(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.url = "/core/about/"

    def test_requires_auth(self):
        self.check_not_authenticated("get", self.url)

    def test_components_and_changelogs(self):
        with TemporaryDirectory() as scripts, TemporaryDirectory() as agents:
            Path(scripts, "CHANGELOG.md").write_text(SAMPLE)
            Path(agents, "src").mkdir()
            Path(agents, "src", "CHANGELOG.md").write_text(
                "## 2.09.10.2026 (2026-10-09)\n- Agent item\n"
            )
            with override_settings(SCRIPTS_DIR=scripts, ULRMM_AGENT_ROOT=agents):
                r = self.client.get(self.url)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["product"], "UniversalLocal RMM")
        comps = {c["key"]: c for c in r.data["components"]}
        self.assertEqual(set(comps), {"server", "agent", "scripts"})
        self.assertEqual(comps["server"]["version"], settings.ULRMM_VERSION)
        self.assertEqual(comps["agent"]["version"], settings.LATEST_AGENT_VER)
        self.assertEqual(comps["agent"]["changelog"][0]["items"], ["Agent item"])
        # the newest entry of the script library stands in for its version
        self.assertEqual(comps["scripts"]["version"], "Unreleased")

    def test_missing_sources_give_empty_changelogs(self):
        with override_settings(
            SCRIPTS_DIR="/nonexistent", ULRMM_AGENT_ROOT="/nonexistent"
        ):
            r = self.client.get(self.url)
        comps = {c["key"]: c for c in r.data["components"]}
        self.assertEqual(comps["agent"]["changelog"], [])
        self.assertIsNone(comps["scripts"]["version"])

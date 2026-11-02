# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.test import SimpleTestCase

from ulrmm.helpers import agent_ver


class TestVersionFile(SimpleTestCase):
    def test_version_comes_from_the_version_file(self):
        self.assertTrue(settings.VERSION_FILE.is_file())
        self.assertEqual(
            settings.ULRMM_VERSION, settings.VERSION_FILE.read_text().strip()
        )
        for ver in (settings.ULRMM_VERSION, settings.LATEST_AGENT_VER):
            self.assertRegex(ver, r"^[1-9]\d*\.\d{2}\.\d{2}\.\d{4}$")


class TestAgentVer(SimpleTestCase):
    def test_dated_order(self):
        ordered = [
            "1.30.09.2026",
            "5.30.09.2026",
            "1.01.10.2026",
            "12.01.10.2026",
            "1.02.10.2026",
            "1.01.01.2027",
        ]
        for lower, higher in zip(ordered, ordered[1:]):
            self.assertLess(agent_ver(lower), agent_ver(higher), (lower, higher))

    def test_legacy_sorts_below_dated(self):
        self.assertLess(agent_ver("2.12.0"), agent_ver("1.23.09.2026"))
        self.assertLess(agent_ver("99.0.0"), agent_ver("1.01.01.2026"))
        # dated versions still pass the old >= 2.x checks
        for threshold in ("1.3.0", "1.6.0", "2.6.0", "2.10.0", "2.11.0"):
            self.assertGreater(agent_ver("1.02.10.2026"), agent_ver(threshold))
        self.assertLess(agent_ver("2.10.0"), agent_ver("2.11.0"))

    def test_spelling_and_garbage(self):
        self.assertEqual(agent_ver("1.23.09.2026"), agent_ver("v1.23.9.2026"))
        self.assertLess(agent_ver("v5.23.09.2026"), agent_ver("v1.24.09.2026"))
        self.assertEqual(agent_ver("not a version"), agent_ver(""))
        self.assertLess(agent_ver(None), agent_ver("0.0.1"))

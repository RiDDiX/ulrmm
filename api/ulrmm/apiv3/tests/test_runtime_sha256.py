# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings

from apiv3.utils import RUNTIME_SHA256, _runtime_sha256

AGENT = SimpleNamespace(plat="linux", goarch="amd64")
SHA = "ab" * 32


@override_settings(INSTALL_NUSHELL_VERSION="0.112.2")
class TestRuntimeSha256(SimpleTestCase):
    def test_sha256_setting_and_custom_url(self):
        table = RUNTIME_SHA256["nushell"]["0.112.2"]["linux/amd64"]
        with override_settings(INSTALL_NUSHELL_URL="", INSTALL_NUSHELL_SHA256=""):
            self.assertEqual(_runtime_sha256("nushell", AGENT), table)
        with override_settings(
            INSTALL_NUSHELL_URL="https://x/nu", INSTALL_NUSHELL_SHA256=""
        ):
            self.assertEqual(_runtime_sha256("nushell", AGENT), "")
        with override_settings(
            INSTALL_NUSHELL_URL="https://x/nu", INSTALL_NUSHELL_SHA256=SHA.upper()
        ):
            self.assertEqual(_runtime_sha256("nushell", AGENT), SHA)
        with override_settings(INSTALL_NUSHELL_URL="", INSTALL_NUSHELL_SHA256="nothex"):
            self.assertEqual(_runtime_sha256("nushell", AGENT), "")

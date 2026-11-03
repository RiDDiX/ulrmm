# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.test import override_settings

from core.utils import get_mesh_ws_url, get_meshagent_url
from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase


class TestMeshHost(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def agent_url(self):
        return get_meshagent_url(
            ident="x", plat=AgentPlat.LINUX, mesh_site="https://m", mesh_device_id="d"
        )

    def test_default_is_loopback(self):
        self.assertTrue(
            self.agent_url().startswith("http://127.0.0.1:4430/meshagents?")
        )
        with patch("core.utils.get_auth_token", return_value="t"):
            self.assertEqual(
                get_mesh_ws_url(), "ws://127.0.0.1:4430/control.ashx?auth=t"
            )

    @override_settings(MESH_HOST="mesh", MESH_PORT=4431)
    def test_mesh_host_setting(self):
        self.assertTrue(self.agent_url().startswith("http://mesh:4431/meshagents?"))
        with patch("core.utils.get_auth_token", return_value="t"):
            self.assertEqual(get_mesh_ws_url(), "ws://mesh:4431/control.ashx?auth=t")

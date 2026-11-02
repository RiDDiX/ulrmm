# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
from unittest.mock import MagicMock, patch

import requests
from django.core.cache import cache
from django.test import override_settings

from core import utils
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

ARGS = {
    "ident": 26,
    "plat": "linux",
    "mesh_device_id": "MESHID",
    "mesh_site": "https://mesh.example.test",
}


def _answer(body: bytes):
    r = MagicMock()
    r.__enter__.return_value = r
    r.iter_content.return_value = [body[:3], body[3:]]
    return r


@override_settings(CACHES=LOCMEM_CACHE, USE_EXTERNAL_MESH=False)
class TestMeshInstallerSha256(ULRMMTestCase):
    def setUp(self):
        cache.clear()

    @patch("core.utils.requests.get")
    def test_hash_from_the_local_mesh_once(self, get):
        get.return_value = _answer(b"\x7fELFmesh")
        sha = hashlib.sha256(b"\x7fELFmesh").hexdigest()
        self.assertEqual(utils.mesh_installer_sha256(**ARGS), sha)
        self.assertEqual(utils.mesh_installer_sha256(**ARGS), sha)
        get.assert_called_once()
        url = get.call_args.args[0]
        self.assertTrue(url.startswith("http://127.0.0.1:"), url)
        self.assertIn("installflags=2&meshinstall=26", url)
        self.assertEqual(get.call_args.kwargs["headers"], {"Host": "mesh.example.test"})
        # another mesh version or group is another binary
        with override_settings(MESH_VER="9.9.9"):
            utils.mesh_installer_sha256(**ARGS)
        utils.mesh_installer_sha256(**{**ARGS, "mesh_device_id": "OTHER"})
        self.assertEqual(get.call_count, 3)

    def test_unreachable_is_logged_and_retried_after_5_minutes(self):
        for failure in (
            {"side_effect": requests.ConnectionError("refused")},
            {"return_value": _answer(b"")},
        ):
            cache.clear()
            with patch("core.utils.requests.get", **failure) as get:
                with patch.object(utils.cache, "set", wraps=utils.cache.set) as put:
                    with self.assertLogs("ulrmm", "WARNING") as logs:
                        self.assertEqual(utils.mesh_installer_sha256(**ARGS), "")
                    self.assertEqual(utils.mesh_installer_sha256(**ARGS), "")
            get.assert_called_once()
            self.assertIn("no sha256", logs.output[0])
            self.assertNotIn("MESHID", logs.output[0])
            self.assertEqual(put.call_args.args[1:], ("", utils.MESH_SHA_FAIL_TTL))

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from django.test import override_settings

from core.utils import get_mesh_ws_url, run_url_rest_action


def _core(site):
    return SimpleNamespace(mesh_site=site, mesh_api_superuser="su", mesh_token="k")


@pytest.mark.parametrize(
    "site, url",
    [
        ("https://mesh.example.test", "wss://mesh.example.test/control.ashx?auth=tok"),
        ("http://mesh.example.test", None),
        ("", None),
        ("httpsx://mesh.example.test", None),
    ],
)
@patch("core.utils.get_auth_token", return_value="tok")
def test_external_mesh_needs_https(_, site, url):
    with override_settings(USE_EXTERNAL_MESH=True), patch(
        "core.utils.get_core_settings", return_value=_core(site)
    ):
        if url is None:
            with pytest.raises(ValueError, match="https"):
                get_mesh_ws_url()
        else:
            assert get_mesh_ws_url() == url


@patch("core.utils.get_auth_token", return_value="tok")
def test_bundled_mesh_stays_on_loopback(_):
    with patch("core.utils.get_core_settings", return_value=_core("http://x")):
        assert get_mesh_ws_url().startswith("ws://127.0.0.1:")


@pytest.mark.django_db
def test_url_action_error_hides_the_url():
    secret = "https://hook.example.test/T0KEN?key=s3cret"
    with patch("core.models.URLAction.objects.get"), patch(
        "core.utils._run_url_rest_action",
        side_effect=requests.exceptions.ConnectionError(f"failed for {secret}"),
    ):
        text, status = run_url_rest_action(action_id=1)
    assert (text, status) == ("URL action failed: ConnectionError", 500)

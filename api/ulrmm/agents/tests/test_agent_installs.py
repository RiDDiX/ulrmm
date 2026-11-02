# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Classic install methods: sha256 pins from the local dist directory."""

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from django.conf import settings
from django.test import override_settings
from model_bakery import baker

from agents.utils import (
    generate_linux_install,
    install_artifact_sha256,
    render_linux_install,
)
from ulrmm.agent_ident import agent_artifact
from ulrmm.test import ULRMMTestCase

VER = settings.LATEST_AGENT_VER


class TestInstallPins(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.site = baker.make("clients.Site")
        self.dist = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dist, ignore_errors=True)
        self.exe = self.dist / agent_artifact(VER, "windows", "amd64")
        self.exe.write_bytes(b"MZ setup")
        self.sha = hashlib.sha256(b"MZ setup").hexdigest()

    def test_sha_with_self_built_agents_url(self):
        # that URL serves the same dist directory
        with override_settings(
            AGENTS_DIST_DIR=str(self.dist),
            SELF_BUILT_AGENTS_URL="https://api.example.test/agentdist",
        ):
            self.assertEqual(install_artifact_sha256("windows", "amd64"), self.sha)
            self.assertEqual(install_artifact_sha256("linux", "amd64"), "")
            self.assertEqual(install_artifact_sha256("windows", "sparc"), "")

    def _powershell(self) -> str:
        r = self.client.post(
            "/agents/installer/",
            {
                "installMethod": "powershell",
                "client": self.site.client_id,
                "site": self.site.pk,
                "expires": 24,
                "agenttype": "server",
                "plat": "windows",
                "goarch": "amd64",
                "api": "https://api.example.test",
                "rdp": 1,
                "ping": 0,
                "power": 0,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def test_powershell_checks_the_download(self):
        with override_settings(
            AGENTS_DIST_DIR=str(self.dist),
            SELF_BUILT_AGENTS_URL="https://api.example.test/agentdist",
        ):
            text = self._powershell()
        self.assertIn(f"$sha256 = '{self.sha}'", text)
        self.assertIn("$enroll = ''", text)
        self.assertIn("Get-FileHash -Algorithm SHA256", text)
        self.assertRegex(text, r"\$auth = '[0-9a-f]{64}'")
        self.assertIn("Write-Secret $authFile $auth", text)
        self.assertIn("'-auth-file'", text)
        self.assertNotIn("'--auth'", text)
        self.assertIn("$cert = ''\n", text)
        self.assertNotRegex(text, r"[a-z0-9]+change\b")

        # no local build: nothing to compare with
        self.exe.unlink()
        with override_settings(AGENTS_DIST_DIR=str(self.dist)):
            self.assertIn("$sha256 = ''", self._powershell())

    @patch("agents.utils.mesh_installer_sha256", return_value="ef" * 32)
    @patch("agents.utils.get_mesh_ws_url", return_value="ws://mesh")
    @patch("agents.utils.get_mesh_device_id", new_callable=AsyncMock)
    def test_classic_bash_script_checks_the_mesh_agent(self, mesh_id, _ws, mesh_sha):
        self.setup_coresettings()
        mesh_id.return_value = "MESHID"
        resp = generate_linux_install(
            client="1",
            site="2",
            agent_type="server",
            arch="arm64",
            token="t",
            api="https://api.example.test",
            download_url="https://api.example.test/agentdist/a",
        )
        text = b"".join(resp.streaming_content).decode()
        self.assertIn(f"meshSha256='{'ef' * 32}'", text)
        kwargs = mesh_sha.call_args.kwargs
        self.assertEqual(
            (str(kwargs["ident"]), kwargs["plat"], kwargs["mesh_device_id"]),
            ("26", "linux", "MESHID"),
        )

    def test_classic_bash_script_keeps_its_mode(self):
        text = render_linux_install(
            download_url="https://api.example.test/agentdist/a",
            sha256="ab" * 32,
            mesh_url="https://mesh.example.test/meshagents?id=1",
            client="1",
            site="2",
            agent_type="server",
            token="t",
            api="https://api.example.test",
        )
        for line in ("enrollJWS=''", "agentBuilds=''", "localBinary=''", "token='t'"):
            self.assertIn(line, text)
        self.assertNotRegex(text, r"[A-Za-z0-9]+Change'")
        self.assertIn(
            'installArgs=(-m install -api "$apiURL" -client-id "$clientID"', text
        )
        self.assertIn('-agent-type "$agentType" -auth-file "$authFile")', text)
        self.assertNotIn('-auth "$token"', text)
        self.assertIn("serverCert=''\n", text)
        # the script still deletes itself, it holds the token
        self.assertRegex(text, re.compile(r"^  self_delete$", re.M))
        r = subprocess.run(
            ["bash", "-n"], input=text, capture_output=True, text=True, timeout=30
        )
        self.assertEqual(r.returncode, 0, r.stderr)

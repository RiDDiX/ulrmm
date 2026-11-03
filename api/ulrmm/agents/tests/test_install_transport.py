# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Install commands of a self-signed server carry its certificate, never
an insecure switch; the token travels in a file."""

import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import override_settings
from model_bakery import baker

from ulrmm.helpers import self_signed_cert_pem
from ulrmm.test import ULRMMTestCase

BODY = "MIIBszCCAVmgAwIBAgIUQ2Vy" + "dA" * 40 + "=="
PEM = (
    f"-----BEGIN CERTIFICATE-----\n{BODY[:64]}\n{BODY[64:]}\n-----END CERTIFICATE-----"
)


class TestSelfSignedInstall(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.cert = tmp / "cert.pem"
        self.cert.write_text(f"{PEM}\n")
        self.key = tmp / "key.pem"
        self.key.write_text(
            "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"
        )

    def install(self, method, plat="windows", **extra):
        data = {
            "installMethod": method,
            "client": self.site.client_id,
            "site": self.site.pk,
            "expires": 24,
            "agenttype": "server",
            "plat": plat,
            "goarch": "amd64",
            "api": "https://api.example.test",
            "rdp": 0,
            "ping": 0,
            "power": 0,
            **extra,
        }
        with override_settings(
            ULRMM_INSECURE=True, CERT_FILE=str(self.cert), KEY_FILE=str(self.key)
        ):
            return self.client.post("/agents/installer/", data, format="json")

    def test_cert_helper(self):
        with override_settings(CERT_FILE=str(self.cert), KEY_FILE=str(self.key)):
            self.assertEqual(self_signed_cert_pem(), "")
            with override_settings(ULRMM_INSECURE=True):
                self.assertEqual(self_signed_cert_pem(), PEM)
                self.cert.write_text("not a certificate")
                self.assertEqual(self_signed_cert_pem(), "")

    def test_unreadable_certificate_refuses(self):
        self.cert.unlink()
        r = self.install("powershell")
        self.assertEqual(r.status_code, 400)
        self.assertIn("cannot be read", r.data)

    def test_powershell_embeds_the_certificate(self):
        r = self.install("powershell")
        self.assertEqual(r.status_code, 200)
        text = r.content.decode()
        self.assertIn(f"$cert = '{PEM}'\n", text)
        self.assertIn("'-cert'", text)
        self.assertNotIn("insecure", text.lower())

    def test_manual_writes_the_certificate(self):
        r = self.install("manual")
        self.assertEqual(r.status_code, 200)
        cmd = r.data["cmd"]
        path = r"C:\Program Files\ULRMM Agent\server.pem"
        self.assertIn(
            "(echo -----BEGIN CERTIFICATE-----& "
            f'echo {BODY}& echo -----END CERTIFICATE-----)> "{path}" && ',
            cmd,
        )
        self.assertTrue(cmd.endswith(f' -cert "{path}"'), cmd)
        self.assertNotIn("insecure", cmd)

    def test_mac_writes_the_certificate(self):
        r = self.install("mac", plat="darwin")
        self.assertEqual(r.status_code, 200)
        cmd = r.data["cmd"]
        self.assertTrue(
            cmd.startswith(
                "printf '%s\\n' '-----BEGIN CERTIFICATE-----' "
                f"'{BODY}' '-----END CERTIFICATE-----' | "
                "sudo tee /etc/ulrmm-agent.server.pem >/dev/null && curl -fL "
                "--proto '=https' --proto-redir '=https' "
                "--cacert /etc/ulrmm-agent.server.pem -o "
            ),
            cmd,
        )
        self.assertTrue(cmd.endswith(" -cert /etc/ulrmm-agent.server.pem"), cmd)
        self.assertNotIn("insecure", cmd)

    def test_freebsd_script_embeds_the_certificate(self):
        r = self.install("freebsd", plat="freebsd")
        self.assertEqual(r.status_code, 200)
        self.assertIn("freebsd_agent_install.sh", r["Content-Disposition"])
        text = b"".join(r.streaming_content).decode()
        self.assertIn(f"\nserverCert='{PEM}'\n", text)
        self.assertNotRegex(text, r"[A-Za-z]+Change'")
        if shutil.which("sh"):
            check = subprocess.run(
                ["sh", "-n"], input=text, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_plain_http_api_is_refused(self):
        with override_settings(ULRMM_INSECURE=False):
            r = self.client.post(
                "/agents/installer/",
                {
                    "installMethod": "manual",
                    "client": self.site.client_id,
                    "site": self.site.pk,
                    "expires": 24,
                    "agenttype": "server",
                    "plat": "windows",
                    "goarch": "amd64",
                    "api": "http://api.example.test",
                },
                format="json",
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn("https address", r.data)


def test_installer_scripts_have_no_insecure_switch():
    from django.conf import settings

    for path in (settings.LINUX_AGENT_SCRIPT, settings.FREEBSD_AGENT_SCRIPT):
        text = Path(path).read_text()
        # the argument is refused, never passed on
        assert '--insecure) die "insecure mode was removed.' in text
        assert "+=(--insecure)" not in text and '"$@" --insecure' not in text
        assert '-auth "$token"' not in text
        assert "--max-redirect=0" in text or "fetch -A" in text
        # downloads from a self-signed server are checked against its certificate
        assert '--cacert "$caFile"' in text
        assert ("--ca-certificate=${caFile}" in text) or ('--ca-cert="$caFile"' in text)
        assert '--proto "=https" --proto-redir "=https"' in text or (
            "--proto =https --proto-redir =https" in text
        )

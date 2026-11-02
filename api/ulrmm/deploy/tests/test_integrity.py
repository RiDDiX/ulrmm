# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test.utils import override_settings
from model_bakery import baker

from apiv3.views import AGENT_EVENT_SEVERITY
from deploy import integrity, signing
from deploy.models import AgentIdentity, SecurityEventKind
from deploy.tests.test_policy import MATRIX, PolicyBase
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

URL = "/api/v3/integrity/"


def _part(text: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def _open(jws: str) -> tuple[dict, dict]:
    h, c, s = jws.split(".")
    sig = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    signing.signing_key().public_key().verify(sig, f"{h}.{c}".encode())
    return _part(h), _part(c)


@override_settings(CACHES=LOCMEM_CACHE)
class TestIntegrityManifest(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        files = {
            "ulrmm-agent-v3.25.10.2026-linux-amd64": b"linux build",
            "ulrmm-agent-v3.25.10.2026-darwin-arm64": b"mac build",
            "ulrmm-agent-v2.25.10.2026-freebsd-amd64": b"old bsd build",
            "ulrmm-agent-v3.25.10.2026-windows-amd64.exe": b"setup",
            "ulrmm-agent-v3.25.10.2026-windows-amd64.exe.agent.sha256": (
                hashlib.sha256(b"agent exe").hexdigest().upper().encode() + b"\n"
            ),
            "ulrmm-agent-v3.25.10.2026-windows-386.exe": b"setup 386",
            "ulrmm-agent-v3.25.10.2026-windows-386.exe.agent.sha256": b"not a sum",
            "ulrmm-agent-v3.25.10.2026-windows-arm64.agent.sha256": b"a" * 64,
            "ulrmm-agent-v3.25.10.2026-linux-amd64.agent.sha256": b"b" * 64,
            ".ulrmm-agent-v3.25.10.2026-linux-386.123.new": b"half written",
            "other-agent-v3.25.10.2026-linux-arm64": b"foreign",
            "ulrmm-agent-v3.25.10.2026-linux-amd64.sig": b"not a build",
            "enroll-pubkey.txt": b"key",
        }
        for name, data in files.items():
            (self.dist / name).write_bytes(data)

    def sha(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def test_builds_from_dist_dir(self):
        with override_settings(AGENTS_DIST_DIR=str(self.dist)):
            got = integrity.builds()
        self.assertEqual(
            got,
            {
                "3.25.10.2026": {
                    "linux-amd64": self.sha(b"linux build"),
                    "darwin-arm64": self.sha(b"mac build"),
                    "windows-amd64": self.sha(b"agent exe"),
                },
                "2.25.10.2026": {"freebsd-amd64": self.sha(b"old bsd build")},
            },
        )

    def test_windows_setup_only_without_sums(self):
        for p in self.dist.glob("*.agent.sha256"):
            p.unlink()
        with override_settings(AGENTS_DIST_DIR=str(self.dist)):
            got = integrity.builds()
            _, claims = _open(self.client.get(URL).data["jws"])
        self.assertNotIn("windows-amd64", got["3.25.10.2026"])
        self.assertEqual(claims["windows"], "setup-only")

    def test_self_built_hashes_only_from_cache(self):
        seen = []

        def cached(url, ver, *, fetch=True):
            seen.append(fetch)
            if url == "https://dl.example.com/a/ulrmm-agent-v3.25.10.2026-linux-arm64":
                return "b" * 64
            return ""

        with override_settings(
            AGENTS_DIST_DIR=str(self.dist),
            SELF_BUILT_AGENTS_URL="https://dl.example.com/a/",
            LATEST_AGENT_VER="3.25.10.2026",
        ), patch.object(integrity, "self_built_sha256", cached):
            got = integrity.builds()
        self.assertEqual(got["3.25.10.2026"]["linux-arm64"], "b" * 64)
        self.assertEqual(got["3.25.10.2026"]["linux-amd64"], self.sha(b"linux build"))
        self.assertTrue(seen)
        self.assertEqual(set(seen), {False})

    def test_build_script_publishes_windows_sums(self):
        # the sum is of the signed exe the setup packs, and a run without it
        # publishes nothing
        repo = Path(settings.BASE_DIR).parents[1]
        build = (repo / "riddix" / "agents" / "build_agents.sh").read_text()
        write = 'sha256sum "$SRC/agent.exe" | cut -d\' \' -f1 >"$TMP/$f.agent.sha256"'
        self.assertEqual(integrity.WINDOWS_SUM_SUFFIX, ".agent.sha256")
        self.assertLess(build.index('sign_win "$SRC/agent.exe"'), build.index(write))
        self.assertLess(build.index(write), build.index("iscc build/setup.iss"))
        self.assertIn(' windows/$a.exe windows/$a.exe.agent.sha256"', build)

    def test_view_serves_signed_manifest(self):
        with override_settings(AGENTS_DIST_DIR=str(self.dist)):
            r = self.client.get(URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        header, claims = _open(r.data["jws"])
        self.assertEqual(header["typ"], "ulrmm-integrity")
        self.assertEqual(header["kid"], signing.key_id())
        self.assertEqual(claims["typ"], "ulrmm-integrity")
        self.assertEqual(claims["v"], 1)
        self.assertEqual(claims["iss"], signing.api_url())
        self.assertNotIn("windows", claims)
        self.assertEqual(
            claims["builds"]["3.25.10.2026"]["linux-amd64"], self.sha(b"linux build")
        )
        self.assertEqual(
            claims["builds"]["3.25.10.2026"]["windows-amd64"], self.sha(b"agent exe")
        )
        self.assertIsInstance(claims["iat"], int)

    def test_view_unavailable_without_https_or_key(self):
        with override_settings(ULRMM_PROTO="http"):
            self.assertEqual(self.client.get(URL).status_code, 503)
        with override_settings(ENROLL_SIGNING_KEY=""):
            r = self.client.get(URL)
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r["Cache-Control"], "no-store")

    def test_throttled_per_ip(self):
        self.assertEqual(integrity.IntegrityThrottle.rate, "120/hour")
        with patch.object(integrity.IntegrityThrottle, "rate", "2/hour"):
            codes = [self.client.get(URL).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_agent_events_known(self):
        self.assertEqual(AGENT_EVENT_SEVERITY["integrity_mismatch"], "high")
        self.assertEqual(AGENT_EVENT_SEVERITY["config_tampered"], "high")
        # the Security Center takes its event labels from these choices
        labels = dict(SecurityEventKind.choices)
        self.assertEqual(
            labels["integrity_mismatch"], "Agent binary does not match the build"
        )
        self.assertEqual(
            labels["config_tampered"], "Agent config changed outside the agent"
        )


class TestMatrixKeystore(PolicyBase):
    def test_keystore_from_identity_caps(self):
        self.login(["can_view_core_settings"])
        AgentIdentity.objects.create(agent=self.agent, caps=["sec2", "ks:creds-tpm"])
        bare = baker.make_recipe("agents.online_agent", site=self.site1)
        AgentIdentity.objects.create(agent=bare, caps=["sec2"])
        r = self.client.get(MATRIX)
        self.assertEqual(r.status_code, 200)
        by_id = {a["agent_id"]: a["keystore"] for a in r.data["agents"]}
        self.assertEqual(by_id[self.agent.agent_id], "creds-tpm")
        self.assertIsNone(by_id[bare.agent_id])
        self.assertIsNone(by_id[self.other.agent_id])

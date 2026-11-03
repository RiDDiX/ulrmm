# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import requests
from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker

from agents.models import Agent
from agents.tasks import send_agent_update_task
from agents.utils import get_agent_url
from deploy.tests.test_security_r1 import jws_parts
from logs.models import DebugLog
from ulrmm.agent_ident import agent_artifact_for, agent_ident_for
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

SELF_BUILT = "https://builds.example.net/agents"
BUILD = b"\x7fELF self-built agent"


def response(body=BUILD, status=200, url=SELF_BUILT + "/a"):
    r = MagicMock(status_code=status, url=url)
    r.iter_content.return_value = [body[:4], body[4:]]
    r.__enter__.return_value = r
    return r


@override_settings(CACHES=LOCMEM_CACHE)
class TestUpdatePayload(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.agent = baker.make_recipe(
            "agents.online_agent", plat="linux", goarch="amd64", version="2.0.0"
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        override = override_settings(AGENTS_DIST_DIR=tmp.name)
        override.enable()
        self.addCleanup(override.disable)
        self.dist = Path(tmp.name)

    def update(self):
        with patch.object(Agent, "nats_cmd", new_callable=AsyncMock) as nats:
            result = self.agent.do_update(force=True)
        payload = nats.call_args.args[0]["payload"] if nats.called else None
        return result, payload

    def assert_signed(self, payload, sha):
        self.assertEqual(payload["sha256"], sha)
        header, claims = jws_parts(payload["sig"])
        self.assertEqual(header["typ"], "ulrmm-update")
        self.assertEqual(claims["agent"], self.agent.agent_id)
        for key in ("url", "version", "sha256"):
            self.assertEqual(claims[key], payload[key])

    def test_local_build_signed(self):
        name = agent_artifact_for(self.agent, self.agent_version())
        (self.dist / name).write_bytes(b"local build")
        result, payload = self.update()
        self.assertEqual(result, "created")
        self.assert_signed(payload, hashlib.sha256(b"local build").hexdigest())
        self.assertTrue(payload["url"].endswith(name))

    def test_no_local_build(self):
        result, payload = self.update()
        self.assertEqual((result, payload), ("no artifact", None))

    @override_settings(SELF_BUILT_AGENTS_URL=SELF_BUILT)
    def test_self_built_hashed_once(self):
        with patch("agents.models.requests.get", return_value=response()) as get:
            result, payload = self.update()
            self.assertEqual(result, "created")
            self.assert_signed(payload, hashlib.sha256(BUILD).hexdigest())
            self.assertTrue(payload["url"].startswith(SELF_BUILT + "/"))
            self.update()
        self.assertEqual(get.call_count, 1)

    @override_settings(SELF_BUILT_AGENTS_URL=SELF_BUILT)
    def test_self_built_unreachable_refused(self):
        failures = (
            {"side_effect": requests.ConnectionError()},
            {"return_value": response(status=404)},
            {"return_value": response(url="http://builds.example.net/a")},
            {"return_value": response(body=b"")},
        )
        for kwargs in failures:
            cache.clear()
            with patch("agents.models.requests.get", **kwargs):
                result, payload = self.update()
            self.assertEqual((result, payload), ("no artifact", None), kwargs)
        self.assertTrue(
            DebugLog.objects.filter(message__contains="self-built").exists()
        )

    @override_settings(SELF_BUILT_AGENTS_URL=SELF_BUILT)
    def test_self_built_failure_not_retried_per_agent(self):
        other = baker.make_recipe(
            "agents.online_agent", plat="linux", goarch="amd64", version="2.0.0"
        )
        with patch(
            "agents.models.requests.get", side_effect=requests.ConnectionError()
        ) as get:
            send_agent_update_task(
                agent_ids=[self.agent.agent_id, other.agent_id], force=True
            )
            self.assertEqual(get.call_count, 1)
            # five minutes later the next run tries again
            url = get_agent_url(agent=self.agent)
            pair = f"{url}\0{self.agent_version()}".encode()
            cache.delete(f"selfbuilt_sha256:{hashlib.sha256(pair).hexdigest()}:failed")
            send_agent_update_task(agent_ids=[self.agent.agent_id], force=True)
            self.assertEqual(get.call_count, 2)

    @override_settings(SELF_BUILT_AGENTS_URL=SELF_BUILT)
    def test_windows_recovery_never_downloads(self):
        agent = baker.make_recipe(
            "agents.online_agent", plat="windows", goarch="amd64", version="2.0.0"
        )
        ident = agent_ident_for(agent)
        with patch("agents.models.requests.get", return_value=response()) as get:
            cmd = agent._windows_recover_command(ident, "https://x/a.exe")
            get.assert_not_called()
            self.assertNotIn("Get-FileHash", cmd)
            # once an update hashed the build, recovery checks it
            self.assertEqual(
                agent._update_sha256(get_agent_url(agent=agent)),
                hashlib.sha256(BUILD).hexdigest(),
            )
            cmd = agent._windows_recover_command(ident, "https://x/a.exe")
        self.assertEqual(get.call_count, 1)
        self.assertIn(hashlib.sha256(BUILD).hexdigest(), cmd)

    @override_settings(SELF_BUILT_AGENTS_URL="http://builds.example.net/agents")
    def test_self_built_plain_http_refused(self):
        with patch("agents.models.requests.get") as get:
            result, _ = self.update()
        self.assertEqual(result, "no artifact")
        get.assert_not_called()

    def test_unsigned_refused(self):
        name = agent_artifact_for(self.agent, self.agent_version())
        (self.dist / name).write_bytes(b"local build")
        with override_settings(ENROLL_SIGNING_KEY=""):
            result, payload = self.update()
        self.assertEqual((result, payload), ("unsigned", None))

    def agent_version(self):
        from django.conf import settings

        return settings.LATEST_AGENT_VER

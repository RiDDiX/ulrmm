# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from django.conf import settings
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import User
from agents.models import Agent
from apiv3.views import InstallerThrottle
from clients.models import InstallerToken
from deploy import signing
from deploy.models import ENROLL_LIMIT, Enrollment, EnrollmentLimit, SecurityEvent
from deploy.signals import agent_enrolled
from deploy.tasks import enrolled_keys_task, enrolled_laps_task
from laps.models import LapsPolicy
from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase
from ulrmm.utils import nats_publish_allow

OTHER_KEY = base64.b64encode(b"o" * 32).decode()
API = "https://api.example.com"


def newagent_data(site, **extra) -> dict:
    return {
        "agent_id": "e" * 40,
        "hostname": "host",
        "site": site.pk,
        "monitoring_type": "server",
        "mesh_node_id": "",
        "goarch": "amd64",
        "plat": "linux",
        **extra,
    }


class EnrollBase(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.installer = User.objects.create_user(
            username="installer", is_installer_user=True, block_dashboard_login=True
        )
        self.site = baker.make("clients.Site")
        self.policy = baker.make("automation.Policy")
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site,
            mon_type="workstation",
            policy=self.policy,
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": False, "ping": True, "rdp": False},
        )

    def jws(self) -> str:
        return signing.mint_for_deployment(self.deployment, api=API)

    def enroll(self, token=None) -> None:
        self.client.credentials(HTTP_AUTHORIZATION=f"Enroll {token or self.jws()}")


class TestEnrollmentAuthentication(EnrollBase):
    def get(self, token=None):
        self.enroll(token)
        return self.client.get("/api/v3/installer/")

    def refused(self, token, why):
        r = self.get(token)
        self.assertEqual(r.status_code, 401)
        self.assertIn(why, r.data["detail"])

    def test_valid(self):
        self.assertEqual(self.get().data, "ok")
        r = self.client.post(
            "/api/v3/installer/", {"version": "9.99.12.2099"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        # authenticated and reached the arch check
        r = self.client.post("/api/v3/meshexe/", {"goarch": "x"}, format="json")
        self.assertEqual((r.status_code, r.data), (400, "Arch not supported"))

    def test_tampered(self):
        header, payload, sig = self.jws().split(".")
        claims = signing.verify(self.jws())
        forged = signing._b64url(signing._json({**claims, "site": 999}))
        self.refused(f"{header}.{forged}.{sig}", "signature does not match")
        none = signing._b64url(signing._json({"alg": "none", "typ": "JWT"}))
        self.refused(f"{none}.{payload}.{sig}", "not signed by this server")

    def test_wrong_key(self):
        with override_settings(ENROLL_SIGNING_KEY=OTHER_KEY):
            token = self.jws()
        self.refused(token, "not signed by this server")

    def test_expired(self):
        token = self.jws()
        self.deployment.expiry = djangotime.now() - dt.timedelta(hours=1)
        self.deployment.save()
        self.refused(token, "expired")

    def test_deleted_deployment(self):
        token = self.jws()
        self.deployment.delete()
        self.refused(token, "deployment not found")

    def test_row_changed(self):
        token = self.jws()
        self.deployment.mon_type = "server"
        self.deployment.save()
        self.refused(token, "does not match")

    def test_malformed_and_unconfigured(self):
        self.refused("a.b", "malformed")
        # base64url parts of length 1 mod 4 cannot be decoded
        for token in ("A.A.A", "AAAAA.AA.AA", "eyJ.A.AB"):
            self.refused(token, "malformed")
        self.client.credentials(HTTP_AUTHORIZATION=f"Enroll {self.jws()} x")
        self.assertEqual(self.client.get("/api/v3/installer/").status_code, 401)
        token = self.jws()
        with override_settings(ENROLL_SIGNING_KEY=""):
            self.refused(token, "not set up")

    def test_installer_user_needed(self):
        token = self.jws()
        self.installer.is_active = False
        self.installer.save()
        self.refused(token, "inactive")
        self.installer.delete()
        self.refused(token, "No installer user")

    def test_not_valid_elsewhere(self):
        self.enroll()
        self.assertEqual(self.client.get("/core/version/").status_code, 401)
        self.assertEqual(self.client.get("/api/v3/checkrunner/").status_code, 401)

    def test_throttle_per_deployment(self):
        throttle = InstallerThrottle()
        request = SimpleNamespace(auth=self.deployment, user=self.installer)
        self.assertEqual(
            throttle.get_cache_key(request, None),
            f"throttle_installer_dep{self.deployment.pk}",
        )


@patch("apiv3.views.cache_agents_alert_template.delay")
@patch("apiv3.views.reload_nats")
class TestNewAgentDeployment(EnrollBase):
    def post(self, **extra):
        data = newagent_data(self.site, **extra)
        return self.client.post("/api/v3/newagent/", data, format="json")

    def test_deployment_decides(self, *mocks):
        received = MagicMock()
        agent_enrolled.connect(received, dispatch_uid="test-enrolled")
        self.addCleanup(agent_enrolled.disconnect, dispatch_uid="test-enrolled")
        self.enroll()
        with self.captureOnCommitCallbacks(execute=True):
            r = self.post(monitoring_type="server")
        self.assertEqual(r.status_code, 200)
        agent = Agent.objects.get(pk=r.data["pk"])
        self.assertEqual(agent.monitoring_type, "workstation")
        self.assertEqual(agent.policy_id, self.policy.pk)
        self.assertEqual(agent.enrollment.deployment, self.deployment)
        received.assert_called_once()
        kwargs = received.call_args.kwargs
        self.assertEqual(
            (kwargs["sender"], kwargs["agent"], kwargs["deployment"]),
            (Agent, agent, self.deployment),
        )

    def test_signal_waits_for_commit(self, *mocks):
        received = MagicMock()
        agent_enrolled.connect(received, dispatch_uid="test-enrolled")
        self.addCleanup(agent_enrolled.disconnect, dispatch_uid="test-enrolled")
        self.enroll()
        self.assertEqual(self.post().status_code, 200)
        received.assert_not_called()

    def test_failing_receiver_does_not_fail_enrollment(self, *mocks):
        calls = []

        def broken(sender, agent, **kwargs):
            calls.append(agent.pk)
            raise RuntimeError("broker down")

        agent_enrolled.connect(broken, dispatch_uid="test-broken")
        self.addCleanup(agent_enrolled.disconnect, dispatch_uid="test-broken")
        self.enroll()
        with self.captureOnCommitCallbacks(execute=True):
            r = self.post()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(calls, [r.data["pk"]])

    def test_body_type_not_needed_and_no_policy(self, *mocks):
        self.deployment.policy = None
        self.deployment.save()
        self.enroll()
        data = newagent_data(self.site)
        del data["monitoring_type"]
        r = self.client.post("/api/v3/newagent/", data, format="json")
        self.assertEqual(r.status_code, 200)
        agent = Agent.objects.get(pk=r.data["pk"])
        self.assertEqual(agent.monitoring_type, "workstation")
        self.assertIsNone(agent.policy_id)

    def test_version_stored_for_the_first_acl(self, *mocks):
        self.enroll()
        r = self.post(version=settings.SEC_R1_MIN_AGENT)
        agent = Agent.objects.get(pk=r.data["pk"])
        self.assertEqual(agent.version, settings.SEC_R1_MIN_AGENT)
        self.assertNotIn(
            agent.agent_id, nats_publish_allow(agent.agent_id, agent.version)
        )

    def test_version_missing_or_invalid_means_old(self, *mocks):
        for i, version in enumerate(
            (None, "", "2.25.10.2026\nx", "9" * 40 + ".1.1.2026")
        ):
            self.enroll()
            extra = {"agent_id": chr(ord("a") + i) * 40, "hostname": f"h{i}"}
            if version is not None:
                extra["version"] = version
            r = self.post(**extra)
            self.assertEqual(r.status_code, 200, version)
            agent = Agent.objects.get(pk=r.data["pk"])
            self.assertEqual(agent.version, "0.1.0", version)
            self.assertIn(
                agent.agent_id, nats_publish_allow(agent.agent_id, agent.version)
            )

    def test_other_site_refused(self, *mocks):
        self.enroll()
        data = newagent_data(baker.make("clients.Site"))
        r = self.client.post("/api/v3/newagent/", data, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Agent.objects.exists())

    def test_knox_deployment_token(self, *mocks):
        token, key = AuthToken.objects.create(
            user=self.installer, expiry=dt.timedelta(hours=2)
        )
        self.deployment.auth_token = token
        self.deployment.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key}")
        r = self.post(monitoring_type="server")
        self.assertEqual(r.status_code, 200)
        agent = Agent.objects.get(pk=r.data["pk"])
        self.assertEqual(
            (agent.monitoring_type, agent.policy_id), ("workstation", self.policy.pk)
        )
        self.assertEqual(agent.enrollment.deployment, self.deployment)

    def test_installer_token_unbound(self, *mocks):
        token, key = AuthToken.objects.create(user=self.installer)
        InstallerToken.objects.create(auth_token=token, site=self.site)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key}")
        r = self.post(monitoring_type="server")
        agent = Agent.objects.get(pk=r.data["pk"])
        self.assertEqual((agent.monitoring_type, agent.policy_id), ("server", None))
        self.assertFalse(Enrollment.objects.exists())


@patch("apiv3.views.cache_agents_alert_template.delay")
@patch("apiv3.views.reload_nats")
class TestEnrollmentCap(EnrollBase):
    def post(self, n: int):
        self.enroll()
        data = newagent_data(self.site, agent_id=chr(ord("a") + n) * 40)
        data["hostname"] = f"host{n}"
        return self.client.post("/api/v3/newagent/", data, format="json")

    def test_cap_reached_refused(self, *mocks):
        self.deployment.max_enrollments = 2
        self.deployment.save()
        self.assertEqual(self.post(0).status_code, 200)
        with CaptureQueriesContext(connection) as queries:
            self.assertEqual(self.post(1).status_code, 200)
        self.assertTrue(any("FOR UPDATE" in q["sql"] for q in queries.captured_queries))
        r = self.post(2)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data["detail"], ENROLL_LIMIT)
        # the agent row of the refused install is rolled back
        self.assertEqual(Agent.objects.count(), 2)
        self.assertEqual(Enrollment.objects.count(), 2)

    def test_cap_refusal_is_recorded(self, *mocks):
        self.deployment.max_enrollments = 1
        self.deployment.save()
        self.post(0)
        self.assertEqual(self.post(1).status_code, 403)
        event = SecurityEvent.objects.get(kind="enroll_limit")
        self.assertEqual(event.severity, "warning")
        self.assertIn(str(self.deployment.pk), event.detail)

    def test_deleted_agent_frees_a_slot(self, *mocks):
        self.deployment.max_enrollments = 1
        self.deployment.save()
        Agent.objects.get(pk=self.post(0).data["pk"]).delete()
        self.assertEqual(self.post(1).status_code, 200)

    def test_no_cap_no_lock(self, *mocks):
        self.assertIsNone(self.deployment.max_enrollments)
        for n in range(3):
            with CaptureQueriesContext(connection) as queries:
                self.assertEqual(self.post(n).status_code, 200)
            self.assertFalse(
                any("FOR UPDATE" in q["sql"] for q in queries.captured_queries)
            )

    def test_record(self, *mocks):
        request = SimpleNamespace(_client_ip="192.0.2.7")
        EnrollmentLimit(self.deployment.pk).record(request, "host9")
        event = SecurityEvent.objects.get()
        self.assertEqual(
            (event.kind, event.severity, event.source_ip),
            ("enroll_limit", "warning", "192.0.2.7"),
        )
        self.assertEqual(event.detail, f"deployment {self.deployment.pk} host host9")


class TestEnrollReceivers(ULRMMTestCase):
    def setUp(self):
        # the software baseline receiver resolves the agent's policies
        self.setup_coresettings()

    def send(self, agent):
        agent_enrolled.send(sender=Agent, agent=agent, deployment=None)

    @patch("deploy.tasks.enrolled_keys_task.apply_async")
    @patch("deploy.tasks.enrolled_laps_task.apply_async")
    def test_laps_and_keys(self, laps, keys):
        win = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        bsd = baker.make_recipe("agents.online_agent", plat=AgentPlat.FREEBSD)
        self.send(win)
        laps.assert_not_called()
        keys.assert_called_once_with((win.pk,), countdown=30 * 60)

        baker.make(LapsPolicy, site=None, enabled=True)
        self.send(win)
        laps.assert_called_once_with((win.pk,), countdown=5 * 60)
        self.send(bsd)
        self.assertEqual((laps.call_count, keys.call_count), (1, 2))

    @patch("laps.tasks.rotate_agent_task")
    def test_laps_task_waits_for_online(self, rotate):
        rotate.return_value = "ok"
        offline = baker.make_recipe("agents.offline_agent")
        self.assertEqual(enrolled_laps_task(offline.pk), "not online")
        rotate.assert_not_called()
        online = baker.make_recipe("agents.online_agent")
        self.assertEqual(enrolled_laps_task(online.pk), "ok")
        rotate.assert_called_once_with(online.pk)

    @patch("encryption.utils.store")
    def test_keys_task(self, store):
        linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        self.assertEqual(enrolled_keys_task(linux.pk), "skipped")
        win = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        with patch.object(Agent, "nats_cmd", AsyncMock(return_value="timeout")):
            enrolled_keys_task(win.pk)
        store.assert_called_once()
        self.assertEqual(store.call_args.args[0].pk, win.pk)

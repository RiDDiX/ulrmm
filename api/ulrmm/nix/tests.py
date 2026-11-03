# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.conf import settings
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType
from ulrmm.test import ULRMMTestCase


class TestNix(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        self.mac = baker.make_recipe("agents.online_agent", plat=AgentPlat.DARWIN)
        self.win = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        self.base = f"/nix/{self.agent.agent_id}"

    @patch("agents.models.Agent.nats_cmd")
    def test_services(self, nats_cmd):
        rows = [{"name": "ssh.service", "status": "running", "manager": "systemd"}]
        nats_cmd.return_value = rows
        r = self.client.get(f"{self.base}/services/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, rows)
        nats_cmd.assert_called_with(data={"func": "posixservices"}, timeout=30)

        nats_cmd.return_value = "natsdown"
        r = self.client.get(f"{self.base}/services/")
        self.assertEqual((r.status_code, r.data), (400, "Unable to contact the agent"))

        nats_cmd.return_value = "systemctl failed: boom"
        r = self.client.get(f"{self.base}/services/")
        self.assertEqual((r.status_code, r.data), (400, "systemctl failed: boom"))

        for old in ("timeout", {"a": 1}, None):
            nats_cmd.return_value = old
            r = self.client.get(f"{self.base}/services/")
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "Agent update required")

        self.check_not_authenticated("get", f"{self.base}/services/")

    @patch("agents.models.Agent.nats_cmd")
    def test_windows_refused(self, nats_cmd):
        for suffix, method in (("services/", "get"), ("logs/", "get")):
            r = getattr(self.client, method)(f"/nix/{self.win.agent_id}/{suffix}")
            self.assertEqual(r.status_code, 400)
            self.assertIn("Linux, macOS and FreeBSD", r.data)
        r = self.client.post(
            f"/nix/{self.win.agent_id}/services/ssh/", {"action": "stop"}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("Linux, macOS and FreeBSD", r.data)
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_service_action(self, nats_cmd):
        url = f"{self.base}/services/ssh.service/"
        nats_cmd.return_value = "ok"
        r = self.client.post(url, {"action": "restart"}, format="json")
        self.assertEqual(r.status_code, 200)
        nats_cmd.assert_called_with(
            {
                "func": "posixsvcaction",
                "payload": {"name": "ssh.service", "action": "restart"},
            },
            timeout=65,
        )
        log = AuditLog.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(log.username, self.john.username)
        self.assertIn("service restart ssh.service", log.message)
        self.assertEqual(log.action, AuditActionType.MODIFY)
        self.assertEqual(
            log.after_value, {"service": "ssh.service", "action": "restart"}
        )

        # validation: nothing reaches the agent
        nats_cmd.reset_mock()
        for action in ("reboot", "", None):
            r = self.client.post(url, {"action": action}, format="json")
            self.assertEqual(r.status_code, 400)
        for name in ("a b", "x;rm", "a" * 201, "a$b", "a`b", "-h", "ssh%0A"):
            r = self.client.post(
                f"{self.base}/services/{name}/", {"action": "stop"}, format="json"
            )
            self.assertEqual(r.status_code, 400)
        nats_cmd.assert_not_called()
        self.assertEqual(
            AuditLog.objects.filter(agent_id=self.agent.agent_id).count(), 1
        )

        # agent errors are not audited
        nats_cmd.return_value = "Unit not found"
        r = self.client.post(url, {"action": "stop"}, format="json")
        self.assertEqual((r.status_code, r.data), (400, "Unit not found"))
        nats_cmd.return_value = "natsdown"
        r = self.client.post(url, {"action": "stop"}, format="json")
        self.assertEqual(r.data, "Unable to contact the agent")
        for old in ("timeout", {"x": 1}):
            nats_cmd.return_value = old
            r = self.client.post(url, {"action": "stop"}, format="json")
            self.assertEqual(r.data, "Agent update required")
        self.assertEqual(
            AuditLog.objects.filter(agent_id=self.agent.agent_id).count(), 1
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_own_service_ends_the_agent_before_it_answers(self, nats_cmd):
        nats_cmd.return_value = "timeout"
        unit = settings.AGENT_NIX_SVC
        for agent, name, action, ok in (
            (self.agent, unit, "restart", "restarting its own service"),
            (self.agent, unit.removesuffix(".service"), "stop", "stays offline"),
            (self.mac, settings.AGENT_MAC_PLIST_LABEL, "restart", "reconnects"),
        ):
            r = self.client.post(
                f"/nix/{agent.agent_id}/services/{name}/",
                {"action": action},
                format="json",
            )
            self.assertEqual(r.status_code, 200, name)
            self.assertIn(ok, r.data)
            log = AuditLog.objects.filter(agent_id=agent.agent_id).last()
            self.assertEqual(log.after_value, {"service": name, "action": action})

        # anything else that stays silent is still an old agent
        for name, action in ((unit, "enable"), ("ssh.service", "restart")):
            r = self.client.post(
                f"{self.base}/services/{name}/", {"action": action}, format="json"
            )
            self.assertEqual((r.status_code, r.data), (400, "Agent update required"))

    @patch("agents.models.Agent.nats_cmd")
    def test_offline_agent_is_not_asked(self, nats_cmd):
        self.agent.last_seen = djangotime.now() - djangotime.timedelta(hours=1)
        self.agent.save(update_fields=["last_seen"])
        for r in (
            self.client.get(f"{self.base}/services/"),
            self.client.get(f"{self.base}/logs/"),
            self.client.post(
                f"{self.base}/services/ssh/", {"action": "stop"}, format="json"
            ),
        ):
            self.assertEqual(
                (r.status_code, r.data), (400, "Unable to contact the agent")
            )
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_logs(self, nats_cmd):
        reply = {"lines": [{"ts": "1", "message": "m"}], "truncated": False}
        nats_cmd.return_value = reply

        r = self.client.get(f"{self.base}/logs/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, reply)
        nats_cmd.assert_called_with(
            data={
                "func": "posixlogs",
                "payload": {"source": "journal", "lines": "200"},
            },
            timeout=65,
        )

        r = self.client.get(
            f"{self.base}/logs/?source=journal&unit=ssh.service&priority=3&lines=500&since=60"
        )
        self.assertEqual(r.status_code, 200)
        nats_cmd.assert_called_with(
            data={
                "func": "posixlogs",
                "payload": {
                    "source": "journal",
                    "lines": "500",
                    "unit": "ssh.service",
                    "priority": "3",
                    "since": "60",
                },
            },
            timeout=65,
        )

        r = self.client.get(f"{self.base}/logs/?source=file&path=/var/log/syslog")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            nats_cmd.call_args.kwargs["data"]["payload"],
            {"source": "file", "lines": "200", "path": "/var/log/syslog"},
        )

        r = self.client.get(f"/nix/{self.mac.agent_id}/logs/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            nats_cmd.call_args.kwargs["data"]["payload"]["source"], "unified"
        )

        nats_cmd.reset_mock()
        bad = [
            "source=bogus",
            "source=file",
            "source=file&path=/etc/passwd",
            "source=file&path=/var/log/../etc/passwd",
            "source=file&path=var/log/x",
            "lines=49",
            "lines=2001",
            "lines=abc",
            "priority=8",
            "priority=-1",
            "since=0",
            "unit=a%20b",
            "unit=a;b",
            "unit=-h",
            "unit=ssh.service%0A",
        ]
        for qs in bad:
            r = self.client.get(f"{self.base}/logs/?{qs}")
            self.assertEqual(r.status_code, 400, qs)
        nats_cmd.assert_not_called()

        for old in ("timeout", ["x"], {"lines": "x"}):
            nats_cmd.return_value = old
            r = self.client.get(f"{self.base}/logs/")
            self.assertEqual((r.status_code, r.data), (400, "Agent update required"))
        nats_cmd.return_value = "natsdown"
        r = self.client.get(f"{self.base}/logs/")
        self.assertEqual(r.data, "Unable to contact the agent")
        # agent errors (e.g. wrong source for the platform) pass through
        nats_cmd.return_value = "journal is not available on macOS"
        r = self.client.get(f"/nix/{self.mac.agent_id}/logs/?source=journal")
        self.assertEqual(
            (r.status_code, r.data), (400, "journal is not available on macOS")
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_permissions(self, nats_cmd):
        nats_cmd.return_value = []
        svc = f"{self.base}/services/"
        logs = f"{self.base}/logs/"
        act = f"{self.base}/services/ssh/"

        for roles, allowed in (
            ([], ()),
            (["can_manage_winsvcs"], (svc, act)),
            (["can_view_eventlogs"], (logs,)),
        ):
            self.client.force_authenticate(user=self.create_user_with_roles(roles))
            for url in (svc, logs, act):
                if url == act:
                    r = self.client.post(url, {"action": "stop"}, format="json")
                else:
                    r = self.client.get(url)
                if url in allowed:
                    self.assertNotEqual(r.status_code, 403, (roles, url))
                else:
                    self.assertEqual(r.status_code, 403, (roles, url))

    @patch("agents.models.Agent.nats_cmd")
    def test_scope_denied(self, nats_cmd):
        nats_cmd.return_value = []
        user = self.create_user_with_roles(["can_manage_winsvcs", "can_view_eventlogs"])
        user.role.can_view_sites.set([baker.make("clients.Site")])
        self.client.force_authenticate(user=user)
        for url in (f"{self.base}/services/", f"{self.base}/logs/"):
            self.assertEqual(self.client.get(url).status_code, 403)
        r = self.client.post(
            f"{self.base}/services/ssh/", {"action": "stop"}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        nats_cmd.assert_not_called()

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import User
from agents.models import Agent
from clients.models import InstallerToken
from logs.models import DebugLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

URL = "/api/v3/syncmesh/"
NODE = "0a" * 48


def newagent_data(site, agent_id="a" * 40):
    return {
        "agent_id": agent_id,
        "hostname": "host",
        "site": site.pk,
        "monitoring_type": "server",
        "description": "",
        "mesh_node_id": "",
        "goarch": "amd64",
        "plat": "linux",
    }


@override_settings(CACHES=LOCMEM_CACHE)
class TestSyncMeshNodeID(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        cache.clear()
        self.agent = baker.make_recipe("agents.online_agent", mesh_node_id="")
        self.authenticate_agent(self.agent)

    def post(self, nodeid):
        return self.client.post(URL, {"nodeid": nodeid}, format="json")

    def test_trailing_newline_stripped(self):
        r = self.post(NODE + "\n")
        self.assertEqual(r.status_code, 200)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.mesh_node_id, NODE)

    def test_stored_newline_heals(self):
        Agent.objects.filter(pk=self.agent.pk).update(mesh_node_id=NODE + "\n")
        self.assertEqual(self.post(NODE + "\n").status_code, 200)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.mesh_node_id, NODE)

    def test_offline_holder_releases(self):
        old = baker.make_recipe(
            "agents.overdue_agent", site=self.agent.site, mesh_node_id=NODE
        )
        self.assertEqual(self.post(NODE).status_code, 200)
        old.refresh_from_db()
        self.agent.refresh_from_db()
        self.assertEqual(old.mesh_node_id, "")
        self.assertEqual(self.agent.mesh_node_id, NODE)

    def test_online_holder_keeps_id(self):
        clone = baker.make_recipe(
            "agents.online_agent",
            site=self.agent.site,
            hostname="CLONE",
            mesh_node_id=NODE,
        )
        for _ in range(3):
            self.assertEqual(self.post(NODE).status_code, 400)
        clone.refresh_from_db()
        self.agent.refresh_from_db()
        self.assertEqual(clone.mesh_node_id, NODE)
        self.assertEqual(self.agent.mesh_node_id, "")
        self.assertEqual(DebugLog.objects.filter(agent=clone).count(), 1)


@patch("apiv3.views.cache_agents_alert_template.delay")
@patch("apiv3.views.sync_mesh_perms_task.delay")
@patch("apiv3.views.reload_nats")
class TestNewAgentNodeID(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        cache.clear()
        self.authenticate()
        self.site = baker.make("clients.Site")
        installer = User.objects.get(is_installer_user=True)
        tok, _ = AuthToken.objects.create(user=installer)
        InstallerToken.objects.create(auth_token=tok, site=self.site)
        self.client.force_authenticate(user=installer, token=tok)

    def install(self, node):
        data = newagent_data(self.site)
        data["mesh_node_id"] = node
        return self.client.post("/api/v3/newagent/", data, format="json")

    def test_newline_stripped(self, *args):
        self.assertEqual(self.install(NODE + "\n").status_code, 200)
        self.assertEqual(Agent.objects.get(agent_id="a" * 40).mesh_node_id, NODE)

    def test_online_holder_keeps_id(self, *args):
        clone = baker.make_recipe(
            "agents.online_agent", site=self.site, mesh_node_id=NODE
        )
        self.assertEqual(self.install(NODE).status_code, 200)
        clone.refresh_from_db()
        self.assertEqual(clone.mesh_node_id, NODE)
        self.assertEqual(Agent.objects.get(agent_id="a" * 40).mesh_node_id, "")

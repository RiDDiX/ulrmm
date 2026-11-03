# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from unittest.mock import PropertyMock, patch

from model_bakery import baker

from agents.models import Agent
from agents.serializers import (
    AgentHostnameSerializer,
    AgentSerializer,
    AgentTableSerializer,
)
from core.tasks import rename_mesh_node_task, sync_mesh_perms_task
from logs.models import AuditLog, DebugLog
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.test import ULRMMTestCase


@patch("agents.views.sync_mesh_perms_task.delay")
@patch("agents.views.rename_mesh_node_task.delay")
class TestDisplayName(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent", hostname="DESKTOP-1")
        self.url = f"/agents/{self.agent.agent_id}/"

    def put(self, name):
        return self.client.put(self.url, {"display_name": name}, format="json")

    def test_validation(self, rename, _):
        r = self.put("  Front desk  ")
        self.assertEqual(r.status_code, 200)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.display_name, "Front desk")
        self.assertEqual(self.agent.effective_name, "Front desk")

        self.assertEqual(self.put("x" * 64).status_code, 200)
        r = self.put("x" * 65)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["display_name"][0],
            "Ensure this field has no more than 64 characters.",
        )

        for bad in ("a\tb", "a\nb", "a\x7fb", "a‮b", "a b"):
            with self.subTest(bad=bad):
                r = self.put(bad)
                self.assertEqual(r.status_code, 400)
                self.assertEqual(
                    r.data["display_name"][0],
                    "Display name must not contain control characters.",
                )
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.display_name, "x" * 64)

        for empty in ("", "   "):
            with self.subTest(empty=empty):
                self.put("Front desk")
                self.assertEqual(self.put(empty).status_code, 200)
                self.agent.refresh_from_db()
                self.assertEqual(self.agent.display_name, "")
                self.assertEqual(self.agent.effective_name, "DESKTOP-1")

        # reported hostname is unchanged
        self.assertEqual(self.agent.hostname, "DESKTOP-1")

    def test_serializers(self, rename, _):
        self.agent.display_name = "Front desk"
        self.agent.save(update_fields=["display_name"])
        for s in (AgentSerializer, AgentTableSerializer, AgentHostnameSerializer):
            with self.subTest(s=s.__name__):
                data = s(self.agent).data
                self.assertEqual(data["hostname"], "DESKTOP-1")
                self.assertEqual(data["display_name"], "Front desk")
                self.assertEqual(data["effective_name"], "Front desk")

        r = self.client.get("/agents/")
        self.assertEqual(r.data[0]["effective_name"], "Front desk")
        r = self.client.get("/agents/?detail=false")
        self.assertEqual(r.data[0]["effective_name"], "Front desk")
        r = self.client.get(self.url)
        self.assertEqual(r.data["effective_name"], "Front desk")

        self.agent.display_name = ""
        self.agent.save(update_fields=["display_name"])
        data = AgentTableSerializer(self.agent).data
        self.assertEqual(data["effective_name"], "DESKTOP-1")

    def test_rename_queued_on_change_with_mesh_sync(self, rename, _):
        self.put("Front desk")
        rename.assert_called_once_with(self.agent.pk)

        rename.reset_mock()
        self.put("Front desk")
        self.client.put(self.url, {"description": "x"}, format="json")
        rename.assert_not_called()

        self.put("")
        rename.assert_called_once_with(self.agent.pk)

        rename.reset_mock()
        self.coresettings.sync_mesh_with_rmm = False
        self.coresettings.save(update_fields=["sync_mesh_with_rmm"])
        self.put("Back office")
        rename.assert_not_called()

    def test_audit(self, rename, _):
        self.put("Front desk")
        audit = AuditLog.objects.get(
            agent_id=self.agent.agent_id, action=AuditActionType.MODIFY
        )
        self.assertEqual(audit.object_type, AuditObjType.AGENT)
        self.assertEqual(audit.username, "john")
        self.assertEqual(audit.before_value["display_name"], "")
        self.assertEqual(audit.after_value["display_name"], "Front desk")


class FakeMeshSocket:
    def __init__(self, replies):
        self.sent = []
        self.replies = replies

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def send(self, msg):
        self.sent.append(json.loads(msg))

    async def recv(self):
        return json.dumps(self.replies.pop(0))


@patch("core.tasks.get_mesh_ws_url", return_value="ws://mesh")
@patch.object(Agent, "hex_mesh_node_id", new_callable=PropertyMock)
class TestRenameMeshNode(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent", hostname="DESKTOP-1", display_name="Front desk"
        )

    def test_sends_changedevice(self, hex_id, _):
        hex_id.return_value = "abc"
        ws = FakeMeshSocket(
            [{"action": "changedevice", "responseid": "meshctrl", "result": "ok"}]
        )
        with patch("core.mesh_utils.websockets.connect", return_value=ws):
            rename_mesh_node_task(self.agent.pk)

        # changedevice only; no users fetch
        self.assertEqual(
            ws.sent,
            [
                {
                    "action": "changedevice",
                    "nodeid": "node//abc",
                    "name": "Front desk",
                    "responseid": "meshctrl",
                }
            ],
        )
        self.assertFalse(DebugLog.objects.exists())

    def test_hostname_and_no_node(self, hex_id, _):
        Agent.objects.filter(pk=self.agent.pk).update(display_name="")
        hex_id.return_value = "abc"
        with patch("core.tasks.MeshSync") as mesh_sync:
            mesh_sync.return_value.rename_node.return_value = {"result": "ok"}
            rename_mesh_node_task(self.agent.pk)
            mesh_sync.return_value.rename_node.assert_called_once_with(
                node_id="node//abc", name="DESKTOP-1", wait=True
            )

            mesh_sync.reset_mock()
            hex_id.return_value = "error"
            rename_mesh_node_task(self.agent.pk)
            mesh_sync.assert_not_called()

    def test_failure_retries_then_logs(self, hex_id, _):
        hex_id.return_value = "abc"
        for reply in ({"result": "Access Denied"}, None, OSError("refused")):
            with self.subTest(reply=reply), patch("core.tasks.MeshSync") as ms:
                DebugLog.objects.all().delete()
                rename = ms.return_value.rename_node
                if isinstance(reply, Exception):
                    rename.side_effect = reply
                else:
                    rename.return_value = reply

                # never raised; 1 try + 3 retries
                rename_mesh_node_task.apply(args=[self.agent.pk]).get()
                self.assertEqual(rename.call_count, 4)
                log = DebugLog.objects.get()
                self.assertIn("Unable to rename DESKTOP-1 to Front desk", log.message)


@patch("core.tasks.get_mesh_ws_url", return_value="ws://mesh")
@patch("core.tasks.MeshSync")
@patch.object(Agent, "hex_mesh_node_id", new_callable=PropertyMock)
class TestMeshNameSync(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent", hostname="DESKTOP-1", mesh_node_id="abc"
        )

    def sync(self, mesh_sync, nodes):
        ms = mesh_sync.return_value
        ms.reset_mock()
        ms.mesh_users = {}
        ms.get_unique_mesh_users.return_value = []
        ms.mesh_action.return_value = {"nodes": {"mesh//x": nodes}}
        sync_mesh_perms_task()
        return ms

    def test_renames_only_differing_nodes(self, hex_id, mesh_sync, _):
        hex_id.return_value = "abc"

        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "DESKTOP-1"}])
        ms.rename_node.assert_not_called()

        # display name set; mesh still has the old hostname
        Agent.objects.filter(pk=self.agent.pk).update(display_name="Front desk")
        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "DESKTOP-1"}])
        ms.rename_node.assert_called_once_with(node_id="node//abc", name="Front desk")

        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "Front desk"}])
        ms.rename_node.assert_not_called()

        # hostname changed, display_name empty
        Agent.objects.filter(pk=self.agent.pk).update(
            display_name="", hostname="DESKTOP-2"
        )
        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "DESKTOP-1"}])
        ms.rename_node.assert_called_once_with(node_id="node//abc", name="DESKTOP-2")

        # leftover mesh nodes and agents without a node
        ms = self.sync(mesh_sync, [{"_id": "node//other", "name": "x"}])
        ms.rename_node.assert_not_called()

        hex_id.return_value = "error"
        ms = self.sync(mesh_sync, [{"_id": "node//error", "name": "x"}])
        ms.rename_node.assert_not_called()

    def test_long_hostname_is_cut_once(self, hex_id, mesh_sync, _):
        hex_id.return_value = "abc"
        Agent.objects.filter(pk=self.agent.pk).update(hostname="h" * 70)
        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "DESKTOP-1"}])
        ms.rename_node.assert_called_once_with(node_id="node//abc", name="h" * 64)

        ms = self.sync(mesh_sync, [{"_id": "node//abc", "name": "h" * 64}])
        ms.rename_node.assert_not_called()

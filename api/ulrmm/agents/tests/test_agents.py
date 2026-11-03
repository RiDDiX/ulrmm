# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import PropertyMock, patch

import pyotp
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey
from accounts.utils import grant_console_stepup
from agents.models import Agent, AgentHistory
from core.mesh_utils import MESH_RIGHTS_CONSOLE
from logs.models import AuditLog
from ulrmm.constants import AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

base_url = "/agents"


class TestBulkActions(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.url = f"{base_url}/actions/bulk/"

    def payload(self, **kwargs):
        data = {
            "mode": "command",
            "target": "all",
            "monType": "all",
            "osType": "all",
            "client": None,
            "site": None,
            "agents": [],
            "cmd": "ipconfig",
            "shell": "cmd",
            "custom_shell": None,
            "timeout": 300,
            "run_as_user": False,
        }
        data.update(kwargs)
        return data

    def online(self, **kwargs):
        return baker.make_recipe(
            "agents.online_agent", last_seen=djangotime.now(), **kwargs
        )

    @patch("scripts.tasks.bulk_command_task.delay")
    def test_bulk_command_skips_offline_agents(self, mock_task):
        online = [self.online() for _ in range(2)]
        baker.make_recipe("agents.offline_agent")
        baker.make_recipe("agents.overdue_agent")

        r = self.client.post(self.url, self.payload(), format="json")

        self.assertEqual(r.status_code, 200)
        self.assertCountEqual(
            mock_task.call_args.kwargs["agent_pks"], [i.pk for i in online]
        )
        self.assertEqual(
            r.data,  # type: ignore
            "Command will now be run on 2 agents, 2 offline agents were skipped. "
            "Check the History tab on the agent to view the results.",
        )

        self.check_not_authenticated("post", self.url)

    @patch("scripts.tasks.bulk_script_task.delay")
    def test_bulk_script_without_online_agents(self, mock_task):
        script = baker.make("scripts.Script")
        data = self.payload(
            mode="script",
            script=script.pk,
            args=[],
            env_vars=[],
            custom_field=None,
            collector_all_output=False,
            save_to_agent_note=False,
        )

        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data,  # type: ignore
            "No agents were found meeting the selected criteria",
        )

        baker.make_recipe("agents.offline_agent", _quantity=3)

        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data,  # type: ignore
            "All 3 agents meeting the selected criteria are offline",
        )
        mock_task.assert_not_called()

    @patch("winupdate.tasks.bulk_install_updates_task.delay")
    def test_bulk_patch_install_skips_offline_agents(self, mock_task):
        agent = self.online()
        baker.make_recipe("agents.offline_agent")

        r = self.client.post(
            self.url, self.payload(mode="patch", patchMode="install"), format="json"
        )

        self.assertEqual(r.status_code, 200)
        mock_task.assert_called_once_with([agent.pk])
        self.assertEqual(
            r.data,  # type: ignore
            "Pending updates will now be installed on 1 agents, "
            "1 offline agents were skipped",
        )

    @patch("scripts.tasks.bulk_command_task.delay")
    def test_bulk_audit_entry_names_agents_reached(self, mock_task):
        online = [self.online(hostname=f"on{i}") for i in range(2)]
        offline = baker.make_recipe("agents.offline_agent", hostname="off1")
        data = self.payload(
            target="agents", agents=[i.agent_id for i in online + [offline]]
        )

        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 200)

        entries = AuditLog.objects.filter(action=AuditActionType.BULK_ACTION)
        audit = entries.get()
        self.assertTrue(
            audit.message.endswith("sent to 2 agents, 1 offline skipped"), audit.message
        )
        self.assertCountEqual(audit.after_value["agent_hostnames"], ["on0", "on1"])
        self.assertEqual(audit.after_value["agents_sent_to"], 2)
        self.assertEqual(audit.after_value["offline_skipped"], 1)

        # a refused request sends nothing and is not audited
        data["agents"] = [offline.agent_id]
        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(entries.count(), 1)

    @patch("scripts.tasks.bulk_command_task.delay")
    def test_bulk_command_needs_the_custom_shell_path(self, mock_task):
        self.online()
        for custom in (None, "", "  "):
            data = self.payload(shell="custom", custom_shell=custom)
            r = self.client.post(self.url, data, format="json")
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "Enter the path of the custom shell")  # type: ignore
        mock_task.assert_not_called()

        data = self.payload(shell="custom", custom_shell="/bin/zsh")
        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_task.call_args.kwargs["shell"], "/bin/zsh")

    @patch("scripts.tasks.bulk_command_task.delay")
    def test_bulk_command_role_scoping(self, mock_task):
        agent = self.online()
        self.online()

        user = self.create_user_with_roles(["can_run_bulk"])
        user.role.can_view_clients.set([agent.client])
        self.client.force_authenticate(user=user)

        r = self.client.post(self.url, self.payload(), format="json")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_task.call_args.kwargs["agent_pks"], [agent.pk])


@patch("agents.models.Agent.nats_cmd", return_value="ok")
class TestSendCommand(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        agent = baker.make_recipe("agents.online_agent")
        self.url = f"{base_url}/{agent.agent_id}/cmd/"

    def test_custom_shell_needs_a_path(self, nats_cmd):
        data = {"cmd": "uptime", "shell": "custom", "timeout": 30}
        for custom in (None, "", "  "):
            r = self.client.post(
                self.url, {**data, "custom_shell": custom}, format="json"
            )
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "Enter the path of the custom shell")  # type: ignore
        nats_cmd.assert_not_called()
        self.assertFalse(AgentHistory.objects.exists())

        r = self.client.post(
            self.url, {**data, "custom_shell": "/bin/zsh"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(nats_cmd.call_args.args[0]["payload"]["shell"], "/bin/zsh")


@override_settings(CACHES=LOCMEM_CACHE)
@patch("agents.views.remove_mesh_agent")
@patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
@patch("agents.views.sync_mesh_perms_task.delay")
@patch("agents.views.reload_nats")
@patch("agents.models.Agent.nats_cmd")
class TestDeleteNeedsTOTP(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.john.totp_key = pyotp.random_base32()
        self.john.save(update_fields=["totp_key"])
        self.totp = pyotp.TOTP(self.john.totp_key)
        self.agent = baker.make_recipe("agents.online_agent")

    def delete(self, agent, code=None):
        data = {} if code is None else {"totp_code": code}
        return self.client.delete(f"{base_url}/{agent.agent_id}/", data, format="json")

    def test_every_delete_needs_its_own_code(self, nats_cmd, *_):
        r = self.delete(self.agent)
        self.assertEqual(r.status_code, 400)
        nats_cmd.assert_not_called()
        self.assertTrue(Agent.objects.filter(pk=self.agent.pk).exists())

        code = self.totp.now()
        r = self.delete(self.agent, code)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Agent.objects.filter(pk=self.agent.pk).exists())

        # same code, other agent
        nats_cmd.reset_mock()
        other = baker.make_recipe("agents.online_agent")
        r = self.delete(other, code)
        self.assertEqual(r.status_code, 400)
        nats_cmd.assert_not_called()
        self.assertTrue(Agent.objects.filter(pk=other.pk).exists())

    def test_console_step_up_is_not_a_delete_code(self, nats_cmd, *_):
        grant_console_stepup(self.john)
        r = self.delete(self.agent)
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Agent.objects.filter(pk=self.agent.pk).exists())

    def test_api_key_uses_the_owners_totp(self, nats_cmd, *_):
        service = baker.make("accounts.User", is_active=True, is_superuser=True)
        APIKey.objects.create(name="svc", key="svckey", user=service)
        APIKey.objects.create(name="john", key="johnkey", user=self.john)
        self.client.force_authenticate(user=None)

        # key owner has no totp
        self.client.credentials(HTTP_X_API_KEY="svckey")
        r = self.delete(self.agent, self.totp.now())
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Agent.objects.filter(pk=self.agent.pk).exists())

        self.client.credentials(HTTP_X_API_KEY="johnkey")
        r = self.delete(self.agent, self.totp.now())
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Agent.objects.filter(pk=self.agent.pk).exists())


@override_settings(CACHES=LOCMEM_CACHE)
@patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
@patch("agents.views.MeshSync")
@patch.object(Agent, "hex_mesh_node_id", new_callable=PropertyMock)
class TestMeshConsole(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=self.token)
        self.agent = baker.make_recipe("agents.online_agent")
        self.url = f"{base_url}/{self.agent.agent_id}/meshcentral/console/"

    def mesh(self, mesh_sync, hex_id):
        hex_id.return_value = "abc123"
        ms = mesh_sync.return_value
        ms.mesh_users = {self.john.mesh_user_id: {}}
        ms.add_users_to_node.return_value = {"result": "ok"}
        return ms

    def test_needs_a_step_up(self, hex_id, mesh_sync, _):
        ms = self.mesh(mesh_sync, hex_id)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)
        ms.add_users_to_node.assert_not_called()

        grant_console_stepup(self.john)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertIn("&viewmode=12", r.data["terminal"])
        self.assertIn("&viewmode=13", r.data["file"])
        self.assertIn("?login=", r.data["terminal"])
        ms.add_users_to_node.assert_called_once_with(
            node_id="node//abc123",
            user_ids=[self.john.mesh_user_id],
            rights=MESH_RIGHTS_CONSOLE,
            wait=True,
        )
        self.assertTrue(
            AuditLog.objects.filter(
                agent_id=self.agent.agent_id,
                message__contains="a terminal and file session",
            ).exists()
        )

    def test_api_key_and_mesh_sync_off(self, hex_id, mesh_sync, _):
        ms = self.mesh(mesh_sync, hex_id)
        grant_console_stepup(self.john)

        # step-up is on the dashboard token, not the api key
        self.client.force_authenticate(user=self.john)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)

        self.client.force_authenticate(user=self.john, token=self.token)
        self.coresettings.sync_mesh_with_rmm = False
        self.coresettings.save(update_fields=["sync_mesh_with_rmm"])
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        ms.add_users_to_node.assert_not_called()

    @override_settings(ULRMM_DISABLE_MESH_SYNC_TASK=True)
    def test_mesh_sync_task_off(self, hex_id, mesh_sync, _):
        # sync task is off, nothing clears the rights later
        ms = self.mesh(mesh_sync, hex_id)
        grant_console_stepup(self.john)

        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        ms.add_users_to_node.assert_not_called()

    def test_mesh_refuses(self, hex_id, mesh_sync, _):
        ms = self.mesh(mesh_sync, hex_id)
        grant_console_stepup(self.john)

        ms.add_users_to_node.return_value = None
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)

        ms.mesh_users = {}
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)

    def test_role_needs_mesh(self, hex_id, mesh_sync, _):
        ms = self.mesh(mesh_sync, hex_id)
        user = self.create_user_with_roles([])
        ms.mesh_users = {user.mesh_user_id: {}}
        grant_console_stepup(user)
        token = AuthToken.objects.create(user=user)[0]
        self.client.force_authenticate(user=user, token=token)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)

        user.role.can_use_mesh = True
        user.role.save()
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)

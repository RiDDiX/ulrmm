# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import PropertyMock, patch


from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker
from redis.connection import parse_url

from accounts.models import User
from accounts.utils import grant_console_stepup
from agents.models import Agent
from core.mesh_utils import MESH_RIGHTS_BASE, MESH_RIGHTS_CONSOLE
from core.utils import _run_url_rest_action
from logs.models import AuditLog
from ulrmm.celery import app as celery_app
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .consumers import TerminalConsumer
from .models import CoreSettings, GlobalKVStore, URLAction
from .serializers import KeyStoreSerializer, URLActionSerializer
from .tasks import sync_mesh_perms_task


class TestBranding(ULRMMTestCase):
    # 1x1 transparent png
    PNG = (
        "data:image/png;base64,"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )

    def setUp(self):
        self.setup_coresettings()

    def test_public_branding_unauthenticated(self):
        # stale token in header must not cause a 401 on the public endpoint
        r = self.client.get("/core/branding/", HTTP_AUTHORIZATION="Token deadbeef")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["product_name"], "UniversalLocal RMM")
        self.assertNotIn("id", r.data)

    def test_edit_branding_requires_auth(self):
        self.check_not_authenticated("get", "/core/branding/edit/")

    def test_edit_branding(self):
        self.authenticate()
        data = {
            "product_name": "Acme RMM",
            "company_name": "Acme Inc",
            "logo": self.PNG,
        }
        r = self.client.put("/core/branding/edit/", data, format="json")
        self.assertEqual(r.status_code, 200)

        r = self.client.get("/core/branding/")
        self.assertEqual(r.data["product_name"], "Acme RMM")
        self.assertEqual(r.data["logo"], self.PNG)

    def test_reject_svg_logo(self):
        self.authenticate()
        data = {"logo": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="}
        r = self.client.put("/core/branding/edit/", data, format="json")
        self.assertEqual(r.status_code, 400)

    def test_reject_javascript_support_url(self):
        self.authenticate()
        for bad in (
            "javascript:alert(1)",
            "//evil.example.com/login",
            "vbscript:msgbox(1)",
        ):
            r = self.client.put(
                "/core/branding/edit/", {"support_url": bad}, format="json"
            )
            self.assertEqual(r.status_code, 400, bad)

        r = self.client.put(
            "/core/branding/edit/",
            {"support_url": "https://support.example.com"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)

    def test_reject_mismatched_image(self):
        self.authenticate()
        # declares png but payload is not png
        data = {"logo": "data:image/png;base64,QUJD"}
        r = self.client.put("/core/branding/edit/", data, format="json")
        self.assertEqual(r.status_code, 400)


class TestForceAgentUpdate(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    @patch("agents.views.send_agent_update_task.delay")
    def test_force_update_reaches_agents_in_scope(self, mock_task):
        # the only path that reaches agents already on LATEST_AGENT_VER, which
        # is what a rebuilt same-version artifact needs
        in_scope = baker.make_recipe("agents.agent")
        r = self.client.post("/agents/update/force/")
        self.assertEqual(r.status_code, 200)
        mock_task.assert_called_once()
        self.assertTrue(mock_task.call_args.kwargs["force"])
        self.assertIn(in_scope.agent_id, mock_task.call_args.kwargs["agent_ids"])

        self.check_not_authenticated("post", "/agents/update/force/")


class TestCorePermissions(ULRMMTestCase):
    def setUp(self):
        self.setup_client()
        self.setup_coresettings()


@override_settings(CACHES=LOCMEM_CACHE)
@patch("core.tasks.get_mesh_ws_url", return_value="ws://mesh")
@patch("core.tasks.MeshSync")
@patch.object(Agent, "hex_mesh_node_id", new_callable=PropertyMock)
class TestMeshRightsSync(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.user = User.objects.create_user(
            username="meshy", password="hunter2x", is_superuser=True
        )
        baker.make_recipe("agents.online_agent", mesh_node_id="abc")

    def sync(self, mesh_sync, rights):
        uid = self.user.mesh_user_id
        ms = mesh_sync.return_value
        ms.reset_mock()
        ms.mesh_users = {uid: {"realname": ""}}
        ms.get_unique_mesh_users.return_value = []
        ms.mesh_action.return_value = {
            "nodes": {
                "mesh//x": [{"_id": "node//abc", "links": {uid: {"rights": rights}}}]
            }
        }
        sync_mesh_perms_task()
        return ms

    def test_console_rights_only_while_stepped_up(self, hex_id, mesh_sync, _):
        hex_id.return_value = "abc"

        # console rights with no live step-up get written back
        ms = self.sync(mesh_sync, MESH_RIGHTS_CONSOLE)
        ms.add_users_to_node.assert_called_once_with(
            node_id="node//abc", user_ids=[self.user.mesh_user_id]
        )

        ms = self.sync(mesh_sync, MESH_RIGHTS_BASE)
        ms.add_users_to_node.assert_not_called()

        grant_console_stepup(self.user)
        ms = self.sync(mesh_sync, MESH_RIGHTS_CONSOLE)
        ms.add_users_to_node.assert_not_called()

        # other masks get reset too, step-up or not
        ms = self.sync(mesh_sync, 0xFFFFFFFF)
        ms.add_users_to_node.assert_called_once()

    def test_console_rights_add_only_terminal_and_files(self, hex_id, mesh_sync, _):
        self.assertEqual(MESH_RIGHTS_BASE & ~MESH_RIGHTS_CONSOLE, 0x200 | 0x400)
        # agent console, run commands, guest sharing
        self.assertEqual(MESH_RIGHTS_CONSOLE & (0x10 | 0x20000 | 0x80000), 0)

        # 4088024 is the old mask, not this set
        hex_id.return_value = "abc"
        grant_console_stepup(self.user)
        ms = self.sync(mesh_sync, 4088024)
        ms.add_users_to_node.assert_called_once()


@override_settings(CACHES=LOCMEM_CACHE)
class TestServerScriptStepUp(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.setup_coresettings()
        self.authenticate()
        self.coresettings.enable_server_scripts = True
        self.coresettings.enable_server_webterminal = True
        self.coresettings.save()
        self.data = {
            "code": "#!/bin/sh\necho ok\n",
            "args": [],
            "env_vars": ["GOOD=1"],
            "timeout": 30,
            "shell": "shell",
        }

    def login(self, stepup: bool) -> None:
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        if stepup:
            grant_console_stepup(self.john)

    def assert_stepup(self, r) -> None:
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

    def test_new_installs_start_without_server_scripts(self):
        core = CoreSettings()
        self.assertFalse(core.enable_server_scripts)
        self.assertFalse(core.enable_server_webterminal)

    @patch("core.views.run_server_script", return_value=("ok", "", 0.1, 0))
    def test_test_server_script(self, run):
        url = "/core/serverscript/test/"
        # step-up on the user still needs a dashboard token
        grant_console_stepup(self.john)
        self.assert_stepup(self.client.post(url, self.data, format="json"))
        cache.clear()
        self.login(stepup=False)
        self.assert_stepup(self.client.post(url, self.data, format="json"))
        run.assert_not_called()

        self.login(stepup=True)
        self.assertEqual(
            self.client.post(url, self.data, format="json").status_code, 200
        )
        data = {**self.data, "env_vars": ["LD_PRELOAD=/tmp/x.so"]}
        self.assertEqual(self.client.post(url, data, format="json").status_code, 400)
        run.assert_called_once()

    @patch("core.utils.run_server_script", return_value=("ok", "", 0.1, 0))
    def test_run_on_server(self, run):
        agent = baker.make_recipe("agents.agent")
        script = baker.make("scripts.Script")
        url = f"/agents/{agent.agent_id}/runscript/"
        data = {
            "script": script.pk,
            "output": "wait",
            "args": [],
            "timeout": 30,
            "run_as_user": False,
            "env_vars": [],
            "run_on_server": True,
        }
        self.assert_stepup(self.client.post(url, data, format="json"))
        self.login(stepup=False)
        self.assert_stepup(self.client.post(url, data, format="json"))
        run.assert_not_called()
        self.login(stepup=True)
        self.assertEqual(self.client.post(url, data, format="json").status_code, 200)
        run.assert_called_once()

    def test_server_terminal_needs_stepup(self):
        consumer = TerminalConsumer()
        consumer.scope = {"user": self.john}
        with patch.object(consumer, "close") as close, patch.object(
            consumer, "accept"
        ) as accept, patch("core.consumers.threading.Thread"):
            consumer.connect()
        close.assert_called_once_with(4403)
        accept.assert_not_called()

        grant_console_stepup(self.john)
        with patch.object(consumer, "close") as close, patch.object(
            consumer, "accept"
        ) as accept, patch("core.consumers.threading.Thread"):
            consumer.connect()
        close.assert_not_called()
        accept.assert_called_once()


class TestAuditMasksCoreSecrets(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def assert_no_secret(self):
        for row in AuditLog.objects.values("before_value", "after_value", "debug_info"):
            self.assertNotIn("hunter2", json.dumps(row))

    @patch("logs.models.get_username", return_value="john")
    def test_key_store_and_url_action(self, _):
        key = GlobalKVStore.objects.create(name="k", value="hunter2")
        key.value = "hunter2 rotated"
        key.save()
        action = URLAction.objects.create(
            name="a",
            pattern="https://example.com/",
            rest_body='{"pw": "hunter2"}',
            rest_headers='{"Authorization": "hunter2"}',
        )
        action.delete()
        self.assertEqual(AuditLog.objects.count(), 4)
        self.assert_no_secret()
        entry = AuditLog.objects.filter(object_type="globalkvstore").last()
        self.assertRegex(entry.after_value["value"], r"^hmac:[0-9a-f]{16}$")
        self.assertNotEqual(entry.before_value["value"], entry.after_value["value"])
        # the api still returns the real value
        self.assertEqual(KeyStoreSerializer(key).data["value"], "hunter2 rotated")
        self.assertEqual(
            URLActionSerializer(action).data["rest_body"], action.rest_body
        )

    def test_url_action_test_audit(self):
        agent = baker.make_recipe("agents.agent")
        AuditLog.audit_url_action_test(
            username="john",
            url="https://example.com/",
            body='{"pw": "hunter2"}',
            headers='{"Authorization": "hunter2"}',
            instance_type="agent",
            instance_id=agent.agent_id,
            debug_info={},
        )
        self.assert_no_secret()

    @patch("core.utils.requests.post")
    @patch("core.utils._is_internal_url", return_value=False)
    @patch("core.utils.logger")
    def test_url_action_logs_no_body(self, logger, *_):
        _run_url_rest_action(
            url="https://example.com/",
            method="post",
            body="hunter2 is no json",
            headers="hunter2 neither",
        )
        self.assertEqual(logger.error.call_count, 2)
        self.assertNotIn("hunter2", str(logger.error.call_args_list))


class TestRedisPassword(ULRMMTestCase):
    def load_settings(self, password: str):
        local = types.ModuleType("ulrmm.local_settings")
        local.REDIS_PASSWORD = password
        path = Path(settings.BASE_DIR) / "ulrmm" / "settings.py"
        spec = importlib.util.spec_from_file_location("ulrmm.settings_copy", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"ulrmm.local_settings": local}):
            spec.loader.exec_module(module)
        return module

    def test_password_reaches_cache_channels_and_celery(self):
        conf = self.load_settings("p@ss/w:rd")
        self.assertEqual(
            conf.REDIS_URL, f"redis://:p%40ss%2Fw%3Ard@{conf.REDIS_HOST}:6379"
        )
        self.assertEqual(conf.CACHES["default"]["LOCATION"], conf.REDIS_URL)
        self.assertEqual(
            conf.CHANNEL_LAYERS["default"]["CONFIG"]["hosts"], [conf.REDIS_URL]
        )
        self.assertEqual(parse_url(conf.REDIS_URL)["password"], "p@ss/w:rd")

        # empty password keeps redis://host:6379
        conf = self.load_settings("")
        self.assertEqual(conf.REDIS_URL, f"redis://{conf.REDIS_HOST}:6379")
        self.assertEqual(celery_app.conf.broker_url, settings.REDIS_URL)
        self.assertEqual(celery_app.conf.result_backend, settings.REDIS_URL)


class TestSmsTest(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        core = CoreSettings.objects.first()
        core.twilio_account_sid = "AC123"
        core.twilio_auth_token = "token"
        core.twilio_number = "+15550000000"
        core.sms_alert_recipients = ["+15551111111"]
        core.save()

    @patch("core.models.TwClient")
    def test_network_error_is_a_message(self, mock_client):
        from requests import ConnectionError as RequestsConnectionError

        from logs.models import DebugLog

        mock_client.return_value.messages.create.side_effect = RequestsConnectionError(
            "network is unreachable"
        )
        r = self.client.post("/core/smstest/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("network is unreachable", r.data)
        self.assertEqual(
            mock_client.call_args.kwargs["http_client"].timeout,
            15,
        )
        self.assertTrue(
            DebugLog.objects.filter(message__startswith="SMS failed to send").exists()
        )

    @patch("core.models.TwClient")
    def test_alert_keeps_the_network_error(self, mock_client):
        from requests import ConnectionError as RequestsConnectionError

        # the alert task releases its claim on an exception and sends again
        mock_client.return_value.messages.create.side_effect = RequestsConnectionError(
            "network is unreachable"
        )
        with self.assertRaises(RequestsConnectionError):
            CoreSettings.objects.first().send_sms("Check failed")


class TestURLActionTestRun(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    @patch("core.views.run_test_url_rest_action", return_value=("ok", "u", ""))
    def test_blank_headers_and_body(self, run):
        data = {
            "pattern": "https://example.com/hook",
            "rest_body": "",
            "rest_headers": None,
            "rest_method": "get",
            "run_instance_type": "none",
            "run_instance_id": None,
        }
        r = self.client.post("/core/urlaction/run/test/", data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(run.call_args.kwargs["headers"], "")
        self.assertEqual(run.call_args.kwargs["body"], "")


class TestDashInfoSuperuser(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()

    def test_is_superuser(self):
        for user, expected in (
            (self.create_user_with_roles(["can_list_agents"]), False),
            (self.create_user_with_roles(["is_superuser"]), True),
            (baker.make("accounts.User", is_superuser=True, role=None), True),
        ):
            self.client.force_authenticate(user=user)
            r = self.client.get("/core/dashinfo/")
            self.assertIs(r.data["is_superuser"], expected)

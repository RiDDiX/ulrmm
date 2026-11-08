# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
from unittest.mock import AsyncMock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from agents.models import UNINSTALL_CODE_INFO, Agent
from winupdate.installing import SCAN_CMD
from agents.serializers import AgentAuditSerializer, AgentSerializer
from alerts.models import Alert
from logs.models import AuditLog
from notify import tamper
from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.constants import AgentPlat, AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

CODE = "a" * 16 + "B" * 16
DISPATCH = "notify.tamper.dispatch"


class TestCheckIn(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", choco_installed=True)
        self.setup_client()
        self.authenticate_agent(self.agent)

    def checkin(self, **data):
        with patch("apiv3.views.abulk_nats_command", new_callable=AsyncMock) as bulk:
            r = self.client.post("/api/v3/checkin/", data, format="json")
        self.assertEqual(r.status_code, 200)
        self.agent.refresh_from_db()
        return bulk

    def test_uninstall_code_stored_encrypted(self):
        self.checkin(uninstall_code=CODE)
        stored = self.agent.uninstall_code
        self.assertNotIn(CODE, stored)
        self.assertEqual(decrypt_secret(stored, UNINSTALL_CODE_INFO), CODE)

        # the same code again leaves the row alone, a malformed one is ignored
        self.checkin(uninstall_code=CODE)
        self.assertEqual(self.agent.uninstall_code, stored)
        for bad in ("short", CODE + "x", "a" * 31 + "-", 12345):
            self.checkin(uninstall_code=bad)
            self.assertEqual(self.agent.uninstall_code, stored)

        new = "c" * 32
        self.checkin(uninstall_code=new)
        self.assertEqual(
            decrypt_secret(self.agent.uninstall_code, UNINSTALL_CODE_INFO), new
        )

    @patch(DISPATCH)
    def test_manual_stop_raises_a_tamper_alert(self, dispatch):
        self.checkin(stop_reason="manual")
        self.assertFalse(Alert.objects.exists())

        self.coresettings.tamper_watch = True
        self.coresettings.save()
        self.checkin(stop_reason="update")
        self.assertFalse(Alert.objects.exists())
        self.checkin(stop_reason="manual")
        alert = Alert.objects.get()
        self.assertEqual(alert.alert_type, "agent")
        self.assertEqual(alert.message, tamper.MESSAGE)
        self.assertEqual(alert.agent, self.agent)
        ev = dispatch.call_args.args[0]
        self.assertEqual((ev["source"], ev["severity"]), ("tamper", "warning"))
        self.assertEqual(ev["alert"], alert)

    def test_windows_commands_share_one_connection(self):
        self.agent.choco_installed = False
        self.agent.save()
        bulk = self.checkin()
        bulk.assert_called_once()
        self.assertEqual(
            [func for _, func in bulk.call_args.kwargs["items"]],
            [{"func": "installchoco"}, SCAN_CMD],
        )
        self.assertEqual(
            {subject for subject, _ in bulk.call_args.kwargs["items"]},
            {self.agent.agent_id},
        )

    def test_posix_agents_get_no_windows_commands(self):
        self.assertTrue(self.checkin().called)
        self.agent.plat = AgentPlat.LINUX
        self.agent.save()
        self.checkin().assert_not_called()


class TestUninstallCode(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.authenticate()
        self.agent = baker.make_recipe(
            "agents.agent", uninstall_code=encrypt_secret(CODE, UNINSTALL_CODE_INFO)
        )
        self.url = f"/agents/{self.agent.agent_id}/uninstall_code/"

    def login(self, user, stepup=True):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_reveal_superuser_with_stepup(self):
        cache.clear()
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        self.login(self.john)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"uninstall_code": CODE})
        self.assertEqual(r["Cache-Control"], "no-store")
        log = AuditLog.objects.get(action=AuditActionType.VIEW)
        self.assertEqual(log.agent_id, self.agent.agent_id)
        self.assertNotIn(CODE, json.dumps(log.after_value))

        Agent.objects.filter(pk=self.agent.pk).update(uninstall_code="")
        self.assertEqual(self.client.post(self.url).status_code, 400)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_not_for_other_roles(self):
        cache.clear()
        user = self.create_user_with_roles(
            ["can_list_agents", "can_uninstall_agents", "can_edit_agent"]
        )
        self.login(user)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("stepup", r.data)

    def test_serializers_never_show_the_code(self):
        data = AgentSerializer(self.agent).data
        self.assertNotIn("uninstall_code", data)
        self.assertTrue(data["uninstall_code_set"])
        audit = AgentAuditSerializer(self.agent).data
        self.assertTrue(audit["uninstall_code"].startswith("hmac:"))
        r = self.client.get(f"/agents/{self.agent.agent_id}/")
        self.assertNotIn(self.agent.uninstall_code, json.dumps(r.data, default=str))


class TestAssetFields(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    @patch("agents.views.sync_mesh_perms_task.delay")
    def test_edit(self, _):
        agent = baker.make_recipe("agents.agent")
        r = self.client.put(
            f"/agents/{agent.agent_id}/",
            {
                "asset_tag": "INV-0042",
                "purchase_date": "2024-03-01",
                "purchase_price": "1299.90",
                "vendor": "Shop",
                "warranty_end": "2027-03-01",
                "lifecycle_notes": "replace 2028",
                "warranty_status": {"end": "2099-01-01"},
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        agent.refresh_from_db()
        self.assertEqual(agent.asset_tag, "INV-0042")
        self.assertEqual(str(agent.purchase_price), "1299.90")
        self.assertEqual(agent.warranty_end, dt.date(2027, 3, 1))
        # looked up only, never written by the form
        self.assertEqual(agent.warranty_status, {})

        r = self.client.put(
            f"/agents/{agent.agent_id}/", {"purchase_price": "-1"}, format="json"
        )
        self.assertEqual(r.status_code, 400)


@patch(DISPATCH)
class TestTamperWatch(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.tamper_watch = True
        self.coresettings.save()
        self.now = djangotime.now()
        self.gone = baker.make_recipe(
            "agents.agent", last_seen=self.now - dt.timedelta(minutes=30)
        )
        # online, offline too briefly, and gone for days
        baker.make_recipe("agents.agent", last_seen=self.now)
        baker.make_recipe("agents.agent", last_seen=self.now - dt.timedelta(minutes=5))
        baker.make_recipe("agents.agent", last_seen=self.now - dt.timedelta(days=3))

    def test_once_until_back_online(self, dispatch):
        self.assertEqual(tamper.watch(self.now), "1 raised")
        self.gone.refresh_from_db()
        self.assertEqual(self.gone.tamper_alerted_at, self.now)
        alert = Alert.objects.get()
        self.assertEqual(alert.agent, self.gone)
        self.assertFalse(alert.resolved)
        self.assertEqual(dispatch.call_args.args[0]["source"], "tamper")

        self.assertEqual(tamper.watch(self.now + dt.timedelta(minutes=5)), "0 raised")

        Agent.objects.filter(pk=self.gone.pk).update(
            last_seen=self.now + dt.timedelta(minutes=6)
        )
        with patch("notify.tamper.notify_alert") as resolved:
            tamper.watch(self.now + dt.timedelta(minutes=7))
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)
        resolved.assert_called_once_with(alert, resolved=True)
        self.gone.refresh_from_db()
        self.assertIsNone(self.gone.tamper_alerted_at)

    def test_shutdown_from_here_is_expected(self, dispatch):
        AuditLog.audit_power_action("john", self.gone, "shutdown")
        AuditLog.objects.update(entry_time=self.now - dt.timedelta(minutes=31))
        self.assertEqual(tamper.watch(self.now), "0 raised")

        # a sleep schedule put it to sleep
        AuditLog.objects.all().delete()
        baker.make(
            "patches.ScheduleRun",
            agent=self.gone,
            state="slept",
            changed=self.now - dt.timedelta(minutes=29),
        )
        self.assertEqual(tamper.watch(self.now), "0 raised")
        dispatch.assert_not_called()

    def test_off_and_maintenance(self, dispatch):
        Agent.objects.filter(pk=self.gone.pk).update(maintenance_mode=True)
        self.assertEqual(tamper.watch(self.now), "0 raised")
        self.coresettings.tamper_watch = False
        self.coresettings.save()
        Agent.objects.filter(pk=self.gone.pk).update(maintenance_mode=False)
        self.assertEqual(tamper.watch(self.now), "off")
        self.assertFalse(Alert.objects.exists())

        # switched off with an alert open: it still closes once the agent is back
        self.coresettings.tamper_watch = True
        self.coresettings.save()
        self.assertEqual(tamper.watch(self.now), "1 raised")
        self.coresettings.tamper_watch = False
        self.coresettings.save()
        Agent.objects.filter(pk=self.gone.pk).update(
            last_seen=self.now + dt.timedelta(minutes=1)
        )
        self.assertEqual(tamper.watch(self.now + dt.timedelta(minutes=2)), "off")
        self.assertTrue(Alert.objects.get().resolved)

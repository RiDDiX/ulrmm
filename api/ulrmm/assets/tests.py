# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from core.models import DELL_API_INFO, CoreSettings
from logs.models import AuditLog, DebugLog
from notify.models import Notification
from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.constants import AgentPlat, AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import warranty
from .models import HKDF_INFO, License
from .tasks import expiry_notify_task, warranty_lookup_task

REQUEST = "assets.warranty.requests.request"
KEY = "ABCDE-12345-FGHIJ"


def resp(data, status=200, url="https://x.example/"):
    r = MagicMock(status_code=status, history=[], url=url)
    r.json.return_value = data
    return r


DELL_ANSWER = [
    {
        "serviceTag": "ABC1234",
        "invalid": False,
        "shipDate": "2023-02-01T06:00:00Z",
        "productLineDescription": "OPTIPLEX 7090",
        "entitlements": [
            {
                "startDate": "2023-02-01T06:00:00Z",
                "endDate": "2026-02-01T05:59:59Z",
                "serviceLevelDescription": "Basic",
            },
            {
                "startDate": "2023-02-01T06:00:00Z",
                "endDate": "2028-02-01T05:59:59Z",
                "serviceLevelDescription": "ProSupport",
            },
        ],
    }
]
LENOVO_ANSWER = {
    "code": 0,
    "data": {
        "machineInfo": {"productName": "ThinkPad T14 Gen 3"},
        "baseWarranties": [
            {"name": "Depot", "startDate": "2022-05-01", "endDate": "2025-05-01"}
        ],
        "upmaWarranties": [
            {"name": "Premier", "startDate": "2025-05-01", "endDate": "2027-05-01"}
        ],
    },
}


def posix_agent(make, serial="ABC1234", **kwargs):
    return baker.make_recipe(
        "agents.agent",
        plat=AgentPlat.LINUX,
        wmi_detail={"make_model": make, "serialnumber": serial},
        **kwargs,
    )


class TestWarranty(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        for field, info in DELL_API_INFO.items():
            setattr(self.coresettings, field, encrypt_secret(f"v-{field}", info))
        self.coresettings.save()

    def test_dell(self):
        agent = posix_agent("Dell Inc. OptiPlex 7090")
        with patch(
            REQUEST,
            side_effect=[resp({"access_token": "tok"}), resp(DELL_ANSWER)],
        ) as req:
            status = warranty.refresh(agent, {})
        token_call, lookup = req.call_args_list
        self.assertEqual(token_call.args, ("POST", warranty.DELL_TOKEN))
        self.assertEqual(
            token_call.kwargs["data"]["client_secret"], "v-dell_api_client_secret"
        )
        self.assertTrue(lookup.args[1].endswith("servicetags=ABC1234"))
        self.assertEqual(lookup.kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(lookup.kwargs["timeout"], 20)
        for call in (token_call, lookup):
            self.assertIs(call.kwargs["allow_redirects"], False)
        self.assertEqual(status["provider"], "dell")
        self.assertEqual(status["end"], "2028-02-01")
        self.assertEqual(status["start"], "2023-02-01")
        self.assertEqual(status["service_level"], "ProSupport")
        self.assertEqual(status["product"], "OPTIPLEX 7090")
        self.assertEqual(status["error"], "")
        agent.refresh_from_db()
        self.assertEqual(agent.warranty_end, dt.date(2028, 2, 1))
        self.assertEqual(agent.warranty_status["service_level"], "ProSupport")

    def test_lenovo(self):
        agent = posix_agent("LENOVO 21AH")
        with patch(REQUEST, return_value=resp(LENOVO_ANSWER)) as req:
            status = warranty.refresh(agent, {})
        self.assertTrue(req.call_args.args[1].endswith("serialNumber=ABC1234"))
        self.assertEqual(status["end"], "2027-05-01")
        self.assertEqual(status["start"], "2022-05-01")
        self.assertEqual(status["product"], "ThinkPad T14 Gen 3")
        self.assertEqual(status["service_level"], "Premier")

    def test_failures_keep_the_old_end(self):
        agent = posix_agent("LENOVO 21AH", warranty_end=dt.date(2025, 1, 1))
        with patch(REQUEST, return_value=resp({}, status=503)):
            status = warranty.refresh(agent, {})
        self.assertEqual(status["error"], "HTTP 503")
        agent.refresh_from_db()
        self.assertEqual(agent.warranty_end, dt.date(2025, 1, 1))
        self.assertEqual(agent.warranty_status["error"], "HTTP 503")
        self.assertTrue(DebugLog.objects.filter(message__contains="HTTP 503").exists())

        redirected = resp(LENOVO_ANSWER)
        redirected.history = [MagicMock(url="http://pcsupport.lenovo.com/")]
        with patch(REQUEST, return_value=redirected):
            self.assertIn("https", warranty.refresh(agent, {})["error"])

        with patch(REQUEST) as req:
            other = posix_agent("Apple MacBookPro18,1")
            self.assertEqual(
                warranty.refresh(other, {})["error"], "no lookup for this vendor"
            )
            self.assertEqual(
                warranty.refresh(posix_agent("Dell Inc. X", serial=""), {})["error"],
                "no serial number reported",
            )
        req.assert_not_called()

    def test_dell_needs_credentials(self):
        CoreSettings.objects.update(dell_api_client_id="", dell_api_client_secret="")
        with patch(REQUEST) as req:
            status = warranty.refresh(posix_agent("Dell Inc. X"), {})
        self.assertIn("client id and secret", status["error"])
        req.assert_not_called()

    def test_weekly_task_reuses_the_dell_token(self):
        posix_agent("Dell Inc. A", serial="A1")
        posix_agent("Dell Inc. B", serial="B2")
        posix_agent("Apple Mac", serial="C3")
        with patch(
            REQUEST,
            side_effect=[
                resp({"access_token": "t"}),
                resp(DELL_ANSWER),
                resp(DELL_ANSWER),
            ],
        ) as req:
            self.assertEqual(warranty_lookup_task(), "2 looked up")
        self.assertEqual(req.call_count, 3)

    def test_manual_lookup_view(self):
        self.authenticate()
        agent = posix_agent("LENOVO 21AH")
        with patch(REQUEST, return_value=resp(LENOVO_ANSWER)):
            r = self.client.post(f"/agents/{agent.agent_id}/warranty/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["warranty_end"], dt.date(2027, 5, 1))
        self.assertEqual(r.data["warranty_status"]["provider"], "lenovo")

        viewer = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=viewer)
        r = self.client.post(f"/agents/{agent.agent_id}/warranty/")
        self.assertEqual(r.status_code, 403)

    def test_dell_settings_are_write_only_and_encrypted(self):
        self.authenticate()
        r = self.client.put(
            "/core/settings/",
            {"dell_api_client_id": "my-id", "dell_api_client_secret": "my-secret"},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        core = CoreSettings.objects.first()
        self.assertEqual(
            decrypt_secret(
                core.dell_api_client_secret, DELL_API_INFO["dell_api_client_secret"]
            ),
            "my-secret",
        )
        r = self.client.get("/core/settings/")
        self.assertTrue(r.data["dell_api_client_id_set"])
        self.assertNotIn("dell_api_client_id", r.data)
        self.assertNotIn("my-secret", json.dumps(r.data, default=str))
        audit = json.dumps(
            AuditLog.objects.filter(object_type="coresettings").last().after_value
        )
        self.assertNotIn("my-secret", audit)

        # blank keeps, clear drops
        self.client.put(
            "/core/settings/", {"dell_api_client_secret": ""}, format="json"
        )
        self.assertTrue(CoreSettings.objects.first().dell_api_client_secret)
        self.client.put(
            "/core/settings/", {"dell_api_client_secret_clear": True}, format="json"
        )
        self.assertEqual(CoreSettings.objects.first().dell_api_client_secret, "")


class TestExpiry(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        channel = baker.make(
            "notify.Channel", kind="ntfy", config={"topic": "t"}, name="n"
        )
        route = baker.make("notify.Route", name="r", sources=["license"])
        route.channels.set([channel])

    @patch("notify.tasks.send_notifications_task.delay")
    def test_once_per_end_date(self, delay):
        today = djangotime.localdate()
        baker.make_recipe("agents.agent", warranty_end=today + dt.timedelta(days=10))
        baker.make_recipe("agents.agent", warranty_end=today + dt.timedelta(days=90))
        baker.make(
            "assets.License", name="Office", expires=today + dt.timedelta(days=3)
        )
        self.assertEqual(expiry_notify_task(), "2 queued")
        self.assertEqual(expiry_notify_task(), "0 queued")
        titles = sorted(Notification.objects.values_list("title", flat=True))
        self.assertTrue(titles[0].startswith("DESKTOP-TEST123: warranty ends"))
        self.assertTrue(titles[1].startswith("License Office expires"))


class LicenseMixin:
    def setup_licenses(self):
        self.setup_coresettings()
        self.authenticate()
        self.site1 = baker.make("clients.Site", name="HQ")
        self.site2 = baker.make("clients.Site", name="Far")
        self.a1 = baker.make_recipe("agents.agent", site=self.site1)
        self.a2 = baker.make_recipe("agents.agent", site=self.site2)
        # a role limited to site1
        self.scoped = self.create_user_with_roles(
            ["can_list_agents", "can_manage_credentials"]
        )
        self.scoped.role.can_view_sites.set([self.site1])

    def lic(self, **kwargs):
        kwargs.setdefault("name", "Office")
        return baker.make(
            "assets.License", key=encrypt_secret(KEY, HKDF_INFO), **kwargs
        )


class TestLicenses(LicenseMixin, ULRMMTestCase):
    def setUp(self):
        self.setup_licenses()

    def test_crud_key_write_only(self):
        r = self.client.post(
            "/lifecycle/licenses/",
            {
                "name": "Office",
                "vendor": "MS",
                "key": KEY,
                "seats": 1,
                "agents": [self.a1.agent_id, self.a2.agent_id],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertNotIn("key", r.data)
        self.assertTrue(r.data["key_set"])
        self.assertEqual(r.data["assigned"], 2)
        self.assertTrue(r.data["over_seats"])
        self.assertEqual(
            {a["agent_id"] for a in r.data["agents"]},
            {self.a1.agent_id, self.a2.agent_id},
        )
        lic = License.objects.get()
        self.assertEqual(decrypt_secret(lic.key, HKDF_INFO), KEY)
        audit = json.dumps(
            AuditLog.objects.filter(object_type="license").last().after_value
        )
        self.assertNotIn(KEY, audit)

        r = self.client.put(
            f"/lifecycle/licenses/{lic.pk}/", {"key": "", "seats": 5}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        lic.refresh_from_db()
        self.assertEqual(decrypt_secret(lic.key, HKDF_INFO), KEY)
        self.assertFalse(r.data["over_seats"])
        r = self.client.put(
            f"/lifecycle/licenses/{lic.pk}/", {"key_clear": True}, format="json"
        )
        self.assertFalse(r.data["key_set"])

        r = self.client.put(
            f"/lifecycle/licenses/{lic.pk}/",
            {"site": self.site1.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

        self.assertEqual(
            self.client.delete(f"/lifecycle/licenses/{lic.pk}/").status_code, 200
        )
        self.assertFalse(License.objects.exists())

    def test_scope(self):
        mine = self.lic(site=self.site1)
        theirs = self.lic(site=self.site2)
        everyone = self.lic(agents=[self.a1, self.a2])
        self.client.force_authenticate(user=self.scoped)

        r = self.client.get("/lifecycle/licenses/")
        self.assertEqual({x["id"] for x in r.data}, {mine.pk, everyone.pk})
        shared = next(x for x in r.data if x["id"] == everyone.pk)
        self.assertEqual([a["agent_id"] for a in shared["agents"]], [self.a1.agent_id])
        self.assertEqual(shared["assigned"], 2)

        self.assertEqual(
            self.client.get(f"/lifecycle/licenses/{theirs.pk}/").status_code, 404
        )
        # a license for every client needs a role without client limits
        r = self.client.post("/lifecycle/licenses/", {"name": "x"}, format="json")
        self.assertEqual(r.status_code, 403)
        r = self.client.put(
            f"/lifecycle/licenses/{everyone.pk}/", {"name": "y"}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.post(
            "/lifecycle/licenses/",
            {"name": "x", "site": self.site1.pk, "agents": [self.a2.agent_id]},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            "/lifecycle/licenses/",
            {"name": "x", "site": self.site2.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        # devices the role cannot see stay assigned
        mine.agents.set([self.a1])
        r = self.client.put(
            f"/lifecycle/licenses/{mine.pk}/", {"agents": []}, format="json"
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(list(mine.agents.all()), [])

    def test_summary(self):
        today = djangotime.localdate()
        self.a1.warranty_end = today + dt.timedelta(days=20)
        self.a1.wmi_detail = {"make_model": "Dell Inc. OptiPlex"}
        self.a1.plat = AgentPlat.LINUX
        self.a1.save()
        self.lic(seats=1, agents=[self.a1, self.a2])
        self.lic(seats=5, agents=[self.a1])
        r = self.client.get("/lifecycle/summary/")
        self.assertEqual(r.status_code, 200)
        # nginx keeps /assets/ internal for report assets, nothing may live there
        self.assertEqual(self.client.get("/assets/summary/").status_code, 404)
        self.assertEqual(r.data["devices"], 2)
        self.assertIn({"vendor": "Dell", "count": 1}, r.data["by_vendor"])
        self.assertEqual(
            [x["agent_id"] for x in r.data["warranty_expiring"]], [self.a1.agent_id]
        )
        self.assertEqual(r.data["warranty_expiring"][0]["days_left"], 20)
        self.assertEqual(len(r.data["licenses_over_seats"]), 1)

        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.assertEqual(self.client.get("/lifecycle/summary/").status_code, 403)


@override_settings(CACHES=LOCMEM_CACHE)
class TestLicenseReveal(LicenseMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_licenses()
        self.mine = self.lic(site=self.site1)

    def login(self, user, stepup=True):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)

    def reveal(self, lic):
        return self.client.post(f"/lifecycle/licenses/{lic.pk}/reveal/")

    def test_reveal(self):
        self.client.force_authenticate(user=self.scoped)
        r = self.reveal(self.mine)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        self.login(self.scoped)
        r = self.reveal(self.mine)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"key": KEY})
        self.assertEqual(r["Cache-Control"], "no-store")
        log = AuditLog.objects.get(
            object_type=AuditObjType.CREDENTIAL, action=AuditActionType.VIEW
        )
        self.assertNotIn(KEY, json.dumps(log.after_value))

        self.assertEqual(self.reveal(self.lic(site=self.site2)).status_code, 404)
        self.assertEqual(self.reveal(self.lic()).status_code, 403)

        viewer = self.create_user_with_roles(["can_list_agents"])
        self.login(viewer)
        self.assertEqual(self.reveal(self.mine).status_code, 403)

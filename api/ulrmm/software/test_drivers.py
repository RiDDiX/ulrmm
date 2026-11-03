# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
from unittest.mock import patch

from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.test import ULRMMTestCase

from .drivers import MAX_DRIVERS, MAX_PROBLEMS, clean_drivers, removable
from .models import InstalledDrivers


def driver(inf="oem12.inf", cls="Net", **kw):
    return {
        "device": "Intel(R) Ethernet",
        "class": cls,
        "manufacturer": "Intel",
        "provider": "Intel",
        "version": "12.19.2.45",
        "date": "2023-03-14",
        "inf": inf,
        "signed": True,
        "device_id": "PCI\\VEN_8086&DEV_15BB",
        **kw,
    }


class TestCleanDrivers(ULRMMTestCase):
    def test_types_and_caps(self):
        body = {
            "v": 1,
            "ts": 1,
            "drivers": [
                driver(device="x" * 300, version=5, date="20230314", signed="yes"),
                driver(inf=""),
                "not a row",
                driver(date="2023-02-30"),
            ],
            "problems": [
                {
                    "name": "Base System Device",
                    "device_id": "PCI\\X",
                    "class": "",
                    "code": 28,
                },
                {"name": "unplugged", "device_id": "", "class": "", "code": 45},
                {"name": "zero", "code": 0},
                {"name": "big", "code": 100},
                {"name": "bool", "code": True},
            ],
            "errors": ["Win32_PnPEntity: timeout" * 10, 5],
            "extra": "dropped",
        }
        data = clean_drivers(body)
        self.assertEqual(set(data), {"drivers", "problems", "errors"})
        self.assertEqual(len(data["drivers"]), 2)
        first = data["drivers"][0]
        self.assertEqual(
            (len(first["device"]), first["version"], first["date"], first["signed"]),
            (255, "", "", None),
        )
        self.assertEqual(data["drivers"][1]["date"], "")
        self.assertEqual(
            data["problems"],
            [
                {
                    "name": "Base System Device",
                    "device_id": "PCI\\X",
                    "class": "",
                    "code": 28,
                }
            ],
        )
        self.assertEqual(len(data["errors"]), 1)
        self.assertEqual(len(data["errors"][0]), 128)

        many = clean_drivers(
            {
                "drivers": [driver()] * (MAX_DRIVERS + 5),
                "problems": [{"name": "p", "code": 1}] * (MAX_PROBLEMS + 5),
                "errors": ["e"] * 20,
            }
        )
        self.assertEqual(
            (len(many["drivers"]), len(many["problems"]), len(many["errors"])),
            (MAX_DRIVERS, MAX_PROBLEMS, 8),
        )
        self.assertEqual(
            clean_drivers({"drivers": "x", "problems": {}, "errors": None}),
            {"drivers": [], "problems": [], "errors": []},
        )
        with self.assertRaises(ValueError):
            clean_drivers([])

    def test_removable(self):
        self.assertTrue(removable("oem12.inf", set()))
        self.assertTrue(removable("OEM12.INF", set()))
        self.assertFalse(removable("oem12.inf", {"oem12.inf"}))
        self.assertFalse(removable("netrtwlane.inf", set()))
        self.assertFalse(removable("oem123456.inf", set()))
        self.assertFalse(removable("", set()))


class TestDriversIngest(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.online_agent")
        self.authenticate_agent(self.agent)
        self.url = f"/api/v3/{self.agent.agent_id}/drivers/"

    def test_ingest_replaces_the_inventory(self):
        body = {"v": 1, "ts": 1, "drivers": [driver()], "problems": [], "errors": []}
        r = self.client.post(self.url, body, format="json")
        self.assertEqual((r.status_code, r.data), (200, "ok"))
        row = InstalledDrivers.objects.get(agent=self.agent)
        self.assertEqual(row.data["drivers"][0]["inf"], "oem12.inf")

        body["drivers"] = [driver(inf="oem13.inf")]
        self.client.post(self.url, body, format="json")
        self.assertEqual(InstalledDrivers.objects.count(), 1)
        row.refresh_from_db()
        self.assertEqual([d["inf"] for d in row.data["drivers"]], ["oem13.inf"])

    def test_bad_bodies(self):
        r = self.client.post(self.url, [1, 2], format="json")
        self.assertEqual(r.status_code, 400)
        big = {"drivers": [driver(device="x" * 255)] * 5000}
        r = self.client.post(self.url, json.dumps(big), content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(InstalledDrivers.objects.exists())

    def test_foreign_agent_is_404(self):
        other = baker.make_recipe("agents.online_agent")
        r = self.client.post(
            f"/api/v3/{other.agent_id}/drivers/", {"drivers": []}, format="json"
        )
        self.assertEqual(r.status_code, 404)
        self.assertFalse(InstalledDrivers.objects.exists())

    def test_config_has_the_interval(self):
        r = self.client.get(f"/api/v3/{self.agent.agent_id}/config/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(80000 <= r.json()["checkin_drivers"] <= 90000)


class TestDriversRead(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.online_agent", site=self.site)
        self.url = f"/software/{self.agent.agent_id}/drivers/"

    def store(self, received=None):
        return InstalledDrivers.objects.create(
            agent=self.agent,
            received=received or djangotime.now(),
            data=clean_drivers(
                {
                    "drivers": [
                        driver(),
                        driver(inf="oem4.inf", cls="SCSIAdapter"),
                        # the same INF on a boot device blocks it everywhere
                        driver(inf="oem5.inf", cls="Media"),
                        driver(inf="oem5.inf", cls="system"),
                        driver(inf="disk.inf", cls="DiskDrive"),
                        driver(inf="keyboard.inf", cls="Keyboard"),
                    ],
                    "problems": [{"name": "PCI Device", "class": "", "code": 28}],
                    "errors": ["Win32_PnPEntity: access denied"],
                }
            ),
        )

    def test_read(self):
        r = self.client.get(self.url)
        self.assertEqual((r.status_code, r.json()), (404, {"detail": "no inventory"}))

        self.store()
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data["stale"])
        self.assertEqual(
            [(d["inf"], d["removable"]) for d in data["drivers"]],
            [
                ("oem12.inf", True),
                ("oem4.inf", False),
                ("oem5.inf", False),
                ("oem5.inf", False),
                ("disk.inf", False),
                ("keyboard.inf", False),
            ],
        )
        self.assertEqual(data["problems"][0]["code"], 28)
        self.assertEqual(data["errors"], ["Win32_PnPEntity: access denied"])

        InstalledDrivers.objects.update(
            received=djangotime.now() - dt.timedelta(days=4)
        )
        self.assertTrue(self.client.get(self.url).json()["stale"])

    def test_permissions_and_scope(self):
        self.store()
        other = baker.make_recipe("agents.online_agent")
        self.check_not_authenticated("get", self.url)

        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.check_not_authorized("get", self.url)
        self.check_not_authorized("post", self.url + "refresh/")

        user = self.create_user_with_roles(["can_list_software"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(
            self.client.get(f"/software/{other.agent_id}/drivers/").status_code, 403
        )
        self.assertEqual(
            self.client.post(
                f"/software/{other.agent_id}/drivers/refresh/"
            ).status_code,
            403,
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_refresh(self, nats_cmd):
        r = self.client.post(self.url + "refresh/")
        self.assertEqual(r.status_code, 200)
        nats_cmd.assert_called_once_with({"func": "drivers"}, wait=False)

        nats_cmd.reset_mock()
        offline = baker.make_recipe("agents.offline_agent")
        r = self.client.post(f"/software/{offline.agent_id}/drivers/refresh/")
        self.assertEqual(r.status_code, 400)
        linux = baker.make_recipe("agents.online_agent", plat="linux")
        r = self.client.post(f"/software/{linux.agent_id}/drivers/refresh/")
        self.assertEqual(r.status_code, 400)
        nats_cmd.assert_not_called()


class TestDemoSeed(ULRMMTestCase):
    def test_fake_agents_drivers(self):
        from agents.management.commands.fake_agents import Command as FakeAgents

        self.authenticate()
        self.setup_coresettings()
        agent = baker.make_recipe("agents.online_agent")
        FakeAgents()._drivers(agent, problems=True)
        row = InstalledDrivers.objects.get(agent=agent)
        self.assertEqual(clean_drivers(row.data), row.data)
        self.assertEqual(len(row.data["problems"]), 2)
        self.assertEqual(
            list(agent.winupdates.filter(is_driver=True).values_list("kb", flat=True)),
            [None, None],
        )
        data = self.client.get(f"/software/{agent.agent_id}/drivers/").json()
        self.assertEqual(
            {d["inf"] for d in data["drivers"] if d["removable"]},
            {"oem12.inf", "oem31.inf", "oem7.inf", "oem55.inf"},
        )

    def test_fake_agents_catalogs(self):
        from agents.management.commands.fake_agents import Command as FakeAgents

        from .models import WingetCatalog
        from .winget import ID_RE

        self.authenticate()
        self.setup_coresettings()
        agent = baker.make_recipe(
            "agents.online_agent",
            operating_system="Windows 11 Pro, 64 bit (build 22631.3447)",
        )
        demo = FakeAgents()
        demo._catalogs()
        demo._drivers(agent, problems=False)
        packages = WingetCatalog.load().packages
        self.assertEqual(len(packages), 50)
        self.assertTrue(all(ID_RE.fullmatch(p[0]) and len(p) == 3 for p in packages))
        rows = self.client.get(f"/software/{agent.agent_id}/drivers/").json()["drivers"]
        self.assertEqual(
            [(r["inf"], (r["catalog"] or {}).get("version")) for r in rows[:3]],
            [("oem12.inf", "12.19.2.66"), ("oem31.inf", None), ("oem7.inf", None)],
        )
        self.assertTrue(all(r["catalog_checked"] for r in rows))
        r = self.client.get(
            "/software/catalog/", {"source": "winget", "search": "7zip"}
        )
        self.assertEqual(r.json()["rows"][0]["id"], "7zip.7zip")

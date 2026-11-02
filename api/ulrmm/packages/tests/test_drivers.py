# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import AuditLog, DebugLog
from software.drivers import clean_drivers
from software.models import InstalledDrivers
from ulrmm.constants import AgentPlat, AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from ..models import InstallState, PackageInstall
from ..tasks import install_batch_task
from ..utils import REMOVE_DRIVER_SCRIPT, SCRIPTS, parse_result
from .test_api import make_package
from .test_tasks import marker, ran

URL = "/packages/drivers/remove/"


def driver(inf, cls="Net", provider="Intel"):
    return {
        "device": f"device {inf}",
        "class": cls,
        "manufacturer": provider,
        "provider": provider,
        "version": "1.0",
        "date": "2024-01-01",
        "inf": inf,
        "signed": True,
        "device_id": "PCI\\VEN_8086",
    }


class TestDriverScripts(ULRMMTestCase):
    def test_static_scripts(self):
        install = SCRIPTS[AgentPlat.WINDOWS].read_text()
        self.assertIn("'driver'", install)
        self.assertIn("/add-driver", install)
        self.assertIn("/subdirs /install", install)
        remove = REMOVE_DRIVER_SCRIPT.read_text()
        self.assertIn("ULRMM-PKG", remove)
        self.assertIn("/delete-driver $inf /uninstall", remove)
        self.assertNotIn("/force", remove)
        for cls in ("SCSIAdapter", "HDC", "DiskDrive", "System", "Computer"):
            self.assertIn(f"'{cls}'", remove)

    def test_pnputil_259_marker(self):
        state, fields = parse_result(
            ran(marker(exit=259, msg="added to the driver store, no device took it")),
            1800,
        )
        self.assertEqual((state, fields["exit_code"]), (InstallState.SUCCEEDED, 259))
        state, fields = parse_result(ran(marker("reboot", exit=3010)), 1800)
        self.assertEqual(state, InstallState.REBOOT_REQUIRED)


@override_settings(CACHES=LOCMEM_CACHE)
class TestDriverInstall(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent")
        self.package = make_package(kind="driver", name="NIC driver")

    @patch("packages.tasks.install_batch_task.delay")
    def test_run_as_user_is_refused(self, delay):
        r = self.client.post(
            f"/packages/{self.package.pk}/install/",
            {"agent_id": self.agent.agent_id, "run_as": "user"},
            format="json",
        )
        self.assertEqual((r.status_code, r.data), (400, "Drivers install as system."))
        r = self.client.post(
            f"/packages/{self.package.pk}/install/",
            {"agent_id": self.agent.agent_id, "run_as": "system"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        delay.assert_called_once()

    @patch("agents.models.Agent.nats_cmd")
    def test_inventory_refresh_after_install(self, nats_cmd):
        for reply, state, refreshed in (
            (ran(marker(exit=259)), InstallState.SUCCEEDED, True),
            (ran(marker("reboot", exit=3010)), InstallState.REBOOT_REQUIRED, True),
            (ran(marker("fail", exit=1)), InstallState.FAILED, False),
        ):
            with self.subTest(state=state):
                nats_cmd.reset_mock()
                nats_cmd.side_effect = [reply, None]
                install = baker.make(
                    "packages.PackageInstall",
                    package=self.package,
                    package_name=self.package.name,
                    agent=self.agent,
                    run_as="system",
                    state=InstallState.QUEUED,
                )
                install_batch_task(str(install.batch))
                install.refresh_from_db()
                self.assertEqual(install.state, state)
                data = nats_cmd.call_args_list[0].args[0]
                self.assertIn("PKG_KIND=driver", data["env_vars"])
                self.assertIn("PKG_MODE=system", data["env_vars"])
                calls = [c.args[0] for c in nats_cmd.call_args_list[1:]]
                self.assertEqual(calls, [{"func": "drivers"}] if refreshed else [])
        self.assertEqual(PackageInstall.objects.count(), 3)


@override_settings(CACHES=LOCMEM_CACHE)
@patch("agents.models.Agent.nats_cmd")
class TestRemoveDriver(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.online_agent", site=self.site)
        InstalledDrivers.objects.create(
            agent=self.agent,
            received=djangotime.now(),
            data=clean_drivers(
                {
                    "drivers": [
                        driver("oem12.inf"),
                        driver("oem9.inf", "Media"),
                        driver("oem4.inf", "SCSIAdapter"),
                        driver("oem7.inf", "Media"),
                        driver("oem7.inf", "volume"),
                        driver("disk.inf", "DiskDrive", "Microsoft"),
                    ]
                }
            ),
        )

    def remove(self, inf="oem12.inf", agent=None):
        agent = agent or self.agent
        return self.client.post(
            URL, {"agent_id": agent.agent_id, "inf": inf}, format="json"
        )

    def test_success(self, nats_cmd):
        seen = {}

        def reply(data, **kwargs):
            if data["func"] == "runscriptfull":
                seen.update(data=data, kwargs=kwargs, lock=cache.get(self.lock))
                return ran("Deleted driver package.\n" + marker(exit=0, sig=""))
            return None

        self.lock = f"pkg_install_{self.agent.agent_id}"
        nats_cmd.side_effect = reply
        r = self.remove("OEM12.INF")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            {k: r.data[k] for k in ("state", "exit_code", "detail")},
            {"state": "succeeded", "exit_code": 0, "detail": ""},
        )
        self.assertIn("Deleted driver package.", r.data["output"])

        data = seen["data"]
        self.assertEqual(
            (data["func"], data["timeout"], data["run_as_user"]),
            ("runscriptfull", 150, False),
        )
        self.assertEqual(data["env_vars"], ["DRV_INF=oem12.inf"])
        self.assertEqual(data["payload"]["shell"], "powershell")
        self.assertIn("/delete-driver", data["payload"]["code"])
        self.assertEqual(seen["kwargs"], {"timeout": 180})
        self.assertIsNotNone(seen["lock"])
        self.assertIsNone(cache.get(self.lock))
        nats_cmd.assert_called_with({"func": "drivers"}, wait=False)

        audit = AuditLog.objects.get(action=AuditActionType.EXEC_COMMAND)
        self.assertEqual(
            audit.message,
            f"john removes driver oem12.inf (Intel Net) from {self.agent.hostname}: "
            "succeeded",
        )
        self.assertEqual(
            audit.after_value,
            {"inf": "oem12.inf", "state": "succeeded", "exit_code": 0},
        )
        self.assertIn("oem12.inf", DebugLog.objects.get(agent=self.agent).message)
        # dropped right away, windows lists it until a reboot
        left = InstalledDrivers.objects.get(agent=self.agent).data["drivers"]
        self.assertNotIn("oem12.inf", [d["inf"] for d in left])
        self.assertEqual(len(left), 5)

    def test_reboot_and_failure(self, nats_cmd):
        nats_cmd.return_value = ran(marker("reboot", exit=3010))
        self.assertEqual(self.remove().data["state"], "reboot_required")
        nats_cmd.return_value = ran(marker("fail", exit=5, msg="in use"))
        r = self.remove("oem9.inf")
        self.assertEqual(
            (r.data["state"], r.data["exit_code"], r.data["detail"]),
            ("failed", 5, "in use"),
        )
        nats_cmd.return_value = "timeout"
        self.assertEqual(self.remove("oem9.inf").data["state"], "failed")
        # a failed removal keeps the row
        left = InstalledDrivers.objects.get(agent=self.agent).data["drivers"]
        self.assertIn("oem9.inf", [d["inf"] for d in left])
        self.assertEqual(AuditLog.objects.count(), 3)

    def test_rejected(self, nats_cmd):
        linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        offline = baker.make_recipe(
            "agents.agent", last_seen=djangotime.now() - dt.timedelta(hours=1)
        )
        InstalledDrivers.objects.create(
            agent=offline,
            received=djangotime.now(),
            data={"drivers": [driver("oem12.inf")]},
        )
        for inf, agent, error in (
            ("disk.inf", None, "third-party"),
            ("oem12.inf.bak", None, "third-party"),
            ("..\\oem12.inf", None, "third-party"),
            (None, None, "third-party"),
            ("oem99.inf", None, "not in the driver list"),
            ("oem4.inf", None, "needs to boot"),
            # a boot class on any row of the INF blocks it
            ("oem7.inf", None, "needs to boot"),
            ("oem12.inf", linux, "only be removed on Windows"),
            ("oem12.inf", offline, "offline"),
        ):
            with self.subTest(inf=inf):
                r = self.remove(inf, agent)
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, r.data)

        cache.add(f"pkg_install_{self.agent.agent_id}", 1, 60)
        r = self.remove()
        self.assertEqual(r.status_code, 400)
        self.assertIn("package install is running", r.data)

        no_inventory = baker.make_recipe("agents.online_agent")
        self.assertIn("not in the driver list", self.remove(agent=no_inventory).data)
        nats_cmd.assert_not_called()
        self.assertFalse(AuditLog.objects.exists())

    def test_permissions(self, nats_cmd):
        nats_cmd.return_value = ran(marker())
        self.check_not_authenticated("post", URL)
        user = self.create_user_with_roles(["can_list_software", "can_manage_packages"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.remove().status_code, 403)

        user = self.create_user_with_roles(["can_install_packages"])
        other = baker.make("clients.Site")
        user.role.can_view_sites.set([other])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.remove().status_code, 403)
        user.role.can_view_sites.set([self.site])
        self.assertEqual(self.remove().status_code, 200)

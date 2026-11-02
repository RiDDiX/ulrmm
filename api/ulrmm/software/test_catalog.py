# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from packages.models import PackageKind, SoftwarePackage
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import catalog, tasks
from .catalog import CatalogError
from .drivers import clean_drivers
from .models import DriverCatalog, InstalledDrivers
from .test_winget import FakeResponse

DATA = Path(__file__).parent / "testdata"
WIN11 = "Windows 11 Pro, 64 bit (build 22631.3447)"
WIN10 = "Windows 10 Pro, 64 bit (build 19045.4291)"
SERVER22 = "Windows Server 2022 Standard, 64 bit (build 20348.2402)"
SERVER19 = "Windows Server 2019 Standard, 64 bit (build 17763.5696)"
NIC = "PCI\\VEN_8086&DEV_15B8&SUBSYS_86721043&REV_10\\3&11583659&0&FE"
NIC_KEYS = ["PCI\\VEN_8086&DEV_15B8&SUBSYS_86721043", "PCI\\VEN_8086&DEV_15B8"]
UID = "ffe0d3f3-52b3-4e26-b9d6-13b5e77bd11d"
UID2 = "9d6cf3f1-6313-42ec-95fd-7d84b59e6e49"
ALL_OS = (
    "Windows 10, Vibranium and later, Servicing Drivers, "
    "Windows 11 Client, version 22H2 and later, Servicing Drivers, "
    "Windows - Server, version 21H2 and later, Servicing Drivers"
)


def page(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def entry(version="12.19.2.66", update_id=UID, products=ALL_OS, **kw):
    return {
        "update_id": update_id,
        "title": f"Intel Net Driver Update ({version})",
        "products": products,
        "classification": "Drivers (Networking)",
        "date": "2025-11-15",
        "version": version,
        "size": 286663,
        **kw,
    }


def nic(version="12.19.2.45", device_id=NIC, **kw):
    return {
        "device": "Intel(R) Ethernet",
        "class": "Net",
        "manufacturer": "Intel",
        "provider": "Intel",
        "version": version,
        "date": "2023-03-14",
        "inf": "oem12.inf",
        "signed": True,
        "device_id": device_id,
        **kw,
    }


class TestParse(SimpleTestCase):
    def test_search_keys(self):
        for device_id, keys in (
            (NIC, NIC_KEYS),
            ("pci\\ven_8086&dev_15b8\\3&1", ["PCI\\VEN_8086&DEV_15B8"]),
            (
                "USB\\VID_046D&PID_C52B&MI_00\\7&2",
                ["USB\\VID_046D&PID_C52B&MI_00", "USB\\VID_046D&PID_C52B"],
            ),
            (
                "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0256&SUBSYS_10431A40&REV_1000\\4&1",
                [
                    "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0256&SUBSYS_10431A40",
                    "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0256",
                ],
            ),
            ("ACPI\\INT33A1\\1", ["ACPI\\INT33A1"]),
            ("ACPI\\PNP0A08\\0", []),
            ("ACPI\\ACPI0010\\2&da", []),
            ("ROOT\\SYSTEM\\0001", []),
            ("SWD\\MMDEVAPI\\{0.0.0.00000000}", []),
            ("PCI\\VEN_8086", []),
            ("", []),
            (None, []),
            # the full id is unusable, the short form still is
            ("PCI\\VEN_8086&DEV_" + "A" * 120 + "\\1", ["PCI\\VEN_8086&DEV_AAAA"]),
            ('PCI\\VEN_8086&DEV_15B8&"x\\1', ["PCI\\VEN_8086&DEV_15B8"]),
            ('PCI\\VEN_80"6&DEV_15B8\\1', []),
        ):
            with self.subTest(device_id):
                self.assertEqual(catalog.search_keys(device_id), keys)

    def test_search_page(self):
        rows = catalog.parse_search(page("search_results.html"))
        self.assertEqual(len(rows), 5)
        self.assertEqual(
            rows[0],
            {
                "update_id": UID,
                "title": "Intel Net Driver Update (12.19.2.66)",
                "products": "Windows 11 Client, version 22H2 and later, Servicing "
                "Drivers, Windows 11 Client, version 22H2 and later, Upgrade & "
                "Servicing Drivers",
                "classification": "Drivers (Networking)",
                "date": "2025-11-15",
                "version": "12.19.2.66",
                "size": 286663,
            },
        )
        self.assertEqual(rows[-1]["title"], "Intel - Net - 12.19.2.62")
        subsys = catalog.parse_search(page("search_subsys.html"))
        self.assertTrue(any("Windows - Server" in r["products"] for r in subsys))

        self.assertEqual(catalog.parse_search(page("search_none.html")), [])
        for bad in (
            page("search_bad.html"),
            page("search_results.html").replace("_C5_R", "_X5_R"),
            "",
        ):
            with self.assertRaisesMessage(CatalogError, "catalog page not understood"):
                catalog.parse_search(bad)

    def test_firmware_is_dropped(self):
        html = page("search_results.html").replace(
            "Drivers (Networking)", "Drivers (Firmware)", 2
        )
        self.assertEqual(len(catalog.parse_search(html)), 3)

    def test_download_and_details(self):
        info = catalog.parse_download(page("download.html"))
        self.assertEqual(
            info,
            {
                "url": "https://catalog.s.download.windowsupdate.com/c/msdownload/"
                "update/driver/drvs/2026/02/3de915d8-3c4d-4341-a002-840a5d8be101_"
                "97f01c46b968a3faa7e4a342a4b1dfb88ed86bbe.cab",
                "sha256": base64.b64decode(
                    "qTvOBuvcgebUujKxwiwQFak1DSAoUDWd0oPC/jUFA38="
                ).hex(),
                "name": "3de915d8-3c4d-4341-a002-840a5d8be101_"
                "97f01c46b968a3faa7e4a342a4b1dfb88ed86bbe.cab",
            },
        )
        dl = page("download.html")
        for bad, error in (
            (
                dl.replace("https://catalog.s.download", "http://catalog.s.download"),
                "unexpected",
            ),
            (
                dl.replace("windowsupdate.com/c", "windowsupdate.com.evil.net/c"),
                "unexpected",
            ),
            (dl.replace(".cab'", ".exe'", 1), "unexpected"),
            (dl.replace("qTvOBuvc", "!!"), "no sha256"),
            (
                dl
                + "downloadInformation[0].files[1].url = 'https://x.microsoft.com/a.cab';",
                "2 files",
            ),
            ("", "0 files"),
        ):
            with self.subTest(error):
                with self.assertRaisesMessage(CatalogError, error):
                    catalog.parse_download(bad)

        self.assertEqual(catalog.parse_arch(page("details.html")), "AMD64")
        with self.assertRaises(CatalogError):
            catalog.parse_arch("<html></html>")
        self.assertTrue(catalog.arch_ok("AMD64", "AMD64"))
        self.assertTrue(catalog.arch_ok("X86, AMD64", "X86"))
        self.assertTrue(catalog.arch_ok("", "AMD64"))
        self.assertTrue(catalog.arch_ok("ARM64", ""))
        self.assertFalse(catalog.arch_ok("AMD64", "ARM64"))
        self.assertFalse(catalog.arch_ok("AMD64", "X86"))

    def test_applicable(self):
        win11 = "Windows 11 Client, version 24H2 and later, Servicing Drivers"
        for operating_system, products, ok in (
            (WIN10, ALL_OS, True),
            (WIN11, ALL_OS, True),
            (SERVER22, ALL_OS, True),
            (SERVER19, ALL_OS, False),
            (WIN11, win11, False),
            ("Windows 11 Pro, 64 bit (build 26100.1)", win11, True),
            (WIN10, win11, False),
            (WIN11, "Windows 11 Client S, version 22H2 and later, Drivers", True),
            (WIN11, "Windows 11 Client, version 99H9 and later, Drivers", True),
            (WIN10, "Windows 7, Windows 8.1", False),
            ("Windows 11 Pro", win11, True),
        ):
            with self.subTest((operating_system, products)):
                family, build = catalog.os_target(operating_system)
                self.assertEqual(
                    catalog.applicable({"products": products}, family, build), ok
                )

    def test_newest(self):
        family, build = catalog.os_target(WIN11)
        entries = [
            entry("12.19.2.64"),
            entry("12.19.2.66", update_id=UID2, date="2025-10-28"),
            entry("12.19.2.66"),
            entry("13.0.0.1", products="Windows 11 Client, version 25H2 and later"),
            entry("x"),
            "not a row",
        ]
        self.assertEqual(
            catalog.newest(entries, nic(), family, build)["update_id"], UID
        )
        self.assertIsNone(catalog.newest(entries, nic("12.19.2.66"), family, build))
        self.assertIsNone(catalog.newest(entries, nic("100.0"), family, build))
        # unreadable version: the date decides
        old = nic("", date="2025-01-01")
        self.assertEqual(
            catalog.newest(entries, old, family, build)["version"], "12.19.2.66"
        )
        self.assertIsNone(
            catalog.newest(entries, nic("", date="2026-01-01"), family, build)
        )
        self.assertIsNone(catalog.newest(entries, nic("", date=""), family, build))


class FakeFetcher:
    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def search(self, key):
        self.asked.append(key)
        answer = self.answers.get(key, [])
        if isinstance(answer, Exception):
            raise answer
        return answer


class TestScan(ULRMMTestCase):
    def scan(self, key_lists, answers, max_requests=300, fresh=dt.timedelta(days=7)):
        fetcher = FakeFetcher(answers)
        stats = catalog.scan(
            key_lists, max_requests, fresh, dt.timedelta(days=1), fetcher
        )
        return stats, fetcher.asked

    def test_fallback_and_freshness(self):
        stats, asked = self.scan([NIC_KEYS], {})
        self.assertEqual(asked, NIC_KEYS)
        self.assertEqual(stats, {"requests": 2, "errors": 0, "stopped": ""})
        # both fresh now
        self.assertEqual(self.scan([NIC_KEYS], {})[1], [])

        DriverCatalog.objects.all().delete()
        stats, asked = self.scan([NIC_KEYS], {NIC_KEYS[0]: [entry()]})
        self.assertEqual(asked, NIC_KEYS[:1])

        old = djangotime.now() - dt.timedelta(days=8)
        DriverCatalog.objects.filter(hwid=NIC_KEYS[0]).update(checked=old)
        self.assertEqual(
            self.scan([NIC_KEYS], {NIC_KEYS[0]: [entry()]})[1], NIC_KEYS[:1]
        )

    def test_errors_keep_entries_and_retry_daily(self):
        DriverCatalog.objects.create(
            hwid=NIC_KEYS[0],
            checked=djangotime.now() - dt.timedelta(days=8),
            entries=[entry()],
        )
        stats, asked = self.scan([NIC_KEYS], {NIC_KEYS[0]: CatalogError("HTTP 503")})
        self.assertEqual(asked, NIC_KEYS[:1])
        row = DriverCatalog.objects.get(hwid=NIC_KEYS[0])
        self.assertEqual((row.error, len(row.entries)), ("HTTP 503", 1))
        self.assertEqual(self.scan([NIC_KEYS], {})[1], [])
        DriverCatalog.objects.update(checked=djangotime.now() - dt.timedelta(hours=25))
        # the full key came back empty, so the short one is next
        self.assertEqual(self.scan([NIC_KEYS], {})[1], NIC_KEYS)
        self.assertEqual(DriverCatalog.objects.get(hwid=NIC_KEYS[0]).error, "")

    def test_caps_and_three_errors(self):
        keys = [[f"PCI\\VEN_8086&DEV_{i:04X}"] for i in range(10)]
        stats, asked = self.scan(keys, {}, max_requests=4)
        self.assertEqual(len(asked), 4)
        self.assertEqual(stats["stopped"], "request limit 4")

        DriverCatalog.objects.all().delete()
        down = {k[0]: CatalogError("ConnectionError") for k in keys}
        down[keys[1][0]] = []
        stats, asked = self.scan(keys, down)
        self.assertEqual(len(asked), 5)
        self.assertEqual(stats["errors"], 4)
        self.assertIn("3 errors in a row", stats["stopped"])

    def test_oldest_first(self):
        now = djangotime.now()
        DriverCatalog.objects.create(
            hwid="PCI\\VEN_1", checked=now - dt.timedelta(days=9)
        )
        DriverCatalog.objects.create(
            hwid="PCI\\VEN_2", checked=now - dt.timedelta(days=20)
        )
        asked = self.scan([["PCI\\VEN_1"], ["PCI\\VEN_2"], ["PCI\\VEN_3"]], {})[1]
        self.assertEqual(asked, ["PCI\\VEN_3", "PCI\\VEN_2", "PCI\\VEN_1"])

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_tasks(self):
        cache.clear()
        agent = baker.make_recipe("agents.online_agent", operating_system=WIN11)
        linux = baker.make_recipe("agents.online_agent", plat="linux")
        for a in (agent, linux):
            InstalledDrivers.objects.create(
                agent=a,
                received=djangotime.now(),
                data=clean_drivers({"drivers": [nic(), nic(inf="oem1.inf")]}),
            )
        with patch("software.catalog.Fetcher.search", return_value=[]) as search:
            self.assertEqual(
                tasks.scan_driver_catalog_task(), "2 catalog searches, 0 failed"
            )
            self.assertEqual([c.args[0] for c in search.call_args_list], NIC_KEYS)
            search.reset_mock()
            self.assertEqual(
                tasks.check_agent_catalog_task(agent.pk), "0 catalog searches, 0 failed"
            )
            cache.add(tasks.SCAN_LOCK, "other", 60)
            self.assertIn("already running", tasks.scan_driver_catalog_task())
            self.assertIn("already running", tasks.check_agent_catalog_task(agent.pk))
            search.assert_not_called()
        cache.clear()


class TestFetch(SimpleTestCase):
    @patch("software.catalog.requests.request")
    def test_every_hop_is_checked(self, request):
        moved = FakeResponse(
            302,
            headers={"Location": "http://catalog.s.download.windowsupdate.com/a.cab"},
        )
        request.return_value = moved
        with self.assertRaisesMessage(CatalogError, "refused"):
            catalog.fetch(
                "GET", "https://dl.windowsupdate.com/a.cab", catalog.DOWNLOAD_HOSTS
            )
        self.assertEqual(request.call_count, 1)

        request.reset_mock()
        request.side_effect = [
            FakeResponse(301, headers={"Location": "/b.cab"}),
            FakeResponse(302, headers={"Location": "https://169.254.169.254/x"}),
        ]
        with self.assertRaisesMessage(CatalogError, "refused"):
            catalog.fetch(
                "GET", "https://dl.windowsupdate.com/a.cab", catalog.DOWNLOAD_HOSTS
            )
        self.assertEqual(
            [c.args[1] for c in request.call_args_list],
            [
                "https://dl.windowsupdate.com/a.cab",
                "https://dl.windowsupdate.com/b.cab",
            ],
        )
        self.assertFalse(request.call_args.kwargs["allow_redirects"])

        request.side_effect = None
        request.return_value = FakeResponse(302, headers={"Location": "/x"})
        with self.assertRaisesMessage(CatalogError, "POST was redirected"):
            catalog.fetch(
                "POST", f"{catalog.CATALOG}/DownloadDialog.aspx", catalog.CATALOG_HOSTS
            )
        with self.assertRaisesMessage(CatalogError, "too many redirects"):
            catalog.fetch(
                "GET", f"{catalog.CATALOG}/Search.aspx", catalog.CATALOG_HOSTS
            )
        for url in (
            "https://windowsupdate.com.evil.net/a.cab",
            "https://evilwindowsupdate.com/a.cab",
            "https://dl.windowsupdate.com:8443/a.cab",
            "ftp://dl.windowsupdate.com/a.cab",
        ):
            self.assertFalse(catalog.host_ok(url, catalog.DOWNLOAD_HOSTS), url)

    @patch("software.catalog.time.sleep")
    @patch("software.catalog.requests.request")
    def test_fetcher(self, request, sleep):
        request.return_value = FakeResponse(200, page("search_none.html").encode())
        fetcher = catalog.Fetcher()
        self.assertEqual(fetcher.search(NIC_KEYS[0]), [])
        self.assertEqual(fetcher.search(NIC_KEYS[1]), [])
        sleep.assert_called_once()
        self.assertGreater(sleep.call_args.args[0], 1.5)
        call = request.call_args
        self.assertEqual(call.kwargs["params"], {"q": NIC_KEYS[1]})
        self.assertIn("(driver catalog)", call.kwargs["headers"]["User-Agent"])

        request.return_value = FakeResponse(429)
        with self.assertRaisesMessage(CatalogError, "HTTP 429"):
            fetcher.search("x")
        request.side_effect = requests.Timeout()
        with self.assertRaisesMessage(CatalogError, "Timeout"):
            fetcher.search("x")


class Base(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", operating_system=WIN11)
        self.url = f"/software/{self.agent.agent_id}/drivers/"

    def store(self, agent=None, drivers=None):
        InstalledDrivers.objects.create(
            agent=agent or self.agent,
            received=djangotime.now(),
            data=clean_drivers(
                {
                    "drivers": drivers
                    or [nic(), nic(inf="oem2.inf", device_id="ROOT\\NET\\0000")]
                }
            ),
        )

    def offer(self, *entries, key=NIC_KEYS[0], error=""):
        DriverCatalog.objects.update_or_create(
            hwid=key,
            defaults={
                "checked": djangotime.now(),
                "entries": list(entries),
                "error": error,
            },
        )


@override_settings(CACHES=LOCMEM_CACHE)
class TestDriversView(Base):
    def test_fields(self):
        self.store()
        rows = self.client.get(self.url).json()["drivers"]
        self.assertEqual(
            [(r["catalog"], r["catalog_checked"], r["catalog_error"]) for r in rows],
            [(None, None, ""), (None, None, "")],
        )

        self.offer()
        row = self.client.get(self.url).json()["drivers"][0]
        # full key empty, the short one not checked yet
        self.assertEqual((row["catalog"], row["catalog_checked"]), (None, None))
        self.offer(entry(), key=NIC_KEYS[1])
        row = self.client.get(self.url).json()["drivers"][0]
        self.assertEqual(
            row["catalog"],
            {
                "version": "12.19.2.66",
                "date": "2025-11-15",
                "title": "Intel Net Driver Update (12.19.2.66)",
                "update_id": UID,
                "size": 286663,
                "classification": "Drivers (Networking)",
                "query": NIC_KEYS[1],
            },
        )
        self.assertIsNotNone(row["catalog_checked"])
        self.assertEqual(row["catalog_error"], "")

        self.offer(entry("12.19.2.40"), error="catalog page not understood")
        row = self.client.get(self.url).json()["drivers"][0]
        self.assertIsNone(row["catalog"])
        self.assertEqual(
            row["catalog_error"],
            "Microsoft Update Catalog unavailable: catalog page not understood",
        )

    @patch("software.tasks.check_agent_catalog_task.delay")
    def test_check(self, delay):
        url = self.url + "catalog/check/"
        self.assertEqual(self.client.post(url).status_code, 400)
        self.store()
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.data["keys"], r.data["seconds"]), (2, 6))
        delay.assert_called_once_with(self.agent.pk)

        cache.add(tasks.SCAN_LOCK, "x", 60)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("A catalog check is running", r.data)
        linux = baker.make_recipe("agents.online_agent", plat="linux")
        self.assertEqual(
            self.client.post(
                f"/software/{linux.agent_id}/drivers/catalog/check/"
            ).status_code,
            400,
        )
        user = self.create_user_with_roles(["can_install_packages"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.assertEqual(delay.call_count, 1)


@override_settings(CACHES=LOCMEM_CACHE)
@patch("software.tasks.catalog_install_task.delay")
class TestInstallView(Base):
    def post(self, device_id=NIC, update_id=UID, agent=None):
        agent = agent or self.agent
        return self.client.post(
            f"/software/{agent.agent_id}/drivers/catalog/install/",
            {"device_id": device_id, "update_id": update_id},
            format="json",
        )

    def test_install_job(self, delay):
        self.store()
        self.offer(entry())
        r = self.post()
        self.assertEqual(r.status_code, 200, r.data)
        job = r.data["job"]
        delay.assert_called_once_with(job, self.agent.pk, NIC, UID, self.john.pk)
        r = self.client.get(f"{self.url}catalog/jobs/{job}/")
        self.assertEqual(
            r.json(),
            {"state": "resolving", "detail": "", "batch": None, "package": None},
        )
        # one at a time per agent
        r = self.post()
        self.assertEqual(r.status_code, 400)
        self.assertIn("being installed", r.data)

        other = baker.make_recipe("agents.online_agent")
        self.assertEqual(
            self.client.get(
                f"/software/{other.agent_id}/drivers/catalog/jobs/{job}/"
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"{self.url}catalog/jobs/nope/").status_code, 404
        )

    def test_guards(self, delay):
        self.assertEqual(self.post().status_code, 400)
        self.store()
        self.offer(entry())
        for kwargs in (
            {"update_id": UID2},
            {"update_id": "x"},
            {"update_id": None},
            {"device_id": "PCI\\VEN_1\\2"},
            {"device_id": 5},
        ):
            with self.subTest(kwargs):
                self.assertEqual(self.post(**kwargs).status_code, 400)
        offline = baker.make_recipe("agents.offline_agent", operating_system=WIN11)
        self.store(agent=offline)
        self.assertEqual(self.post(agent=offline).status_code, 400)
        delay.assert_not_called()

        user = self.create_user_with_roles(["can_list_software"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.post().status_code, 403)
        scoped = self.create_user_with_roles(["can_install_packages"])
        scoped.role.can_view_sites.set([baker.make("clients.Site")])
        self.client.force_authenticate(user=scoped)
        self.assertEqual(self.post().status_code, 403)
        delay.assert_not_called()


CAB = b"MSCF" + b"\0" * 1000


def dialog(body=CAB, url="https://catalog.s.download.windowsupdate.com/c/x/a_b.cab"):
    return {"url": url, "sha256": hashlib.sha256(body).hexdigest(), "name": "a_b.cab"}


@override_settings(CACHES=LOCMEM_CACHE)
@patch("packages.services.install_batch_task.delay")
@patch("software.catalog.Fetcher.download")
@patch("software.catalog.Fetcher.arch", return_value="AMD64")
@patch("software.catalog.requests.request")
class TestInstallTask(Base):
    def setUp(self):
        super().setUp()
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.dir = os.path.join(root, "packages")
        self.enterContext(override_settings(PACKAGES_DIR=self.dir))
        self.store()
        self.offer(
            entry(size=len(CAB)),
            entry(update_id=UID2, size=len(CAB)),
            entry("12.19.2.64", update_id="0" * 8 + UID[8:]),
        )

    def run_job(self):
        job = "j1"
        cache.add(tasks.agent_job_key(self.agent.agent_id), job, 60)
        tasks.set_job(job, agent=self.agent.agent_id, state="resolving")
        result = tasks.catalog_install_task(job, self.agent.pk, NIC, UID, self.john.pk)
        self.assertIsNone(cache.get(tasks.agent_job_key(self.agent.agent_id)))
        return result, cache.get(tasks.job_key(job))

    def test_install(self, request, arch, download, delay):
        download.return_value = dialog()
        request.return_value = FakeResponse(200, CAB)
        result, job = self.run_job()
        self.assertTrue(result.startswith("queued"), result)
        package = SoftwarePackage.objects.get()
        self.assertEqual(
            (package.name, package.kind, package.plat, package.allow_unsigned),
            (
                "Intel Net Driver Update (12.19.2.66)",
                PackageKind.DRIVER,
                "windows",
                False,
            ),
        )
        self.assertEqual((package.filename, package.size), ("a_b.cab", len(CAB)))
        self.assertEqual(package.created_by, "john")
        self.assertEqual(Path(package.file_path).read_bytes(), CAB)
        self.assertEqual(job["state"], "queued")
        self.assertEqual(job["package"], package.pk)
        install = package.installs.get()
        self.assertEqual((install.run_as, str(install.batch)), ("system", job["batch"]))
        delay.assert_called_once()
        self.assertEqual(sorted(os.listdir(self.dir)), [package.sha256])

        # same file again: same package
        result, job = self.run_job()
        self.assertEqual(SoftwarePackage.objects.count(), 1)
        self.assertEqual(job["package"], package.pk)
        self.assertEqual(sorted(os.listdir(self.dir)), [package.sha256])

    def test_name_taken_and_arch(self, request, arch, download, delay):
        baker.make(
            "packages.SoftwarePackage",
            name="Intel Net Driver Update (12.19.2.66)",
            sha256="1" * 64,
        )
        arch.side_effect = ["ARM64", "X86, AMD64"]
        download.return_value = dialog()
        request.return_value = FakeResponse(200, CAB)
        result, job = self.run_job()
        self.assertEqual(job["state"], "queued", job)
        self.assertEqual([c.args[0] for c in arch.call_args_list], [UID, UID2])
        download.assert_called_once_with(UID2)
        self.assertEqual(
            SoftwarePackage.objects.get(sha256=dialog()["sha256"]).name,
            f"Intel Net Driver Update (12.19.2.66) {UID2[:8]}",
        )

        arch.side_effect = None
        arch.return_value = "ARM64"
        result, job = self.run_job()
        self.assertEqual(job["state"], "failed")
        self.assertEqual(
            job["detail"], "No catalog entry of version 12.19.2.66 is for AMD64."
        )

    def test_download_failures(self, request, arch, download, delay):
        bad_sha = {**dialog(), "sha256": "0" * 64}
        for answer, response, error in (
            (dialog(), FakeResponse(200, CAB + b"x"), "downloaded 1005 bytes"),
            (bad_sha, FakeResponse(200, CAB), "sha256"),
            (
                dialog(b"MZ" + b"\0" * 1002),
                FakeResponse(200, b"MZ" + b"\0" * 1002),
                "not a cab",
            ),
            (dialog(), FakeResponse(404), "HTTP 404"),
            (
                dialog(),
                FakeResponse(302, headers={"Location": "https://example.com/a.cab"}),
                "refused",
            ),
            (
                {**dialog(), "name": "a.exe"},
                FakeResponse(200, CAB),
                "unexpected file name",
            ),
        ):
            with self.subTest(error):
                download.return_value = answer
                request.return_value = response
                result, job = self.run_job()
                self.assertEqual(job["state"], "failed")
                self.assertIn(error, job["detail"])
                self.assertFalse(SoftwarePackage.objects.exists())
                self.assertEqual(os.listdir(self.dir), [])
        download.side_effect = CatalogError("the download dialog lists 0 files")
        result, job = self.run_job()
        self.assertEqual(job["detail"], "the download dialog lists 0 files")
        with patch.object(tasks, "MAX_CAB", 10):
            download.side_effect = None
            download.return_value = dialog()
            request.return_value = FakeResponse(200, CAB)
            result, job = self.run_job()
            self.assertIn("larger than", job["detail"])
        delay.assert_not_called()

    def test_offer_gone(self, request, arch, download, delay):
        DriverCatalog.objects.all().delete()
        result, job = self.run_job()
        self.assertEqual(job["state"], "failed")
        self.assertIn("no longer offers", job["detail"])
        arch.assert_not_called()

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase
from model_bakery import baker

from core.models import NVD_KEY_INFO, CoreSettings
from logs.models import AuditLog, DebugLog
from remote.utils import decrypt_secret, encrypt_secret
from software.models import InstalledSoftware
from ulrmm.constants import AuditObjType
from ulrmm.test import ULRMMTestCase
from vulns import cpe_map, feeds
from vulns.models import Advisory, AgentScan, Finding, MsrcMap, NvdLookup
from vulns.tasks import scan
from winupdate.models import WinUpdate

FIXTURES = Path(__file__).with_name("fixtures")
CHROME = "cpe:2.3:a:google:chrome:129.0.6668.58:*:*:*:*:*:*:*"
FIREFOX = "cpe:2.3:a:mozilla:firefox:131.0.2:*:*:*:*:*:*:*"
EMPTY_NVD = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0}


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


class FakeResponse:
    def __init__(self, data=None, status=200, url="https://example.test/", history=()):
        self.data, self.status_code, self.url = data, status, url
        self.history = list(history)

    def json(self):
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise feeds.requests.HTTPError(f"{self.status_code} error")


class FakeFeeds:
    """Stands in for requests.get: MSRC from fixtures, NVD per CPE name."""

    def __init__(self, nvd=None):
        self.nvd = {CHROME: fixture("nvd_chrome.json"), **(nvd or {})}
        self.calls = []

    def __call__(self, url, params=None, headers=None, timeout=None, **kwargs):
        self.calls.append((url, params, headers, timeout))
        if url == f"{feeds.MSRC_API}/updates":
            return FakeResponse(fixture("msrc_updates.json"), url=url)
        if url == f"{feeds.MSRC_API}/cvrf/2024-Oct":
            return FakeResponse(fixture("msrc_cvrf_2024-Oct.json"), url=url)
        if url.startswith(f"{feeds.MSRC_API}/cvrf/"):
            return FakeResponse({"Vulnerability": []}, url=url)
        if url == feeds.NVD_API:
            answer = self.nvd.get(params["cpeName"], EMPTY_NVD)
            if isinstance(answer, int):
                return FakeResponse(None, status=answer, url=url)
            return FakeResponse(answer, url=url)
        raise AssertionError(url)

    def urls(self, prefix: str) -> list:
        return [c for c in self.calls if c[0].startswith(prefix)]


def fake_notify():
    """notify.dispatch as the notify app would provide it."""
    dispatch = MagicMock()
    module = types.ModuleType("notify.dispatch")
    module.dispatch = dispatch
    package = types.ModuleType("notify")
    package.dispatch = module
    return dispatch, patch.dict(
        sys.modules, {"notify": package, "notify.dispatch": module}
    )


class TestParsing(SimpleTestCase):
    def test_cvrf_maps_kbs_to_cves(self):
        kbs = feeds.parse_cvrf(fixture("msrc_cvrf_2024-Oct.json"))
        self.assertEqual(sorted(kbs), ["5044281", "5044285"])
        self.assertEqual(sorted(kbs["5044285"]), ["CVE-2024-43572", "CVE-2024-43582"])
        self.assertEqual(
            kbs["5044285"]["CVE-2024-43582"],
            {
                "id": "CVE-2024-43582",
                "title": "Remote Desktop Protocol Server Remote Code Execution "
                "Vulnerability",
                "severity": "Critical",
                "score": 8.1,
            },
        )
        self.assertEqual(kbs["5044281"]["CVE-2024-38124"]["severity"], "Important")
        self.assertEqual(feeds.parse_cvrf({"Vulnerability": "junk"}), {})
        self.assertEqual(feeds.parse_cvrf(None), {})

    def test_nvd_answer(self):
        cves = feeds.parse_nvd(fixture("nvd_chrome.json"), CHROME)
        # rejected entries are dropped
        self.assertEqual([c["id"] for c in cves], ["CVE-2024-9602", "CVE-2024-9603"])
        self.assertEqual(
            cves[0],
            {
                "id": "CVE-2024-9602",
                "summary": "Type Confusion in V8 in Google Chrome prior to "
                "129.0.6668.100 allowed a remote attacker to perform an out of "
                "bounds memory read via a crafted HTML page. (Chromium security "
                "severity: High)",
                "score": 8.8,
                "severity": "HIGH",
                "fixed": ["129.0.6668.100"],
            },
        )
        # highest 3.x score, first line, only this product's criteria
        self.assertEqual(
            (cves[1]["score"], cves[1]["severity"], cves[1]["fixed"]),
            (9.6, "CRITICAL", ["129.0.6668.100", "129.0.6668.89"]),
        )
        self.assertNotIn("\n", cves[1]["summary"])
        self.assertEqual(feeds.parse_nvd({"vulnerabilities": [1, None]}, CHROME), [])

    def test_names_map_to_cpes(self):
        cases = {
            "Google Chrome": "google chrome",
            "Mozilla Firefox (x64 en-US)": "mozilla firefox",
            "7-Zip 23.01 (x64)": "7-zip",
            "Notepad++ (64-bit x64)": "notepad++",
            "Java 8 Update 381 (64-bit)": "java update",
            "Java(TM) SE Development Kit 17.0.8 (64-bit)": "java se development kit",
            "PuTTY release 0.79 (64-bit)": "putty release",
            "Wireshark 4.2.0 x64": "wireshark",
            "Oracle VM VirtualBox 7.0.12": "oracle vm virtualbox",
            "Microsoft Visual Studio Code (User)": "microsoft visual studio code",
        }
        for name, normalised in cases.items():
            with self.subTest(name):
                self.assertEqual(cpe_map.normalise(name), normalised)
                self.assertIn(normalised, cpe_map.CPE_MAP)

        apps, unmapped = cpe_map.match(
            [
                {"name": "Google Chrome", "version": "129.0.6668.58"},
                {"name": "Notepad++ (64-bit x64)", "version": "8.6.2"},
                {"name": "Zoom Workplace (64-bit)", "version": "6.2.0 (46690)"},
                {"name": "Microsoft Edge WebView2 Runtime", "version": "129.0"},
                {"name": "Python 3.12.0 Core Interpreter (64-bit)", "version": "3"},
                {"name": "Git", "version": "unknown"},
                {"name": None},
                "junk",
            ]
        )
        self.assertEqual(
            apps,
            {
                ("Google Chrome", "129.0.6668.58", CHROME),
                (
                    "Notepad++",
                    "8.6.2",
                    "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6.2:*:*:*:*:*:*:*",
                ),
                ("Zoom", "6.2.0", "cpe:2.3:a:zoom:zoom:6.2.0:*:*:*:*:*:*:*"),
            },
        )
        self.assertEqual(unmapped, 3)
        self.assertEqual(cpe_map.match(None), (set(), 0))
        self.assertGreaterEqual(len(set(cpe_map.CPE_MAP.values())), 40)


class TestRequests(SimpleTestCase):
    @patch("vulns.feeds.requests.get")
    def test_https_only_on_every_hop(self, get):
        get.return_value = FakeResponse(
            {}, url="https://b.test/", history=[FakeResponse(url="http://a.test/")]
        )
        with self.assertRaisesMessage(ValueError, "redirected to http://a.test/"):
            feeds.https_get("https://x.test/")
        self.assertEqual(get.call_args.kwargs["timeout"], 20)

    @patch("vulns.feeds.requests.get")
    def test_nvd_key_never_follows_a_redirect(self, get):
        get.return_value = FakeResponse(status=302, url=feeds.NVD_API)
        with self.assertRaisesMessage(ValueError, "HTTP 302"):
            feeds.Nvd("key-123").cves(CHROME)
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)

    @patch("vulns.feeds.time.sleep")
    @patch("vulns.feeds.time.monotonic")
    def test_nvd_rate_limit_and_key(self, monotonic, sleep):
        fake = FakeFeeds({FIREFOX: 404})
        monotonic.return_value = 100.0
        with patch("vulns.feeds.requests.get", fake):
            client = feeds.Nvd()
            for _ in range(5):
                self.assertEqual(len(client.cves(CHROME)), 2)
            sleep.assert_not_called()
            # the sixth request in the window waits for the first to age out
            self.assertEqual(client.cves(FIREFOX), [])
            sleep.assert_called_once_with(feeds.NVD_WINDOW)

            self.assertNotIn("apiKey", fake.calls[0][2])
            feeds.Nvd("key-123").cves(CHROME)
        self.assertEqual(fake.calls[-1][2]["apiKey"], "key-123")
        self.assertEqual(
            fake.calls[-1][1],
            {"cpeName": CHROME, "resultsPerPage": 2000, "startIndex": 0},
        )

    @patch("vulns.feeds.requests.get")
    def test_nvd_pages(self, get):
        page = {**fixture("nvd_chrome.json"), "resultsPerPage": 2, "totalResults": 3}
        get.side_effect = [
            FakeResponse(page, url=feeds.NVD_API),
            FakeResponse(
                {**page, "startIndex": 2, "resultsPerPage": 1}, url=feeds.NVD_API
            ),
        ]
        with patch("vulns.feeds.time.sleep"):
            feeds.Nvd("k").cves(CHROME)
        self.assertEqual(
            [c.kwargs["params"]["startIndex"] for c in get.call_args_list], [0, 2]
        )


class TestScanWindowsMac(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.win = baker.make_recipe(
            "agents.agent",
            plat="windows",
            operating_system="Windows 11 Pro, 64 bit v23H2 (build 22631.4249)",
        )
        self.mac = baker.make_recipe(
            "agents.agent", plat="darwin", operating_system="macOS 15.0 arm64"
        )
        InstalledSoftware.objects.create(
            agent=self.win,
            software=[
                {"name": "Google Chrome", "version": "129.0.6668.58"},
                {"name": "Contoso Widget 1.2", "version": "1.2"},
                {"name": "Microsoft Edge WebView2 Runtime", "version": "129.0"},
            ],
        )
        InstalledSoftware.objects.create(
            agent=self.mac,
            software=[
                {"name": "Firefox", "version": "131.0.2", "source": "app"},
                {"name": "Safari", "version": "18.0", "source": "app"},
            ],
        )
        self.kb = baker.make(
            "winupdate.WinUpdate", agent=self.win, kb="KB5044285", installed=False
        )
        baker.make(
            "winupdate.WinUpdate", agent=self.win, kb="KB890830", installed=False
        )
        baker.make(
            "winupdate.WinUpdate",
            agent=self.win,
            kb="KB5044281",
            installed=True,
        )

    def run_scan(self, fake=None):
        fake = fake or FakeFeeds()
        dispatch, modules = fake_notify()
        with patch("vulns.feeds.requests.get", fake), patch(
            "vulns.feeds.time.sleep"
        ), modules:
            scan()
        return fake, dispatch

    def findings(self, agent, source) -> dict:
        return {
            (f.package, f.version, f.vuln_id): f.status
            for f in Finding.objects.filter(agent=agent, source=source)
        }

    def test_msrc_and_nvd_findings(self):
        fake, dispatch = self.run_scan()

        package = "Windows (KB5044285)"
        self.assertEqual(
            self.findings(self.win, "msrc"),
            {
                (package, "", "CVE-2024-43582"): "open",
                (package, "", "CVE-2024-43572"): "open",
            },
        )
        self.assertEqual(
            self.findings(self.win, "nvd"),
            {
                ("Google Chrome", "129.0.6668.58", "CVE-2024-9602"): "open",
                ("Google Chrome", "129.0.6668.58", "CVE-2024-9603"): "open",
            },
        )
        self.assertEqual(self.findings(self.mac, "nvd"), {})
        self.assertFalse(Finding.objects.filter(agent=self.mac, source="msrc").exists())

        rdp = Advisory.objects.get(vuln_id="CVE-2024-43582")
        self.assertEqual(
            (rdp.level, rdp.score, rdp.severity, rdp.fixed),
            # the score decides the level, as for OSV
            ("high", 8.1, "Critical", {f"Windows|{package}": ["KB5044285"]}),
        )
        v8 = Advisory.objects.get(vuln_id="CVE-2024-9603")
        self.assertEqual(
            v8.fixed, {"Windows|Google Chrome": ["129.0.6668.100", "129.0.6668.89"]}
        )

        win = AgentScan.objects.get(agent=self.win)
        self.assertEqual(
            (win.ecosystem, win.packages, win.unchecked, win.unmapped),
            ("Windows", 3, 0, 2),
        )
        mac = AgentScan.objects.get(agent=self.mac)
        self.assertEqual((mac.ecosystem, mac.packages, mac.unmapped), ("macOS", 1, 1))

        # the three newest months, the bogus id is never requested
        self.assertEqual(
            sorted(c[0].rsplit("/", 1)[1] for c in fake.urls(f"{feeds.MSRC_API}/cvrf")),
            ["2024-Aug", "2024-Oct", "2024-Sep"],
        )
        self.assertEqual(
            fake.urls(f"{feeds.MSRC_API}/cvrf/2024-Oct")[0][2]["Accept"],
            "application/json",
        )
        self.assertEqual(
            sorted(c[1]["cpeName"] for c in fake.urls(feeds.NVD_API)), [CHROME, FIREFOX]
        )

        # one notification for the agent with new critical/high findings
        dispatch.assert_called_once()
        event = dispatch.call_args.args[0]
        self.assertEqual(
            (event["source"], event["severity"], event["agent"]),
            ("vuln", "error", self.win),
        )
        self.assertIn("4 new critical or high", event["title"])

    def test_second_run_uses_caches_and_installed_kb_fixes(self):
        self.run_scan()
        self.kb.installed = True
        self.kb.save()

        fake, dispatch = self.run_scan()
        # revised dates did not move, NVD answers are cached
        self.assertEqual(fake.urls(f"{feeds.MSRC_API}/cvrf"), [])
        self.assertEqual(fake.urls(feeds.NVD_API), [])
        self.assertEqual(set(self.findings(self.win, "msrc").values()), {"fixed"})
        self.assertEqual(set(self.findings(self.win, "nvd").values()), {"open"})
        dispatch.assert_not_called()

    def test_failed_lookup_keeps_findings(self):
        self.run_scan()
        NvdLookup.objects.update(fetched_at="2000-01-01T00:00:00Z")
        DebugLog.objects.all().delete()

        self.run_scan(FakeFeeds({CHROME: 503}))
        self.assertEqual(set(self.findings(self.win, "nvd").values()), {"open"})
        self.assertEqual(AgentScan.objects.get(agent=self.win).unchecked, 1)
        self.assertTrue(
            DebugLog.objects.filter(message__contains="NVD lookup failed").exists()
        )

    def test_nvd_key_is_decrypted_and_sent(self):
        CoreSettings.objects.update(nvd_api_key=encrypt_secret("nvd-key", NVD_KEY_INFO))
        fake, _ = self.run_scan()
        self.assertEqual(
            {c[2].get("apiKey") for c in fake.urls(feeds.NVD_API)}, {"nvd-key"}
        )

    def test_without_notify_app_the_scan_still_works(self):
        with patch.dict(sys.modules, {"notify.dispatch": None}), patch(
            "vulns.feeds.requests.get", FakeFeeds()
        ), patch("vulns.feeds.time.sleep"):
            scan()
        self.assertEqual(Finding.objects.filter(agent=self.win).count(), 4)

    def test_osv_advisory_keeps_its_data(self):
        Advisory.objects.create(
            vuln_id="CVE-2024-9602",
            summary="from osv",
            level="medium",
            score=5.0,
            fixed={"Alpine:v3.20|chromium": ["129.0.6668.100-r0"]},
            fetched_at="2024-10-10T00:00:00Z",
        )
        self.run_scan()
        a = Advisory.objects.get(vuln_id="CVE-2024-9602")
        self.assertEqual((a.summary, a.score, a.level), ("from osv", 5.0, "medium"))
        self.assertEqual(
            a.fixed,
            {
                "Alpine:v3.20|chromium": ["129.0.6668.100-r0"],
                "Windows|Google Chrome": ["129.0.6668.100"],
            },
        )
        self.assertEqual(
            sorted(
                MsrcMap.objects.filter(month="2024-Oct").values_list("kb", flat=True)
            ),
            ["", "5044281", "5044285"],
        )


class TestAPI(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.win = baker.make_recipe("agents.agent", plat="windows")
        InstalledSoftware.objects.create(
            agent=self.win,
            software=[
                {"name": "Google Chrome", "version": "129.0.6668.58"},
                {"name": "Contoso Widget", "version": "1.2"},
            ],
        )
        WinUpdate.objects.create(agent=self.win, kb="KB5044285", installed=False)
        with patch("vulns.feeds.requests.get", FakeFeeds()), patch(
            "vulns.feeds.time.sleep"
        ):
            scan()

    def test_findings_show_source_platform_and_links(self):
        r = self.client.get(f"/vulns/?agent={self.win.agent_id}&source=msrc")
        self.assertEqual(r.status_code, 200)
        rows = {f["vuln_id"]: f for f in r.json()["findings"]}
        self.assertEqual(sorted(rows), ["CVE-2024-43572", "CVE-2024-43582"])
        rdp = rows["CVE-2024-43582"]
        self.assertEqual(
            (rdp["source"], rdp["plat"], rdp["package"], rdp["fixed_in"]),
            ("msrc", "windows", "Windows (KB5044285)", ["KB5044285"]),
        )
        self.assertEqual(
            rdp["url"],
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43582",
        )

        nvd = self.client.get("/vulns/?source=nvd").json()["findings"]
        self.assertEqual(
            {(f["vuln_id"], f["url"]) for f in nvd},
            {
                (c, f"https://nvd.nist.gov/vuln/detail/{c}")
                for c in ("CVE-2024-9602", "CVE-2024-9603")
            },
        )
        self.assertEqual(nvd[0]["fixed_in"], ["129.0.6668.100", "129.0.6668.89"])
        self.assertEqual(self.client.get("/vulns/?source=bad").status_code, 400)

    def test_agent_view_counts_unmapped_apps(self):
        data = self.client.get(f"/vulns/{self.win.agent_id}/").json()
        self.assertEqual(
            (
                data["supported"],
                data["ecosystem"],
                data["plat"],
                data["unmapped"],
                data["count"],
            ),
            (True, "Windows", "windows", 1, 4),
        )
        summary = self.client.get("/vulns/summary/").json()
        self.assertIn("MSRC", summary["coverage"])
        self.assertNotIn("Linux only", summary["coverage"])


class TestNvdKeySetting(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_key_is_write_only_and_encrypted(self):
        r = self.client.get("/core/settings/")
        self.assertFalse(r.data["nvd_api_key_set"])
        self.assertNotIn("nvd_api_key", r.data)

        r = self.client.put(
            "/core/settings/", {"nvd_api_key": " nvd-secret "}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        stored = CoreSettings.objects.get().nvd_api_key
        self.assertNotIn("nvd-secret", stored)
        self.assertEqual(decrypt_secret(stored, NVD_KEY_INFO), "nvd-secret")

        r = self.client.get("/core/settings/")
        self.assertTrue(r.data["nvd_api_key_set"])
        self.assertNotIn("nvd-secret", json.dumps(r.data))

        # an empty value keeps the key, the clear flag removes it
        self.client.put("/core/settings/", {"nvd_api_key": ""}, format="json")
        self.assertEqual(CoreSettings.objects.get().nvd_api_key, stored)

        audit = (
            AuditLog.objects.filter(object_type=AuditObjType.CORE).order_by("pk").last()
        )
        self.assertNotIn(stored, json.dumps(audit.after_value))
        self.assertNotIn("nvd-secret", json.dumps(audit.after_value))

        self.client.put("/core/settings/", {"nvd_api_key_clear": True}, format="json")
        self.assertEqual(CoreSettings.objects.get().nvd_api_key, "")

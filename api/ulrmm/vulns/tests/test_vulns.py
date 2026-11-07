# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests
from django.conf import settings
from django.test import SimpleTestCase
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import AuditLog, DebugLog
from software.models import InstalledSoftware
from ulrmm.constants import DebugLogType
from ulrmm.test import ULRMMTestCase
from vulns import osv
from vulns.models import Advisory, AgentScan, Finding, Lookup
from vulns.tasks import scan

FIXTURES = Path(__file__).with_name("fixtures")
DEBIAN = "Debian 12.5 x86_64 6.1.0-18-amd64"
OPENSSH = ("openssh", "1:9.2p1-2+deb12u2")
SUDO = ("sudo", "1.9.13p3-1+deb12u1")
NONE = ("ulrmm-none", "1.0")


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


def inventory(*packages, source="dpkg") -> list[dict]:
    return [
        {"name": n, "version": v, "publisher": "", "source": source}
        for n, v in packages
    ]


class FakeOSV:
    """Stands in for osv_request. Answers querybatch from the recorded Debian 12
    response (plus extra answers per key), advisories from fixtures."""

    def __init__(self, extra=None):
        recorded = fixture("querybatch_debian12.json")["results"]
        queries = fixture("querybatch_debian12_request.json")["queries"]
        self.answers = {
            (q["package"]["name"], q["version"]): r for q, r in zip(queries, recorded)
        }
        self.answers.update(extra or {})
        self.bodies = []
        self.gets = []

    def __call__(self, method, path, body=None):
        if method == "POST":
            self.bodies.append(body)
            return {
                "results": [
                    self.answers.get((q["package"]["name"], q["version"]), {})
                    for q in body["queries"]
                ]
            }
        vuln_id = path.removeprefix("vulns/")
        self.gets.append(vuln_id)
        name = FIXTURES / f"{vuln_id.replace(':', '_')}.json"
        if name.exists():
            return json.loads(name.read_text())
        return {
            "id": vuln_id,
            "summary": f"{vuln_id} summary",
            "modified": "2030-01-01T00:00:00Z",
        }

    def queried(self) -> list[tuple[str, str]]:
        return [
            (q["package"]["name"], q["version"])
            for body in self.bodies
            for q in body["queries"]
        ]


class TestEcosystem(SimpleTestCase):
    def test_mapping(self):
        cases = {
            DEBIAN: "Debian:12",
            "Debian 13.1 aarch64 6.12.48+deb13-arm64": "Debian:13",
            "Ubuntu 24.04 x86_64 6.8.0-45-generic": "Ubuntu:24.04:LTS",
            "Ubuntu 22.04 x86_64 5.15.0-91-generic": "Ubuntu:22.04:LTS",
            "Ubuntu 24.10 x86_64 6.11.0-8-generic": "Ubuntu:24.10",
            "Ubuntu 23.04 x86_64 6.2.0-20-generic": "Ubuntu:23.04",
            "Alpine 3.20.3 x86_64 6.6.49-0-virt": "Alpine:v3.20",
            "Rocky 9.4 x86_64 5.14.0-427.el9.x86_64": "Rocky Linux:9",
            "Almalinux 8.10 x86_64 4.18.0-553.el8_10.x86_64": "AlmaLinux:8",
            "Opensuse-Leap 15.6 x86_64 6.4.0-150600.23-default": "openSUSE:Leap 15.6",
            "Opensuse-Tumbleweed 20241001 x86_64 6.11.0-1-default": "openSUSE:Tumbleweed",
        }
        for os_string, eco in cases.items():
            with self.subTest(os_string):
                self.assertEqual(osv.ecosystem("linux", os_string), (eco, ""))

    def test_not_covered(self):
        for os_string in (
            "Arch x86_64 6.10.10-arch1-1",
            "Fedora 41 x86_64 6.11.4-301.fc41.x86_64",
            "Centos 9 x86_64 5.14.0-503.el9.x86_64",
            "Redhat 9.4 x86_64 5.14.0-427.el9.x86_64",
            "Sles 15.6 x86_64 6.4.0-150600.23-default",
            "Linuxmint 21.3 x86_64 5.15.0-91-generic",
            "Debian trixie/sid x86_64 6.10.6-amd64",
            "",
            None,
        ):
            with self.subTest(os_string):
                eco, reason = osv.ecosystem("linux", os_string)
                self.assertIsNone(eco)
                self.assertIn("not covered by OSV", reason)

        for plat in ("windows", "darwin"):
            self.assertEqual(
                osv.ecosystem(plat, "Windows 11 Pro, 64 bit"), (None, osv.NO_ECOSYSTEM)
            )

    def test_packages_match_the_package_manager(self):
        software = inventory(("libc6:amd64", "2.36-9+deb12u7"), SUDO) + [
            {"name": "org.gimp.GIMP", "version": "2.10", "source": "flatpak"},
            {"name": "", "version": "1", "source": "dpkg"},
            {"name": "x", "version": None, "source": "dpkg"},
            "junk",
        ]
        self.assertEqual(
            osv.packages(software, "Debian:12"),
            {("libc6", "2.36-9+deb12u7"), SUDO},
        )
        self.assertEqual(osv.packages(software, "Rocky Linux:9"), set())
        self.assertEqual(osv.packages(None, "Debian:12"), set())

    def test_packages_prefer_the_source_package(self):
        def row(source, name, version, src=None, src_ver=None):
            item = {"name": name, "version": version, "source": source}
            if src is not None:
                item.update(source_name=src, source_version=src_ver)
            return item

        ssh = "1:10.0p1-7+deb13u4"
        software = [
            row("dpkg", "openssh-server", ssh, "openssh", ssh),
            row("dpkg", "openssh-client", ssh, "openssh", ssh),
            row(
                "dpkg",
                "bsdutils",
                "1:2.41.5-0+deb13u1",
                "util-linux",
                "2.41.5-0+deb13u1",
            ),
            # inventories from older agents only have the binary name
            row("dpkg", "curl", "8.14.1-2"),
            row("dpkg", "broken", "1", 5, "1"),
            row("dpkg", "half", "2", "half-src", ""),
        ]
        self.assertEqual(
            osv.packages(software, "Debian:13"),
            {
                ("openssh", ssh),
                ("util-linux", "2.41.5-0+deb13u1"),
                ("curl", "8.14.1-2"),
                ("broken", "1"),
                ("half", "2"),
            },
        )

        apk = [row("apk", "openssh-server", "10.0_p1-r10", "openssh", "10.0_p1-r10")]
        self.assertEqual(
            osv.packages(apk, "Alpine:v3.22"), {("openssh", "10.0_p1-r10")}
        )

        # AlmaLinux advisories list the binary packages, Rocky and SUSE the source
        rpm = [
            row("rpm", "python3", "3.9.25-7.el9_8.3", "python3.9", "3.9.25-7.el9_8.3")
        ]
        self.assertEqual(
            osv.packages(rpm, "AlmaLinux:9"), {("python3", "3.9.25-7.el9_8.3")}
        )
        self.assertEqual(
            osv.packages(rpm, "Rocky Linux:9"), {("python3.9", "3.9.25-7.el9_8.3")}
        )
        ver = "3.1.4-150600.5.50.1"
        suse = [row("rpm", "libopenssl3", ver, "openssl-3", ver)]
        self.assertEqual(osv.packages(suse, "openSUSE:Leap 15.6"), {("openssl-3", ver)})


class TestOSVParsing(SimpleTestCase):
    def test_cvss3_base_score(self):
        cases = {
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L": 6.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N": 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H": None,
            "CVSS:3.1/AV:N/AC:L": None,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": None,
            "AV:N/AC:L/Au:N/C:P/I:P/A:P": None,
            None: None,
        }
        for vector, score in cases.items():
            with self.subTest(vector):
                self.assertEqual(osv.cvss3_base_score(vector), score)

    @patch("vulns.osv.osv_request")
    def test_querybatch_body_and_recorded_answer(self, request):
        request.return_value = fixture("querybatch_debian12.json")
        keys = [("Debian:12", *OPENSSH), ("Debian:12", *SUDO), ("Debian:12", *NONE)]

        found = osv.query_batch(keys)

        request.assert_called_once_with(
            "POST", "querybatch", fixture("querybatch_debian12_request.json")
        )
        self.assertEqual(len(found[keys[0]]), 32)
        self.assertIn(
            {"id": "DEBIAN-CVE-2024-6387", "modified": "2026-09-15T09:03:11.707005Z"},
            found[keys[0]],
        )
        self.assertEqual(
            [v["id"] for v in found[keys[1]]][-2:],
            ["DEBIAN-CVE-2026-96512", "DSA-5954-1"],
        )
        self.assertEqual(found[keys[2]], [])

    @patch("vulns.osv.osv_request")
    def test_querybatch_pages(self, request):
        keys = [("Debian:12", *OPENSSH), ("Debian:12", *SUDO)]
        request.side_effect = [
            {
                "results": [
                    {"vulns": [{"id": "A", "modified": "m"}], "next_page_token": "t1"},
                    {"vulns": [{"id": "B", "modified": "m"}]},
                ]
            },
            {"results": [{"vulns": [{"id": "C", "modified": "m"}]}]},
        ]

        found = osv.query_batch(keys)

        second = request.call_args_list[1].args[2]["queries"]
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0]["page_token"], "t1")
        self.assertEqual([v["id"] for v in found[keys[0]]], ["A", "C"])
        self.assertEqual([v["id"] for v in found[keys[1]]], ["B"])

    @patch("vulns.osv.osv_request")
    def test_querybatch_rejects_a_short_answer(self, request):
        request.return_value = {"results": []}
        with self.assertRaises(ValueError):
            osv.query_batch([("Debian:12", *SUDO)])

    def test_parse_recorded_advisories(self):
        debian = osv.parse_vuln(fixture("DEBIAN-CVE-2024-6387.json"))
        self.assertEqual(debian["score"], 8.1)
        self.assertEqual(debian["severity"], "not yet assigned")
        self.assertEqual(debian["level"], "high")
        self.assertTrue(debian["summary"].startswith("A security regression"))
        self.assertEqual(debian["fixed"]["Debian:12|openssh"], ["1:9.2p1-2+deb12u3"])
        self.assertEqual(debian["modified"].year, 2026)

        dsa = osv.parse_vuln(fixture("DSA-5724-1.json"))
        self.assertEqual(dsa["summary"], "openssh - security update")
        self.assertEqual(
            (dsa["score"], dsa["severity"], dsa["level"]), (None, "", "unknown")
        )

        alma = osv.parse_vuln(fixture("ALSA-2023_2523.json"))
        self.assertEqual(
            (alma["score"], alma["severity"], alma["level"]), (None, "Low", "low")
        )
        self.assertEqual(alma["fixed"]["AlmaLinux:9|openssl-libs"], ["1:3.0.7-6.el9_2"])

    def test_parse_severity_sources(self):
        ubuntu = osv.parse_vuln(
            {"id": "UBUNTU-CVE-1", "severity": [{"type": "Ubuntu", "score": "medium"}]}
        )
        self.assertEqual((ubuntu["severity"], ubuntu["level"]), ("medium", "medium"))

        both = osv.parse_vuln(
            {
                "id": "X",
                "database_specific": {"severity": "MODERATE"},
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
            }
        )
        self.assertEqual(
            (both["severity"], both["score"], both["level"]),
            ("MODERATE", 9.8, "critical"),
        )

        suse = osv.parse_vuln(
            {
                "id": "SUSE-SU-1",
                "affected": [
                    {
                        "package": {"ecosystem": eco, "name": "openssl-3"},
                        "ranges": [
                            {"type": "ECOSYSTEM", "events": [{"fixed": "3.1.4-1"}]}
                        ],
                    }
                    for eco in (
                        "SUSE:Linux Enterprise Server 15 SP6",
                        "openSUSE:Leap 15.6",
                    )
                ],
            }
        )
        self.assertEqual(suse["fixed"], {"openSUSE:Leap 15.6|openssl-3": ["3.1.4-1"]})


class TestOSVRequest(SimpleTestCase):
    @staticmethod
    def response(status: int):
        r = requests.Response()
        r.status_code = status
        r._content = b'{"ok": true}'
        return r

    @patch("vulns.osv.time.sleep")
    @patch("vulns.osv.requests.request")
    def test_retries_server_errors_only(self, request, sleep):
        request.side_effect = [
            self.response(503),
            self.response(502),
            self.response(200),
        ]
        self.assertEqual(
            osv.osv_request("POST", "querybatch", {"queries": []}), {"ok": True}
        )
        self.assertEqual(request.call_count, 3)
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 10)
        self.assertEqual(
            kwargs["headers"]["User-Agent"], f"ulrmm/{settings.ULRMM_VERSION}"
        )
        self.assertEqual(
            request.call_args.args, ("POST", "https://api.osv.dev/v1/querybatch")
        )

        request.reset_mock()
        request.side_effect = [self.response(400)]
        with self.assertRaises(requests.HTTPError):
            osv.osv_request("POST", "querybatch", {})
        self.assertEqual(request.call_count, 1)

        request.reset_mock()
        request.side_effect = [self.response(500)] * 3
        with self.assertRaises(requests.HTTPError):
            osv.osv_request("GET", "vulns/X")
        self.assertEqual(request.call_count, 3)

        request.reset_mock()
        request.side_effect = requests.ConnectionError("down")
        with self.assertRaises(requests.ConnectionError):
            osv.osv_request("GET", "vulns/X")
        self.assertEqual(request.call_count, 1)


class TestScan(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent", plat="linux", operating_system=DEBIAN
        )
        self.software = InstalledSoftware.objects.create(
            agent=self.agent,
            software=inventory(OPENSSH, SUDO, NONE)
            + [{"name": "org.gimp.GIMP", "version": "2.10", "source": "flatpak"}],
        )

    def statuses(self) -> dict[str, int]:
        ret: dict[str, int] = {}
        for status in Finding.objects.values_list("status", flat=True):
            ret[status] = ret.get(status, 0) + 1
        return ret

    def test_findings_created_updated_fixed(self):
        fake = FakeOSV(
            {
                ("openssh", "1:9.2p1-2+deb12u3"): {
                    "vulns": [
                        {
                            "id": "DEBIAN-CVE-2007-2243",
                            "modified": "2026-01-01T00:00:00Z",
                        }
                    ]
                }
            }
        )
        with patch("vulns.osv.osv_request", fake):
            scan()

        self.assertEqual(fake.bodies, [fixture("querybatch_debian12_request.json")])
        self.assertEqual(self.statuses(), {"open": 39})
        finding = Finding.objects.get(vuln_id="DEBIAN-CVE-2024-6387")
        self.assertEqual(
            (finding.package, finding.version, finding.ecosystem),
            (*OPENSSH, "Debian:12"),
        )
        self.assertEqual(finding.advisory.level, "high")
        self.assertEqual(finding.advisory.score, 8.1)
        self.assertEqual(Advisory.objects.count(), 39)
        scan_row = AgentScan.objects.get(agent=self.agent)
        self.assertEqual(
            (scan_row.ecosystem, scan_row.packages, scan_row.unchecked),
            ("Debian:12", 3, 0),
        )

        ignored = Finding.objects.get(vuln_id="DSA-5954-1")
        ignored.status = "ignored"
        ignored.save()
        first_seen = ignored.first_seen

        # openssh upgraded
        self.software.software = inventory(("openssh", "1:9.2p1-2+deb12u3"), SUDO, NONE)
        self.software.save()
        fake.bodies.clear()
        fake.gets.clear()
        with patch("vulns.osv.osv_request", fake):
            scan()

        # sudo and ulrmm-none came from the lookup cache, known advisories were not refetched
        self.assertEqual(fake.queried(), [("openssh", "1:9.2p1-2+deb12u3")])
        self.assertEqual(fake.gets, [])
        self.assertEqual(self.statuses(), {"open": 7, "ignored": 1, "fixed": 32})
        self.assertFalse(
            Finding.objects.filter(package="openssh", version=OPENSSH[1])
            .exclude(status="fixed")
            .exists()
        )
        new = Finding.objects.get(package="openssh", version="1:9.2p1-2+deb12u3")
        self.assertEqual((new.vuln_id, new.status), ("DEBIAN-CVE-2007-2243", "open"))
        ignored.refresh_from_db()
        self.assertEqual(ignored.status, "ignored")
        self.assertEqual(ignored.first_seen, first_seen)
        self.assertGreater(ignored.last_seen, first_seen)

        # downgraded again: the fixed findings reopen
        self.software.software = inventory(OPENSSH, SUDO, NONE)
        self.software.save()
        with patch("vulns.osv.osv_request", fake):
            scan()
        self.assertEqual(
            Finding.objects.filter(
                package="openssh", version=OPENSSH[1], status="open"
            ).count(),
            32,
        )

    def test_changed_advisory_is_refetched(self):
        with patch("vulns.osv.osv_request", FakeOSV()):
            scan()
        Advisory.objects.filter(vuln_id="DSA-5724-1").update(
            modified=djangotime.now() - dt.timedelta(days=3650)
        )
        Lookup.objects.update(fetched_at=djangotime.now() - dt.timedelta(days=8))
        fake = FakeOSV()
        with patch("vulns.osv.osv_request", fake):
            scan()
        self.assertEqual(fake.gets, ["DSA-5724-1"])

    def test_lookup_cache_ttl(self):
        now = djangotime.now()
        Lookup.objects.create(
            ecosystem="Debian:12",
            name=SUDO[0],
            version=SUDO[1],
            result=[],
            fetched_at=now - dt.timedelta(days=6),
        )
        Lookup.objects.create(
            ecosystem="Debian:12",
            name=NONE[0],
            version=NONE[1],
            result=[],
            fetched_at=now - dt.timedelta(days=8),
        )
        # nothing installed uses it any more
        Lookup.objects.create(
            ecosystem="Debian:12",
            name="gone",
            version="1",
            fetched_at=now - dt.timedelta(days=8),
        )
        fake = FakeOSV()
        with patch("vulns.osv.osv_request", fake):
            scan()

        self.assertEqual(sorted(fake.queried()), sorted([OPENSSH, NONE]))
        self.assertFalse(Lookup.objects.filter(name="gone").exists())
        # the fresh cached answer wins over what OSV would say today
        self.assertFalse(Finding.objects.filter(package="sudo").exists())
        self.assertGreater(
            Lookup.objects.get(name=NONE[0]).fetched_at, now - dt.timedelta(minutes=1)
        )

    def test_network_error_does_not_abort_the_run(self):
        baker.make(
            "vulns.Finding",
            agent=self.agent,
            package=SUDO[0],
            version=SUDO[1],
            ecosystem="Debian:12",
            vuln_id="OLD-1",
            first_seen=djangotime.now(),
            last_seen=djangotime.now(),
        )
        fake = FakeOSV()

        def flaky(method, path, body=None):
            if method == "POST" and body["queries"][0]["package"]["name"] == "sudo":
                raise requests.ConnectionError("osv unreachable")
            if method == "GET" and path.endswith("DSA-5724-1"):
                raise requests.Timeout("slow")
            return fake(method, path, body)

        with patch("vulns.osv.BATCH_SIZE", 1), patch("vulns.osv.osv_request", flaky):
            scan()

        # openssh was checked, sudo was not and keeps its finding
        self.assertEqual(Finding.objects.filter(package="openssh").count(), 32)
        self.assertEqual(Finding.objects.get(vuln_id="OLD-1").status, "open")
        self.assertIsNone(Finding.objects.get(vuln_id="DSA-5724-1").advisory)
        self.assertEqual(AgentScan.objects.get(agent=self.agent).unchecked, 1)
        logs = DebugLog.objects.filter(log_type=DebugLogType.SYSTEM_ISSUES)
        self.assertTrue(logs.filter(message__contains="osv unreachable").exists())
        self.assertTrue(logs.filter(message__contains="DSA-5724-1").exists())

    def test_malformed_advisory_does_not_abort_the_run(self):
        fake = FakeOSV()

        def broken(method, path, body=None):
            if path.endswith("DSA-5724-1"):
                pkg = {"ecosystem": "Debian:12", "name": "openssh"}
                return {"id": "DSA-5724-1", "affected": [{"package": pkg, "ranges": 5}]}
            return fake(method, path, body)

        with patch("vulns.osv.osv_request", broken):
            scan()

        self.assertEqual(Finding.objects.filter(package="openssh").count(), 32)
        self.assertIsNone(Finding.objects.get(vuln_id="DSA-5724-1").advisory)
        self.assertIsNotNone(
            Finding.objects.get(vuln_id="DEBIAN-CVE-2024-6387").advisory
        )
        self.assertTrue(
            DebugLog.objects.filter(message__contains="DSA-5724-1").exists()
        )

    def test_late_advisory_is_notified(self):
        fake = FakeOSV()

        def missing(method, path, body=None):
            if path.endswith("DEBIAN-CVE-2024-6387"):
                raise requests.Timeout("slow")
            return fake(method, path, body)

        with patch("vulns.osv.osv_request", missing), patch(
            "vulns.tasks.notify"
        ) as notify:
            scan()
        self.assertIsNone(Finding.objects.get(vuln_id="DEBIAN-CVE-2024-6387").advisory)
        notify.assert_not_called()

        with patch("vulns.osv.osv_request", fake), patch(
            "vulns.tasks.notify"
        ) as notify:
            scan()
        notify.assert_called_once()
        self.assertIn("DEBIAN-CVE-2024-6387", notify.call_args.args[0]["body"])

    def test_ignore_survives_a_version_change(self):
        with patch("vulns.osv.osv_request", FakeOSV()):
            scan()
        Finding.objects.filter(vuln_id="DEBIAN-CVE-2024-6387").update(status="ignored")

        newer = ("openssh", "1:9.2p1-2+deb12u3")
        listed = [
            {"id": vuln_id, "modified": "2026-01-01T00:00:00Z"}
            for vuln_id in ("DEBIAN-CVE-2024-6387", "DEBIAN-CVE-2007-2243")
        ]
        self.software.software = inventory(newer, SUDO, NONE)
        self.software.save()
        with patch("vulns.osv.osv_request", FakeOSV({newer: {"vulns": listed}})):
            scan()

        status = dict(
            Finding.objects.filter(package="openssh", version=newer[1]).values_list(
                "vuln_id", "status"
            )
        )
        self.assertEqual(
            status, {"DEBIAN-CVE-2024-6387": "ignored", "DEBIAN-CVE-2007-2243": "open"}
        )
        # the old version is gone, its row stays ignored until pruned
        self.assertEqual(
            Finding.objects.get(
                vuln_id="DEBIAN-CVE-2024-6387", version=OPENSSH[1]
            ).status,
            "ignored",
        )

    def test_skips_agents_without_ecosystem_or_inventory(self):
        baker.make_recipe(
            "agents.agent", plat="windows", operating_system="Windows 11 Pro, 64 bit"
        )
        arch = baker.make_recipe(
            "agents.agent", plat="linux", operating_system="Arch x86_64 6.10.10-arch1-1"
        )
        InstalledSoftware.objects.create(
            agent=arch, software=inventory(SUDO, source="pacman")
        )
        empty = baker.make_recipe(
            "agents.agent", plat="linux", operating_system="Ubuntu 24.04 x86_64 6.8.0"
        )

        fake = FakeOSV()
        with patch("vulns.osv.osv_request", fake):
            scan()

        self.assertEqual(
            {q["package"]["ecosystem"] for b in fake.bodies for q in b["queries"]},
            {"Debian:12"},
        )
        self.assertEqual(AgentScan.objects.get(agent=empty).packages, 0)
        self.assertFalse(AgentScan.objects.filter(agent=arch).exists())


class TestVulnsAPI(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site1 = baker.make("clients.Site")
        self.site2 = baker.make("clients.Site")
        self.agent1 = baker.make_recipe(
            "agents.agent", plat="linux", operating_system=DEBIAN, site=self.site1
        )
        self.agent2 = baker.make_recipe(
            "agents.agent", plat="linux", operating_system=DEBIAN, site=self.site2
        )
        now = djangotime.now()
        levels = {}
        for level in ("critical", "high", "medium", "low", "unknown"):
            levels[level] = baker.make(
                "vulns.Advisory",
                vuln_id=f"V-{level}",
                level=level,
                summary=f"{level} bug",
                fetched_at=now,
                fixed={"Debian:12|pkg": ["2.0"]},
            )
        self.findings = {}
        for agent, level, status in (
            (self.agent1, "critical", "open"),
            (self.agent1, "high", "open"),
            (self.agent1, "low", "ignored"),
            (self.agent1, "medium", "fixed"),
            (self.agent2, "high", "open"),
            (self.agent2, "unknown", "open"),
        ):
            self.findings[(agent.pk, level)] = baker.make(
                "vulns.Finding",
                agent=agent,
                package="pkg",
                version="1.0",
                ecosystem="Debian:12",
                vuln_id=f"V-{level}",
                advisory=levels[level],
                status=status,
                first_seen=now,
                last_seen=now,
            )
        baker.make(
            "vulns.Finding",
            agent=self.agent2,
            package="other",
            version="1",
            ecosystem="Debian:12",
            vuln_id="V-none",
            status="open",
            first_seen=now,
            last_seen=now,
        )
        AgentScan.objects.create(
            agent=self.agent1, ecosystem="Debian:12", scanned_at=now, packages=3
        )

    def test_summary_counts(self):
        r = self.client.get("/vulns/summary/")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(
            {
                k: data[k]
                for k in (
                    "agents_affected",
                    "open",
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "unknown",
                )
            },
            # severities count what an update fixes, V-none has no advisory
            {
                "agents_affected": 2,
                "open": 5,
                "critical": 1,
                "high": 2,
                "medium": 0,
                "low": 0,
                "unknown": 1,
            },
        )
        self.assertEqual((data["needs_update"], data["no_fix"]), (4, 1))
        self.assertIsNotNone(data["last_scan"])
        self.assertIn("Windows", data["coverage"])

    def test_list_and_filters(self):
        r = self.client.get("/vulns/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["count"], 7)
        first = r.json()["findings"][0]
        self.assertEqual(
            (first["vuln_id"], first["level"], first["fixed_in"]),
            ("V-critical", "critical", ["2.0"]),
        )
        self.assertEqual(first["url"], "https://osv.dev/vulnerability/V-critical")

        def ids(query: dict):
            r = self.client.get("/vulns/", query)
            self.assertEqual(r.status_code, 200)
            return sorted(f["vuln_id"] for f in r.json()["findings"])

        self.assertEqual(
            ids({"agent": self.agent2.agent_id}), ["V-high", "V-none", "V-unknown"]
        )
        self.assertEqual(ids({"severity": "high"}), ["V-high", "V-high"])
        self.assertEqual(ids({"severity": "unknown"}), ["V-none", "V-unknown"])
        self.assertEqual(ids({"status": "ignored"}), ["V-low"])
        self.assertEqual(ids({"status": "no_fix"}), ["V-none"])
        self.assertEqual(
            ids({"status": "needs_update"}),
            ["V-critical", "V-high", "V-high", "V-unknown"],
        )
        self.assertEqual(len(ids({"status": "open"})), 5)
        self.assertEqual(
            ids({"status": "needs_update", "agent": self.agent2.agent_id}),
            ["V-high", "V-unknown"],
        )
        self.assertEqual(ids({"search": "critical bug"}), ["V-critical"])
        self.assertEqual(self.client.get("/vulns/?severity=bad").status_code, 400)
        self.assertEqual(self.client.get("/vulns/?status=bad").status_code, 400)

    def test_agent_view(self):
        r = self.client.get(f"/vulns/{self.agent1.agent_id}/")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(
            (data["ecosystem"], data["supported"], data["packages"], data["count"]),
            ("Debian:12", True, 3, 4),
        )
        self.assertEqual(
            data["counts"],
            {
                "needs_update": 2,
                "no_fix": 0,
                "open": 2,
                "ignored": 1,
                "fixed": 1,
                "all": 4,
            },
        )
        self.assertEqual(
            data["by_severity"],
            {"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0},
        )
        r = self.client.get(f"/vulns/{self.agent1.agent_id}/", {"status": "fixed"})
        self.assertEqual([f["vuln_id"] for f in r.json()["findings"]], ["V-medium"])
        # counts stay over the whole set
        self.assertEqual(r.json()["counts"]["all"], 4)
        self.assertEqual(
            self.client.get(
                f"/vulns/{self.agent1.agent_id}/", {"status": "bad"}
            ).status_code,
            400,
        )

        r = self.client.get(f"/vulns/{self.agent2.agent_id}/")
        self.assertEqual(r.json()["reason"], "Not checked yet.")

        # Windows and macOS go through MSRC and NVD
        win = baker.make_recipe("agents.agent", plat="windows")
        r = self.client.get(f"/vulns/{win.agent_id}/")
        self.assertEqual(
            (r.json()["supported"], r.json()["ecosystem"], r.json()["reason"]),
            (True, "Windows", "Not checked yet."),
        )
        arch = baker.make_recipe(
            "agents.agent", plat="linux", operating_system="Arch x86_64 6.10.10"
        )
        self.assertEqual(
            self.client.post(f"/vulns/{arch.agent_id}/scan/").status_code, 400
        )
        self.assertEqual(self.client.get("/vulns/notanagent/").status_code, 404)

    def test_ignore_toggle(self):
        finding = self.findings[(self.agent1.pk, "critical")]
        url = f"/vulns/findings/{finding.pk}/ignore/"

        r = self.client.post(url)
        self.assertEqual(r.json(), {"id": finding.pk, "status": "ignored"})
        self.assertEqual(self.client.post(url).json()["status"], "open")
        finding.refresh_from_db()
        self.assertEqual(finding.status, "open")
        self.assertEqual(
            AuditLog.objects.filter(agent_id=self.agent1.agent_id).count(), 2
        )
        self.assertIn(
            "ignored V-critical in pkg 1.0",
            AuditLog.objects.order_by("id").first().message,
        )

        fixed = self.findings[(self.agent1.pk, "medium")]
        self.assertEqual(
            self.client.post(f"/vulns/findings/{fixed.pk}/ignore/").status_code, 400
        )
        self.assertEqual(
            self.client.post("/vulns/findings/999999/ignore/").status_code, 404
        )

    @patch("vulns.views.scan_vulnerabilities_task.delay")
    def test_scan_queues(self, delay):
        win = baker.make_recipe("agents.agent", plat="windows")
        r = self.client.post("/vulns/scan/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            sorted(delay.call_args.kwargs["agent_pks"]),
            sorted([self.agent1.pk, self.agent2.pk, win.pk]),
        )

        r = self.client.post(f"/vulns/{self.agent1.agent_id}/scan/")
        self.assertEqual(r.status_code, 200)
        delay.assert_called_with(agent_pks=[self.agent1.pk])

    @patch("vulns.views.scan_vulnerabilities_task.delay", MagicMock())
    def test_permissions_and_role_filter(self):
        f1 = self.findings[(self.agent1.pk, "critical")]
        f2 = self.findings[(self.agent2.pk, "high")]
        urls = (
            ("get", "/vulns/"),
            ("get", "/vulns/summary/"),
            ("get", f"/vulns/{self.agent1.agent_id}/"),
            ("post", "/vulns/scan/"),
            ("post", f"/vulns/{self.agent1.agent_id}/scan/"),
            ("post", f"/vulns/findings/{f1.pk}/ignore/"),
        )
        for method, url in urls:
            self.check_not_authenticated(method, url)

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        for method, url in urls:
            self.check_not_authorized(method, url)

        user = self.create_user_with_roles(["can_view_vulnerabilities"])
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)

        r = self.client.get("/vulns/")
        self.assertEqual(
            {f["agent_id"] for f in r.json()["findings"]}, {self.agent1.agent_id}
        )
        self.assertEqual(
            self.client.get(f"/vulns/?agent={self.agent2.agent_id}").json()["count"], 0
        )
        summary = self.client.get("/vulns/summary/").json()
        self.assertEqual((summary["agents_affected"], summary["open"]), (1, 2))
        self.assertEqual(
            self.client.get(f"/vulns/{self.agent1.agent_id}/").status_code, 200
        )
        self.assertEqual(
            self.client.get(f"/vulns/{self.agent2.agent_id}/").status_code, 403
        )
        # scan and ignore need can_approve_patches
        for url in (
            "/vulns/scan/",
            f"/vulns/{self.agent1.agent_id}/scan/",
            f"/vulns/findings/{f1.pk}/ignore/",
        ):
            self.assertEqual(self.client.post(url).status_code, 403, url)
        user.role.can_approve_patches = True
        user.role.save()
        user.refresh_from_db()

        self.assertEqual(
            self.client.post(f"/vulns/{self.agent2.agent_id}/scan/").status_code, 403
        )
        self.assertEqual(
            self.client.post(f"/vulns/findings/{f2.pk}/ignore/").status_code, 403
        )
        self.assertEqual(
            self.client.post(f"/vulns/findings/{f1.pk}/ignore/").status_code, 200
        )

        with patch("vulns.views.scan_vulnerabilities_task.delay") as delay:
            self.client.post("/vulns/scan/")
        delay.assert_called_once_with(agent_pks=[self.agent1.pk])


class TestFixAvailable(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent", plat="linux", operating_system=DEBIAN
        )
        self.now = djangotime.now()

    def finding(self, vuln_id, package="pkg", eco="Debian:12", **kw):
        fixed = kw.pop("fixed", None)
        advisory = (
            None
            if fixed is None
            else baker.make(
                "vulns.Advisory",
                vuln_id=vuln_id,
                level=kw.pop("level", "high"),
                fetched_at=self.now,
                fixed=fixed,
            )
        )
        return baker.make(
            "vulns.Finding",
            agent=self.agent,
            package=package,
            version=kw.pop("version", "1.0"),
            ecosystem=eco,
            vuln_id=vuln_id,
            advisory=advisory,
            first_seen=self.now,
            last_seen=self.now,
            **kw,
        )

    def rows(self, **query) -> dict:
        r = self.client.get("/vulns/", {"agent": self.agent.agent_id, **query})
        self.assertEqual(r.status_code, 200)
        return {
            f["vuln_id"]: (f["fix_available"], f["fixed_version"])
            for f in r.json()["findings"]
        }

    def test_per_source(self):
        self.finding("osv", fixed={"Debian:12|pkg": ["1.1", "1.2"]})
        self.finding("other-release", fixed={"Debian:11|pkg": ["1.1"]})
        self.finding("osv-empty", fixed={"Debian:12|pkg": []})
        self.finding("not-a-list", fixed={"Debian:12|pkg": "1.1"})
        self.finding("no-advisory")
        self.finding(
            "msrc",
            package="Windows (KB5044285)",
            eco="Windows",
            source="msrc",
            version="",
            fixed={"Windows|Windows (KB5044285)": ["KB5044285"]},
        )
        self.finding(
            "nvd-empty", package="Chrome", eco="Windows", source="nvd", fixed={}
        )
        self.finding(
            "nvd-empty-list",
            package="Chrome",
            eco="Windows",
            source="nvd",
            fixed={"Windows|Chrome": []},
        )
        # string order: 129.0.6668.100 sorts before 129.0.6668.89
        self.finding(
            "nvd",
            package="Chrome",
            eco="Windows",
            source="nvd",
            version="129.0.6668.58",
            fixed={"Windows|Chrome": ["129.0.6668.100", "129.0.6668.89", "1.0"]},
        )
        self.finding(
            "nvd-all-older",
            package="Chrome",
            eco="Windows",
            source="nvd",
            version="200.0",
            fixed={"Windows|Chrome": ["129.0.6668.100", "129.0.6668.89"]},
        )
        self.assertEqual(
            self.rows(),
            {
                "osv": (True, "1.2"),
                "other-release": (False, None),
                "osv-empty": (False, None),
                "not-a-list": (False, None),
                "no-advisory": (False, None),
                "msrc": (True, "KB5044285"),
                "nvd-empty": (False, None),
                "nvd-empty-list": (False, None),
                "nvd": (True, "129.0.6668.89"),
                "nvd-all-older": (True, "129.0.6668.100"),
            },
        )
        self.assertEqual(
            sorted(self.rows(status="needs_update")),
            ["msrc", "nvd", "nvd-all-older", "osv"],
        )
        summary = self.client.get("/vulns/summary/").json()
        self.assertEqual(
            (summary["open"], summary["needs_update"], summary["no_fix"]), (10, 4, 6)
        )

    def test_fixed_version_rules(self):
        from vulns.views import fixed_version

        self.assertIsNone(fixed_version("osv", "1", []))
        self.assertIsNone(fixed_version("nvd", "1", None))
        self.assertEqual(fixed_version("osv", "1", ["2", "3"]), "3")
        self.assertEqual(fixed_version("msrc", "", ["KB1"]), "KB1")
        self.assertEqual(fixed_version("nvd", "1.5", ["1.10", "1.2", "1.6"]), "1.6")
        self.assertEqual(fixed_version("nvd", "9", ["1.10", "1.2"]), "1.10")
        self.assertEqual(fixed_version("nvd", "", ["x", "2"]), "2")

    def test_agent_counts_over_the_row_cap(self):
        advisory = baker.make(
            "vulns.Advisory",
            vuln_id="FIXED",
            level="low",
            fetched_at=self.now,
            fixed={"Debian:12|pkg": ["2"]},
        )
        Finding.objects.bulk_create(
            Finding(
                agent=self.agent,
                package="pkg",
                version=str(i),
                ecosystem="Debian:12",
                vuln_id="FIXED",
                advisory=advisory,
                status="fixed",
                # newer than the open rows, so an unfiltered list cuts those off
                first_seen=self.now,
                last_seen=self.now + dt.timedelta(days=1),
            )
            for i in range(1100)
        )
        self.finding("open-crit", level="critical", fixed={"Debian:12|pkg": ["2"]})
        self.finding("open-nofix", level="critical", fixed={"Debian:12|pkg": []})

        url = f"/vulns/{self.agent.agent_id}/"
        data = self.client.get(url).json()
        self.assertEqual((data["count"], data["truncated"]), (1102, True))
        self.assertEqual(
            data["counts"],
            {
                "needs_update": 1,
                "no_fix": 1,
                "open": 2,
                "ignored": 0,
                "fixed": 1100,
                "all": 1102,
            },
        )
        self.assertEqual(data["by_severity"]["critical"], 1)
        self.assertEqual(data["by_severity"]["low"], 0)

        data = self.client.get(url, {"status": "needs_update"}).json()
        self.assertEqual((data["count"], data["truncated"]), (1, False))
        self.assertEqual(data["findings"][0]["vuln_id"], "open-crit")
        data = self.client.get(url, {"search": "nofix"}).json()
        self.assertEqual([f["vuln_id"] for f in data["findings"]], ["open-nofix"])

    def test_notification_skips_findings_without_fix(self):
        from vulns.tasks import _notify_new

        new = [
            self.finding("fixable", level="critical", fixed={"Debian:12|pkg": ["2"]}),
            self.finding("nofix", level="critical", fixed={"Debian:12|pkg": []}),
            self.finding("elsewhere", level="high", fixed={"Debian:11|pkg": ["2"]}),
        ]
        with patch("vulns.tasks.notify") as notify:
            _notify_new(self.agent, new)
        notify.assert_called_once()
        event = notify.call_args.args[0]
        self.assertEqual(event["severity"], "error")
        self.assertTrue(
            event["title"].startswith(
                "1 new critical or high vulnerabilities with an update on "
            )
        )
        self.assertNotIn("nofix", event["body"])

        with patch("vulns.tasks.notify") as notify:
            _notify_new(self.agent, new[1:])
        notify.assert_not_called()


class TestPkgAudit(ULRMMTestCase):
    """FreeBSD findings come from pkg audit on the device, through the
    package scan (winupdate.tasks._import_refresh)."""

    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", plat="freebsd")
        self.stdout = (
            settings.BASE_DIR
            / "ulrmm"
            / "test_data"
            / "posix"
            / "freebsd144_refresh.txt"
        ).read_text()

    def refresh(self, stdout):
        from winupdate.tasks import _import_refresh

        reply = {"stdout": stdout, "stderr": "", "retcode": 0}
        with patch("winupdate.tasks.mirror.mirror_agent_updates"):
            return _import_refresh(self.agent, reply, "refresh")

    def test_findings_from_the_scan(self):
        from vulns.tasks import ecosystem

        self.assertEqual(ecosystem(self.agent), ("FreeBSD", ""))
        self.assertEqual(self.refresh(self.stdout), "ok")

        findings = Finding.objects.filter(agent=self.agent).order_by("vuln_id")
        self.assertEqual(
            [(f.package, f.version, f.source, f.ecosystem) for f in findings],
            [("sudo", "1.9.5", "vuxml", "FreeBSD")] * 3,
        )
        self.assertEqual(
            [f.vuln_id for f in findings],
            [
                "24f4b495-56a1-11f0-9621-93abbef07693",
                "3310014a-5ef9-11ed-812b-206a8a720317",
                "f3cf4b33-6013-11eb-9a0e-206a8a720317",
            ],
        )
        advisory = findings[0].advisory
        self.assertEqual(
            advisory.summary,
            "sudo -- privilege escalation vulnerability through host and chroot "
            "options (CVE-2025-32462, CVE-2025-32463)",
        )
        self.assertEqual(advisory.level, "unknown")
        self.assertEqual(advisory.fixed, {"FreeBSD|sudo": ["1.9.17p1"]})
        self.assertEqual(findings[1].advisory.fixed, {"FreeBSD|sudo": ["1.9.12p1"]})
        scan = AgentScan.objects.get(agent=self.agent)
        self.assertEqual((scan.ecosystem, scan.packages), ("FreeBSD", 5))

        r = self.client.get(f"/vulns/{self.agent.agent_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["supported"])
        self.assertEqual(r.data["counts"]["needs_update"], 3)
        row = next(f for f in r.data["findings"] if f["vuln_id"].startswith("24f4b495"))
        self.assertEqual(
            row["url"],
            "https://vuxml.FreeBSD.org/freebsd/24f4b495-56a1-11f0-9621-93abbef07693.html",
        )
        self.assertEqual(row["fixed_version"], "1.9.17p1")

        update = self.agent.winupdates.get()
        self.assertEqual(
            (update.guid, update.severity), ("pkg:sudo::1.9.17p2_2", "Important")
        )

        # sudo updated: the next scan lists nothing, the findings are fixed
        fixed = re.sub(
            r"A\tBEGIN\n.*?\nA\tEND\n",
            'A\tBEGIN\n{"pkg_count":0}\nA\tEND\n',
            self.stdout,
            flags=re.S,
        )
        self.refresh(fixed)
        self.assertEqual(
            set(
                Finding.objects.filter(agent=self.agent).values_list(
                    "status", flat=True
                )
            ),
            {"fixed"},
        )
        # a scan whose audit failed keeps them as they are
        Finding.objects.filter(agent=self.agent).update(status="open")
        self.refresh(fixed.replace('{"pkg_count":0}', "pkg: no vuln.xml"))
        self.assertEqual(
            Finding.objects.filter(agent=self.agent, status="open").count(), 3
        )

    def test_ranges(self):
        from vulns.tasks import _vuxml_fixed

        self.assertEqual(
            _vuxml_fixed(
                ["< 2.0.5", ">= 1.0 : < 1.4.2", "<= 3.1", ">= 4.0", "< 1.4.2"]
            ),
            ["1.4.2", "2.0.5"],
        )
        self.assertEqual(_vuxml_fixed("< 1.0"), [])
        self.assertEqual(_vuxml_fixed([None, 5]), [])

    def test_other_platforms_ignore_the_block(self):
        self.agent.plat = "linux"
        self.agent.save(update_fields=["plat"])
        self.refresh(self.stdout)
        self.assertFalse(Finding.objects.exists())

    @patch("winupdate.tasks.posix_refresh_task.delay")
    @patch("vulns.views.scan_vulnerabilities_task.delay")
    def test_scan_button_queues_a_package_scan(self, osv_scan, package_scan):
        r = self.client.post(f"/vulns/{self.agent.agent_id}/scan/")
        self.assertEqual(r.status_code, 200)
        package_scan.assert_called_once_with(self.agent.pk, "scan")
        osv_scan.assert_not_called()

    @patch("winupdate.tasks.maintenance.install_finished")
    @patch("winupdate.tasks.mirror.mirror_agent_updates")
    def test_install_rescan_updates_the_findings(self, *_):
        from winupdate.tasks import _install_locked

        self.refresh(self.stdout)
        installed = {"stdout": "I\tpkg:sudo::1.9.17p2_2\t0\tok\nR\t0\n", "retcode": 0}
        rescan = {
            "stdout": 'A\tBEGIN\n{"pkg_count":0}\nA\tEND\nR\t0\n',
            "retcode": 0,
        }
        with patch(
            "winupdate.tasks.run_packages_script", side_effect=[installed, rescan]
        ):
            _install_locked(self.agent, ["pkg:sudo::1.9.17p2_2"], "admin")
        self.assertEqual(
            set(
                Finding.objects.filter(agent=self.agent).values_list(
                    "status", flat=True
                )
            ),
            {"fixed"},
        )

    def test_odd_cve_values_and_the_cap(self):
        from vulns.tasks import import_pkg_audit

        def issue(n, cve):
            return {
                "description": f"issue {n}",
                "cve": cve,
                "url": f"https://vuxml.FreeBSD.org/freebsd/{n:08d}-0000-0000-0000-000000000000.html",
                "Affected versions": ["< 2"],
            }

        audit = {
            "a": {"version": "1", "issues": [issue(1, 5), issue(2, "CVE-2024-1")]},
            "b": {"version": "1", "issues": [issue(3, ["CVE-2024-3", 4])]},
        }
        import_pkg_audit(self.agent, audit)
        summaries = sorted(
            Finding.objects.filter(agent=self.agent).values_list(
                "advisory__summary", flat=True
            )
        )
        self.assertEqual(summaries, ["issue 1", "issue 2", "issue 3 (CVE-2024-3)"])

        # over the cap: the rest is not imported and its findings stay open
        with patch("vulns.tasks.MAX_AUDIT_ISSUES", 2):
            import_pkg_audit(self.agent, audit)
        self.assertEqual(
            Finding.objects.filter(agent=self.agent, status="open").count(), 3
        )
        self.assertEqual(AgentScan.objects.get(agent=self.agent).unchecked, 1)
        logged = DebugLog.objects.filter(
            agent=self.agent, message__contains="pkg audit"
        )
        self.assertEqual(
            list(logged.values_list("message", flat=True)),
            [
                f"pkg audit on {self.agent.hostname} listed 3 issues, "
                "only the first 2 were imported"
            ],
        )

    @patch("winupdate.tasks.posix_refresh_task.delay")
    @patch("vulns.views.scan_vulnerabilities_task.delay")
    def test_fleet_scan_includes_freebsd(self, osv_scan, package_scan):
        offline = baker.make_recipe("agents.offline_agent", plat="freebsd")
        linux = baker.make_recipe("agents.online_agent", plat="linux")
        r = self.client.post("/vulns/scan/")
        self.assertEqual(r.status_code, 200)
        package_scan.assert_called_once_with(self.agent.pk, "scan")
        self.assertIn(linux.pk, osv_scan.call_args.kwargs["agent_pks"])
        self.assertNotIn(offline.pk, osv_scan.call_args.kwargs["agent_pks"])
        self.assertNotIn(self.agent.pk, osv_scan.call_args.kwargs["agent_pks"])

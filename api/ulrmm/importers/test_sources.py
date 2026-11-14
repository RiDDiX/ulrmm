# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Adapters against answers recorded from a seeded upstream 1.5.2 server
and examples built from the NinjaOne OpenAPI spec (test_data/)."""

import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import requests
from django.test import SimpleTestCase

from ulrmm.utils import BodyTooLarge, capped_json

from .sources import SourceError, validate
from .sources import base
from .sources.base import NotFound, Source
from .sources.ninjaone import NinjaOne
from .sources.upstream import Upstream

DATA = Path(__file__).parent / "test_data"


class Recorded:
    """Stands in for Source.call: answers by path, records every request."""

    def __init__(self, name: str, **extra):
        self.answers = {**json.loads((DATA / f"{name}.json").read_text()), **extra}
        self.calls = []

    def __call__(self, source, method, path, timeout=30, **kwargs):
        self.calls.append((method, path, kwargs))
        if (
            kwargs.get("params")
            and (query := f"{path}?{urlencode(kwargs['params'])}") in self.answers
        ):
            return self.answers[query]
        if path not in self.answers:
            raise NotFound(f"{path} answered 404")
        return self.answers[path]


class TestUpstream(SimpleTestCase):
    def fetch(self, rec):
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            return validate(Upstream("https://old", True, {}, {"api_key": "K"}).fetch())

    def test_fetch(self):
        rec = Recorded("upstream")
        data = self.fetch(rec)
        clients = {c["name"]: c for c in data["clients"]}
        self.assertEqual(set(clients), {"Contoso GmbH", "Fabrikam AG"})
        hq = clients["Contoso GmbH"]["sites"][0]
        self.assertEqual((hq["ref"], hq["name"]), ("1", "Berlin HQ"))
        self.assertTrue(hq["custom_fields"])
        self.assertEqual(len(data["devices"]), 6)
        dc = next(d for d in data["devices"] if d["hostname"] == "CONTOSO-DC01")
        self.assertEqual(dc["site_ref"], "1")
        self.assertEqual(dc["serial"], "CZC1234XYZ")
        self.assertEqual(dc["plat"], "windows")
        self.assertEqual(
            dc["notes"],
            [
                "Primary DC, do not reboot during business hours.",
                "Backup job runs 02:00.",
            ],
        )
        self.assertIn(["DNS", "DHCP"], dc["custom_fields"].values())
        self.assertIn(True, dc["custom_fields"].values())
        self.assertEqual(len(data["scripts"]), 5)
        disk = next(s for s in data["scripts"] if s["name"] == "Disk Usage Report")
        self.assertTrue(disk["body"].startswith("param([int]$Threshold"))
        self.assertEqual(disk["env_vars"], ["REPORT_MODE=short"])
        self.assertEqual(disk["platforms"], ["windows"])
        self.assertEqual(
            {k["name"] for k in data["keystore"]}, {"smtp_relay", "backup_token"}
        )
        self.assertEqual(len(data["snippets"]), 2)
        self.assertTrue(
            {"model": "agent", "name": "Asset Tag"}.items()
            <= next(
                f for f in data["custom_fields"] if f["name"] == "Asset Tag"
            ).items()
        )
        self.assertIn(("GET", "/agents/", {"params": {"detail": "true"}}), rec.calls)

    def test_fetch_more(self):
        data = self.fetch(Recorded("upstream"))
        hooks = {u["name"]: u for u in data["url_actions"]}
        self.assertEqual(set(hooks), {"Notify chat hook", "Open ticket page"})
        rest = hooks["Notify chat hook"]
        self.assertEqual((rest["action_type"], rest["rest_method"]), ("rest", "post"))
        self.assertIn("Bearer MASKED", rest["rest_headers"])

        templates = {t["name"]: t for t in data["alert_templates"]}
        self.assertEqual(
            [n for n, t in templates.items() if t["default"]], ["Quiet nights"]
        )
        strict = templates["Strict paging"]
        self.assertEqual(
            strict["action"], {"name": "Disk Usage Report", "shell": "powershell"}
        )
        self.assertEqual(strict["excluded_sites"], [["Contoso GmbH", "Berlin HQ"]])
        self.assertEqual(strict["fields"]["text_recipients"], ["+4915112345678"])
        self.assertIs(strict["fields"]["agent_always_email"], True)
        self.assertNotIn("agent_always_email", templates["Quiet nights"]["fields"])
        self.assertNotIn("id", strict["fields"])
        self.assertEqual(strict["lost"], [])
        # a library script and a URL action id the lists do not hold
        library = templates["Library paging"]
        self.assertEqual(library["lost"], ["action", "resolved_action_rest"])
        self.assertIsNone(library["action"])

        policies = {p["name"]: p for p in data["policies"]}
        servers = policies["Servers baseline"]
        self.assertEqual(len(servers["checks"]), 5)
        self.assertEqual(len(servers["tasks"]), 2)
        self.assertEqual(servers["patch_policy"]["critical"], "approve")
        self.assertEqual(servers["patch_policy"]["run_time_days"], [1, 3])
        ws = policies["Workstations baseline"]
        self.assertEqual(
            (ws["enforced"], ws["alert_template"]), (True, "Strict paging")
        )
        script_check = next(c for c in ws["checks"] if c["script"])
        self.assertEqual(script_check["script"]["name"], "Disk Usage Report")
        weekly = next(t for t in servers["tasks"] if t["name"] == "Weekly cleanup")
        self.assertEqual(
            [a["type"] for a in weekly["actions"]], ["script", "cmd"], weekly
        )
        self.assertEqual(weekly["actions"][0]["script"]["shell"], "powershell")
        # Monday, Wednesday and Friday
        self.assertEqual(weekly["fields"]["run_time_bit_weekdays"], 42)

        clients = {c["name"]: c for c in data["clients"]}
        fab = clients["Fabrikam AG"]
        self.assertEqual(
            (fab["server_policy"], fab["workstation_policy"], fab["alert_template"]),
            ("Servers baseline", "Workstations baseline", "Strict paging"),
        )
        hamburg = next(
            s for s in clients["Contoso GmbH"]["sites"] if s["name"] == "Hamburg Branch"
        )
        self.assertEqual(hamburg["workstation_policy"], "Workstations baseline")

        devices = {d["hostname"]: d for d in data["devices"]}
        dc = devices["CONTOSO-DC01"]
        self.assertEqual(
            dc["settings"],
            {
                "time_zone": "Europe/Berlin",
                "check_interval": 45,
                "offline_time": 7,
                "overdue_time": 60,
                "overdue_email_alert": True,
                "overdue_text_alert": True,
                "overdue_dashboard_alert": False,
                "maintenance_mode": True,
                "block_policy_inheritance": True,
            },
        )
        self.assertEqual(
            [c["fields"]["check_type"] for c in dc["checks"]], ["diskspace"]
        )
        self.assertEqual([t["name"] for t in dc["tasks"]], ["Local nightly job"])
        self.assertTrue(dc["patch_policy"])
        self.assertEqual(devices["CONTOSO-WS014"]["policy"], "Workstations baseline")
        self.assertEqual(
            devices["contoso-web01"]["excluded_policies"], ["Servers baseline"]
        )
        # no detail recorded for this one: the exclusion still comes along
        pi = devices["fab-pi-sensor"]
        self.assertEqual(pi["excluded_templates"], ["Strict paging"])
        self.assertEqual((pi["settings"], pi["policy"]), ({}, ""))

        roles = {r["name"]: r for r in data["roles"]}
        helpdesk = roles["Helpdesk"]
        self.assertIs(helpdesk["perms"]["can_list_agents"], True)
        self.assertEqual(helpdesk["unknown"], 1)
        self.assertEqual(helpdesk["clients"], ["Contoso GmbH"])
        self.assertEqual(
            helpdesk["sites"],
            [["Contoso GmbH", "Berlin HQ"], ["Contoso GmbH", "Hamburg Branch"]],
        )
        users = {u["username"]: u for u in data["users"]}
        self.assertEqual(users["olaf.audit"]["role"], "Auditor")
        self.assertEqual(users["admin"]["role"], "")
        self.assertNotIn("password", json.dumps(data["users"]))

        self.assertEqual(
            data["report_templates"][0]["template_html"], "Corporate frame"
        )
        self.assertEqual(data["report_html"][0]["name"], "Corporate frame")
        self.assertEqual(data["report_queries"][0]["json_query"]["model"], "agent")

    def test_without_reporting(self):
        rec = Recorded("upstream")
        for path in [p for p in rec.answers if p.startswith("/reporting/")]:
            del rec.answers[path]
        data = self.fetch(rec)
        self.assertEqual(data["report_templates"], [])
        del rec.answers["/core/urlaction/"]
        with self.assertRaisesRegex(SourceError, "urlaction"):
            self.fetch(rec)

    def test_needs_key(self):
        with self.assertRaises(SourceError):
            Upstream("https://old", True, {}, {}).fetch()

    def test_device_and_remove(self):
        from agents.models import Agent

        from .removal import _ipv4

        dc = "DEMOAGENT00xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxCONTOSO-DC01"
        rec = Recorded("upstream")
        up = Upstream("https://old", True, {}, {"api_key": "K"})
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            detail = up.device(dc)
            with self.assertRaises(NotFound):
                up.device("GONE")
            with self.assertRaisesRegex(SourceError, "characters"):
                up.remove("../clients/1", "x")
        # what the same-machine proof reads from the live detail
        theirs = Agent(plat=detail["plat"], wmi_detail=detail["wmi_detail"])
        self.assertEqual(theirs.serial_number, "CZC1234XYZ")
        self.assertEqual(
            {str(ip) for ip in _ipv4(detail["local_ips"])},
            {"172.17.9.121", "172.17.9.6", "172.17.9.122"},
        )
        self.assertEqual(
            {
                str(ip)
                for ip in _ipv4(
                    Agent(plat="windows", wmi_detail=detail["wmi_detail"]).local_ips
                )
            },
            {"172.17.9.121", "172.17.9.6", "172.17.9.122"},
        )

        path = f"/agents/{dc}/"
        for answer, ok in (
            ("CONTOSO-DC01 will now be uninstalled.", True),
            ("CONTOSO-DC01 was offline, uninstall it manually", False),
            ({"detail": "x"}, False),
        ):
            rec = Recorded("upstream", **{path: answer})
            with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
                if ok:
                    up.remove(dc, "CONTOSO-DC01")
                else:
                    with self.assertRaisesRegex(SourceError, "unexpected answer"):
                        up.remove(dc, "CONTOSO-DC01")
            self.assertEqual(rec.calls[0][:2], ("DELETE", path))

    def test_push(self):
        rec = Recorded(
            "upstream", **{"/agents/A1/cmd/": "", "/agents/OFF/cmd/": "natsdown"}
        )
        up = Upstream("https://old", True, {}, {"api_key": "K"})
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            up.push("A1", "linux", "echo hi")
            with self.assertRaisesRegex(SourceError, "offline"):
                up.push("OFF", "windows", "x")
        method, path, kw = rec.calls[0]
        self.assertEqual((method, path), ("POST", "/agents/A1/cmd/"))
        self.assertEqual(
            kw["json"],
            {
                "shell": "/bin/bash",
                "cmd": "echo hi",
                "timeout": 60,
                "run_as_user": False,
                "custom_shell": None,
            },
        )


class TestNinjaOne(SimpleTestCase):
    def source(self, **options):
        return NinjaOne(
            "https://eu.ninjarmm.com",
            True,
            {"client_id": "CID", **options},
            {"client_secret": "SEC"},
        )

    def test_fetch(self):
        rec = Recorded("ninjaone")
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            src = self.source()
            data = validate(src.fetch())
        self.assertEqual(src.session.headers["Authorization"].split()[0], "Bearer")
        token = rec.calls[0]
        self.assertEqual(token[1], "/ws/oauth/token")
        self.assertEqual(token[2]["data"]["grant_type"], "client_credentials")
        self.assertEqual(token[2]["data"]["scope"], "monitoring management")

        self.assertEqual(len(data["clients"]), 2)
        self.assertEqual(sum(len(c["sites"]) for c in data["clients"]), 3)
        self.assertEqual(len(data["devices"]), 6)
        ws = next(d for d in data["devices"] if d["ref"] == "1001")
        self.assertEqual(
            (
                ws["plat"],
                ws["monitoring_type"],
                ws["site_ref"],
                ws["serial"],
                ws["goarch"],
            ),
            ("windows", "workstation", "201", "SYN-WS-0001", "amd64"),
        )
        self.assertEqual(ws["notes"], ["Synthetic note for WS-ALPHA01"])
        self.assertEqual(ws["custom_fields"]["Asset Tag"], "AT-SYN-0001")
        self.assertIs(ws["custom_fields"]["Critical"], False)
        self.assertFalse(data["scripts"])
        plats = {d["plat"] for d in data["devices"]}
        self.assertEqual(plats, {"windows", "linux", "darwin"})

    def test_paging(self):
        page = [{"id": i, "name": f"o{i}", "locations": []} for i in range(1, 201)]
        rec = Recorded("ninjaone")
        answers = iter([page, page[:3]])
        src = self.source()
        with patch.object(Source, "call", lambda s, *a, **k: next(answers)):
            self.assertEqual(len(src._pages("/v2/organizations-detailed")), 203)
        del rec

    def test_push_needs_script(self):
        rec = Recorded("ninjaone", **{"/v2/device/1001/script/run": None})
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            with self.assertRaisesRegex(SourceError, "script id"):
                self.source().push("1001", "windows", "cmd", "https://u")
            self.source(script_windows="77").push(
                "1001", "windows", "cmd", "https://api/clients/x/deploy/?fmt=ps1"
            )
        method, path, kw = rec.calls[-1]
        self.assertEqual((method, path), ("POST", "/v2/device/1001/script/run"))
        self.assertEqual(
            kw["json"],
            {
                "type": "SCRIPT",
                "id": 77,
                "parameters": "https://api/clients/x/deploy/?fmt=ps1",
            },
        )

    def test_needs_credentials(self):
        with self.assertRaises(SourceError):
            NinjaOne("https://eu.ninjarmm.com", True, {}, {}).fetch()


class TestCall(SimpleTestCase):
    def response(self, status, body=b"", headers=None):
        r = requests.Response()
        r.status_code, r._content, r._content_consumed = status, body, True
        r.headers.update(headers or {})
        return r

    def test_refuses_redirects_and_errors(self):
        src = Source("https://old", True, {}, {})
        cases = [
            (self.response(302, headers={"Location": "https://evil"}), "redirect"),
            (self.response(401), "refused"),
            (self.response(500), "answered 500"),
            (self.response(200, b"<html>"), "JSON"),
        ]
        for response, error in cases:
            with patch.object(src.session, "request", return_value=response):
                with self.assertRaisesRegex(SourceError, error):
                    src.call("GET", "/x/")
        with patch.object(src.session, "request", return_value=self.response(204)):
            self.assertIsNone(src.call("POST", "/x/"))
        with patch.object(
            src.session, "request", side_effect=requests.ConnectionError("boom")
        ):
            with self.assertRaisesRegex(SourceError, "ConnectionError"):
                src.call("GET", "/x/")
        with patch.object(base, "MAX_BODY", 1):
            with patch.object(
                src.session, "request", return_value=self.response(200, b"[1]" * 20)
            ):
                with self.assertRaisesRegex(SourceError, "too much data"):
                    src.call("GET", "/x/")

    def test_body_cap_stops_reading(self):
        class Endless:
            read = 0
            closed = False

            def iter_content(self, size):
                while True:
                    self.read += size
                    yield b" " * size

            def close(self):
                self.closed = True

        r = Endless()
        with self.assertRaises(BodyTooLarge):
            capped_json(r, 200_000)
        self.assertTrue(r.closed)
        self.assertLess(r.read, 300_000)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Adapters against answers recorded from a seeded upstream 1.5.2 server
and examples built from the NinjaOne OpenAPI spec (test_data/)."""

import json
from pathlib import Path
from unittest.mock import patch

import requests
from django.test import SimpleTestCase

from .sources import SourceError, validate
from .sources.base import Source
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
        if path not in self.answers:
            raise SourceError(f"{path} answered 404")
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

    def test_needs_key(self):
        with self.assertRaises(SourceError):
            Upstream("https://old", True, {}, {}).fetch()

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
        r.status_code, r._content = status, body
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

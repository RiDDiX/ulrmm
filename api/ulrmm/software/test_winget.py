# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import hashlib
import io
import os
import sqlite3
import tempfile
import zipfile
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker

from logs.models import AuditLog, PendingAction
from ulrmm.constants import PAAction
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import winget
from .models import ChocoSoftware, WingetCatalog
from .tasks import refresh_winget_task

GOOD = [
    ("Mozilla.Firefox", "Mozilla Firefox (en-US)", "157.0.1"),
    ("7zip.7zip", "7-Zip", "26.04"),
    ("Febooti.Hash&CRC", "Hash & CRC", "1.0"),
    ("BRÖTJE.ProfiTool", "ProfiTool", "2.1"),
    ("IDMComputerSolutions,Inc.UltraEdit", "UltraEdit", "31.0"),
    ("long.Name", "n" * 200, "v" * 100),
]
BAD = [("-x", "dash", "1"), ("a b", "space", "1"), ("_x", "underscore", "1")]


def make_msix(rows=GOOD + BAD, major="2", member="Public/index.db") -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "index.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT)")
        db.executemany(
            "INSERT INTO metadata VALUES (?, ?)",
            [("majorVersion", major), ("lastwritetime", "1792475130")],
        )
        db.execute(
            "CREATE TABLE packages (rowid INTEGER PRIMARY KEY, id TEXT, name TEXT, "
            "moniker TEXT, latest_version TEXT)"
        )
        db.executemany(
            "INSERT INTO packages (id, name, latest_version) VALUES (?, ?, ?)", rows
        )
        db.commit()
        db.close()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(path, member)
            z.writestr("AppxManifest.xml", "<Package/>")
        return buf.getvalue()


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, url=""):
        self.status_code = status
        self.body = body
        self.headers = headers or {}
        self.url = url
        self.text = body.decode("latin-1") if isinstance(body, bytes) else body

    def iter_content(self, size):
        for i in range(0, len(self.body), size):
            yield self.body[i : i + size]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def ok(body: bytes, **headers) -> FakeResponse:
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    return FakeResponse(200, body, {"ETag": '"0x8DF"', "Content-MD5": md5, **headers})


@patch.object(winget, "MIN_ROWS", 3)
@patch("software.winget.fetch")
class TestRefresh(ULRMMTestCase):
    def test_store_and_304(self, fetch):
        body = make_msix()
        fetch.return_value = ok(body)
        self.assertEqual(winget.refresh(), "winget catalog has 6 packages")
        self.assertEqual(fetch.call_args.kwargs["headers"], {})
        self.assertEqual(fetch.call_args.args[2], ("cdn.winget.microsoft.com",))
        cat = WingetCatalog.load()
        self.assertEqual(
            [p[0] for p in cat.packages],
            [
                "7zip.7zip",
                "BRÖTJE.ProfiTool",
                "Febooti.Hash&CRC",
                "IDMComputerSolutions,Inc.UltraEdit",
                "long.Name",
                "Mozilla.Firefox",
            ],
        )
        self.assertEqual([len(cat.packages[4][1]), len(cat.packages[4][2])], [128, 64])
        self.assertEqual(
            (cat.etag, cat.sha256, cat.index_time, cat.error),
            ('"0x8DF"', hashlib.sha256(body).hexdigest(), 1792475130, ""),
        )
        updated = cat.updated

        fetch.return_value = FakeResponse(304)
        self.assertEqual(winget.refresh(), "winget catalog unchanged")
        self.assertEqual(
            fetch.call_args.kwargs["headers"], {"If-None-Match": '"0x8DF"'}
        )
        cat.refresh_from_db()
        self.assertEqual((cat.updated, len(cat.packages)), (updated, 6))
        self.assertGreater(cat.checked, updated)

    def test_failures_keep_the_last_good(self, fetch):
        fetch.return_value = ok(make_msix())
        winget.refresh()
        cases = [
            (ok(make_msix(), **{"Content-MD5": "AAAA"}), "Content-MD5"),
            (ok(make_msix(major="1")), "index format '1'"),
            (ok(make_msix(rows=GOOD[:2] + BAD)), "only 2 usable packages"),
            (ok(make_msix(member="Public/other.db")), "Public/index.db is missing"),
            (ok(b"not a zip"), "source2.msix"),
            (FakeResponse(500), "HTTP 500"),
            (ok(b"x", **{"Content-Length": str(64 << 20)}), "larger than 32 MiB"),
        ]
        for response, error in cases:
            with self.subTest(error):
                fetch.return_value = response
                self.assertIn("not updated", winget.refresh())
                cat = WingetCatalog.load()
                self.assertIn(error, cat.error)
                self.assertEqual(len(cat.packages), 6)

        fetch.side_effect = requests.ConnectionError("boom")
        winget.refresh()
        self.assertEqual(WingetCatalog.load().error, "boom")

    def test_caps_while_streaming(self, fetch):
        body = make_msix()
        fetch.return_value = ok(body)
        with patch.object(winget, "MAX_MSIX", len(body) - 1):
            winget.refresh()
        self.assertIn("larger than", WingetCatalog.load().error)
        fetch.return_value = ok(body)
        with patch.object(winget, "MAX_INDEX", 1000):
            winget.refresh()
        self.assertIn("Public/index.db is larger", WingetCatalog.load().error)
        self.assertEqual(WingetCatalog.load().packages, [])

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_task_lock(self, fetch):
        cache.clear()
        cache.add("winget-catalog", "other", 60)
        self.assertEqual(
            refresh_winget_task(), "winget catalog refresh already running"
        )
        fetch.assert_not_called()
        cache.clear()


class TestIds(ULRMMTestCase):
    def test_id_regex(self):
        for good in ("7zip.7zip", "Febooti.Hash&CRC", "nitichote@dev.thaikeyfix", "a"):
            self.assertTrue(winget.ID_RE.fullmatch(good), good)
        for bad in ("-x", "_x", "a b", "a'b", "a\n", "a" * 129, ""):
            self.assertFalse(winget.ID_RE.fullmatch(bad), bad)


def catalog(*rows):
    WingetCatalog.objects.update_or_create(pk=1, defaults={"packages": list(rows)})


@override_settings(CACHES=LOCMEM_CACHE)
@patch("software.tasks.refresh_winget_task.delay")
class TestCatalogSearch(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        ChocoSoftware.objects.create(
            chocos=[{"name": "firefox"}, {"name": "7zip"}, {"name": "vlc"}, 5]
        )

    def get(self, **params):
        return self.client.get("/software/catalog/", params)

    def test_search(self, delay):
        catalog(
            ["Mozilla.Firefox", "Mozilla Firefox (en-US)", "157.0.1"],
            ["Mozilla.Firefox.ESR", "Firefox ESR", "140.4.0"],
            ["7zip.7zip", "7-Zip", "26.04"],
            ["bad"],
        )
        data = self.get(search="firefox").json()
        self.assertEqual(
            [(r["source"], r["id"]) for r in data["rows"]],
            [
                ("choco", "firefox"),
                ("winget", "Mozilla.Firefox.ESR"),
                ("winget", "Mozilla.Firefox"),
            ],
        )
        self.assertEqual((data["total"], data["truncated"]), (3, False))
        self.assertEqual(data["winget"]["count"], 3)
        self.assertEqual(
            self.get(source="winget", search="7").json()["rows"],
            [
                {
                    "source": "winget",
                    "id": "7zip.7zip",
                    "name": "7-Zip",
                    "version": "26.04",
                }
            ],
        )
        self.assertEqual(
            [r["id"] for r in self.get(source="choco").json()["rows"]],
            ["7zip", "firefox", "vlc"],
        )
        self.assertEqual(self.get(source="x").status_code, 400)
        self.assertEqual(self.get(search="x" * 101).status_code, 400)
        delay.assert_not_called()

    def test_truncation_and_queue_once(self, delay):
        ChocoSoftware.objects.all().delete()
        ChocoSoftware.objects.create(
            chocos=[{"name": f"pkg{i:04}"} for i in range(600)]
        )
        data = self.get().json()
        self.assertEqual((len(data["rows"]), data["total"]), (500, 600))
        self.assertTrue(data["truncated"])
        self.assertEqual(
            data["winget"], {"count": 0, "checked": None, "updated": None, "error": ""}
        )
        self.get()
        delay.assert_called_once_with()

    def test_needs_login(self, delay):
        self.check_not_authenticated("get", "/software/catalog/")


@patch("agents.models.Agent.nats_cmd")
class TestWingetInstall(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", version="3.20.10.2026")
        self.url = f"/software/{self.agent.agent_id}/"
        catalog(["7zip.7zip", "7-Zip", "26.04"], ["Febooti.Hash&CRC", "Hash", "1"])

    def post(self, name, source="winget"):
        return self.client.post(
            self.url, {"name": name, "source": source}, format="json"
        )

    def test_install(self, nats_cmd):
        nats_cmd.return_value = "ok"
        r = self.post("7ZIP.7zip")
        self.assertEqual(r.status_code, 200, r.data)
        action = PendingAction.objects.get(agent=self.agent)
        self.assertEqual(action.action_type, PAAction.WINGET_INSTALL)
        self.assertEqual(
            action.details,
            {
                "name": "7-Zip",
                "id": "7zip.7zip",
                "source": "winget",
                "output": None,
                "installed": False,
                "exit_code": None,
                "reboot": False,
            },
        )
        nats_cmd.assert_called_once_with(
            {
                "func": "installwithwinget",
                "winget_id": "7zip.7zip",
                "pending_action_pk": action.pk,
            },
            timeout=2,
        )
        audit = AuditLog.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(
            audit.after_value,
            "winget install --id 7zip.7zip --exact --source winget --scope machine",
        )
        self.assertIn("issued winget command", audit.message)
        self.assertEqual(
            (action.due, action.description), ("ASAP", "7-Zip software install")
        )
        self.assertEqual(self.post("Febooti.Hash&CRC").status_code, 200)

    def test_refusals(self, nats_cmd):
        nats_cmd.return_value = "ok"
        self.assertEqual(self.post("-x").data, "name must be a winget package id")
        self.assertEqual(
            self.post("Not.There").data, "Not.There is not in the winget catalog"
        )
        self.assertEqual(self.post("7zip.7zip", source="npm").status_code, 400)
        self.agent.version = "2.20.10.2026"
        self.agent.save(update_fields=["version"])
        r = self.post("7zip.7zip")
        self.assertEqual(r.status_code, 400)
        self.assertIn("needs agent 3.20.10.2026 or newer", r.data)
        nats_cmd.assert_not_called()
        self.assertFalse(PendingAction.objects.exists())

        linux = baker.make_recipe("agents.online_agent", plat="linux")
        r = self.client.post(
            f"/software/{linux.agent_id}/",
            {"name": "7zip.7zip", "source": "winget"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_agent_down_drops_the_action(self, nats_cmd):
        nats_cmd.return_value = "timeout"
        r = self.post("7zip.7zip")
        self.assertEqual((r.status_code, r.data), (400, "Unable to contact the agent"))
        self.assertFalse(PendingAction.objects.exists())

    def test_choco_unchanged(self, nats_cmd):
        nats_cmd.return_value = "ok"
        r = self.client.post(self.url, {"name": "vlc"}, format="json")
        self.assertEqual(r.status_code, 200)
        action = PendingAction.objects.get()
        self.assertEqual(
            (action.action_type, action.details),
            (
                PAAction.CHOCO_INSTALL,
                {"name": "vlc", "output": None, "installed": False},
            ),
        )
        nats_cmd.assert_called_once_with(
            {
                "func": "installwithchoco",
                "choco_prog_name": "vlc",
                "pending_action_pk": action.pk,
            },
            timeout=2,
        )
        self.assertEqual(self.post("vlc", source="choco").status_code, 200)

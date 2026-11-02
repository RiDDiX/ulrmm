# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import json
from unittest.mock import patch

from django.db import connection
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import AgentCustomField, Note
from clients.models import Client, Deployment, Site
from core.models import CustomField, GlobalKVStore
from scripts.models import Script, ScriptSnippet
from ulrmm.test import ULRMMTestCase

from . import engine, link, migrate
from .models import ImportedDevice, ImportSource, MigrateState
from .sources import SourceError, validate
from .sources.base import Source
from .tasks import fetch

BASE = "/importers/sources"

SNAPSHOT = {
    "clients": [
        {
            "ref": "1",
            "name": "Acme",
            "custom_fields": {"Contract": "gold"},
            "sites": [
                {"ref": "11", "name": "HQ", "custom_fields": {}},
                {"ref": "12", "name": "Branch", "custom_fields": {}},
            ],
        },
        {"ref": "2", "name": "Globex", "custom_fields": {}, "sites": []},
    ],
    "custom_fields": [
        {"model": "client", "name": "Contract", "type": "text", "options": []},
        {"model": "agent", "name": "Owner", "type": "text", "options": []},
        {"model": "agent", "name": "Managed", "type": "checkbox", "options": []},
    ],
    "scripts": [
        {"name": "Clean temp", "shell": "powershell", "body": "Remove-Item $env:TEMP"},
        {"name": "Uptime", "shell": "shell", "body": "uptime", "timeout": 30},
    ],
    "snippets": [{"name": "Helpers", "code": "function x {}"}],
    "keystore": [{"name": "LICENSE", "value": "abc-123"}],
    "devices": [
        {
            "ref": "d1",
            "site_ref": "11",
            "hostname": "ws01.acme.local",
            "plat": "windows",
            "monitoring_type": "workstation",
            "description": "front desk",
            "notes": ["new disk 2026"],
            "custom_fields": {"Owner": "Bob", "Managed": True},
        },
        {"ref": "d2", "site_ref": "11", "hostname": "srv01", "plat": "linux"},
        {"ref": "d3", "site_ref": "12", "hostname": "mac01", "plat": "darwin"},
        {"ref": "d4", "site_ref": "99", "hostname": "lost01", "plat": "windows"},
    ],
}


class FakeSource(Source):
    KIND = "upstream"
    SECRETS = ("api_key",)
    PUSH_PLATS = ("windows", "linux")
    pushed: list = []

    def fetch(self):
        return SNAPSHOT

    def push(self, ref, plat, command, url=""):
        if ref == "d2-fail":
            raise SourceError("agent offline")
        FakeSource.pushed.append((ref, plat, command, url))


def _source(**kw) -> ImportSource:
    return baker.make(
        ImportSource,
        kind="upstream",
        name="old",
        url="https://old.example.com",
        snapshot=validate(SNAPSHOT),
        last_fetch=djangotime.now(),
        **kw,
    )


class TestValidate(ULRMMTestCase):
    def test_cuts_and_drops(self):
        data = validate(
            {
                "clients": [
                    {"name": "  A   b ", "sites": [{"name": "x"}, {"name": "X"}]},
                    {"name": "a b"},
                    {"name": ""},
                    "junk",
                ],
                "devices": [
                    {"ref": "1", "hostname": "h", "plat": "BeOS", "goarch": "amd64"},
                    {"ref": "1", "hostname": "dup"},
                    {"ref": "2"},
                ],
                "scripts": [{"name": "s", "shell": "zsh", "timeout": True}],
                "keystore": [{"name": "k" * 40, "value": 5}],
            }
        )
        self.assertEqual([c["name"] for c in data["clients"]], ["A b"])
        self.assertEqual([s["name"] for s in data["clients"][0]["sites"]], ["x"])
        self.assertEqual(len(data["devices"]), 1)
        self.assertEqual(data["devices"][0]["plat"], "")
        self.assertEqual(data["scripts"][0]["shell"], "powershell")
        self.assertEqual(data["scripts"][0]["timeout"], 90)
        self.assertEqual(data["keystore"][0], {"name": "k" * 25, "value": "5"})

    def test_rejects_non_lists(self):
        with self.assertRaises(SourceError):
            validate({"clients": {"a": 1}})
        with self.assertRaises(SourceError):
            validate("nope")


class TestEngine(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_plan_then_import_twice(self):
        existing = baker.make("clients.Client", name="ACME")
        baker.make("clients.Site", client=existing, name="hq")
        baker.make(Script, name="Uptime", shell="shell")
        src = _source()

        plan = engine.plan(src)
        self.assertEqual(plan["clients"]["new"], ["Globex"])
        self.assertEqual(plan["sites"]["new"], ["Acme / Branch"])
        self.assertEqual(plan["scripts"]["new"], ["Clean temp"])
        self.assertEqual(plan["devices"]["new_count"], 4)
        self.assertEqual(plan["devices"]["without_site"], 1)

        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["clients"], 1)
        self.assertEqual(done["sites"], 1)
        self.assertEqual(done["custom_fields"], 3)
        self.assertEqual(done["scripts"], 1)
        self.assertEqual(done["snippets"], 1)
        self.assertEqual(done["keystore"], 1)
        self.assertEqual(done["devices"], 4)
        self.assertEqual(Client.objects.count(), 2)
        self.assertEqual(Site.objects.filter(client=existing).count(), 2)
        self.assertEqual(GlobalKVStore.objects.get(name="LICENSE").value, "abc-123")
        self.assertTrue(ScriptSnippet.objects.filter(name="Helpers").exists())
        field = CustomField.objects.get(model="client", name="Contract")
        self.assertEqual(field.get_or_create_field_value(existing).value, "gold")
        lost = ImportedDevice.objects.get(ref="d4")
        self.assertIsNone(lost.site)

        again = engine.run(src, engine.PARTS)
        self.assertEqual(
            {k: v for k, v in again.items() if v}, {}, "a second run adds nothing"
        )
        self.assertEqual(Script.objects.count(), 2)

    def test_existing_values_and_secrets_stay(self):
        GlobalKVStore.objects.create(name="LICENSE", value="mine")
        src = _source()
        engine.run(src, ["keystore", "custom_fields", "clients"])
        self.assertEqual(GlobalKVStore.objects.get(name="LICENSE").value, "mine")
        acme = Client.objects.get(name="Acme")
        field = CustomField.objects.get(model="client", name="Contract")
        row = field.get_or_create_field_value(acme)
        row.save_to_field("silver")
        engine.run(src, ["clients"])
        self.assertEqual(field.get_or_create_field_value(acme).value, "silver")


class TestLink(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.src = _source()
        engine.run(self.src, engine.PARTS)
        self.hq = Site.objects.get(name="HQ")

    def test_enroll_links_same_site_only(self):
        other = Site.objects.get(name="Branch")
        stranger = baker.make("agents.Agent", site=other, hostname="WS01")
        link.on_enroll(stranger)
        self.assertIsNone(ImportedDevice.objects.get(ref="d1").agent)

        agent = baker.make("agents.Agent", site=self.hq, hostname="WS01")
        link.on_enroll(agent)
        device = ImportedDevice.objects.get(ref="d1")
        self.assertEqual(device.agent, agent)
        self.assertEqual(device.migrate_state, MigrateState.LINKED)
        agent.refresh_from_db()
        self.assertEqual(agent.description, "front desk")
        self.assertEqual(
            list(Note.objects.filter(agent=agent).values_list("note", flat=True)),
            ["new disk 2026"],
        )
        owner = AgentCustomField.objects.get(agent=agent, field__name="Owner")
        self.assertEqual(owner.value, "Bob")
        managed = AgentCustomField.objects.get(agent=agent, field__name="Managed")
        self.assertIs(managed.value, True)

    def test_link_run_takes_unique_matches(self):
        baker.make("agents.Agent", site=self.hq, hostname="srv01")
        # two lost01 elsewhere and no site on the device: told apart by serial
        a = baker.make(
            "agents.Agent",
            hostname="lost01",
            plat="linux",
            wmi_detail={"serialnumber": "S1"},
        )
        baker.make(
            "agents.Agent",
            hostname="lost01",
            plat="linux",
            wmi_detail={"serialnumber": "S2"},
        )
        ImportedDevice.objects.filter(ref="d4").update(serial="s1")
        self.assertEqual(link.link_source(self.src), 2)
        self.assertEqual(ImportedDevice.objects.get(ref="d4").agent, a)
        self.assertEqual(link.link_source(self.src), 0)


@patch("importers.migrate.signing.api_url", return_value="https://api.example.com")
@patch("importers.migrate.for_source")
class TestMigrate(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.src = _source()
        engine.run(self.src, engine.PARTS)
        FakeSource.pushed = []

    def test_sends_per_site_deployment(self, for_source, _):
        for_source.return_value = FakeSource("https://x", True, {}, {})
        ids = list(ImportedDevice.objects.values_list("pk", flat=True))
        result = migrate.send(self.src, ids)
        # d3 is macOS (no push), d4 has no site
        self.assertEqual(result, {"sent": 2, "failed": 1, "skipped": 1})
        win = next(p for p in FakeSource.pushed if p[0] == "d1")
        uid = win[3].split("/clients/")[1].split("/")[0]
        dep = Deployment.objects.get(uid=uid)
        self.assertEqual(
            (dep.mon_type, dep.site.name, dep.max_enrollments), ("workstation", "HQ", 1)
        )
        self.assertEqual(
            win[3], f"https://api.example.com/clients/{uid}/deploy/?fmt=ps1&arch=amd64"
        )
        self.assertTrue(win[2].startswith("Start-Process -WindowStyle Hidden"))
        encoded = win[2].split("'-EncodedCommand','")[1].rstrip("'")
        self.assertIn(win[3], base64.b64decode(encoded).decode("utf-16-le"))
        lin = next(p for p in FakeSource.pushed if p[0] == "d2")
        self.assertTrue(lin[3].endswith("?fmt=sh"))
        script = base64.b64decode(lin[2].split("echo ")[1].split(" ")[0]).decode()
        self.assertIn(
            f"curl -fsSL --proto '=https' --proto-redir '=https' -o /tmp/ulrmm-install.sh '{lin[3]}'",
            script,
        )
        self.assertTrue(script.startswith("trap 'rm -f /tmp/ulrmm-import.sh' EXIT"))
        mac = ImportedDevice.objects.get(ref="d3")
        self.assertEqual(mac.migrate_state, MigrateState.FAILED)
        self.assertEqual(
            ImportedDevice.objects.get(ref="d1").migrate_state, MigrateState.SENT
        )

    def test_push_error_is_kept(self, for_source, _):
        for_source.return_value = FakeSource("https://x", True, {}, {})
        ImportedDevice.objects.filter(ref="d2").update(ref="d2-fail")
        d = ImportedDevice.objects.get(ref="d2-fail")
        self.assertEqual(migrate.send(self.src, [d.pk])["failed"], 1)
        d.refresh_from_db()
        self.assertEqual(d.migrate_error, "agent offline")
        self.assertFalse(Deployment.objects.exists(), "an unused link is deleted")

    def test_linked_devices_are_skipped(self, for_source, _):
        for_source.return_value = FakeSource("https://x", True, {}, {})
        d = ImportedDevice.objects.get(ref="d1")
        d.agent = baker.make("agents.Agent")
        d.save()
        self.assertEqual(
            migrate.send(self.src, [d.pk]), {"sent": 0, "failed": 0, "skipped": 1}
        )
        self.assertFalse(Deployment.objects.exists())


class TestViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_superuser_only(self):
        user = self.create_user_with_roles(["can_manage_integrations"])
        self.client.force_authenticate(user=user)
        for method, url in (
            ("get", f"{BASE}/"),
            ("post", f"{BASE}/"),
            ("post", f"{BASE}/1/migrate/"),
        ):
            self.check_not_authorized(method, url)
        self.check_not_authenticated("get", f"{BASE}/")

    def test_secrets_write_only_and_url_change(self):
        r = self.client.post(
            f"{BASE}/",
            {
                "kind": "upstream",
                "name": "old",
                "url": "https://old.example.com",
                "secrets": {"api_key": "K1"},
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertNotIn("secrets", r.data)
        self.assertEqual(r.data["secrets_set"], ["api_key"])
        src = ImportSource.objects.get()
        self.assertEqual(json.loads(src.secret), {"api_key": "K1"})
        with connection.cursor() as cur:
            cur.execute("SELECT secret FROM importers_importsource")
            self.assertNotIn("K1", cur.fetchone()[0])

        url = f"{BASE}/{src.pk}/"
        r = self.client.put(url, {"url": "https://evil.example.com"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(
            url, {"name": "renamed", "secrets": {"api_key": ""}}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        src.refresh_from_db()
        self.assertEqual(json.loads(src.secret), {"api_key": "K1"})
        r = self.client.put(url, {"kind": "ninjaone"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            f"{BASE}/",
            {"kind": "upstream", "name": "x", "url": "http://plain"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_flow(self):
        src = baker.make(ImportSource, kind="upstream", name="old", url="https://old")
        with patch(
            "importers.tasks.for_source",
            return_value=FakeSource("https://x", True, {}, {}),
        ):
            fetch(src)
        src.refresh_from_db()
        self.assertTrue(src.last_fetch)
        r = self.client.get(f"{BASE}/{src.pk}/plan/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["clients"]["new_count"], 2)
        r = self.client.post(
            f"{BASE}/{src.pk}/import/", {"parts": ["bogus"]}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            f"{BASE}/{src.pk}/import/", {"parts": list(engine.PARTS)}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["devices"], 4)
        r = self.client.get(f"{BASE}/{src.pk}/devices/")
        self.assertEqual(len(r.data), 4)
        with patch("importers.views.migrate_task.delay") as delay:
            r = self.client.post(
                f"{BASE}/{src.pk}/migrate/",
                {"devices": [r.data[0]["id"], 999999]},
                format="json",
            )
        self.assertEqual(r.status_code, 202)
        delay.assert_called_once()
        self.assertEqual(len(delay.call_args.args[1]), 1)

    def test_fetch_error_is_stored(self):
        src = baker.make(ImportSource, kind="upstream", name="old", url="https://old")

        class Broken(FakeSource):
            def fetch(self):
                raise SourceError("/clients/ answered 500")

        with patch(
            "importers.tasks.for_source", return_value=Broken("https://x", True, {}, {})
        ):
            fetch(src)
        src.refresh_from_db()
        self.assertEqual(src.last_error, "/clients/ answered 500")
        self.assertIsNone(src.last_fetch)

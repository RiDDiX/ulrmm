# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import copy
import json
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from accounts.models import Role, User
from accounts.tests import wrong_code
from accounts.utils import DELETE_NEEDS_TOTP
from agents.models import AgentCustomField, Note
from alerts.models import AlertTemplate
from automation.models import Policy
from clients.models import Client, Deployment, Site
from core.models import CoreSettings, CustomField, GlobalKVStore, URLAction
from logs.models import AuditLog
from reporting.models import ReportTemplate
from scripts.models import Script, ScriptSnippet
from winupdate.models import WinUpdatePolicy
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

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
        self.assertEqual(result, {"sent": 2, "failed": 2, "skipped": 0})
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
            "curl -fsSL --proto '=https' --proto-redir '=https' "
            f"-o \"$d/install.sh\" '{lin[3]}'",
            script,
        )
        self.assertTrue(script.startswith('rm -f "$0"\nd=$(mktemp -d) && trap'))
        for command in (lin[2], script):
            self.assertIn("mktemp -d", command)
            self.assertNotIn("/tmp/ulrmm-", command)
        mac = ImportedDevice.objects.get(ref="d3")
        self.assertEqual(mac.migrate_state, MigrateState.FAILED)
        lost = ImportedDevice.objects.get(ref="d4")
        self.assertEqual(
            (lost.migrate_state, lost.migrate_error),
            (MigrateState.FAILED, "no site, assign one first"),
        )
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
        # space and "!" are not in base64, the token cannot hold it by chance
        key = "K1 secret!"
        r = self.client.post(
            f"{BASE}/",
            {
                "kind": "upstream",
                "name": "old",
                "url": "https://old.example.com",
                "secrets": {"api_key": key},
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertNotIn("secrets", r.data)
        self.assertEqual(r.data["secrets_set"], ["api_key"])
        src = ImportSource.objects.get()
        self.assertEqual(json.loads(src.secret), {"api_key": key})
        with connection.cursor() as cur:
            cur.execute("SELECT secret FROM importers_importsource")
            self.assertNotIn(key, cur.fetchone()[0])

        url = f"{BASE}/{src.pk}/"
        r = self.client.put(url, {"url": "https://evil.example.com"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(
            url, {"name": "renamed", "secrets": {"api_key": ""}}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        src.refresh_from_db()
        self.assertEqual(json.loads(src.secret), {"api_key": key})
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
        for path in ("import", "migrate"):
            r = self.client.post(f"{BASE}/{src.pk}/{path}/", ["x"], format="json")
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


def _recorded() -> dict:
    from .sources.upstream import Upstream
    from .test_sources import Recorded

    rec = Recorded("upstream")
    with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
        return validate(Upstream("https://old", True, {}, {"api_key": "K"}).fetch())


MORE = ("url_actions", "alert_templates", "policies", "roles", "users", "reports")
# the template whose actions over there are not in the source's lists
LIBRARY_LOST = [
    {
        "name": "Library paging: failure action",
        "reason": "its script is not in the source's list, set one here",
    },
    {
        "name": "Library paging: resolved action",
        "reason": "its URL action is not in the source's list, set one here",
    },
]


class TestMoreParts(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.snap = _recorded()

    def source(self, snap=None) -> ImportSource:
        return baker.make(
            ImportSource,
            kind="upstream",
            name="old",
            url="https://old.example.com",
            snapshot=snap or self.snap,
            last_fetch=djangotime.now(),
        )

    def test_plan_import_twice(self):
        src = self.source()
        plan = engine.plan(src)
        self.assertEqual(plan["url_actions"]["new_count"], 2)
        self.assertEqual(plan["alert_templates"]["new_count"], 4)
        self.assertEqual(plan["alert_templates"]["existing_count"], 0)
        self.assertEqual(plan["policies"]["new_count"], 3)
        self.assertEqual(plan["roles"]["new_count"], 2)
        self.assertEqual(plan["roles"]["unknown_permissions"], 2)
        self.assertEqual(plan["users"]["new_count"], 3)
        self.assertIn("inactive", plan["users"]["note"])
        self.assertEqual(
            sorted(plan["reports"]["new"]),
            [
                "Data query: Offline agents",
                "HTML template: Corporate frame",
                "Report: Inventory summary",
            ],
        )
        # two devices have no detail recorded and no exclusions
        self.assertEqual(plan["devices"]["with_device_data"], 4)
        for part in MORE:
            want = LIBRARY_LOST if part == "alert_templates" else []
            self.assertEqual(plan[part]["skipped"], want, part)

        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["skipped"], {"alert_templates": LIBRARY_LOST})
        self.assertEqual(
            {p: done[p] for p in MORE},
            {
                "url_actions": 2,
                "alert_templates": 4,
                "policies": 3,
                "roles": 2,
                "users": 3,
                "reports": 3,
            },
        )

        hook = URLAction.objects.get(name="Notify chat hook")
        self.assertIn("Bearer MASKED", hook.rest_headers)
        with connection.cursor() as cur:
            cur.execute(
                "SELECT rest_headers FROM core_urlaction WHERE id=%s", [hook.pk]
            )
            self.assertNotIn("Bearer", cur.fetchone()[0])

        strict = AlertTemplate.objects.get(name="Strict paging")
        self.assertEqual(strict.action.name, "Disk Usage Report")
        self.assertEqual([s.name for s in strict.excluded_sites.all()], ["Berlin HQ"])
        self.assertEqual(strict.text_recipients, ["+4915112345678"])
        library = AlertTemplate.objects.get(name="Library paging")
        self.assertEqual((library.action, library.resolved_action_rest), (None, None))
        core = CoreSettings.objects.first()
        self.assertEqual(core.alert_template.name, "Quiet nights")

        fab = Client.objects.get(name="Fabrikam AG")
        self.assertEqual(
            (fab.server_policy.name, fab.workstation_policy.name, fab.alert_template),
            ("Servers baseline", "Workstations baseline", strict),
        )
        servers = Policy.objects.get(name="Servers baseline")
        self.assertEqual(servers.policychecks.count(), 5)
        self.assertEqual(servers.autotasks.count(), 2)
        self.assertEqual(servers.winupdatepolicy.get().critical, "approve")
        ws = Policy.objects.get(name="Workstations baseline")
        self.assertTrue(ws.enforced)
        script_check = ws.policychecks.get(check_type="script")
        self.assertEqual(script_check.script.name, "Disk Usage Report")
        weekly = servers.autotasks.get(name="Weekly cleanup")
        script = Script.objects.get(name="Disk Usage Report")
        self.assertEqual(weekly.actions[0]["script"], script.pk)

        helpdesk = Role.objects.get(name="Helpdesk")
        self.assertTrue(helpdesk.can_list_agents)
        self.assertFalse(helpdesk.is_superuser)
        self.assertEqual(
            sorted(s.name for s in helpdesk.can_view_sites.all()),
            ["Berlin HQ", "Hamburg Branch"],
        )
        for name in ("admin", "helen.help", "olaf.audit"):
            user = User.objects.get(username=name)
            self.assertFalse(user.is_active, name)
            self.assertFalse(user.has_usable_password(), name)
            self.assertFalse(user.is_superuser, name)
        self.assertEqual(User.objects.get(username="olaf.audit").role.name, "Auditor")

        report = ReportTemplate.objects.get(name="Inventory summary")
        self.assertEqual(report.template_html.name, "Corporate frame")

        again = engine.run(src, engine.PARTS)
        self.assertEqual({k: v for k, v in again.items() if v}, {})
        self.assertEqual(engine.plan(src)["policies"]["new_count"], 0)
        self.assertEqual(engine.plan(src)["alert_templates"]["skipped"], [])

    def test_what_exists_stays(self):
        mine = baker.make(Policy, name="servers BASELINE")
        other = baker.make(Policy, name="Mine")
        template = baker.make(AlertTemplate, name="Here")
        core = CoreSettings.objects.first()
        core.alert_template = template
        core.save()
        engine.run(self.source(), ["clients"])
        fab = Client.objects.get(name="Fabrikam AG")
        fab.server_policy = other
        fab.save()
        baker.make(User, username="helen.help", is_active=True)

        done = engine.run(self.source(), ["alert_templates", "policies", "users"])
        self.assertEqual(done["policies"], 2)
        self.assertFalse(mine.policychecks.exists(), "a matched policy is not filled")
        fab.refresh_from_db()
        self.assertEqual(fab.server_policy, other)
        self.assertEqual(fab.workstation_policy.name, "Workstations baseline")
        core.refresh_from_db()
        self.assertEqual(core.alert_template, template)
        self.assertTrue(User.objects.get(username="helen.help").is_active)

    def test_unresolved_references(self):
        snap = copy.deepcopy(self.snap)
        snap["scripts"] = [
            s for s in snap["scripts"] if s["name"] != "Disk Usage Report"
        ]
        helpdesk = next(r for r in snap["roles"] if r["name"] == "Helpdesk")
        helpdesk["clients"] = ["Nobody Inc"]
        auditor = next(r for r in snap["roles"] if r["name"] == "Auditor")
        auditor["superuser"] = True
        ws = next(p for p in snap["policies"] if p["name"] == "Workstations baseline")
        failing = ws["checks"][0]
        ws["tasks"].append(
            {
                "ref": "99",
                "name": "On failure",
                "fields": {"name": "On failure", "task_type": "checkfailure"},
                "actions": [
                    {"type": "cmd", "command": "echo", "shell": "cmd", "timeout": 30}
                ],
                "assigned_check": failing["ref"],
                "custom_field": "",
            }
        )
        src = self.source(snap)

        plan = engine.plan(src)
        self.assertIn(
            {"name": "Strict paging", "reason": "script Disk Usage Report is not here"},
            plan["alert_templates"]["skipped"],
        )
        reasons = {s["name"]: s["reason"] for s in plan["policies"]["skipped"]}
        self.assertEqual(
            reasons["Workstations baseline: " + failing["desc"]],
            "script Disk Usage Report is not here",
        )
        self.assertEqual(
            reasons["Workstations baseline: On failure"], "its check was not imported"
        )
        self.assertEqual(
            reasons["Servers baseline: Daily inventory"],
            "script Disk Usage Report is not here",
        )
        roles = {s["name"]: s["reason"] for s in plan["roles"]["skipped"]}
        self.assertEqual(roles["Helpdesk"], "client Nobody Inc is not here")
        self.assertIn("superuser", roles["Auditor"])
        self.assertIn(
            {
                "name": "CONTOSO-WS014: Local manual script",
                "reason": "script Disk Usage Report is not here",
            },
            plan["devices"]["skipped"],
        )
        users = {s["name"]: s["reason"] for s in plan["users"]["skipped"]}
        self.assertEqual(
            users,
            {
                "helen.help: role Helpdesk": engine.NO_ROLE,
                "olaf.audit: role Auditor": engine.NO_ROLE,
            },
        )
        self.assertEqual(plan["users"]["new_count"], 3)

        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["alert_templates"], 3)
        self.assertEqual(done["policies"], 3, "a left out check never stops its policy")
        self.assertEqual(
            {s["name"] for s in done["skipped"]["alert_templates"]},
            {"Strict paging"} | {s["name"] for s in LIBRARY_LOST},
        )
        names = {s["name"] for s in done["skipped"]["policies"]}
        self.assertIn("Workstations baseline: On failure", names)
        self.assertIn("Workstations baseline: alert template Strict paging", names)
        self.assertFalse(
            Policy.objects.get(name="Workstations baseline").alert_template
        )
        self.assertEqual(done["roles"], 0)
        # imported without a role, which grants nothing, and listed
        self.assertEqual(done["users"], 3)
        self.assertEqual(
            {s["name"] for s in done["skipped"]["users"]},
            {"helen.help: role Helpdesk", "olaf.audit: role Auditor"},
        )
        for name in ("helen.help", "olaf.audit"):
            user = User.objects.get(username=name)
            self.assertEqual((user.role, user.is_active), (None, False), name)
        self.assertFalse(Role.objects.exists())

    def test_plan_counts_left_out(self):
        snap = copy.deepcopy(self.snap)
        snap["scripts"] = [
            s for s in snap["scripts"] if s["name"] != "Disk Usage Report"
        ]
        next(r for r in snap["roles"] if r["name"] == "Auditor")["superuser"] = True
        report = next(
            r for r in snap["report_templates"] if r["name"] == "Inventory summary"
        )
        report["template_html"] = "Gone frame"
        baker.make(Role, name="Helpdesk")
        baker.make(User, username="admin")
        plan = engine.plan(self.source(snap))

        def counts(part):
            p = plan[part]
            return (p["total"], p["new_count"], p["existing_count"], p["skipped_count"])

        # left out as a whole: neither new nor existing
        self.assertEqual(counts("roles"), (2, 0, 1, 1))
        # the library template comes without its actions, listed twice
        self.assertEqual(counts("alert_templates"), (4, 3, 0, 3))
        self.assertEqual(counts("reports"), (3, 2, 0, 1))
        # a user without its role and a policy without a check are still added
        self.assertEqual(counts("users"), (3, 2, 1, 1))
        self.assertEqual(counts("policies")[:3], (3, 3, 0))
        self.assertGreater(counts("policies")[3], 0)

    def test_invalid_rows_are_left_out(self):
        snap = copy.deepcopy(self.snap)
        snap["url_actions"][0]["action_type"] = "web"
        snap["url_actions"][0]["pattern"] = ""
        snap["users"][1]["username"] = "bad name!"
        src = self.source(snap)
        done = engine.run(src, ["url_actions", "roles", "users"])
        self.assertEqual(done["url_actions"], 1)
        self.assertEqual(done["users"], 2)
        self.assertEqual([s["name"] for s in done["skipped"]["users"]], ["bad name!"])
        self.assertTrue(done["skipped"]["url_actions"][0]["reason"])


@patch("autotasks.tasks.create_win_task_schedule.delay")
class TestLinkDeviceData(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.src = baker.make(
            ImportSource,
            kind="upstream",
            name="old",
            url="https://old.example.com",
            snapshot=_recorded(),
            last_fetch=djangotime.now(),
        )
        engine.run(self.src, engine.PARTS)
        self.hq = Site.objects.get(name="Berlin HQ")

    def enroll(self, hostname, site, patch_policy=None, plat="windows", **kw):
        agent = baker.make(
            "agents.Agent", site=site, hostname=hostname, plat=plat, **kw
        )
        WinUpdatePolicy.objects.create(agent=agent, **(patch_policy or {}))
        with self.captureOnCommitCallbacks(execute=True):
            link.on_enroll(agent)
        agent.refresh_from_db()
        return agent

    def test_defaults_take_the_device_data(self, delay):
        device = ImportedDevice.objects.get(hostname="CONTOSO-DC01")
        device.data["patch_policy"]["critical"] = "approve"
        device.save()
        agent = self.enroll("CONTOSO-DC01", self.hq, monitoring_type="server")
        self.assertEqual(
            (
                agent.time_zone,
                agent.check_interval,
                agent.offline_time,
                agent.maintenance_mode,
                agent.block_policy_inheritance,
                agent.overdue_email_alert,
            ),
            ("Europe/Berlin", 45, 7, True, True, True),
        )
        self.assertEqual(
            list(agent.agentchecks.values_list("check_type", flat=True)), ["diskspace"]
        )
        task = agent.autotasks.get()
        self.assertEqual(task.name, "Local nightly job")
        delay.assert_called_once_with(pk=task.pk)
        self.assertEqual(agent.winupdatepolicy.get().critical, "approve")
        device = ImportedDevice.objects.get(agent=agent)
        self.assertEqual(device.data["link_skipped"], [])

        self.assertEqual(link.link_source(self.src), 0)
        self.assertEqual(agent.agentchecks.count(), 1, "linking stays idempotent")

    def test_operator_values_stay(self, delay):
        mine = baker.make(Policy, name="Mine")
        device = ImportedDevice.objects.get(hostname="CONTOSO-WS014")
        device.data["patch_policy"]["critical"] = "approve"
        device.save()
        agent = self.enroll(
            "CONTOSO-WS014",
            self.hq,
            patch_policy={"critical": "manual"},
            monitoring_type="workstation",
            check_interval=300,
            policy=mine,
        )
        self.assertEqual(agent.check_interval, 300)
        self.assertEqual(agent.policy, mine)
        self.assertEqual(agent.winupdatepolicy.get().critical, "manual")
        self.assertEqual(agent.time_zone, "America/New_York")

        other = self.enroll("CONTOSO-WS014", self.hq, monitoring_type="workstation")
        self.assertIsNone(other.policy, "a device links once")

    def test_policy_and_exclusions(self, delay):
        hamburg = Site.objects.get(name="Hamburg Branch")
        device = ImportedDevice.objects.get(hostname="contoso-web01")
        service = {"check_type": "winsvc", "svc_name": "Spooler"}
        device.data["checks"] = [
            {"ref": "1", "desc": "Spooler", "script": None, "fields": service}
        ]
        device.save()
        web = self.enroll(
            "contoso-web01", hamburg, plat="linux", monitoring_type="server"
        )
        servers = Policy.objects.get(name="Servers baseline")
        self.assertIn(web, servers.excluded_agents.all())
        device.refresh_from_db()
        self.assertEqual(
            device.data["link_skipped"],
            [
                {
                    "name": "Spooler",
                    "reason": "winsvc checks are only supported on Windows agents",
                }
            ],
        )
        ws = self.enroll("CONTOSO-WS014", self.hq, monitoring_type="workstation")
        self.assertEqual(ws.policy.name, "Workstations baseline")

    def test_left_out_is_kept(self, delay):
        Policy.objects.filter(name="Workstations baseline").delete()
        agent = self.enroll("CONTOSO-WS014", self.hq, monitoring_type="workstation")
        device = ImportedDevice.objects.get(agent=agent)
        self.assertIn(
            {"name": "policy Workstations baseline", "reason": "it is not here"},
            device.data["link_skipped"],
        )
        r = self.client.get(f"{BASE}/{self.src.pk}/devices/")
        row = next(d for d in r.data if d["id"] == device.pk)
        self.assertEqual(row["link_skipped"], device.data["link_skipped"])
        # a new import keeps what the link step reported
        engine.run(self.src, ["devices"])
        device.refresh_from_db()
        self.assertTrue(device.data["link_skipped"])


class TestMoreViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_parts_per_source_and_import(self):
        src = baker.make(
            ImportSource,
            kind="upstream",
            name="old",
            url="https://old",
            snapshot=_recorded(),
            last_fetch=djangotime.now(),
        )
        ninja = baker.make(ImportSource, kind="ninjaone", name="n", url="https://n")
        r = self.client.get(f"{BASE}/")
        parts = {s["kind"]: s["parts"] for s in r.data}
        self.assertEqual(set(parts["upstream"]), set(engine.PARTS))
        self.assertNotIn("policies", parts["ninjaone"])
        del ninja

        r = self.client.get(f"{BASE}/{src.pk}/plan/")
        self.assertEqual(r.data["users"]["new_count"], 3)
        self.assertNotIn("MASKED", json.dumps(r.data))
        r = self.client.post(
            f"{BASE}/{src.pk}/import/", {"parts": ["url_actions"]}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["url_actions"], 2)
        self.assertNotIn("MASKED", json.dumps(r.data))
        self.assertTrue(
            AuditLog.objects.filter(object_type="urlaction", action="add").exists()
        )

        # one entry for the run, next to the entries per object
        r = self.client.post(
            f"{BASE}/{src.pk}/import/",
            {"parts": ["roles", "url_actions", "clients"]},
            format="json",
        )
        entry = AuditLog.objects.filter(object_type="bulk").latest("pk")
        self.assertEqual(entry.username, "john")
        self.assertIn("john imported from old", entry.message)
        self.assertEqual(
            entry.after_value,
            {
                "source": "old",
                "parts": ["clients", "url_actions", "roles"],
                "added": {"clients": 2, "url_actions": 0, "roles": 2, "sites": 3},
                "left_out": {"clients": 0, "url_actions": 0, "roles": 0},
            },
        )


class TestEncryptedData(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def raw(self, table, column, pk):
        with connection.cursor() as cur:
            cur.execute(f"SELECT {column}::text FROM {table} WHERE id=%s", [pk])
            return cur.fetchone()[0]

    def device_with_secret(self, src):
        check = {"check_type": "script", "env_vars": ["TOKEN=s3cret-env"]}
        return ImportedDevice.objects.create(
            source=src,
            ref="d9",
            hostname="h9",
            data={"checks": [{"ref": "1", "desc": "x", "fields": check}]},
        )

    def test_stored_encrypted_read_as_dict(self):
        src = _source()
        device = self.device_with_secret(src)
        self.assertNotIn(
            "abc-123", self.raw("importers_importsource", "snapshot", src.pk)
        )
        self.assertNotIn(
            "s3cret-env", self.raw("importers_importeddevice", "data", device.pk)
        )
        src.refresh_from_db()
        self.assertEqual(src.snapshot["keystore"][0]["value"], "abc-123")
        device.refresh_from_db()
        self.assertEqual(
            device.data["checks"][0]["fields"]["env_vars"], ["TOKEN=s3cret-env"]
        )
        ImportSource.objects.filter(pk=src.pk).update(snapshot={"keystore": []})
        self.assertEqual(ImportSource.objects.get(pk=src.pk).snapshot, {"keystore": []})

    def test_migration_back_and_forth(self):
        from django.db.migrations.executor import MigrationExecutor

        src = _source()
        device = self.device_with_secret(src)
        with connection.cursor() as cur:
            # rows written in this test would block the ALTER TABLE otherwise
            cur.execute("SET CONSTRAINTS ALL IMMEDIATE")

        def migrate(target):
            executor = MigrationExecutor(connection)
            executor.migrate([("importers", target)])

        migrate("0003_old_agent_removal")
        snapshot = self.raw("importers_importsource", "snapshot", src.pk)
        self.assertEqual(json.loads(snapshot)["keystore"][0]["value"], "abc-123")
        self.assertIn(
            "s3cret-env", self.raw("importers_importeddevice", "data", device.pk)
        )
        migrate("0004_encrypt_snapshot")
        self.assertNotIn(
            "abc-123", self.raw("importers_importsource", "snapshot", src.pk)
        )
        self.assertNotIn(
            "s3cret-env", self.raw("importers_importeddevice", "data", device.pk)
        )
        src.refresh_from_db()
        self.assertEqual(src.snapshot["keystore"][0]["value"], "abc-123")


def _wmi(serial, ips) -> dict:
    return {
        "bios": [[{"SerialNumber": serial}]],
        "network_config": [[{"IPAddress": [ip, "fe80::1"]}] for ip in ips],
    }


class FakeRemote:
    """The other server's live device view and removal call."""

    def __init__(self, detail):
        self.detail = detail
        self.removed = []
        self.answer_error = None
        self.detail_error = None

    def device(self, ref):
        if self.detail_error:
            raise self.detail_error
        return self.detail

    def remove(self, ref, hostname):
        self.removed.append((ref, hostname))
        if self.answer_error:
            raise self.answer_error


@patch("importers.tasks.recover_task.apply_async")
class TestRemoval(ULRMMTestCase):
    def setUp(self):
        from . import removal

        self.removal = removal
        self.authenticate()
        self.setup_coresettings()
        self.src = baker.make(
            ImportSource, kind="upstream", name="old", url="https://o"
        )
        now = djangotime.now()
        self.agent = baker.make(
            "agents.Agent",
            hostname="WS01",
            plat="windows",
            last_seen=now,
            public_ip="203.0.113.10",
            wmi_detail=_wmi("CZC1234XYZ", ["172.17.9.121", "172.17.9.6"]),
        )
        self.device = ImportedDevice.objects.create(
            source=self.src,
            ref="AGENT1",
            hostname="ws01.acme.local",
            serial="CZC1234XYZ",
            plat="windows",
            agent=self.agent,
            sent_at=now - djangotime.timedelta(hours=1),
        )
        self.removal.request(self.src, [self.device.pk], "john")
        self.remote = FakeRemote(
            {
                "hostname": "WS01",
                "plat": "windows",
                "status": "online",
                "public_ip": "203.0.113.10",
                "local_ips": "172.17.9.121, 172.17.9.6",
                "wmi_detail": _wmi("CZC1234XYZ", ["172.17.9.121", "172.17.9.6"]),
            }
        )

    def step(self):
        device = ImportedDevice.objects.select_related("source").get(pk=self.device.pk)
        return self.removal.step(device, self.remote), device

    def state(self):
        d = ImportedDevice.objects.get(pk=self.device.pk)
        return d.remove_state, d.remove_reason

    def test_removed_once_with_recovery_on_windows(self, later):
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(self.remote.removed, [("AGENT1", "WS01")])
        d = ImportedDevice.objects.get(pk=self.device.pk)
        self.assertEqual((d.remove_state, d.recovery), ("removed", "pending"))
        self.assertTrue(d.remove_at)
        later.assert_called_once_with((d.pk,), countdown=300)
        self.assertTrue(
            AuditLog.objects.filter(message__contains="asked to remove").exists()
        )
        self.assertTrue(
            AuditLog.objects.filter(message__contains="sent the removal").exists()
        )
        # never a second call, not even after a new request
        self.assertEqual(self.step()[0], "")
        self.assertEqual(self.removal.request(self.src, [d.pk], "john"), 0)
        from .tasks import remove_task

        self.assertEqual(remove_task(), "idle")
        self.assertEqual(len(self.remote.removed), 1)

    def test_each_condition_blocks(self, later):
        now = djangotime.now()
        hour = djangotime.timedelta(hours=1)
        cases = [
            ("not linked", {"agent": None}, {}, {}, "waiting_here"),
            (
                "installed by hand",
                {"sent_at": None},
                {"last_seen": now - 2 * hour},
                {},
                "waiting_here",
            ),
            ("no check-in", {}, {"last_seen": now - 2 * hour}, {}, "waiting_here"),
            (
                "offline here",
                {"sent_at": now - 3 * hour},
                {"last_seen": now - 2 * hour},
                {},
                "waiting_here",
            ),
            ("offline there", {}, {}, {"status": "offline"}, "waiting_there"),
            ("other host", {}, {}, {"hostname": "WS02"}, "waiting_there"),
            ("other platform", {}, {}, {"plat": "linux"}, "waiting_there"),
        ]
        good = dict(self.remote.detail)
        for name, device, agent, detail, state in cases:
            with self.subTest(name):
                ImportedDevice.objects.filter(pk=self.device.pk).update(
                    **{
                        "agent": self.agent,
                        "sent_at": now - hour,
                        "remove_state": "waiting_here",
                        **device,
                    }
                )
                type(self.agent).objects.filter(pk=self.agent.pk).update(
                    **{"last_seen": now, **agent}
                )
                self.remote.detail = {**good, **detail}
                self.assertEqual(self.step()[0], state)
                self.assertTrue(self.state()[1])
                self.assertEqual(self.remote.removed, [])
        later.assert_not_called()

    def test_errors_over_there_keep_waiting(self, later):
        self.remote.detail_error = SourceError("/agents/AGENT1/ answered 500")
        self.assertEqual(self.step()[0], "waiting_there")
        self.assertEqual(self.state()[1], "/agents/AGENT1/ answered 500")
        from .sources.base import NotFound

        # gone over there before any call: nothing to wait for
        self.remote.detail_error = NotFound("404")
        self.assertEqual(self.step()[0], "not_removed")
        self.assertEqual(self.state()[1], self.removal.GONE)
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_state="waiting_there"
        )
        self.remote.detail_error = ValueError("odd")
        self.assertEqual(self.step()[0], "waiting_there")
        self.assertEqual(self.state()[1], "unexpected error: ValueError")
        self.remote.detail_error = None
        self.remote.answer_error = SourceError("the removal got an unexpected answer")
        self.assertEqual(self.step()[0], "waiting_there")
        self.assertEqual(self.state()[1], "the removal got an unexpected answer")
        later.assert_not_called()
        # retried on the next round
        self.remote.answer_error = None
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(len(self.remote.removed), 2)

    def test_same_machine_proof(self, later):
        same = self.removal.same_machine
        device = ImportedDevice.objects.get(pk=self.device.pk)
        detail = self.remote.detail
        self.assertEqual(same(detail, self.agent, device), "")
        # one common address is not enough: bridges repeat across hosts
        unserialed = {**detail, "wmi_detail": {}}
        bridge = {**unserialed, "local_ips": "172.17.9.121, 172.17.0.1"}
        self.assertIn("not proven", same(bridge, self.agent, device))
        self.assertEqual(same(unserialed, self.agent, device), "")
        no_ip = {**detail, "public_ip": "198.51.100.1"}
        self.assertEqual(same(no_ip, self.agent, device), "", "the serial alone")
        # a cloned machine here: the serial proves nothing, the addresses do
        baker.make("agents.Agent", plat="windows", wmi_detail=_wmi(" czc1234xyz ", []))
        self.assertEqual(same(detail, self.agent, device), "")
        self.assertIn("not proven", same(no_ip, self.agent, device))
        other_lan = {**detail, "local_ips": "10.0.0.5", "wmi_detail": {}}
        self.assertIn("not proven", same(other_lan, self.agent, device))
        Agent = type(self.agent)
        Agent.objects.exclude(pk=self.agent.pk).delete()
        self.assertEqual(same(no_ip, self.agent, device), "")
        # or another device of the source has it
        ImportedDevice.objects.create(
            source=self.src, ref="AGENT2", hostname="ws99", serial="CZC1234XYZ"
        )
        self.assertIn("not proven", same(no_ip, self.agent, device))
        self.assertIn(
            "not proven", same({**no_ip, "wmi_detail": {}}, self.agent, device)
        )

    def test_unproven_machine_waits_then_ends(self, later):
        self.remote.detail = {**self.remote.detail, "wmi_detail": {}, "public_ip": ""}
        self.assertEqual(self.step()[0], "waiting_there")
        reason = self.state()[1]
        self.assertIn("not proven", reason)
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_requested_at=djangotime.now() - djangotime.timedelta(days=8)
        )
        self.assertEqual(self.step()[0], "not_removed")
        self.assertEqual(self.state(), ("not_removed", reason))
        self.assertEqual(self.remote.removed, [])

    def test_linux_gets_no_recovery(self, later):
        type(self.agent).objects.filter(pk=self.agent.pk).update(
            plat="linux", wmi_detail={"serialnumber": "VMW-1", "local_ips": []}
        )
        self.remote.detail = {
            **self.remote.detail,
            "plat": "linux",
            "wmi_detail": {"serialnumber": "VMW-1"},
        }
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(ImportedDevice.objects.get(pk=self.device.pk).recovery, "")
        later.assert_not_called()

    def test_two_workers_send_once(self, later):
        # the second worker read the row while it was still waiting
        device = ImportedDevice.objects.select_related("source").get(pk=self.device.pk)
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(self.removal.step(device, self.remote), "")
        ImportedDevice.objects.filter(pk=self.device.pk).update(remove_state="sending")
        self.assertEqual(self.removal.step(device, self.remote), "")
        self.assertEqual(len(self.remote.removed), 1)

    def test_withdraw_and_stale_claim(self, later):
        removal = self.removal
        self.assertEqual(removal.withdraw(self.src, [self.device.pk], "alice"), 1)
        d = ImportedDevice.objects.get(pk=self.device.pk)
        self.assertEqual((d.remove_state, d.remove_requested_at), ("", None))
        self.assertEqual(self.step()[0], "")
        self.assertTrue(AuditLog.objects.filter(message__contains="withdrew").exists())
        removal.request(self.src, [d.pk], "john")
        ImportedDevice.objects.filter(pk=d.pk).update(
            remove_state="sending",
            remove_at=djangotime.now() - djangotime.timedelta(hours=2),
        )
        self.assertEqual(removal.withdraw(self.src, [d.pk], "alice"), 0)
        self.assertEqual(removal.end_stale_claims(), 1)
        self.assertEqual(self.state(), ("waiting_there", "the removal was interrupted"))
        # still listed over there: the first call never took effect
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(len(self.remote.removed), 1)

    def test_stale_claim_then_gone(self, later):
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_state="sending",
            remove_at=djangotime.now() - djangotime.timedelta(hours=2),
            remove_tried_at=djangotime.now() - djangotime.timedelta(hours=2),
        )
        self.removal.end_stale_claims()
        from .sources.base import NotFound

        self.remote.detail_error = NotFound("404")
        self.assertEqual(self.step()[0], "removed")
        self.assertIn("its answer was lost", self.state()[1])
        self.assertEqual(self.remote.removed, [])
        later.assert_called_once()

    def test_lost_answer(self, later):
        from .sources.base import NotFound

        self.remote.answer_error = SourceError("/agents/AGENT1/: ReadTimeout")
        self.assertEqual(self.step()[0], "waiting_there")
        self.assertTrue(ImportedDevice.objects.get(pk=self.device.pk).remove_tried_at)
        self.remote.detail_error = NotFound("404")
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(
            self.state(), ("removed", f"{self.removal.GONE}, its answer was lost")
        )
        later.assert_called_once()
        self.assertEqual(
            ImportedDevice.objects.get(pk=self.device.pk).recovery, "pending"
        )
        self.assertEqual(len(self.remote.removed), 1)

    def test_lost_answer_linux_and_late(self, later):
        from .sources.base import NotFound

        type(self.agent).objects.filter(pk=self.agent.pk).update(
            plat="linux", wmi_detail={"serialnumber": "VMW-1", "local_ips": []}
        )
        self.remote.detail = {
            **self.remote.detail,
            "plat": "linux",
            "wmi_detail": {"serialnumber": "VMW-1"},
        }
        # the call went through, recording it failed
        with patch.object(self.removal, "_audit", side_effect=RuntimeError):
            self.assertEqual(self.step()[0], "waiting_there")
        self.assertEqual(len(self.remote.removed), 1)
        # past the 7 days a tried device is still asked about
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_requested_at=djangotime.now() - djangotime.timedelta(days=8)
        )
        self.remote.detail_error = NotFound("404")
        self.assertEqual(self.step()[0], "removed")
        self.assertEqual(ImportedDevice.objects.get(pk=self.device.pk).recovery, "")
        later.assert_not_called()
        self.assertEqual(len(self.remote.removed), 1)

    def test_filler_serials_prove_nothing(self, later):
        Agent = type(self.agent)
        device = ImportedDevice.objects.get(pk=self.device.pk)
        for serial in (
            "1234",
            "AAAAAAAA",
            "To Be Filled By O.E.M.",
            " Default string ",
            "0123456789",
        ):
            with self.subTest(serial):
                Agent.objects.filter(pk=self.agent.pk).update(
                    wmi_detail=_wmi(serial, ["172.17.9.121", "172.17.9.6"])
                )
                agent = Agent.objects.get(pk=self.agent.pk)
                detail = {
                    **self.remote.detail,
                    "wmi_detail": _wmi(serial, []),
                    "public_ip": "198.51.100.1",
                }
                self.assertIn(
                    "not proven", self.removal.same_machine(detail, agent, device)
                )
                # the addresses still can
                detail["public_ip"] = "203.0.113.10"
                self.assertEqual(self.removal.same_machine(detail, agent, device), "")

    def test_hand_installed_device(self, later):
        ImportedDevice.objects.filter(pk=self.device.pk).update(sent_at=None)
        self.assertEqual(self.step()[0], "waiting_here")
        self.assertEqual(
            self.state()[1], "no check-in here since the removal was requested"
        )
        type(self.agent).objects.filter(pk=self.agent.pk).update(
            last_seen=djangotime.now()
        )
        self.assertEqual(self.step()[0], "removed")

    def test_recovery_outcome(self, later):
        from .tasks import recover_task

        with patch("agents.models.Agent.recover", return_value=("ok", False)) as rec:
            self.assertEqual(recover_task(self.device.pk), "ok")
        rec.assert_called_once_with("mesh", "")
        with patch("agents.models.Agent.recover", return_value=("timeout", True)):
            recover_task(self.device.pk)
        self.assertEqual(
            ImportedDevice.objects.get(pk=self.device.pk).recovery, "failed: timeout"
        )

    def test_task_and_new_import_keep_the_state(self, later):
        from ulrmm.celery import app

        beat = {v["task"] for v in app.conf.beat_schedule.values()}
        self.assertIn("importers.tasks.remove_task", beat)
        with patch("importers.tasks.for_source", return_value=self.remote):
            from .tasks import remove_task

            self.assertEqual(remove_task(), "ok")
        self.assertEqual(self.state()[0], "removed")
        # the other server dropped the device; a new import keeps the row
        self.src.snapshot = validate({"devices": []})
        self.src.save()
        engine.run(self.src, ["devices"])
        self.assertEqual(self.state()[0], "removed")


@override_settings(CACHES=LOCMEM_CACHE)
class TestRemovalViews(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.john.totp_key = pyotp.random_base32()
        self.john.save(update_fields=["totp_key"])
        self.totp = pyotp.TOTP(self.john.totp_key)
        self.src = _source()
        engine.run(self.src, ["custom_fields", "clients", "devices"])
        self.ids = list(ImportedDevice.objects.values_list("pk", flat=True))

    def requested(self) -> int:
        return ImportedDevice.objects.exclude(remove_requested_at=None).count()

    def test_switch_rows_and_withdraw(self):
        url = f"{BASE}/{self.src.pk}"
        with patch("importers.views.migrate_task.delay") as delay:
            r = self.client.post(
                f"{url}/migrate/", {"devices": self.ids}, format="json"
            )
            self.assertEqual(r.data["remove_requested"], 0, "off by default")
            r = self.client.post(
                f"{url}/migrate/",
                {"devices": self.ids, "remove_old": "yes"},
                format="json",
            )
            self.assertEqual(r.status_code, 400)
            for bad in ({}, {"totp_code": wrong_code(self.totp)}):
                body = {"devices": self.ids, "remove_old": True, **bad}
                r = self.client.post(f"{url}/migrate/", body, format="json")
                self.assertEqual((r.status_code, r.data), (400, DELETE_NEEDS_TOTP))
            self.assertEqual(delay.call_count, 1, "no installer without the code")
            self.assertEqual(self.requested(), 0)
            code = self.totp.now()
            r = self.client.post(
                f"{url}/migrate/",
                {"devices": self.ids, "remove_old": True, "totp_code": code},
                format="json",
            )
            self.assertEqual(r.status_code, 202)
            again = self.client.post(
                f"{url}/migrate/",
                {"devices": self.ids, "remove_old": True, "totp_code": code},
                format="json",
            )
            self.assertEqual(again.status_code, 400, "a code works once")
        self.assertEqual(r.data["remove_requested"], 4)
        self.assertEqual(delay.call_count, 2)
        entry = AuditLog.objects.get(message__contains="asked to remove")
        self.assertEqual(
            (entry.username, len(entry.after_value["devices"])), ("john", 4)
        )
        r = self.client.get(f"{url}/devices/")
        row = r.data[0]
        self.assertEqual(row["remove_state"], "waiting_here")
        for key in ("remove_requested_at", "remove_at", "remove_reason", "recovery"):
            self.assertIn(key, row)
        r = self.client.get(f"{BASE}/")
        self.assertTrue(r.data[0]["removes_agent"])

        r = self.client.post(
            f"{url}/withdraw/", {"devices": self.ids[:1]}, format="json"
        )
        self.assertEqual(r.data, {"withdrawn": 1})
        r = self.client.post(f"{url}/withdraw/", {"devices": "x"}, format="json")
        self.assertEqual(r.status_code, 400)

    @patch("importers.views.migrate_task.delay")
    def test_remove_without_installer(self, delay):
        url = f"{BASE}/{self.src.pk}/remove/"
        ninja = baker.make(ImportSource, kind="ninjaone", name="n", url="https://n")
        code = self.totp.now()
        r = self.client.post(
            f"{BASE}/{ninja.pk}/remove/",
            {"devices": self.ids, "totp_code": code},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(url, {"devices": "x", "totp_code": code}, format="json")
        self.assertEqual(r.status_code, 400)
        for bad in ({}, {"totp_code": wrong_code(self.totp)}):
            r = self.client.post(url, {"devices": self.ids, **bad}, format="json")
            self.assertEqual((r.status_code, r.data), (400, DELETE_NEEDS_TOTP))
        self.assertEqual(self.requested(), 0)

        # the refusals before did not use up the code
        r = self.client.post(
            url, {"devices": self.ids[:2], "totp_code": code}, format="json"
        )
        self.assertEqual(r.data, {"remove_requested": 2})
        delay.assert_not_called()
        self.assertEqual(self.requested(), 2)
        entry = AuditLog.objects.get(message__contains="asked to remove")
        self.assertEqual(
            (entry.username, len(entry.after_value["devices"])), ("john", 2)
        )
        self.assertEqual(
            set(
                ImportedDevice.objects.filter(pk__in=self.ids[:2]).values_list(
                    "remove_state", flat=True
                )
            ),
            {"waiting_here"},
        )

    def test_superusers_only_and_other_sources(self):
        ninja = baker.make(ImportSource, kind="ninjaone", name="n", url="https://n")
        r = self.client.post(
            f"{BASE}/{ninja.pk}/migrate/",
            {"devices": [1], "remove_old": True, "totp_code": self.totp.now()},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        user = self.create_user_with_roles(["can_uninstall_agents"])
        self.client.force_authenticate(user=user)
        for path in ("migrate", "remove", "withdraw"):
            self.check_not_authorized(
                "post", f"{BASE}/{self.src.pk}/{path}/", {"devices": self.ids}
            )
        self.assertFalse(ImportedDevice.objects.exclude(remove_state="").exists())

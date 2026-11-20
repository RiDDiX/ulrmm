# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import copy
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import Note
from alerts.models import AlertTemplate
from automation.models import Policy
from autotasks.models import AutomatedTask
from checks.models import Check
from clients.models import Client, ClientCustomField, Site
from core.models import CustomField, GlobalKVStore
from logs.models import DebugLog
from scripts.models import Script
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import build, engine, link, removal
from .models import ImportedDevice, ImportSource
from .sources import validate
from .sources.base import LONG, MAX_BODY
from .tasks import remove_task
from .tests import SNAPSHOT, FakeRemote, _recorded

SERIAL = "CZC1234567"


def _src(snap) -> ImportSource:
    return baker.make(
        ImportSource,
        kind="upstream",
        name="old",
        url="https://old.example.com",
        snapshot=validate(snap),
        last_fetch=djangotime.now(),
    )


def _twin(answers):
    """a second "Disk Usage Report" over there"""
    listed = next(s for s in answers["/scripts/"] if s["id"] == 2)
    answers["/scripts/"].append({**listed, "id": 6})
    answers["/scripts/6/"] = {
        **answers["/scripts/2/"],
        "id": 6,
        "script_body": "Write-Output B",
    }


def _linux(site, serial, hostname="srv01"):
    return baker.make(
        "agents.Agent",
        site=site,
        hostname=hostname,
        plat="linux",
        wmi_detail={"serialnumber": serial},
    )


class TestLinkRules(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.snap = copy.deepcopy(SNAPSHOT)
        self.snap["devices"][1]["serial"] = SERIAL
        self.src = _src(self.snap)
        engine.run(self.src, engine.PARTS)
        self.hq = Site.objects.get(name="HQ")
        self.branch = Site.objects.get(name="Branch")

    def srv01(self):
        return ImportedDevice.objects.get(ref="d2").agent

    def test_out_of_site_agent_needs_the_same_serial(self):
        stranger = _linux(self.branch, "CZC7654321")
        self.assertEqual(link.link_source(self.src), 0)
        self.assertIsNone(self.srv01())
        stranger.wmi_detail = {"serialnumber": "To Be Filled By O.E.M."}
        stranger.save()
        self.assertEqual(link.link_source(self.src), 0)
        # the same filler value on both sides proves nothing
        ImportedDevice.objects.filter(ref="d2").update(serial="To Be Filled By O.E.M.")
        self.assertEqual(link.link_source(self.src), 0)
        ImportedDevice.objects.filter(ref="d2").update(serial=SERIAL)
        stranger.wmi_detail = {"serialnumber": SERIAL.lower()}
        stranger.save()
        self.assertEqual(link.link_source(self.src), 1)
        self.assertEqual(self.srv01(), stranger)

    def test_replacement_machine_is_not_linked(self):
        agent = _linux(self.hq, "CZC7654321")
        self.assertEqual(link.link_source(self.src), 0)
        self.assertEqual(engine.run(self.src, ["devices"])["linked"], 0)
        row = ImportedDevice.objects.get(ref="d2")
        self.assertIsNone(row.agent)
        self.assertEqual(row.migrate_error, link.OTHER_SERIAL)
        # an agent without a real serial proves nothing either way
        agent.wmi_detail = {"serialnumber": "To Be Filled By O.E.M."}
        agent.save()
        self.assertEqual(link.link_source(self.src), 1)
        row.refresh_from_db()
        self.assertEqual((row.agent, row.migrate_error), (agent, ""))

    def test_candidates_hold_only_agents_of_the_host_name(self):
        ImportedDevice.objects.create(
            source=self.src, ref="w7", site=self.hq, hostname="WS07.corp.example"
        )
        _linux(self.hq, "CZC7654321")
        _linux(self.hq, "CZC7654322", hostname="ws07")
        _linux(self.branch, "CZC7654323", hostname="nas01.corp.example")
        with patch.object(link, "_candidates", wraps=link._candidates) as spy:
            link.link_source(self.src)
        seen = {}
        for (device, agents), _ in spy.call_args_list:
            name = link.short(device.hostname)
            self.assertEqual({link.short(a.hostname) for a in agents} - {name}, set())
            seen[name] = len(agents)
        self.assertEqual((seen["srv01"], seen["ws07"]), (1, 1))

    def test_in_site_match_goes_first(self):
        # srv01 of Branch has no agent of its own and the same serial; its row
        # comes first in the table
        ImportedDevice.objects.create(
            source=self.src, ref="b1", site=self.branch, hostname="srv01", serial=SERIAL
        )
        d2 = ImportedDevice.objects.get(ref="d2")
        d2.delete()
        d2.pk = None
        d2.save()
        mine = _linux(self.hq, SERIAL)
        self.assertEqual(link.link_source(self.src), 1)
        self.assertEqual(self.srv01(), mine)

    def test_twin_rows_link_only_by_serial(self):
        # both rows are in the last read
        self.src.snapshot["devices"].append({"ref": "stale"})
        self.src.save()
        ImportedDevice.objects.create(
            source=self.src,
            ref="stale",
            site=self.hq,
            hostname="srv01",
            serial="CZC0000001",
            data={"notes": ["stale note"]},
        )
        agent = _linux(self.hq, "CZC7654321")
        self.assertEqual(link.link_source(self.src), 0, "never a guess")
        agent.wmi_detail = {"serialnumber": SERIAL}
        agent.save()
        self.assertEqual(link.link_source(self.src), 1)
        self.assertEqual(self.srv01(), agent)
        self.assertFalse(Note.objects.filter(note="stale note").exists())

    def test_twin_gone_over_there_gives_way(self):
        # the last read no longer lists it; the row and its data stay
        ImportedDevice.objects.create(
            source=self.src,
            ref="stale",
            site=self.hq,
            hostname="srv01",
            serial="CZC0000001",
            data={"notes": ["stale note"]},
        )
        # the live row comes after the stale one in the table
        d2 = ImportedDevice.objects.get(ref="d2")
        d2.delete()
        d2.pk = None
        d2.save()
        agent = _linux(self.hq, "")
        done = engine.run(self.src, ["devices"])
        self.assertEqual(done["linked"], 1)
        self.assertEqual(self.srv01(), agent)
        self.assertTrue(ImportedDevice.objects.filter(ref="stale", agent=None).exists())
        self.assertFalse(Note.objects.filter(note="stale note").exists())


class TestImportRules(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.snap = copy.deepcopy(SNAPSHOT)

    def test_block_policy_inheritance(self):
        def edit(answers):
            for c in answers["/clients/"]:
                c["block_policy_inheritance"] = True
                for site in c["sites"]:
                    site["block_policy_inheritance"] = True

        here = baker.make(Client, name="Contoso GmbH")
        baker.make(Site, client=here, name="Berlin HQ")
        src = _src(_recorded(edit))
        reason = engine.BLOCK_LEFT_OUT
        expected = [
            {"name": "Contoso GmbH: block policy inheritance", "reason": reason},
            {
                "name": "Contoso GmbH / Berlin HQ: block policy inheritance",
                "reason": reason,
            },
        ]
        self.assertEqual(engine.plan(src)["clients"]["skipped"], expected)
        done = engine.run(src, ["clients"])
        self.assertEqual(done["skipped"]["clients"], expected)
        self.assertTrue(Client.objects.get(name="Fabrikam AG").block_policy_inheritance)
        self.assertTrue(Site.objects.get(name="Main Office").block_policy_inheritance)
        self.assertTrue(
            Site.objects.get(name="Hamburg Branch").block_policy_inheritance
        )
        self.assertFalse(Site.objects.get(name="Berlin HQ").block_policy_inheritance)
        self.assertFalse(Client.objects.get(pk=here.pk).block_policy_inheritance)

    def test_run_once_in_the_past_is_left_out(self):
        row = {
            "fields": {"task_type": "runonce", "run_time_date": "2020-01-01T10:00:00Z"},
            "actions": [{"type": "cmd", "command": "x"}],
        }
        self.assertEqual(
            build.missing(row, "tasks", lambda r: True),
            "it runs once at a time that has passed",
        )
        row["fields"]["run_time_date"] = djangotime.now().isoformat()
        self.assertEqual(build.missing(row, "tasks", lambda r: True), "")

    def test_past_run_once_is_listed_once(self):
        fields = {
            "name": "Once",
            "task_type": "runonce",
            "run_time_date": "2020-01-01T10:00:00Z",
        }
        task = {"fields": fields, "actions": [{"type": "cmd", "command": "x"}]}
        self.snap["policies"] = [{"name": "P", "tasks": [task]}]
        src = _src(self.snap)
        passed = {"name": "P: Once", "reason": "it runs once at a time that has passed"}
        self.assertEqual(engine.plan(src)["policies"]["skipped"], [passed])
        self.assertEqual(engine.run(src, ["policies"])["skipped"]["policies"], [passed])
        # the policy is here now: completing it lists nothing
        self.assertEqual(engine.plan(src)["policies"]["skipped"], [])
        self.assertEqual(engine.plan(src)["policies"]["to_complete_count"], 0)
        self.assertNotIn("policies", engine.run(src, ["policies"])["skipped"])

    def test_multiple_choice_values(self):
        roles = CustomField.objects.create(
            model="client", name="Roles", type="multiple", options=["Berlin, DE", "X"]
        )
        flag = CustomField.objects.create(model="client", name="Flag", type="multiple")
        client = baker.make(Client, name="Acme")
        link.fill(client, "client", {"Roles": ["Berlin, DE", "X"], "Flag": True})
        value = ClientCustomField.objects.get(client=client, field=roles)
        self.assertEqual(value.multiple_value, ["Berlin, DE", "X"])
        value = ClientCustomField.objects.get(client=client, field=flag)
        self.assertEqual(value.multiple_value, ["True"])

    def test_task_names_compare_collapsed(self):
        policy = baker.make(Policy, name="P")
        baker.make("autotasks.AutomatedTask", policy=policy, name="Nightly  job")
        _, tasks, _ = build.missing_children(
            policy.policychecks,
            policy.autotasks,
            {"checks": [], "tasks": [{"name": "Nightly job"}]},
        )
        self.assertEqual(tasks, [])

    def test_repeated_script_is_left_out(self):
        self.snap["scripts"].append({"name": "uptime", "shell": "shell", "body": "x"})
        src = _src(self.snap)
        plan = engine.plan(src)
        repeated = [
            {"name": name, "reason": engine.REPEATED_SCRIPT}
            for name in ("Uptime", "uptime")
        ]
        self.assertEqual(plan["scripts"]["skipped"], repeated)
        self.assertEqual(plan["scripts"]["new_count"], 1)
        self.assertEqual(plan["scripts"]["existing_count"], 0)
        done = engine.run(src, ["scripts"])
        self.assertEqual(done["skipped"]["scripts"], repeated)
        self.assertFalse(Script.objects.filter(name__iexact="uptime").exists())
        # one of that name here: still both left out while the name repeats
        baker.make(Script, name="Uptime", shell="shell")
        self.assertEqual(engine.plan(src)["scripts"]["skipped"], repeated)
        self.assertEqual(engine.run(src, ["scripts"])["skipped"]["scripts"], repeated)

    def test_repeated_script_never_resolves_here(self):
        mine = baker.make(Script, name="Disk Usage Report", shell="powershell")
        src = _src({})
        src.snapshot = _recorded(_twin)
        src.save()
        repeated = {"name": "Disk Usage Report", "reason": engine.REPEATED_SCRIPT}
        self.assertEqual(engine.plan(src)["scripts"]["skipped"], [repeated, repeated])
        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["skipped"]["scripts"], [repeated, repeated])
        self.assertFalse(Check.objects.filter(script=mine).exists())
        actions = AutomatedTask.objects.values_list("actions", flat=True)
        used = {a.get("script") for row in actions for a in row}
        self.assertNotIn(mine.pk, used)
        self.assertEqual(Script.objects.filter(name="Disk Usage Report").count(), 1)
        # what a linked device brings resolves through Refs
        ref = {"name": "Disk Usage Report", "shell": "powershell"}
        self.assertIsNone(build.Refs(src.snapshot["scripts"]).script(ref))
        self.assertEqual(build.Refs().script(ref), mine.pk)

    def test_renamed_twin_keeps_its_references(self):
        def renamed(answers):
            _twin(answers)
            for row in (answers["/scripts/2/"], *answers["/scripts/"]):
                if row["id"] == 2:
                    row["name"] = "Disk Usage v2"

        src = _src({})
        src.snapshot = _recorded(_twin)
        src.save()
        repeated = {"name": "Disk Usage Report", "reason": engine.REPEATED_SCRIPT}
        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["skipped"]["scripts"], [repeated, repeated])
        self.assertFalse(Script.objects.filter(name="Disk Usage Report").exists())
        ws = Policy.objects.get(name="Workstations baseline")
        self.assertFalse(ws.policychecks.filter(check_type="script").exists())

        src.snapshot = _recorded(renamed)
        src.save()
        engine.run(src, engine.PARTS)
        first = Script.objects.get(name="Disk Usage v2")
        self.assertTrue(first.script_body.startswith("param("))
        self.assertEqual(
            Script.objects.get(name="Disk Usage Report").script_body, "Write-Output B"
        )
        self.assertEqual(ws.policychecks.get(check_type="script").script, first)

    def test_repeated_names_over_there(self):
        def edit(answers):
            policies = answers["/automation/policies/"]
            templates = answers["/alerts/templates/"]
            # differ from policy 2 and template 1 only in case and spaces
            policies.append({**policies[1], "id": 9, "name": " servers  BASELINE "})
            templates.append({**templates[0], "id": 9, "name": "contoso  SERVERS"})
            answers["/clients/"][1]["server_policy"] = 9

        src = _src(_recorded(edit))
        tlost = {"name": "Contoso GmbH: alert template", "reason": engine.TEMPLATE_LOST}
        plost = {"name": "Fabrikam AG: server policy", "reason": build.POLICY_LOST}
        own = {
            "name": "Contoso Server Baseline: alert template",
            "reason": engine.TEMPLATE_LOST,
        }
        plan = engine.plan(src)
        self.assertIn(tlost, plan["alert_templates"]["skipped"])
        self.assertIn(plost, plan["policies"]["skipped"])
        self.assertIn(own, plan["policies"]["skipped"])
        done = engine.run(src, engine.PARTS)
        self.assertIn(tlost, done["skipped"]["alert_templates"])
        self.assertIn(plost, done["skipped"]["policies"])
        self.assertIn(own, done["skipped"]["policies"])
        fabrikam = Client.objects.get(name="Fabrikam AG")
        self.assertIsNone(fabrikam.server_policy)
        self.assertIsNone(Client.objects.get(name="Contoso GmbH").alert_template)
        # set by hand here: no longer listed
        fabrikam.server_policy = Policy.objects.get(name="Servers baseline")
        fabrikam.save()
        Client.objects.filter(name="Contoso GmbH").update(
            alert_template=AlertTemplate.objects.first()
        )
        plan = engine.plan(src)
        self.assertNotIn(tlost, plan["alert_templates"]["skipped"])
        self.assertNotIn(plost, plan["policies"]["skipped"])
        done = engine.run(src, engine.PARTS)
        self.assertNotIn(tlost, done["skipped"].get("alert_templates", []))
        self.assertNotIn(plost, done["skipped"].get("policies", []))

    def test_exclusions_wait_for_their_clients(self):
        self.snap["policies"] = [{"name": "P", "excluded_clients": ["Acme"]}]
        self.snap["alert_templates"] = [
            {"name": "T", "excluded_sites": [["Acme", "HQ"]]}
        ]
        src = _src(self.snap)
        done = engine.run(src, ["alert_templates", "policies"])
        self.assertEqual(
            done["skipped"]["policies"],
            [{"name": "P", "reason": "it excludes Acme, which is not here yet"}],
        )
        self.assertEqual(
            done["skipped"]["alert_templates"],
            [{"name": "T", "reason": "it excludes Acme / HQ, which is not here yet"}],
        )
        self.assertFalse(Policy.objects.exists())
        engine.run(src, ["clients", "alert_templates", "policies"])
        policy = Policy.objects.get(name="P")
        self.assertEqual(list(policy.excluded_clients.values_list("name")), [("Acme",)])
        template = AlertTemplate.objects.get(name="T")
        self.assertEqual(list(template.excluded_sites.values_list("name")), [("HQ",)])

    def test_exclusion_of_a_dropped_client_is_lost(self):
        # validate keeps the first of two names that differ only in case
        self.snap["clients"].append(
            {"ref": "3", "name": "ACME", "sites": [{"ref": "31", "name": "Remote"}]}
        )
        self.snap["policies"] = [{"name": "P", "excluded_sites": [["ACME", "Remote"]]}]
        src = _src(self.snap)
        lost = {"name": "P: clients and sites", "reason": engine.EXCLUSION_LOST}
        self.assertIn(lost, engine.plan(src)["policies"]["skipped"])
        done = engine.run(src, ["clients", "policies"])
        self.assertEqual(done["skipped"]["policies"], [lost])
        self.assertTrue(Policy.objects.filter(name="P").exists())

    def test_long_values_are_listed(self):
        over = "x" * (MAX_BODY + 1)
        self.snap["keystore"].append({"name": "OVER", "value": over})
        self.snap["devices"][1]["notes"] = [over]
        src = _src(self.snap)
        entry = {"name": "OVER", "reason": build.TOO_LONG}
        note = {"name": "note 1", "reason": build.TOO_LONG}
        plan = engine.plan(src)
        self.assertEqual(plan["keystore"]["skipped"], [entry])
        self.assertEqual(plan["keystore"]["new_count"], 1)
        self.assertIn({**note, "name": "srv01: note 1"}, plan["devices"]["skipped"])
        done = engine.run(src, engine.PARTS)
        self.assertEqual(done["skipped"]["keystore"], [entry])
        self.assertFalse(GlobalKVStore.objects.filter(name="OVER").exists())
        _linux(Site.objects.get(name="HQ"), "")
        self.assertEqual(link.link_source(src), 1)
        row = ImportedDevice.objects.get(ref="d2")
        self.assertEqual(row.data["link_skipped"], [note])

    def test_values_over_the_caps_are_marked(self):
        action = {"type": "script", "script": {"name": "Uptime", "shell": "shell"}}
        task = {"fields": {"name": "t", "task_type": "manual"}, "actions": [action]}
        action["script_args"] = ["a" * 300]
        data = validate({"devices": [{"ref": "1", "hostname": "h", "tasks": [task]}]})
        row = data["devices"][0]["tasks"][0]
        self.assertEqual(row["actions"][0]["script_args"], ["a" * 300])
        self.assertFalse(row["too_long"])
        action["script_args"] = ["a" * (LONG + 1)]
        data = validate({"devices": [{"ref": "1", "hostname": "h", "tasks": [task]}]})
        row = data["devices"][0]["tasks"][0]
        self.assertEqual(build.missing(row, "tasks", lambda r: True), build.TOO_LONG)

        self.snap["scripts"][1]["args"] = ["b" * 1001]
        self.snap["policies"] = [
            {
                "name": "P",
                "checks": [
                    {
                        "ref": "1",
                        "desc": "Up",
                        "script": {"name": "Uptime", "shell": "shell"},
                        "fields": {"check_type": "script"},
                    }
                ],
            }
        ]
        src = _src(self.snap)
        plan = engine.plan(src)
        long = {"name": "Uptime", "reason": build.TOO_LONG}
        self.assertEqual(plan["scripts"]["skipped"], [long])
        self.assertEqual(
            plan["policies"]["skipped"],
            [{"name": "P: Up", "reason": "script Uptime is not here"}],
        )
        done = engine.run(src, ["scripts"])
        self.assertEqual(done["skipped"]["scripts"], [long])
        self.assertFalse(Script.objects.filter(name="Uptime").exists())
        # added here by hand: counts as existing
        baker.make(Script, name="Uptime", shell="shell")
        self.assertEqual(engine.plan(src)["scripts"]["skipped"], [])
        self.assertNotIn("scripts", engine.run(src, ["scripts"])["skipped"])


@patch("autotasks.tasks.create_win_task_schedule.delay")
class TestRelink(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.snap = _recorded()

    def source(self):
        src = baker.make(
            ImportSource,
            kind="upstream",
            name="old",
            url="https://old.example.com",
            snapshot=self.snap,
            last_fetch=djangotime.now(),
        )
        engine.run(src, engine.PARTS)
        return src

    def test_source_added_again_adds_nothing_twice(self, delay):
        self.source()
        hq = Site.objects.get(name="Berlin HQ")
        agent = baker.make(
            "agents.Agent",
            site=hq,
            hostname="CONTOSO-DC01",
            plat="windows",
            monitoring_type="server",
        )
        with self.captureOnCommitCallbacks(execute=True):
            link.on_enroll(agent)
        before = (
            agent.agentchecks.count(),
            agent.autotasks.count(),
            Note.objects.filter(agent=agent).count(),
        )
        ImportSource.objects.all().delete()
        with self.captureOnCommitCallbacks(execute=True):
            self.source()
        self.assertEqual(
            ImportedDevice.objects.get(hostname="CONTOSO-DC01").agent, agent
        )
        after = (
            agent.agentchecks.count(),
            agent.autotasks.count(),
            Note.objects.filter(agent=agent).count(),
        )
        self.assertEqual(before, after)
        self.assertEqual(before[0:2], (1, 1))

    def test_unknown_exclusion_is_listed(self, delay):
        device = next(
            d for d in self.snap["devices"] if d["hostname"] == "CONTOSO-DC01"
        )
        device["excluded_policies"] = ["Gone"]
        self.source()
        agent = baker.make(
            "agents.Agent",
            site=Site.objects.get(name="Berlin HQ"),
            hostname="CONTOSO-DC01",
            plat="windows",
        )
        link.on_enroll(agent)
        row = ImportedDevice.objects.get(agent=agent)
        self.assertIn(
            {"name": "exclusion from policy Gone", "reason": "it is not here"},
            row.data["link_skipped"],
        )

    def test_repeated_policy_name_is_listed(self, delay):
        def edit(answers):
            policies = answers["/automation/policies/"]
            # differs from policy 2 only in case and spaces
            policies.append({**policies[1], "id": 9, "name": " servers  BASELINE "})
            dc01 = next(k for k in answers if k.endswith("CONTOSO-DC01/"))
            answers[dc01]["policy"] = 9

        self.snap = _recorded(edit)
        self.source()
        agent = baker.make(
            "agents.Agent",
            site=Site.objects.get(name="Berlin HQ"),
            hostname="CONTOSO-DC01",
            plat="windows",
        )
        link.on_enroll(agent)
        row = ImportedDevice.objects.get(agent=agent)
        self.assertIn(
            {"name": "policy", "reason": build.POLICY_LOST}, row.data["link_skipped"]
        )
        agent.refresh_from_db()
        self.assertIsNone(agent.policy)


class TestRemovalLog(ULRMMTestCase):
    @override_settings(CACHES=LOCMEM_CACHE)
    def test_round_logs_only_the_type(self):
        src = baker.make(ImportSource, kind="upstream", name="old", url="https://o")
        device = ImportedDevice.objects.create(
            source=src, ref="AGENT1", hostname="ws01", plat="windows"
        )
        removal.request(src, [device.pk], "john")
        with (
            patch("importers.tasks.for_source", return_value=FakeRemote({})),
            patch("importers.tasks.removal.step", side_effect=ValueError("k3y")),
        ):
            self.assertEqual(remove_task(), "ok")
        logged = " ".join(DebugLog.objects.values_list("message", flat=True))
        self.assertIn("ValueError", logged)
        self.assertNotIn("k3y", logged)

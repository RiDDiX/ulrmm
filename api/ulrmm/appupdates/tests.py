# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import sys
import types
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import Agent, AgentHistory
from logs.models import AuditLog, DebugLog
from ulrmm.constants import AgentHistoryType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .models import AppUpdate, AppUpdateScan, AppUpdateSettings
from .tasks import (
    APPLYING,
    ID_RE,
    NO_ANSWER,
    TIMED_OUT,
    _outcome,
    apply_app_updates_task,
    collect_app_updates_task,
    effective,
    mark_applying,
    parse_list,
    store,
)

# list answer of the agent on a Windows 11 machine (winget upgrade, parsed)
WINGET_LIST = [
    {
        "source": "winget",
        "id": "Google.Chrome",
        "name": "Google Chrome",
        "installed": "129.0.6668.59",
        "available": "130.0.6723.70",
    },
    {
        "source": "winget",
        "id": "7zip.7zip",
        "name": "7-Zip 23.01 (x64)",
        "installed": "23.01",
        "available": "24.08",
    },
    {
        "source": "winget",
        "id": "Notepad++.Notepad++",
        "name": "Notepad++ (64-bit x64)",
        "installed": "8.6.2",
        "available": "8.7",
    },
    {
        "source": "winget",
        "id": "Microsoft.VCRedist.2015+.x64",
        "name": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135",
        "installed": "14.38.33135.0",
        "available": "14.40.33810.0",
    },
    {"source": "winget", "id": "-rf", "name": "option", "available": "1"},
    {"source": "winget", "id": "a b", "name": "space", "available": "1"},
    {"source": "choco", "id": "git", "name": "other source", "available": "1"},
    "junk",
]
BREW_LIST = [
    {
        "source": "brew",
        "id": "openssl@3",
        "name": "openssl@3",
        "installed": "3.3.2",
        "available": "3.4.0",
    },
    {
        "source": "mas",
        "id": "497799835",
        "name": "Xcode",
        "installed": "15.4",
        "available": "16.0",
    },
]


def fake_nats(answers: dict, calls: list):
    """Agent.nats_cmd answering per agent_id. A callable gets the payload."""

    async def nats_cmd(self, data, timeout=30, wait=True):
        calls.append((self.agent_id, data, timeout))
        answer = answers.get(self.agent_id, "timeout")
        return answer(data) if callable(answer) else answer

    return patch.object(Agent, "nats_cmd", nats_cmd)


def fake_notify():
    dispatch = MagicMock()
    module = types.ModuleType("notify.dispatch")
    module.dispatch = dispatch
    package = types.ModuleType("notify")
    package.dispatch = module
    return dispatch, patch.dict(
        sys.modules, {"notify": package, "notify.dispatch": module}
    )


def upgraded(ok_ids, tail="0x8a15002b: no applicable upgrade"):
    def answer(data):
        ids = data["payload"]["ids"].split(",")
        return {
            "results": [
                {"id": i, "ok": i in ok_ids, "output_tail": "" if i in ok_ids else tail}
                for i in ids
                if i != "Microsoft.VCRedist.2015+.x64"
            ]
        }

    return answer


class TestParse(SimpleTestCase):
    def test_id_re(self):
        # the agent's appIDRe, ids travel comma-joined so no comma
        for good in ("7zip.7zip", "openssl@3", "Febooti.Hash&CRC", "BRÖTJE.ProfiTool"):
            self.assertTrue(ID_RE.fullmatch(good), good)
        for bad in ("-x", "a,b", "a b", "a\n", "a" * 129, ""):
            self.assertFalse(ID_RE.fullmatch(bad), bad)

    def test_list_answer(self):
        rows = parse_list(WINGET_LIST + BREW_LIST)
        self.assertEqual(
            sorted(rows),
            [
                ("brew", "openssl@3"),
                ("mas", "497799835"),
                ("winget", "7zip.7zip"),
                ("winget", "Google.Chrome"),
                ("winget", "Microsoft.VCRedist.2015+.x64"),
                ("winget", "Notepad++.Notepad++"),
            ],
        )
        self.assertEqual(
            rows[("winget", "Google.Chrome")],
            {
                "name": "Google Chrome",
                "installed": "129.0.6668.59",
                "available": "130.0.6723.70",
            },
        )
        # JSON text works as well
        self.assertEqual(parse_list(json.dumps(BREW_LIST)), parse_list(BREW_LIST))
        self.assertEqual(parse_list([]), {})

    def test_errors(self):
        for answer, message in (
            ("timeout", NO_ANSWER),
            ("winget was not found", "winget was not found"),
            ({"results": []}, "Unexpected answer from the agent."),
            (None, "Unexpected answer from the agent."),
        ):
            with self.subTest(answer):
                with self.assertRaisesMessage(ValueError, message):
                    parse_list(answer)


class TestOutcome(SimpleTestCase):
    def test_markers(self):
        for result, want in (
            ({"ok": True, "output_tail": "time limit reached"}, "done"),
            ({"status": "not_started"}, "not_started"),
            ({"timed_out": True, "output_tail": "exit 1"}, "timed_out"),
            ({"output_tail": "not started: time limit reached"}, "not_started"),
            ({"output_tail": "Installing\nwinget: time limit reached\n"}, "timed_out"),
            ({"output_tail": "0x8a15002b: no applicable upgrade"}, "failed"),
        ):
            self.assertEqual(_outcome(result), want, result)


class Base(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.win = baker.make_recipe(
            "agents.online_agent", plat="windows", site=self.site, time_zone="UTC"
        )
        self.mac = baker.make_recipe(
            "agents.online_agent", plat="darwin", site=self.site, time_zone="UTC"
        )
        self.settings = AppUpdateSettings.load()

    def rows(self, agent) -> dict:
        return {u.app_id: u for u in AppUpdate.objects.filter(agent=agent)}

    def enable(self, **kwargs):
        AppUpdateSettings.objects.filter(pk=1).update(
            enabled=True, hour=djangotime.now().hour, **kwargs
        )


class TestStoreAndPolicy(Base):
    def test_store_keeps_exclusions_and_failures(self):
        store(self.win, parse_list(WINGET_LIST))
        self.assertEqual(len(self.rows(self.win)), 4)
        AppUpdate.objects.filter(app_id="Notepad++.Notepad++").update(state="excluded")
        AppUpdate.objects.filter(app_id="Microsoft.VCRedist.2015+.x64").update(
            state="failed", last_error="exit 1"
        )
        AppUpdate.objects.filter(app_id="7zip.7zip").update(
            state="failed", last_error="exit 1"
        )

        later = [
            {**WINGET_LIST[1], "available": "24.09"},
            WINGET_LIST[3],
        ]
        store(self.win, parse_list(later))
        rows = self.rows(self.win)
        # Chrome is current now, Notepad++ stays as the exclusion marker
        self.assertNotIn("Google.Chrome", rows)
        self.assertEqual(
            (rows["Notepad++.Notepad++"].state, rows["Notepad++.Notepad++"].available),
            ("excluded", ""),
        )
        # same version: the failure stays, a newer one is offered again
        self.assertEqual(rows["Microsoft.VCRedist.2015+.x64"].state, "failed")
        self.assertEqual(
            (rows["7zip.7zip"].state, rows["7zip.7zip"].available),
            ("available", "24.09"),
        )
        self.assertEqual(AppUpdateScan.objects.get(agent=self.win).error, "")

        store(self.win, {}, "winget was not found")
        self.assertEqual(len(self.rows(self.win)), 3)
        self.assertEqual(
            AppUpdateScan.objects.get(agent=self.win).error, "winget was not found"
        )

    def test_effective_policy(self):
        self.assertEqual(effective(self.win, False), (False, "global"))
        self.assertEqual(effective(self.win, True), (True, "global"))
        self.site.app_updates = "on"
        self.site.save()
        self.win.refresh_from_db()
        self.assertEqual(effective(self.win, False), (True, "site"))
        self.win.app_updates = "off"
        self.assertEqual(effective(self.win, True), (False, "agent"))


class TestTasks(Base):
    def test_collect_asks_online_windows_and_macos_agents(self):
        linux = baker.make_recipe("agents.online_agent", plat="linux")
        offline = baker.make_recipe("agents.offline_agent", plat="windows")
        old = baker.make_recipe("agents.online_agent", plat="windows")
        calls = []
        answers = {self.win.agent_id: WINGET_LIST, self.mac.agent_id: BREW_LIST}
        with fake_nats(answers, calls):
            result = collect_app_updates_task()

        self.assertEqual(result, "2 of 3 agents listed their app updates")
        self.assertEqual(
            sorted(c[0] for c in calls),
            sorted([self.win.agent_id, self.mac.agent_id, old.agent_id]),
        )
        self.assertEqual(
            calls[0][1:], ({"func": "appupdates", "payload": {"action": "list"}}, 120)
        )
        self.assertEqual(sorted(self.rows(self.mac)), ["497799835", "openssl@3"])
        self.assertEqual(AppUpdateScan.objects.get(agent=old).error, NO_ANSWER)
        self.assertFalse(AppUpdateScan.objects.filter(agent__in=[linux, offline]))

    def test_scheduled_run(self):
        store(self.win, parse_list(WINGET_LIST))
        store(self.mac, parse_list(BREW_LIST))
        self.mac.app_updates = "off"
        self.mac.save()
        AppUpdate.objects.filter(app_id="Notepad++.Notepad++").update(state="excluded")
        self.enable(exclusions=["7zip.7zip"])

        calls = []
        ok = ["Google.Chrome"]
        dispatch, modules = fake_notify()
        with fake_nats({self.win.agent_id: upgraded(ok)}, calls), modules:
            result = apply_app_updates_task()

        self.assertEqual(result, "1 app updates installed, 1 failed on 1 agents")
        self.assertEqual(len(calls), 1)
        agent_id, data, timeout = calls[0]
        self.assertEqual((agent_id, timeout), (self.win.agent_id, 1800))
        self.assertEqual(
            (data["func"], data["payload"]["action"], data["payload"]["source"]),
            ("appupdates", "upgrade", "winget"),
        )
        self.assertEqual(
            sorted(data["payload"]["ids"].split(",")),
            ["Google.Chrome", "Microsoft.VCRedist.2015+.x64"],
        )

        rows = self.rows(self.win)
        self.assertEqual(rows["Google.Chrome"].state, "done")
        failed = rows["Microsoft.VCRedist.2015+.x64"]
        self.assertEqual(
            (failed.state, failed.last_error), ("failed", "No result from the agent.")
        )
        self.assertEqual(rows["7zip.7zip"].state, "available")
        self.assertEqual(rows["Notepad++.Notepad++"].state, "excluded")

        history = AgentHistory.objects.get(agent=self.win)
        self.assertEqual(
            (history.type, history.username), (AgentHistoryType.APP_UPDATE, "system")
        )
        self.assertIn("winget upgrade", history.command)
        self.assertIn(
            "Google.Chrome 129.0.6668.59 -> 130.0.6723.70: ok", history.results
        )
        self.assertTrue(
            DebugLog.objects.filter(
                agent=self.win, message__contains="Microsoft.VCRedist"
            ).exists()
        )
        event = dispatch.call_args.args[0]
        self.assertEqual(
            (event["source"], event["severity"], event["agent"]),
            ("appupdate", "warning", self.win),
        )

    def test_scheduled_run_needs_the_hour_and_an_effective_on(self):
        store(self.win, parse_list(WINGET_LIST))
        calls = []
        with fake_nats({}, calls):
            # global off
            AppUpdateSettings.objects.filter(pk=1).update(hour=djangotime.now().hour)
            apply_app_updates_task()
            # on, another hour
            self.enable()
            AppUpdateSettings.objects.filter(pk=1).update(
                hour=(djangotime.now().hour + 1) % 24
            )
            apply_app_updates_task()
        self.assertEqual(calls, [])

        self.win.app_updates = "on"
        self.win.save()
        self.enable(max_per_run=1)
        AppUpdateSettings.objects.filter(pk=1).update(enabled=False)
        store(self.mac, parse_list(BREW_LIST))
        self.mac.app_updates = "on"
        self.mac.save()
        with fake_nats({}, calls):
            apply_app_updates_task()
        # agent policy wins over the global off, max_per_run caps the agents
        self.assertEqual(len({c[0] for c in calls}), 1)

    def test_old_agent_and_chunks(self):
        rows = {
            ("winget", f"App{i}.Id"): {"name": f"App {i}", "available": "2"}
            for i in range(150)
        }
        store(self.win, rows)
        self.enable()
        calls = []
        with fake_nats({}, calls):
            apply_app_updates_task()
        # 4 ids per call, after a timeout the agent is not asked again
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0][1]["payload"]["ids"].split(",")), 4)
        states = list(AppUpdate.objects.values_list("state", "last_error"))
        self.assertEqual(states.count(("failed", NO_ANSWER)), 4)
        # the calls that were never sent are not failures
        self.assertEqual(states.count(("available", "")), 146)

        calls = []
        with fake_nats({self.win.agent_id: upgraded([])}, calls):
            apply_app_updates_task()
        self.assertEqual(
            [len(c[1]["payload"]["ids"].split(",")) for c in calls], [4] * 37 + [2]
        )

    def test_not_started_and_timed_out(self):
        rows = {
            ("winget", f"App{i}.Id"): {"name": f"App {i}", "available": "2"}
            for i in range(4)
        }
        store(self.win, rows)
        self.enable()
        hint = "Hint: close the app and run the update again."
        tails = {
            "App0.Id": "",
            "App1.Id": "x" * 2000 + "\n" + hint,
            "App2.Id": "Installing\nwinget: time limit reached",
            "App3.Id": "not started: time limit reached",
        }

        def answer(data):
            ids = data["payload"]["ids"].split(",")
            return {
                "results": [
                    {"id": i, "ok": i == "App0.Id", "output_tail": tails[i]}
                    for i in ids
                ]
            }

        with fake_nats({self.win.agent_id: answer}, []):
            result = apply_app_updates_task()
        self.assertEqual(result, "1 app updates installed, 1 failed on 1 agents")
        got = self.rows(self.win)
        self.assertEqual(got["App0.Id"].state, "done")
        failed = got["App1.Id"]
        self.assertEqual((failed.state, len(failed.last_error)), ("failed", 1500))
        self.assertTrue(failed.last_error.endswith(hint))
        timed_out = got["App2.Id"]
        self.assertEqual(timed_out.state, "updating")
        self.assertTrue(timed_out.last_error.endswith(TIMED_OUT))
        self.assertIn("winget: time limit reached", timed_out.last_error)
        self.assertEqual(
            (got["App3.Id"].state, got["App3.Id"].last_error), ("available", "")
        )
        history = AgentHistory.objects.get(agent=self.win).results
        self.assertIn("App3.Id  -> 2: not started", history)
        self.assertIn(hint, history)

        # the next collect settles it: installed meanwhile, so no longer listed
        del rows[("winget", "App2.Id")]
        store(self.win, rows)
        self.assertNotIn("App2.Id", self.rows(self.win))

    def test_busy_agent_is_not_started(self):
        rows = {
            ("winget", f"App{i}.Id"): {"name": f"App {i}", "available": "2"}
            for i in range(10)
        }
        store(self.win, rows)
        self.enable()
        calls = []
        dispatch, modules = fake_notify()
        busy = "app updates are already running"
        with fake_nats({self.win.agent_id: busy}, calls), modules:
            result = apply_app_updates_task()
        self.assertEqual(result, "0 app updates installed, 0 failed on 1 agents")
        # the agent refused the first call, the others are not sent
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            set(AppUpdate.objects.values_list("state", "last_error")),
            {("available", "")},
        )
        history = "\n".join(
            AgentHistory.objects.filter(agent=self.win).values_list(
                "results", flat=True
            )
        )
        self.assertIn("App0.Id  -> 2: not started", history)
        self.assertNotIn("failed", history)
        dispatch.assert_not_called()

    def test_agent_timed_out_note_not_doubled(self):
        store(self.win, {("winget", "App0.Id"): {"name": "App 0", "available": "2"}})
        self.enable()
        note = "timed out, the installer may still finish; rescan"

        def answer(data):
            return {
                "results": [
                    {
                        "id": "App0.Id",
                        "ok": False,
                        "status": "timed_out",
                        "output_tail": f"Installing\n{note}",
                    }
                ]
            }

        with fake_nats({self.win.agent_id: answer}, []):
            apply_app_updates_task()
        row = self.rows(self.win)["App0.Id"]
        self.assertEqual(
            (row.state, row.last_error), ("updating", f"Installing\n{note}")
        )

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_collect_while_upgrading(self):
        cache.clear()
        store(self.win, parse_list(WINGET_LIST))
        before = AppUpdateScan.objects.get(agent=self.win).collected_at
        busy = "app updates are already running"
        with fake_nats({self.win.agent_id: busy}, []):
            collect_app_updates_task()
            r = self.client.post(f"/appupdates/{self.win.agent_id}/collect/")
        self.assertEqual(r.status_code, 400)
        scan = AppUpdateScan.objects.get(agent=self.win)
        self.assertEqual((scan.collected_at, scan.error), (before, ""))

        # a queued or running upgrade keeps its rows
        mark_applying([self.win], 1)
        AppUpdate.objects.filter(app_id="Google.Chrome").update(state="updating")
        store(self.win, parse_list(WINGET_LIST))
        self.assertEqual(self.rows(self.win)["Google.Chrome"].state, "updating")
        cache.delete(APPLYING.format(self.win.pk))
        store(self.win, parse_list(WINGET_LIST))
        self.assertEqual(self.rows(self.win)["Google.Chrome"].state, "available")

    def test_dashboard_run(self):
        store(self.win, parse_list(WINGET_LIST))
        pk = self.rows(self.win)["Google.Chrome"].pk
        calls = []
        with fake_nats({self.win.agent_id: upgraded(["Google.Chrome"])}, calls):
            apply_app_updates_task(pks=[pk], username="john")
        self.assertEqual(calls[0][1]["payload"]["ids"], "Google.Chrome")
        self.assertEqual(AppUpdate.objects.get(pk=pk).state, "done")
        self.assertEqual(AgentHistory.objects.get(agent=self.win).username, "john")

    def test_scheduled_run_picks_up_rows_left_updating(self):
        store(self.win, parse_list(WINGET_LIST))
        AppUpdate.objects.filter(app_id="Google.Chrome").update(state="updating")
        self.enable()
        calls = []
        with fake_nats({self.win.agent_id: upgraded(["Google.Chrome"])}, calls):
            apply_app_updates_task()
        self.assertIn("Google.Chrome", calls[0][1]["payload"]["ids"].split(","))
        self.assertEqual(self.rows(self.win)["Google.Chrome"].state, "done")


class TestViews(Base):
    def setUp(self):
        super().setUp()
        store(self.win, parse_list(WINGET_LIST))
        self.url = f"/appupdates/{self.win.agent_id}"

    def test_get(self):
        AppUpdate.objects.filter(app_id="Notepad++.Notepad++").update(state="excluded")
        AppUpdateSettings.objects.filter(pk=1).update(exclusions=["7zip.7zip"])
        r = self.client.get(f"{self.url}/")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(
            {k: data[k] for k in ("supported", "policy", "effective", "pending")},
            {"supported": True, "policy": "inherit", "effective": False, "pending": 2},
        )
        self.assertEqual(
            (data["site_policy"], data["global_enabled"], data["effective_from"]),
            ("inherit", False, "global"),
        )
        self.assertIsNotNone(data["collected_at"])
        row = next(u for u in data["updates"] if u["app_id"] == "7zip.7zip")
        self.assertEqual(
            set(row),
            {
                "id",
                "source",
                "app_id",
                "name",
                "installed",
                "available",
                "state",
                "last_error",
                "seen_at",
                "excluded_globally",
            },
        )
        self.assertTrue(row["excluded_globally"])
        self.assertEqual(self.client.get("/appupdates/nope/").status_code, 404)

    def test_settings_singleton_first_save_in_a_request(self):
        # a preset pk with no row must not break the audit save
        AppUpdateSettings.objects.all().delete()
        with patch("logs.models.get_username", return_value="riddix"):
            settings = AppUpdateSettings.load()
        self.assertEqual(settings.pk, 1)
        self.assertEqual(AppUpdateSettings.objects.count(), 1)
        self.assertTrue(
            AuditLog.objects.filter(
                object_type="appupdatesettings", action="add"
            ).exists()
        )

    def test_collect(self):
        calls = []
        with fake_nats({self.win.agent_id: BREW_LIST[:1]}, calls):
            r = self.client.post(f"{self.url}/collect/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([u["app_id"] for u in r.json()["updates"]], ["openssl@3"])
        self.assertEqual(calls[0][2], 120)

        with fake_nats({}, calls):
            r = self.client.post(f"{self.url}/collect/")
        self.assertEqual((r.status_code, r.json()), (400, NO_ANSWER))

        linux = baker.make_recipe("agents.online_agent", plat="linux")
        offline = baker.make_recipe("agents.offline_agent", plat="windows")
        for agent in (linux, offline):
            r = self.client.post(f"/appupdates/{agent.agent_id}/collect/")
            self.assertEqual(r.status_code, 400)

    @patch("appupdates.views.apply_app_updates_task.delay")
    def test_apply(self, delay):
        AppUpdate.objects.filter(app_id="Notepad++.Notepad++").update(state="excluded")
        ids = ["Google.Chrome", "Notepad++.Notepad++", "Not.Listed"]
        r = self.client.post(f"{self.url}/apply/", {"ids": ids}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.json(),
            {
                "queued": ["Google.Chrome"],
                "skipped": ["Not.Listed", "Notepad++.Notepad++"],
            },
        )
        chrome = self.rows(self.win)["Google.Chrome"]
        self.assertEqual(chrome.state, "updating")
        delay.assert_called_once_with(pks=[chrome.pk], username="john")
        self.assertTrue(
            AuditLog.objects.filter(
                agent_id=self.win.agent_id, message__contains="Google.Chrome"
            ).exists()
        )

        # a row left updating by a killed worker is queued again
        r = self.client.post(f"{self.url}/apply/", {"ids": ids}, format="json")
        self.assertEqual(r.json()["queued"], ["Google.Chrome"])

        # bad ids, nothing given
        for body in ({"ids": ["-rf"]}, {"ids": []}, {}):
            r = self.client.post(f"{self.url}/apply/", body, format="json")
            self.assertEqual(r.status_code, 400, body)
        self.assertEqual(delay.call_count, 2)

    def test_exclude(self):
        url = f"{self.url}/exclude/"
        body = {"app_id": "Google.Chrome", "excluded": True}
        r = self.client.put(url, body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.rows(self.win)["Google.Chrome"].state, "excluded")
        self.assertEqual(r.json()["pending"], 3)

        r = self.client.put(url, {**body, "excluded": False}, format="json")
        self.assertEqual(self.rows(self.win)["Google.Chrome"].state, "available")

        # a marker row without a pending version goes away
        AppUpdate.objects.filter(app_id="Google.Chrome").update(
            state="excluded", available=""
        )
        self.client.put(url, {**body, "excluded": False}, format="json")
        self.assertNotIn("Google.Chrome", self.rows(self.win))

        for bad in (
            {"app_id": "Not.Listed", "excluded": True},
            {"app_id": "7zip.7zip", "excluded": "yes"},
            {"app_id": "a b", "excluded": True},
        ):
            self.assertEqual(self.client.put(url, bad, format="json").status_code, 400)

    def test_policies(self):
        r = self.client.patch(
            f"{self.url}/policy/", {"app_updates": "on"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            (r.json()["policy"], r.json()["effective"], r.json()["effective_from"]),
            ("on", True, "agent"),
        )
        self.win.refresh_from_db()
        self.assertEqual(self.win.app_updates, "on")
        bad = self.client.patch(
            f"{self.url}/policy/", {"app_updates": "x"}, format="json"
        )
        self.assertEqual(bad.status_code, 400)

        url = f"/appupdates/sites/{self.site.pk}/policy/"
        r = self.client.patch(url, {"app_updates": "off"}, format="json")
        self.assertEqual(r.json(), {"id": self.site.pk, "app_updates": "off"})
        self.site.refresh_from_db()
        self.assertEqual(self.site.app_updates, "off")

        r = self.client.get("/appupdates/settings/")
        self.assertEqual(
            [(s["id"], s["app_updates"]) for s in r.json()["sites"]],
            [(self.site.pk, "off")],
        )

    def test_settings(self):
        r = self.client.get("/appupdates/settings/")
        self.assertEqual(
            {k: r.json()[k] for k in ("enabled", "hour", "max_per_run", "exclusions")},
            {"enabled": False, "hour": 3, "max_per_run": 50, "exclusions": []},
        )
        r = self.client.put(
            "/appupdates/settings/",
            {"enabled": True, "hour": 22, "exclusions": ["b.b", "openssl@3", "b.b"]},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["exclusions"], ["b.b", "openssl@3"])
        s = AppUpdateSettings.load()
        self.assertEqual((s.enabled, s.hour, s.max_per_run), (True, 22, 50))

        for bad in (
            {"hour": 24},
            {"max_per_run": 0},
            {"exclusions": ["-x"]},
            {"exclusions": "Google.Chrome"},
        ):
            r = self.client.put("/appupdates/settings/", bad, format="json")
            self.assertEqual(r.status_code, 400, bad)

    @patch("appupdates.views.apply_app_updates_task.delay", MagicMock())
    def test_permissions(self):
        other = baker.make_recipe("agents.online_agent", plat="windows")
        store(other, parse_list(WINGET_LIST))
        urls = (
            ("get", f"{self.url}/"),
            ("post", f"{self.url}/collect/"),
            ("post", f"{self.url}/apply/"),
            ("put", f"{self.url}/exclude/"),
            ("patch", f"{self.url}/policy/"),
            ("patch", f"/appupdates/sites/{self.site.pk}/policy/"),
            ("get", "/appupdates/settings/"),
            ("put", "/appupdates/settings/"),
        )
        for method, url in urls:
            self.check_not_authenticated(method, url)

        self.client.force_authenticate(user=self.create_user_with_roles([]))
        for method, url in urls:
            self.check_not_authorized(method, url)

        # viewing needs can_list_software, changes can_manage_app_updates
        user = self.create_user_with_roles(["can_list_software"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(f"{self.url}/").status_code, 200)
        self.assertEqual(
            self.client.get(f"/appupdates/{other.agent_id}/").status_code, 403
        )
        body = {"ids": ["Google.Chrome"]}
        r = self.client.post(f"{self.url}/apply/", body, format="json")
        self.assertEqual(r.status_code, 403)

        user = self.create_user_with_roles(["can_manage_app_updates"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        r = self.client.post(
            f"/appupdates/{other.agent_id}/apply/", body, format="json"
        )
        self.assertEqual(r.status_code, 403)
        r = self.client.post(f"{self.url}/apply/", body, format="json")
        self.assertEqual(r.status_code, 200)
        policy = {"app_updates": "on"}
        r = self.client.patch(f"{self.url}/policy/", policy, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.get("/appupdates/settings/").status_code, 403)

        user = self.create_user_with_roles(["can_edit_agent", "can_manage_sites"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        r = self.client.patch(f"{self.url}/policy/", policy, format="json")
        self.assertEqual(r.status_code, 200)
        r = self.client.patch(
            f"/appupdates/{other.agent_id}/policy/", policy, format="json"
        )
        self.assertEqual(r.status_code, 403)
        url = f"/appupdates/sites/{other.site.pk}/policy/"
        self.assertEqual(self.client.patch(url, policy, format="json").status_code, 403)
        url = f"/appupdates/sites/{self.site.pk}/policy/"
        self.assertEqual(self.client.patch(url, policy, format="json").status_code, 200)

        user = self.create_user_with_roles(["can_view_core_settings"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get("/appupdates/settings/").status_code, 200)
        r = self.client.put("/appupdates/settings/", {"hour": 1}, format="json")
        self.assertEqual(r.status_code, 403)

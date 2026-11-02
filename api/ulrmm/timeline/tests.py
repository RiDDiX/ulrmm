# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid
from datetime import timedelta

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.test import ULRMMTestCase

ALL_TYPES = {
    "script", "command", "task", "app_update", "audit", "debug",
    "alert", "pending", "patch", "schedule", "package",
}  # fmt: skip


def populate(agent, n=1, base=None):
    """n rows per source for one agent, newest first by the given offsets"""
    base = base or djangotime.now() - timedelta(hours=1)
    script = baker.make("scripts.Script", name="Clean temp")
    patch = baker.make("patches.Patch", package="libfoo")
    device = baker.make("patches.PatchDevice", patch=patch, agent=agent)
    sched = baker.make("patches.MaintenanceSchedule", name="Nightly")
    for i in range(n):
        at = base - timedelta(minutes=i)
        h = [
            baker.make(
                "agents.AgentHistory",
                agent=agent,
                type="script_run",
                script=script,
                username="john",
                script_results={"retcode": 1, "stdout": "SECRET"},
            ),
            baker.make(
                "agents.AgentHistory",
                agent=agent,
                type="cmd_run",
                command="net user x hunter2",
                username="john",
            ),
            baker.make(
                "agents.AgentHistory",
                agent=agent,
                type="task_run",
                command="Backup",
            ),
            baker.make(
                "agents.AgentHistory",
                agent=agent,
                type="app_update",
                command="winget upgrade Mozilla.Firefox",
                results="Mozilla.Firefox 1 -> 2: failed\nLONG OUTPUT",
            ),
        ]
        e = [
            baker.make(
                "logs.AuditLog",
                agent=agent.hostname,
                agent_id=agent.agent_id,
                username="john",
                action="exec_command",
                message="john ran a command",
            ),
            baker.make("logs.DebugLog", agent=agent, log_level="error", message="boom"),
            baker.make(
                "alerts.Alert",
                agent=agent,
                message="disk full",
                severity="error",
                resolved=True,
                resolved_on=at,
            ),
            baker.make("logs.PendingAction", agent=agent, action_type="agentupdate"),
            baker.make(
                "patches.PatchEvent",
                patch_device=device,
                event_type="approved",
                actor="john",
                at=at,
                prev_hash=f"h{i}",
                hash=f"h{i + 1}",
            ),
            baker.make(
                "patches.ScheduleRun",
                schedule=sched,
                agent=agent,
                state="done",
                occurrence=at,
                ends=at,
                changed=at,
                detail="ok",
            ),
            baker.make(
                "packages.PackageInstall",
                agent=agent,
                package_name="7zip",
                batch=uuid.uuid4(),
                run_as="system",
                state="failed",
                detail="exit 1",
                requested_by="john",
                output="LONG OUTPUT",
            ),
        ]
        # auto_now_add fields can only be set after the insert
        for obj, field in zip(
            h + e[:4] + e[6:],
            ["time"] * 4
            + ["entry_time", "entry_time", "alert_time", "entry_time"]
            + ["created"],
        ):
            type(obj).objects.filter(pk=obj.pk).update(**{field: at})
    return base


class TestTimeline(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.agent = baker.make_recipe("agents.agent")
        self.url = f"/timeline/{self.agent.agent_id}/"

    def get(self, url=None, **params):
        r = self.client.get(url or self.url, params)
        self.assertEqual(r.status_code, 200, r.data)
        return r.data

    def test_every_type_with_shape(self):
        populate(self.agent)
        data = self.get()
        by_type = {}
        for i in data["items"]:
            by_type.setdefault(i["type"], []).append(i)
        self.assertEqual(set(by_type), ALL_TYPES)
        # an alert yields a created and a resolved item
        self.assertEqual(len(by_type["alert"]), 2)
        for i in data["items"]:
            self.assertEqual(
                set(i),
                {"ts", "type", "title", "detail", "user", "severity", "ref", "agent"},
            )
            self.assertEqual(set(i["ref"]), {"kind", "id"})
            self.assertLessEqual(len(i["detail"]), 500)
            self.assertIn(i["severity"], ("info", "warning", "error"))
            self.assertEqual(i["agent"]["agent_id"], self.agent.agent_id)
        stamps = [i["ts"] for i in data["items"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        # populate() gives every row the same time
        self.assertEqual(data["next_before"], f"{stamps[-1]}~{len(stamps)}")

        script = by_type["script"][0]
        self.assertEqual(script["title"], "Clean temp")
        self.assertEqual(script["severity"], "error")
        self.assertEqual(script["detail"], "exit code 1")
        self.assertEqual(by_type["package"][0]["severity"], "error")
        self.assertEqual(
            by_type["app_update"][0]["title"], "winget upgrade Mozilla.Firefox"
        )

    def test_no_secrets_in_items(self):
        populate(self.agent)
        text = str(self.get()["items"])
        for secret in ("SECRET", "hunter2", "LONG OUTPUT"):
            self.assertNotIn(secret, text)

    def test_filter_types(self):
        populate(self.agent)
        data = self.get(types="script,package")
        self.assertEqual({i["type"] for i in data["items"]}, {"script", "package"})
        data = self.get(types="command")
        self.assertEqual([i["type"] for i in data["items"]], ["command"])
        r = self.client.get(self.url, {"types": "nope"})
        self.assertEqual(r.status_code, 400)

    def test_pagination_before(self):
        populate(self.agent, n=4)
        first = self.get(limit=10)
        self.assertEqual(len(first["items"]), 10)
        seen = {
            (i["type"], i["ref"]["id"], i["ts"], i["title"]) for i in first["items"]
        }
        second = self.get(limit=10, before=first["next_before"])
        self.assertTrue(second["items"])
        cursor = first["next_before"].split("~")[0]
        for i in second["items"]:
            self.assertLessEqual(i["ts"], cursor)
            self.assertNotIn((i["type"], i["ref"]["id"], i["ts"], i["title"]), seen)
        empty = self.get(before="2000-01-01T00:00:00Z")
        self.assertEqual(empty, {"items": [], "next_before": None})
        now = djangotime.now().isoformat()
        for bad in (
            "yesterday",
            "2026-02-30T00:00:00",
            f"{now}~x",
            f"{now}~-1",
            f"{now}~10001",
            f"{now}~{'9' * 5000}",
            "~1",
        ):
            r = self.client.get(self.url, {"before": bad})
            self.assertEqual(r.status_code, 400)

    def test_alerts_resolved_after_the_cursor_keep_no_slots(self):
        cursor = djangotime.now() - timedelta(hours=1)
        spanning = [
            baker.make(
                "alerts.Alert",
                agent=self.agent,
                resolved=True,
                resolved_on=cursor + timedelta(minutes=5),
            )
            for _ in range(2)
        ]
        just_before = baker.make("alerts.Alert", agent=self.agent)
        for alert, at in ((spanning[0], 30), (spanning[1], 20), (just_before, 1)):
            type(alert).objects.filter(pk=alert.pk).update(
                alert_time=cursor - timedelta(minutes=at)
            )
        items = self.get(types="alert", limit=2, before=cursor.isoformat())["items"]
        self.assertEqual(
            [i["ref"]["id"] for i in items], [just_before.pk, spanning[1].pk]
        )
        self.assertEqual({i["title"] for i in items}, {"Alert created"})

    def test_items_sharing_the_page_boundary_are_all_shown_once(self):
        at = djangotime.now() - timedelta(hours=1)
        sched = baker.make("patches.MaintenanceSchedule", name="Nightly")
        runs = [
            baker.make(
                "patches.ScheduleRun",
                schedule=sched,
                agent=self.agent,
                state="done",
                occurrence=at - timedelta(days=i),
                ends=at,
                changed=at,
            )
            for i in range(5)
        ]
        older = baker.make("agents.AgentHistory", agent=self.agent, type="cmd_run")
        type(older).objects.filter(pk=older.pk).update(time=at - timedelta(seconds=1))

        pages, before = [], None
        while True:
            params = {"limit": 2, **({"before": before} if before else {})}
            data = self.get(**params)
            if not data["items"]:
                break
            pages.append([(i["type"], i["ref"]["id"]) for i in data["items"]])
            before = data["next_before"]
        shown = [ref for page in pages for ref in page]
        self.assertEqual(
            shown,
            [("schedule", r.pk) for r in reversed(runs)] + [("command", older.pk)],
        )
        self.assertEqual(len(pages), 3)

    def test_alert_resolved_after_the_page_does_not_hide_newer_ones(self):
        before = djangotime.now() - timedelta(hours=1)
        spanning = baker.make(
            "alerts.Alert",
            agent=self.agent,
            resolved=True,
            resolved_on=before + timedelta(minutes=5),
        )
        newer = baker.make("alerts.Alert", agent=self.agent)
        baker.make("alerts.Alert", agent=self.agent)
        for alert, at in ((spanning, 30), (newer, 1)):
            type(alert).objects.filter(pk=alert.pk).update(
                alert_time=before - timedelta(minutes=at)
            )
        items = self.get(types="alert", limit=1, before=before.isoformat())["items"]
        self.assertEqual(
            [(i["title"], i["ref"]["id"]) for i in items], [("Alert created", newer.pk)]
        )

    def test_types_need_the_flags_of_their_own_views(self):
        populate(self.agent)
        user = self.create_user_with_roles(["can_view_auditlogs"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.get("/timeline/").status_code, 403)

        user.role.can_view_auditlogs = False
        user.role.can_list_agents = True
        user.role.save()
        seen = {"schedule"}
        self.assertEqual({i["type"] for i in self.get()["items"]}, seen)
        self.assertEqual(self.get(types="audit,debug,script")["items"], [])
        for flag, types in (
            ("can_list_agent_history", {"script", "command", "task", "app_update"}),
            ("can_view_auditlogs", {"audit"}),
            ("can_view_debuglogs", {"debug"}),
            ("can_list_alerts", {"alert"}),
            ("can_list_pendingactions", {"pending"}),
            ("can_view_patches", {"patch"}),
            ("can_install_packages", {"package"}),
        ):
            setattr(user.role, flag, True)
            user.role.save()
            seen |= types
            with self.subTest(flag=flag):
                self.assertEqual({i["type"] for i in self.get()["items"]}, seen)
                fleet = self.get("/timeline/", limit=200)["items"]
                self.assertEqual({i["type"] for i in fleet}, seen)
        self.assertEqual(seen, ALL_TYPES)

    def test_scope_denied(self):
        populate(self.agent)
        user = self.create_user_with_roles(["can_list_agents", "can_view_auditlogs"])
        other = baker.make_recipe("agents.agent")
        user.role.can_view_sites.set([other.site])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.get(f"/timeline/{other.agent_id}/")["items"], [])

        user.role.can_view_sites.set([self.agent.site])
        self.assertTrue(self.get()["items"])

    def test_unknown_agent_and_anonymous(self):
        self.assertEqual(self.client.get("/timeline/nope/").status_code, 404)
        self.check_not_authenticated("get", self.url)
        self.check_not_authenticated("get", "/timeline/")

    def test_fleet_feed_is_role_filtered(self):
        other = baker.make_recipe("agents.agent")
        populate(self.agent)
        populate(other)
        full = self.get("/timeline/", limit=200)
        self.assertEqual(
            {i["agent"]["agent_id"] for i in full["items"]},
            {self.agent.agent_id, other.agent_id},
        )

        user = self.create_user_with_roles(["can_list_agents", "can_view_auditlogs"])
        user.role.can_view_sites.set([other.site])
        self.client.force_authenticate(user=user)
        data = self.get("/timeline/", limit=200)
        self.assertTrue(data["items"])
        self.assertEqual(
            {i["agent"]["agent_id"] for i in data["items"]}, {other.agent_id}
        )
        # no debug flag
        self.assertNotIn("debug", {i["type"] for i in data["items"]})
        self.assertIn("audit", {i["type"] for i in data["items"]})

        norole = self.create_user_with_roles([])
        norole.role = None
        norole.save()
        self.client.force_authenticate(user=norole)
        self.assertEqual(self.client.get("/timeline/").status_code, 403)

    def test_limit_is_applied_after_merge(self):
        populate(self.agent, n=3)
        data = self.get(limit=5)
        self.assertEqual(len(data["items"]), 5)

    def test_query_count_does_not_grow_with_rows(self):
        populate(self.agent, n=1)
        with CaptureQueriesContext(connection) as small:
            self.get()
        populate(self.agent, n=6, base=djangotime.now() - timedelta(hours=3))
        with CaptureQueriesContext(connection) as large:
            self.get()
        self.assertEqual(len(small), len(large))
        self.assertLessEqual(len(large), 20)

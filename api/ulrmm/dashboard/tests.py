# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker

from accounts.models import User
from discovery.models import DiscoveredDevice
from groups.models import DeviceGroup
from timeline.sources import LIST_FLAGS
from ulrmm.test import ULRMMTestCase

from .views import DEFAULT
from .widgets import WIDGETS

LAYOUT = "/dashboard/layout/"

# queries per widget for a superuser. a scoped role adds two (its clients
# and sites). more rows do not add queries
BUDGET = {
    "fleet": 2,
    "alerts": 2,
    "offline": 2,
    "patches": 1,
    "checks": 2,
    "activity": 8,
    "vulns": 2,
    "netmon": 2,
    "top_cpu": 1,
    "top_mem": 1,
    "discovery": 2,
    "groups": 2,
    "encryption": 4,
    "notes": 0,
    "actions": 3,
}

FLAGS = {
    "alerts": "can_list_alerts",
    "offline": "can_list_agents",
    "checks": "can_list_checks",
    "vulns": "can_view_vulnerabilities",
    "netmon": "can_list_network_devices",
    "top_cpu": "can_list_agents",
    "top_mem": "can_list_agents",
    "discovery": "can_run_network_discovery",
    "groups": "can_list_agents",
    "encryption": "can_view_recovery_keys",
    "activity": "can_list_agents",
    "actions": "can_list_pendingactions",
}


def widget(kind="fleet", size="m", settings=None, **extra) -> dict:
    w = {"id": str(uuid.uuid4()), "type": kind, "size": size}
    if settings is not None:
        w["settings"] = settings
    w.update(extra)
    return w


class TestLayout(ULRMMTestCase):
    def setUp(self):
        self.authenticate()

    def put(self, body, status=200):
        r = self.client.put(LAYOUT, body, format="json")
        self.assertEqual(r.status_code, status, r.data)
        return r.data

    def test_default_layout(self):
        r = self.client.get(LAYOUT)
        self.assertEqual(r.status_code, 200)
        widgets = r.data["widgets"]
        self.assertEqual(
            [(w["type"], w["size"]) for w in widgets],
            [("fleet", "m"), ("alerts", "m"), ("offline", "m"), ("patches", "s")]
            + [("activity", "l")],
        )
        for w in widgets:
            self.assertEqual(uuid.UUID(w["id"]).version, 4)
        self.assertEqual(widgets[-1]["settings"], {"limit": 20, "types": []})
        # nothing saved yet. the default layout still validates
        self.john.refresh_from_db()
        self.assertEqual(self.john.dashboard_layout, {})
        self.assertEqual(self.put(r.data), r.data)

    def test_default_follows_the_role(self):
        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        types = [w["type"] for w in self.client.get(LAYOUT).data["widgets"]]
        self.assertEqual(types, ["fleet", "patches"])

        user = self.create_user_with_roles(["can_list_alerts", "can_list_agents"])
        self.client.force_authenticate(user=user)
        types = [w["type"] for w in self.client.get(LAYOUT).data["widgets"]]
        self.assertEqual(types, [t for _, t, _ in DEFAULT])

    def test_delete_resets_to_the_role_default(self):
        johns = self.put({"widgets": [widget("notes")]})
        user = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=user)
        self.put({"widgets": [widget("alerts"), widget("notes")]})
        r = self.client.delete(LAYOUT)
        self.assertEqual(r.status_code, 200)
        types = [w["type"] for w in r.data["widgets"]]
        self.assertEqual(types, ["fleet", "offline", "patches", "activity"])
        self.assertEqual(self.client.get(LAYOUT).data, r.data)
        user.refresh_from_db()
        self.assertEqual(user.dashboard_layout, {})
        self.john.refresh_from_db()
        self.assertEqual(self.john.dashboard_layout, johns)

    def test_put_replaces_the_layout(self):
        group = baker.make("groups.DeviceGroup", name="Servers")
        body = {
            "widgets": [
                widget("top_cpu", "l", {"range": "7d"}),
                widget("notes", "s", {"text": "  call the ISP  "}),
                widget("groups", settings={"group_ids": [group.pk, group.pk]}),
                widget("vulns"),
            ]
        }
        saved = self.put(body)
        self.assertEqual(
            [w["id"] for w in saved["widgets"]], [w["id"] for w in body["widgets"]]
        )
        settings = [w["settings"] for w in saved["widgets"]]
        self.assertEqual(
            settings,
            [
                {"range": "7d", "limit": 10},
                {"text": "  call the ISP  "},
                {"group_ids": [group.pk]},
                {},
            ],
        )
        self.john.refresh_from_db()
        self.assertEqual(self.john.dashboard_layout, saved)
        self.assertEqual(self.client.get(LAYOUT).data, saved)

        one = {"widgets": [widget("checks", "s")]}
        self.put(one)
        self.assertEqual(
            self.client.get(LAYOUT).data["widgets"],
            [{**one["widgets"][0], "settings": {}}],
        )

        # a saved empty layout stays empty. the default is for a user with no row
        self.put({"widgets": []})
        self.assertEqual(self.client.get(LAYOUT).data, {"widgets": []})

    def test_only_the_own_layout(self):
        mine = self.put({"widgets": [widget("notes", settings={"text": "john"})]})
        self.client.force_authenticate(user=self.alice)
        self.assertEqual(len(self.client.get(LAYOUT).data["widgets"]), len(DEFAULT))
        self.put({"widgets": [widget("fleet")]})
        self.john.refresh_from_db()
        self.assertEqual(self.john.dashboard_layout, mine)

    def test_validation_matrix(self):
        group = baker.make("groups.DeviceGroup", name="Servers")
        first = widget()
        bad = {
            "not an object": [],
            "extra top key": {"widgets": [], "columns": 3},
            "widgets not a list": {"widgets": "fleet"},
            "too many": {"widgets": [widget() for _ in range(25)]},
            "widget not an object": {"widgets": ["fleet"]},
            "unknown widget key": {"widgets": [widget(color="red")]},
            "no id": {"widgets": [{"type": "fleet", "size": "m"}]},
            "no type": {"widgets": [{"id": str(uuid.uuid4()), "size": "m"}]},
            "no size": {"widgets": [{"id": str(uuid.uuid4()), "type": "fleet"}]},
            "id not a uuid": {"widgets": [widget(id="widget-1")]},
            "id a number": {"widgets": [widget(id=5)]},
            "uuid1": {"widgets": [widget(id=str(uuid.uuid1()))]},
            "uuid upper case": {"widgets": [widget(id=str(uuid.uuid4()).upper())]},
            "duplicate id": {"widgets": [first, {**first, "type": "alerts"}]},
            "unknown type": {"widgets": [widget("weather")]},
            "type a list": {"widgets": [widget(["fleet"])]},
            "bad size": {"widgets": [widget(size="xl")]},
            "settings a list": {"widgets": [widget(settings=[])]},
            "unknown setting": {"widgets": [widget(settings={"range": "1h"})]},
            "group_ids text": {
                "widgets": [widget("groups", settings={"group_ids": "1"})]
            },
            "group_ids no pk": {
                "widgets": [widget("groups", settings={"group_ids": ["x"]})]
            },
            "group missing": {
                "widgets": [widget("groups", settings={"group_ids": [group.pk + 99]})]
            },
            "too many groups": {
                "widgets": [
                    widget("groups", settings={"group_ids": list(range(1, 22))})
                ]
            },
            "notes too long": {
                "widgets": [widget("notes", settings={"text": "x" * 2001})]
            },
            "notes not text": {"widgets": [widget("notes", settings={"text": []})]},
            "range": {"widgets": [widget("top_cpu", settings={"range": "2y"})]},
            "limit": {"widgets": [widget("top_mem", settings={"limit": 0})]},
            "activity types": {
                "widgets": [widget("activity", settings={"types": ["nope"]})]
            },
        }
        for name, body in bad.items():
            with self.subTest(name):
                r = self.client.put(LAYOUT, body, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertIsInstance(r.data, str)
        self.john.refresh_from_db()
        self.assertEqual(self.john.dashboard_layout, {})

        r = self.client.put(
            LAYOUT, {"widgets": [widget(), widget(size="xl")]}, format="json"
        )
        self.assertTrue(r.data.startswith("Widget 2: size"), r.data)

        self.put({"widgets": [widget() for _ in range(24)]})
        self.put({"widgets": [widget("notes", settings={"text": "x" * 2000})]})

    def test_anonymous_and_installer_user(self):
        self.check_not_authenticated("get", LAYOUT)
        self.check_not_authenticated("put", LAYOUT)
        self.check_not_authenticated("delete", LAYOUT)
        installer = User.objects.filter(is_installer_user=True).first()
        self.client.force_authenticate(user=installer)
        self.assertEqual(self.client.get(LAYOUT).status_code, 403)
        r = self.client.put(LAYOUT, {"widgets": []}, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.delete(LAYOUT).status_code, 403)
        self.assertEqual(self.client.get("/dashboard/widgets/fleet/").status_code, 403)


class TestWidgets(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        now = djangotime.now()
        self.site = baker.make("clients.Site")
        self.other_site = baker.make("clients.Site")
        self.mine = baker.make_recipe(
            "agents.online_agent", site=self.site, hostname="mine"
        )
        self.lost = baker.make_recipe(
            "agents.overdue_agent", site=self.site, hostname="lost"
        )
        self.theirs = baker.make_recipe(
            "agents.offline_agent", site=self.other_site, hostname="theirs"
        )
        self.populate(now)

    def populate(self, now, agents=None):
        mine, lost, theirs = agents or (self.mine, self.lost, self.theirs)
        tag = uuid.uuid4().hex[:8]

        baker.make("alerts.Alert", agent=mine, severity="error", message="disk")
        baker.make("alerts.Alert", agent=theirs, severity="warning")
        baker.make("alerts.Alert", agent=mine, severity="error", resolved=True)
        baker.make("alerts.Alert", agent=mine, severity="info", snoozed=True)

        update = {"action": "approve", "installed": False}
        baker.make("winupdate.WinUpdate", agent=mine, **update)
        baker.make("winupdate.WinUpdate", agent=lost, result="failed", **update)
        baker.make("winupdate.WinUpdate", agent=theirs, result="failed", **update)
        baker.make(
            "winupdate.WinUpdate", agent=theirs, action="approve", installed=True
        )

        disk = baker.make_recipe("checks.diskspace_check", agent=mine)
        script = baker.make_recipe("checks.script_check", agent=theirs)
        passing = baker.make_recipe("checks.ping_check", agent=mine)
        baker.make(
            "checks.CheckResult",
            agent=mine,
            assigned_check=disk,
            status="failing",
            alert_severity="error",
            last_run=now,
            more_info="C: 95% used",
        )
        baker.make(
            "checks.CheckResult",
            agent=theirs,
            assigned_check=script,
            status="failing",
            last_run=now - djangotime.timedelta(minutes=5),
        )
        baker.make(
            "checks.CheckResult", agent=mine, assigned_check=passing, status="passing"
        )

        for agent in (mine, theirs):
            baker.make(
                "agents.AgentHistory", agent=agent, type="cmd_run", command="dir"
            )
            baker.make(
                "logs.AuditLog",
                agent=agent.hostname,
                agent_id=agent.agent_id,
                username="john",
                action="exec_command",
                message="john ran a command",
            )
            baker.make("logs.DebugLog", agent=agent, log_level="error", message="boom")

        for agent, level in ((mine, "critical"), (theirs, "high")):
            adv = baker.make(
                "vulns.Advisory",
                vuln_id=f"CVE-{tag}-{level}",
                level=level,
                fetched_at=now,
                fixed={"Debian:12|openssl": ["3.0.2"]},
            )
            baker.make(
                "vulns.Finding",
                agent=agent,
                package="openssl",
                version="3.0.1",
                ecosystem="Debian:12",
                vuln_id=adv.vuln_id,
                advisory=adv,
                first_seen=now,
                last_seen=now,
            )
            baker.make("vulns.AgentScan", agent=agent, scanned_at=now)

        site, other = mine.site, theirs.site
        down = baker.make(
            "netmon.NetworkDevice",
            site=site,
            name="switch",
            host="10.0.0.2",
            status="down",
        )
        baker.make(
            "netmon.NetworkDevice", site=site, name="nas", host="10.0.0.3", status="up"
        )
        baker.make(
            "netmon.NetworkDevice",
            site=other,
            name="ap",
            host="10.0.0.4",
            status="degraded",
        )
        baker.make(
            "netmon.NetworkDevice",
            site=site,
            name="old",
            host="10.0.0.5",
            status="down",
            enabled=False,
        )
        baker.make("alerts.Alert", network_device=down, severity="error")

        for agent, cpu in ((mine, 80.0), (theirs, 20.0)):
            baker.make(
                "metrics.Sample",
                agent=agent,
                ts=now,
                cpu=cpu,
                mem_used=int(cpu * 10),
                mem_total=1000,
            )

        scan = baker.make("discovery.Scan", status="done", networks=["10.0.0.0/24"])
        for state in ("new", "new", "ignored", "agent"):
            baker.make(
                "discovery.DiscoveredDevice",
                ip=f"10.1.0.{DiscoveredDevice.objects.count() + 1}",
                state=state,
                last_seen=now,
                last_scan=scan,
            )

        static = baker.make("groups.DeviceGroup", name=f"all {tag}", kind="static")
        static.members.set([mine, lost, theirs])
        baker.make(
            "groups.DeviceGroup",
            name=f"windows {tag}",
            kind="dynamic",
            rules={
                "match": "all",
                "conditions": [{"field": "plat", "op": "eq", "value": "windows"}],
            },
        )

        baker.make(
            "encryption.EncryptionState",
            agent=mine,
            volumes=[{"volume": "C:", "kind": "bitlocker", "protection": "on"}],
            collected_at=now,
        )
        baker.make(
            "encryption.EncryptionState",
            agent=theirs,
            volumes=[{"volume": "C:", "kind": "bitlocker", "protection": "off"}],
            collected_at=now,
        )
        baker.make(
            "encryption.RecoveryKey", agent=mine, kind="bitlocker", volume="C:", key="x"
        )

    def get(self, kind, status=200, **params):
        r = self.client.get(f"/dashboard/widgets/{kind}/", params)
        self.assertEqual(r.status_code, status, getattr(r, "data", r))
        return r.data

    def scoped(self, *flags):
        """a role limited to self.site"""
        user = self.create_user_with_roles(list(flags))
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        return user

    def test_fleet(self):
        data = self.get("fleet")
        self.assertEqual(
            {k: data[k] for k in ("total", "online", "offline", "overdue")},
            {"total": 3, "online": 1, "offline": 1, "overdue": 1},
        )
        self.assertEqual(data["servers"] + data["workstations"], 3)
        self.assertEqual(data["by_plat"], [{"plat": "windows", "count": 3}])
        self.assertEqual(
            set(data),
            {
                "total",
                "online",
                "offline",
                "overdue",
                "servers",
                "workstations",
                "needs_reboot",
                "maintenance_mode",
                "by_plat",
            },
        )
        self.scoped()
        data = self.get("fleet")
        self.assertEqual((data["total"], data["offline"], data["overdue"]), (2, 0, 1))

    def test_alerts(self):
        data = self.get("alerts")
        # open: not resolved, not snoozed; agent, device and other site
        self.assertEqual(
            {k: data[k] for k in ("total", "error", "warning", "info")},
            {"total": 3, "error": 2, "warning": 1, "info": 0},
        )
        self.assertEqual(len(data["latest"]), 3)
        self.assertEqual(
            set(data["latest"][0]),
            {
                "id",
                "severity",
                "message",
                "alert_time",
                "alert_type",
                "agent_id",
                "name",
            },
        )
        self.assertIn("switch", {a["name"] for a in data["latest"]})

        self.scoped("can_list_alerts")
        data = self.get("alerts")
        self.assertEqual((data["total"], data["warning"]), (2, 0))
        self.assertEqual({a["name"] for a in data["latest"]}, {"mine", "switch"})

    def test_offline(self):
        data = self.get("offline")
        self.assertEqual((data["offline"], data["overdue"]), (1, 1))
        self.assertEqual(
            [(a["hostname"], a["overdue"]) for a in data["agents"]],
            [("theirs", False), ("lost", True)],
        )
        self.assertEqual(
            set(data["agents"][0]),
            {
                "agent_id",
                "hostname",
                "display_name",
                "client",
                "site",
                "plat",
                "last_seen",
                "overdue",
            },
        )
        self.assertEqual(data["agents"][1]["site"], self.site.name)

        self.scoped("can_list_agents")
        data = self.get("offline")
        self.assertEqual((data["offline"], data["overdue"]), (0, 1))
        self.assertEqual([a["hostname"] for a in data["agents"]], ["lost"])

    def test_actions(self):
        for agent, status in (
            (self.mine, "pending"),
            (self.lost, "completed"),
            (self.theirs, "pending"),
        ):
            baker.make(
                "logs.PendingAction",
                agent=agent,
                action_type="agentupdate",
                status=status,
                details={"version": "6.20.10.2026"},
            )
        data = self.get("actions")
        self.assertEqual((data["pending"], data["completed"]), (2, 1))
        self.assertEqual(
            [r["hostname"] for r in data["pending_rows"]], ["mine", "theirs"]
        )
        row = data["completed_rows"][0]
        self.assertEqual(
            (row["hostname"], row["description"], row["status"]),
            ("lost", "Agent update to 6.20.10.2026", "completed"),
        )
        data = self.get("actions", client_ids=str(self.other_site.client_id))
        self.assertEqual((data["pending"], data["completed"]), (1, 0))
        self.scoped("can_list_pendingactions")
        data = self.get("actions")
        self.assertEqual((data["pending"], data["completed"]), (1, 1))
        # another client's id gives nothing, not an error
        data = self.get("actions", client_ids=str(self.other_site.client_id))
        self.assertEqual(data["pending_rows"], [])

    def test_patches(self):
        self.assertEqual(
            self.get("patches"),
            {
                "pending_agents": 3,
                "failed_agents": 2,
                "pending_updates": 3,
                "failed_updates": 2,
            },
        )
        self.scoped()
        data = self.get("patches")
        self.assertEqual((data["pending_agents"], data["failed_agents"]), (2, 1))

    def test_checks(self):
        data = self.get("checks")
        self.assertEqual(
            {k: data[k] for k in ("failing", "error", "warning", "info")},
            {"failing": 2, "error": 1, "warning": 1, "info": 0},
        )
        first, second = data["items"]
        self.assertEqual(
            set(first),
            {
                "id",
                "check_id",
                "agent_id",
                "hostname",
                "display_name",
                "check",
                "check_type",
                "severity",
                "last_run",
                "more_info",
            },
        )
        self.assertEqual((first["hostname"], first["severity"]), ("mine", "error"))
        self.assertTrue(first["check"].startswith("Disk Space Check: Drive C:"))
        self.assertEqual(second["check"], "Script Check: Script Name")

        self.scoped("can_list_checks")
        data = self.get("checks")
        self.assertEqual(data["failing"], 1)
        self.assertEqual([i["hostname"] for i in data["items"]], ["mine"])

    def test_activity(self):
        data = self.get("activity")
        self.assertEqual(
            {i["type"] for i in data["items"]}, {"command", "audit", "debug", "alert"}
        )
        self.assertEqual(
            set(data["items"][0]),
            {"ts", "type", "title", "detail", "user", "severity", "ref", "agent"},
        )
        data = self.get("activity", types="audit,command", limit=3)
        self.assertEqual(len(data["items"]), 3)
        self.assertLessEqual({i["type"] for i in data["items"]}, {"audit", "command"})
        self.get("activity", 400, types="nope")
        self.get("activity", 400, limit=51)

        # each type uses the flag from its own view. other agents are left out
        self.scoped("can_list_agents")
        self.assertEqual(self.get("activity")["items"], [])
        self.scoped("can_list_agents", "can_list_agent_history", "can_list_alerts")
        data = self.get("activity")
        self.assertEqual({i["type"] for i in data["items"]}, {"command", "alert"})
        self.assertEqual(
            {i["agent"]["agent_id"] for i in data["items"]}, {self.mine.agent_id}
        )
        self.scoped("can_list_agents", "can_view_auditlogs")
        self.assertIn("audit", {i["type"] for i in self.get("activity")["items"]})

    def test_vulns(self):
        data = self.get("vulns")
        self.assertEqual(
            set(data),
            {
                "agents_affected",
                "open",
                "needs_update",
                "no_fix",
                "critical",
                "high",
                "medium",
                "low",
                "unknown",
                "last_scan",
                "coverage",
            },
        )
        self.assertEqual(
            (data["open"], data["needs_update"], data["critical"], data["high"]),
            (2, 2, 1, 1),
        )
        self.scoped("can_view_vulnerabilities")
        data = self.get("vulns")
        self.assertEqual(
            (data["open"], data["needs_update"], data["critical"], data["high"]),
            (1, 1, 1, 0),
        )

    def test_netmon(self):
        data = self.get("netmon")
        self.assertEqual(
            {k: v for k, v in data.items() if k != "problems"},
            {
                "total": 4,
                "disabled": 1,
                "maintenance": 0,
                "pending": 0,
                "up": 1,
                "degraded": 1,
                "down": 1,
                "error": 0,
            },
        )
        self.assertEqual([d["name"] for d in data["problems"]], ["switch", "ap"])
        self.assertEqual(
            set(data["problems"][0]),
            {"id", "name", "host", "status", "last_checked", "client", "site"},
        )
        self.scoped("can_list_network_devices")
        data = self.get("netmon")
        self.assertEqual((data["total"], data["degraded"]), (3, 0))
        self.assertEqual([d["name"] for d in data["problems"]], ["switch"])

    def test_top_cpu_and_mem(self):
        data = self.get("top_cpu")
        self.assertEqual((data["range"], data["metric"]), ("24h", "cpu"))
        self.assertEqual([a["hostname"] for a in data["agents"]], ["mine", "theirs"])
        self.assertEqual(
            set(data["agents"][0]),
            {
                "agent_id",
                "hostname",
                "display_name",
                "client",
                "site",
                "avg",
                "max",
                "samples",
            },
        )
        data = self.get("top_mem", range="7d", limit=1)
        self.assertEqual((data["range"], data["metric"]), ("7d", "mem"))
        self.assertEqual(
            [(a["hostname"], a["avg"]) for a in data["agents"]], [("mine", 80.0)]
        )
        self.get("top_cpu", 400, range="2y")
        self.get("top_cpu", 400, metric="mem")

        self.scoped("can_list_agents")
        data = self.get("top_cpu")
        self.assertEqual([a["hostname"] for a in data["agents"]], ["mine"])

    def test_discovery(self):
        data = self.get("discovery")
        self.assertEqual(
            {k: v for k, v in data.items() if k != "last_scan"},
            {"total": 4, "new": 2, "agent": 1, "netmon": 0, "ignored": 1},
        )
        self.assertEqual(
            set(data["last_scan"]),
            {
                "id",
                "status",
                "networks",
                "started_at",
                "finished_at",
                "hosts_total",
                "hosts_up",
            },
        )

    def test_groups(self):
        groups = {g.name.split()[0]: g for g in DeviceGroup.objects.all()}
        data = self.get("groups")
        self.assertEqual(
            [(g["kind"], g["members"], g["offline"]) for g in data["groups"]],
            [("static", 3, 2), ("dynamic", 3, 2)],
        )
        self.assertEqual(
            set(data["groups"][0]), {"id", "name", "kind", "members", "offline"}
        )

        ids = f"{groups['windows'].pk},{groups['all'].pk + 999}"
        data = self.get("groups", group_ids=ids)
        self.assertEqual([g["id"] for g in data["groups"]], [groups["windows"].pk])
        self.get("groups", 400, group_ids="x")

        self.scoped("can_list_agents")
        data = self.get("groups")
        self.assertEqual(
            [(g["members"], g["offline"]) for g in data["groups"]], [(2, 1), (2, 1)]
        )

    def test_encryption(self):
        self.assertEqual(
            self.get("encryption"),
            {
                "agents": 3,
                "encrypted": 1,
                "not_encrypted": 1,
                "unknown": 1,
                "keys_escrowed": 1,
            },
        )
        self.scoped("can_view_recovery_keys")
        data = self.get("encryption")
        self.assertEqual((data["agents"], data["not_encrypted"]), (2, 0))

    def test_notes(self):
        self.assertEqual(self.get("notes", text="hello"), {"text": "hello"})
        self.assertEqual(self.get("notes"), {"text": ""})
        self.get("notes", 400, text="x" * 2001)

    def test_unknown_type_and_settings(self):
        self.get("weather", 404)
        self.get("fleet", 400, range="24h")
        self.check_not_authenticated("get", "/dashboard/widgets/fleet/")

    def test_flags(self):
        for kind, flag in FLAGS.items():
            with self.subTest(kind):
                self.scoped()
                self.get(kind, 403)
                self.scoped(flag)
                self.get(kind)
        # any role can open these. the numbers follow the role
        for kind in set(WIDGETS) - set(FLAGS):
            with self.subTest(kind):
                self.scoped()
                self.get(kind)

        norole = self.create_user_with_roles([])
        norole.role = None
        norole.save()
        self.client.force_authenticate(user=norole)
        self.assertEqual(self.get("fleet")["total"], 0)
        self.get("alerts", 403)

    def test_query_counts(self):
        params = {"text": "x"}
        for kind, budget in BUDGET.items():
            with self.subTest(kind), self.assertNumQueries(budget):
                self.get(kind, **(params if kind == "notes" else {}))

        user = self.scoped(*FLAGS.values(), *LIST_FLAGS.values())
        small = {}
        for kind in BUDGET:
            self.get(kind, **(params if kind == "notes" else {}))
            with CaptureQueriesContext(connection) as q:
                self.get(kind, **(params if kind == "notes" else {}))
            small[kind] = len(q)

        # more agents, and a row of every kind. query count stays the same
        now = djangotime.now()
        for _ in range(3):
            self.populate(
                now,
                (
                    baker.make_recipe("agents.online_agent", site=self.site),
                    baker.make_recipe("agents.overdue_agent", site=self.site),
                    baker.make_recipe("agents.offline_agent", site=self.other_site),
                ),
            )
        self.client.force_authenticate(user=user)
        for kind, budget in BUDGET.items():
            with self.subTest(kind):
                with CaptureQueriesContext(connection) as q:
                    self.get(kind, **(params if kind == "notes" else {}))
                self.assertEqual(len(q), small[kind])
                self.assertLessEqual(len(q), budget + 2)

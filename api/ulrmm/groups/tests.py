# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework.serializers import ValidationError

from logs.models import AuditLog
from ulrmm.constants import AgentMonType, AgentPlat, AuditObjType
from ulrmm.constants import CustomFieldModel, CustomFieldType
from ulrmm.test import ULRMMTestCase

from .models import DeviceGroup, GroupKind, Tag
from .rules import MAX_CONDITIONS, OPS, clean_rules

base_url = "/groups"


def minutes_ago(m):
    return djangotime.now() - djangotime.timedelta(minutes=m)


class Fleet(ULRMMTestCase):
    """win online, lin offline, mac overdue, new never seen."""

    def make_fleet(self):
        self.client1 = baker.make("clients.Client", name="c1")
        self.client2 = baker.make("clients.Client", name="c2")
        self.site1 = baker.make("clients.Site", client=self.client1)
        self.site2 = baker.make("clients.Site", client=self.client1)
        self.site3 = baker.make("clients.Site", client=self.client2)

        def agent(hostname, **kw):
            return baker.make_recipe("agents.agent", hostname=hostname, **kw)

        self.win = agent(
            "WIN-SRV01",
            plat=AgentPlat.WINDOWS,
            site=self.site1,
            operating_system="Windows Server 2022 Datacenter",
            monitoring_type=AgentMonType.SERVER,
            version="1.27.09.2026",
            last_seen=djangotime.now(),
            needs_reboot=True,
        )
        self.lin = agent(
            "lin-web01",
            plat=AgentPlat.LINUX,
            site=self.site2,
            operating_system="Debian 12 bookworm",
            monitoring_type=AgentMonType.SERVER,
            version="2.12.0",
            last_seen=minutes_ago(7),
        )
        self.mac = agent(
            "MacBook",
            plat=AgentPlat.DARWIN,
            site=self.site3,
            operating_system="macOS 15.6",
            monitoring_type=AgentMonType.WORKSTATION,
            version="1.06.10.2026",
            last_seen=minutes_ago(60 * 48),
            overdue_email_alert=True,
        )
        self.new = agent(
            "NEW-PC",
            plat=AgentPlat.WINDOWS,
            site=self.site1,
            operating_system="Windows 11 Pro",
            monitoring_type=AgentMonType.WORKSTATION,
            version="1.07.10.2026",
            last_seen=None,
        )

        self.tag_a = baker.make("groups.Tag", name="prod")
        self.tag_b = baker.make("groups.Tag", name="web")
        self.tag_a.agents.set([self.win, self.lin])
        self.tag_b.agents.set([self.lin])

        baker.make(
            "software.InstalledSoftware",
            agent=self.win,
            software=[{"name": "Google Chrome", "version": "129"}, "junk"],
        )
        baker.make(
            "software.InstalledSoftware",
            agent=self.lin,
            software=[{"name": "openssh-server", "version": "9.2"}],
        )
        # not a list: must not break the query
        baker.make("software.InstalledSoftware", agent=self.mac, software={"x": 1})

        self.cf_text = baker.make(
            "core.CustomField", model=CustomFieldModel.AGENT, type=CustomFieldType.TEXT
        )
        self.cf_check = baker.make(
            "core.CustomField",
            model=CustomFieldModel.AGENT,
            type=CustomFieldType.CHECKBOX,
        )
        self.cf_multi = baker.make(
            "core.CustomField",
            model=CustomFieldModel.AGENT,
            type=CustomFieldType.MULTIPLE,
        )
        acf = "agents.AgentCustomField"
        baker.make(acf, agent=self.win, field=self.cf_text, string_value="Berlin")
        baker.make(acf, agent=self.lin, field=self.cf_text, string_value="Hamburg")
        baker.make(acf, agent=self.win, field=self.cf_check, bool_value=True)
        baker.make(acf, agent=self.lin, field=self.cf_check, bool_value=False)
        baker.make(
            acf, agent=self.mac, field=self.cf_multi, multiple_value=["alpha", "beta"]
        )

        wu = "winupdate.WinUpdate"
        baker.make(
            wu, agent=self.lin, action="approve", installed=False, result="failed"
        )
        baker.make(wu, agent=self.win, action="approve", installed=False)
        baker.make(
            wu, agent=self.mac, action="approve", installed=True, result="failed"
        )

    def scoped_user(self, flags, clients):
        user = self.create_user_with_roles(flags)
        user.role.can_view_clients.set(clients)
        return user


class TestRules(Fleet):
    def setUp(self):
        self.setup_coresettings()
        self.make_fleet()

    def match(self, *conditions, how="all"):
        rules = clean_rules({"match": how, "conditions": list(conditions)})
        return set(DeviceGroup(rules=rules).agents().values_list("hostname", flat=True))

    def c(self, field, op, value, **kw):
        return {"field": field, "op": op, "value": value, **kw}

    def test_every_field(self):
        win, lin, mac, new = "WIN-SRV01", "lin-web01", "MacBook", "NEW-PC"
        c1, c2 = self.client1.pk, self.client2.pk
        cases = [
            (self.c("plat", "eq", "linux"), {lin}),
            (self.c("plat", "neq", "windows"), {lin, mac}),
            (self.c("plat", "in", ["linux", "darwin"]), {lin, mac}),
            (self.c("client", "eq", c1), {win, lin, new}),
            (self.c("client", "neq", c1), {mac}),
            (self.c("client", "in", [c2]), {mac}),
            (self.c("site", "eq", self.site2.pk), {lin}),
            (self.c("site", "in", [self.site1.pk]), {win, new}),
            (self.c("tag", "eq", self.tag_a.pk), {win, lin}),
            (self.c("tag", "neq", self.tag_a.pk), {mac, new}),
            (self.c("tag", "in", [self.tag_b.pk]), {lin}),
            (self.c("hostname", "contains", "WEB"), {lin}),
            (self.c("hostname", "starts", "win"), {win}),
            (self.c("hostname", "starts", "web"), set()),
            (self.c("os", "contains", "debian"), {lin}),
            (self.c("os", "contains", "Solaris"), set()),
            (self.c("status", "eq", "online"), {win}),
            (self.c("status", "eq", "offline"), {lin, new}),
            (self.c("status", "eq", "overdue"), {mac}),
            (self.c("status", "neq", "online"), {lin, mac, new}),
            (self.c("status", "in", ["online", "overdue"]), {win, mac}),
            (self.c("monitoring_type", "eq", "workstation"), {mac, new}),
            (self.c("monitoring_type", "neq", "workstation"), {win, lin}),
            (self.c("agent_version", "lt", "1.01.10.2026"), {win, lin}),
            (self.c("agent_version", "gte", "1.01.10.2026"), {mac, new}),
            (self.c("agent_version", "gte", " v1.07.10.2026 "), {new}),
            (self.c("agent_version", "lt", "2.13.0"), {lin}),
            (self.c("software", "contains", "chrome"), {win}),
            (self.c("software", "contains", "SSH"), {lin}),
            (self.c("software", "contains", "firefox"), set()),
            (self.c("needs_reboot", "eq", True), {win}),
            (self.c("needs_reboot", "eq", False), {lin, mac, new}),
            (self.c("patches_failed", "eq", True), {lin}),
            (self.c("patches_failed", "eq", False), {win, mac, new}),
        ]
        cf = [
            ("eq", "berlin", self.cf_text, {win}),
            ("contains", "burg", self.cf_text, {lin}),
            ("eq", "Paris", self.cf_text, set()),
            ("eq", True, self.cf_check, {win}),
            ("eq", False, self.cf_check, {lin}),
            ("eq", "beta", self.cf_multi, {mac}),
            ("contains", "alp", self.cf_multi, {mac}),
            ("eq", "alp", self.cf_multi, set()),
        ]
        for op, value, field, expected in cf:
            cases.append(
                (self.c("custom_field", op, value, custom_field=field.pk), expected)
            )

        for cond, expected in cases:
            with self.subTest(cond=cond):
                self.assertEqual(self.match(cond), expected)

        self.assertEqual({cond["field"] for cond, _ in cases}, set(OPS))

    def test_unmonitored_silent_agent_is_offline(self):
        self.mac.overdue_email_alert = False
        self.mac.save(update_fields=["overdue_email_alert"])
        self.assertEqual(self.mac.status, "offline")
        self.assertEqual(self.match(self.c("status", "eq", "overdue")), set())
        self.assertIn("MacBook", self.match(self.c("status", "eq", "offline")))

    def test_any_and_all(self):
        conds = [self.c("plat", "eq", "linux"), self.c("needs_reboot", "eq", True)]
        self.assertEqual(self.match(*conds, how="all"), set())
        self.assertEqual(self.match(*conds, how="any"), {"WIN-SRV01", "lin-web01"})

        conds = [self.c("tag", "eq", self.tag_a.pk), self.c("status", "eq", "offline")]
        self.assertEqual(self.match(*conds), {"lin-web01"})
        self.assertEqual(
            self.match(*conds, how="any"), {"WIN-SRV01", "lin-web01", "NEW-PC"}
        )

    def test_validation(self):
        ok = self.c("plat", "eq", "linux")
        client_cf = baker.make("core.CustomField", model=CustomFieldModel.CLIENT)
        bad_conditions = [
            self.c("ip", "eq", "1.2.3.4"),
            self.c(["plat"], "eq", "linux"),
            self.c("plat", "contains", "lin"),
            self.c("plat", "eq", "solaris"),
            self.c("plat", "in", []),
            self.c("plat", "in", "linux"),
            {**ok, "extra": 1},
            "plat",
            self.c("client", "eq", 999999),
            self.c("client", "eq", "1"),
            self.c("tag", "in", [self.tag_a.pk, 999999]),
            self.c("site", "eq", True),
            self.c("needs_reboot", "eq", "true"),
            self.c("hostname", "contains", "  "),
            self.c("hostname", "contains", "x" * 256),
            self.c("custom_field", "eq", "x"),
            self.c("custom_field", "eq", "x", custom_field=client_cf.pk),
            self.c("custom_field", "contains", True, custom_field=self.cf_check.pk),
            self.c("agent_version", "gte", "latest"),
            self.c("agent_version", "lt", "0"),
        ]
        bad = [
            [],
            {"match": "some", "conditions": [ok]},
            {"match": "all", "conditions": []},
            {"match": "all", "conditions": [ok], "x": 1},
            {"conditions": [ok] * (MAX_CONDITIONS + 1)},
        ] + [{"conditions": [ok, c]} for c in bad_conditions]
        for rules in bad:
            with self.subTest(rules=rules), self.assertRaises(ValidationError):
                clean_rules(rules)

        self.assertEqual(
            clean_rules({"conditions": [self.c("hostname", "starts", " web ")]}),
            {
                "match": "all",
                "conditions": [{"field": "hostname", "op": "starts", "value": "web"}],
            },
        )
        clean_rules({"conditions": [ok] * MAX_CONDITIONS})

    def test_empty_or_static(self):
        self.assertFalse(DeviceGroup(rules={}).agents().exists())
        group = baker.make("groups.DeviceGroup", kind=GroupKind.STATIC)
        group.members.set([self.mac, self.new])
        self.assertCountEqual(group.agents(), [self.mac, self.new])


class TestTags(Fleet):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.make_fleet()

    def test_tag_crud(self):
        url = f"{base_url}/tags/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([t["name"] for t in r.data], ["prod", "web"])

        r = self.client.post(url, {"name": " db ", "color": "#AABBCC"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["name"], "db")
        self.assertEqual(r.data["color"], "#aabbcc")
        pk = r.data["id"]
        self.assertTrue(AuditLog.objects.filter(object_type=AuditObjType.TAG).exists())

        for data in (
            {"name": "PROD", "color": "#000000"},
            {"name": "", "color": "#000000"},
            {"name": "x" * 41, "color": "#000000"},
            {"name": "ok", "color": "red"},
        ):
            with self.subTest(data=data):
                r = self.client.post(url, data, format="json")
                self.assertEqual(r.status_code, 400)

        r = self.client.put(f"{url}{pk}/", {"name": "Prod"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(f"{url}{pk}/", {"name": "database"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Tag.objects.get(pk=pk).name, "database")
        # renaming to its own name in another case is fine
        r = self.client.put(f"{url}{pk}/", {"name": "Database"}, format="json")
        self.assertEqual(r.status_code, 200)

        r = self.client.delete(f"{url}{pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Tag.objects.filter(pk=pk).exists())
        self.assertEqual(self.client.delete(f"{url}{pk}/").status_code, 404)

        self.check_not_authenticated("get", url)

    def test_tag_permissions(self):
        url = f"{base_url}/tags/"
        reader = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=reader)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.check_not_authorized("post", url, {"name": "x", "color": "#000000"})
        self.check_not_authorized("put", f"{url}{self.tag_a.pk}/", {"name": "y"})
        self.check_not_authorized("delete", f"{url}{self.tag_a.pk}/")

        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.check_not_authorized("get", url)

        manager = self.create_user_with_roles(["can_manage_device_groups"])
        self.client.force_authenticate(user=manager)
        r = self.client.post(url, {"name": "x", "color": "#000000"}, format="json")
        self.assertEqual(r.status_code, 200)

    def test_set_agent_tags(self):
        url = f"{base_url}/agents/{self.mac.agent_id}/tags/"
        r = self.client.put(
            url, {"tags": [self.tag_b.pk, self.tag_a.pk]}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual([t["name"] for t in r.data], ["prod", "web"])
        self.assertCountEqual(self.mac.tags.all(), [self.tag_a, self.tag_b])

        audit = AuditLog.objects.filter(agent_id=self.mac.agent_id).last()
        self.assertEqual(audit.before_value["tags"], [])
        self.assertEqual(audit.after_value["tags"], ["prod", "web"])

        r = self.client.put(url, {"tags": [999999]}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(url, {"tags": []}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(self.mac.tags.exists())

        # can_edit_agent and the agent in scope
        user = self.scoped_user(["can_edit_agent"], [self.client1])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("put", url, {"tags": [self.tag_a.pk]})
        self.assertFalse(self.mac.tags.exists())
        lin_url = f"{base_url}/agents/{self.lin.agent_id}/tags/"
        r = self.client.put(lin_url, {"tags": [self.tag_a.pk]}, format="json")
        self.assertEqual(r.status_code, 200)

        user = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("put", lin_url, {"tags": []})

    def test_agent_detail_carries_tags(self):
        r = self.client.get(f"/agents/{self.lin.agent_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data["tags"],
            [
                {"id": self.tag_a.pk, "name": "prod", "color": self.tag_a.color},
                {"id": self.tag_b.pk, "name": "web", "color": self.tag_b.color},
            ],
        )
        r = self.client.get(f"/agents/{self.mac.agent_id}/")
        self.assertEqual(r.data["tags"], [])

    def test_table_rows_carry_tags_without_n_plus_1(self):
        url = "/agents/"
        with CaptureQueriesContext(connection) as ctx:
            r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        rows = {a["hostname"]: a for a in r.data}
        self.assertEqual(
            rows["lin-web01"]["tags"],
            [
                {"id": self.tag_a.pk, "name": "prod", "color": self.tag_a.color},
                {"id": self.tag_b.pk, "name": "web", "color": self.tag_b.color},
            ],
        )
        self.assertEqual(rows["MacBook"]["tags"], [])

        for i in range(6):
            extra = baker.make_recipe("agents.agent", site=self.site1)
            tag = baker.make("groups.Tag", name=f"t{i}")
            tag.agents.set([extra, self.mac])

        with self.assertNumQueries(len(ctx.captured_queries)):
            r = self.client.get(url)
        self.assertEqual(len(r.data), 10)


class TestGroups(Fleet):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.make_fleet()

    def rules(self, *conditions, how="all"):
        return {"match": how, "conditions": list(conditions)}

    def test_group_crud(self):
        url = f"{base_url}/"
        data = {
            "name": "Linux servers",
            "description": "all of them",
            "kind": "dynamic",
            "rules": self.rules({"field": "plat", "op": "eq", "value": "linux"}),
        }
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        pk = r.data["id"]
        self.assertEqual(r.data["count"], 1)
        self.assertEqual(r.data["members"], [])
        self.assertTrue(
            AuditLog.objects.filter(object_type=AuditObjType.DEVICE_GROUP).exists()
        )

        self.assertEqual(self.client.post(url, data, format="json").status_code, 400)
        data["name"] = "other"
        data["rules"] = self.rules({"field": "plat", "op": "starts", "value": "lin"})
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("plat does not support op", str(r.data))

        r = self.client.put(
            f"{url}{pk}/",
            {"rules": self.rules({"field": "plat", "op": "neq", "value": "linux"})},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["count"], 3)
        r = self.client.put(f"{url}{pk}/", {"description": "x"}, format="json")
        self.assertEqual(r.status_code, 200)

        r = self.client.get(url)
        self.assertEqual(
            [(g["name"], g["count"]) for g in r.data], [("Linux servers", 3)]
        )
        r = self.client.get(f"{url}{pk}/")
        self.assertEqual(r.data["description"], "x")

        # static: members by agent_id, rules dropped
        r = self.client.put(
            f"{url}{pk}/",
            {"kind": "static", "members": [self.mac.agent_id, self.new.agent_id]},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["rules"], {})
        self.assertEqual(r.data["members"], [self.mac.agent_id, self.new.agent_id])
        audit = AuditLog.objects.filter(object_type=AuditObjType.DEVICE_GROUP).last()
        self.assertEqual(audit.after_value, {"members": ["MacBook", "NEW-PC"]})

        r = self.client.put(f"{url}{pk}/", {"members": ["nope"]}, format="json")
        self.assertEqual(r.status_code, 400)

        # back to dynamic needs rules and drops the members
        r = self.client.put(f"{url}{pk}/", {"kind": "dynamic"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(
            f"{url}{pk}/",
            {
                "kind": "dynamic",
                "rules": self.rules({"field": "status", "op": "eq", "value": "online"}),
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(DeviceGroup.objects.get(pk=pk).members.exists())

        r = self.client.delete(f"{url}{pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(DeviceGroup.objects.exists())

        self.check_not_authenticated("get", url)

    def test_group_permissions(self):
        group = baker.make("groups.DeviceGroup", name="g", rules={})
        url = f"{base_url}/"
        data = {"name": "x", "kind": "static"}

        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.check_not_authorized("get", url)
        self.check_not_authorized("get", f"{url}{group.pk}/agents/")
        self.check_not_authorized("post", f"{url}preview/", {"conditions": []})

        reader = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=reader)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(self.client.get(f"{url}{group.pk}/").status_code, 200)
        self.check_not_authorized("post", url, data)
        self.check_not_authorized("put", f"{url}{group.pk}/", data)
        self.check_not_authorized("delete", f"{url}{group.pk}/")

        manager = self.create_user_with_roles(["can_manage_device_groups"])
        self.client.force_authenticate(user=manager)
        self.assertEqual(self.client.post(url, data, format="json").status_code, 200)
        self.assertEqual(self.client.delete(f"{url}{group.pk}/").status_code, 200)

    def test_static_members_scoped(self):
        group = baker.make("groups.DeviceGroup", name="g", kind=GroupKind.STATIC)
        group.members.set([self.win, self.mac])

        user = self.scoped_user(
            ["can_list_agents", "can_manage_device_groups"], [self.client1]
        )
        self.client.force_authenticate(user=user)
        url = f"{base_url}/{group.pk}/"

        r = self.client.get(url)
        self.assertEqual(r.data["members"], [self.win.agent_id])
        self.assertEqual(r.data["count"], 1)

        # an agent outside the scope can't be added
        r = self.client.put(url, {"members": [self.mac.agent_id]}, format="json")
        self.assertEqual(r.status_code, 400)

        # members the user can't see survive an edit
        r = self.client.put(url, {"members": [self.lin.agent_id]}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertCountEqual(group.members.all(), [self.lin, self.mac])

    def test_group_agents_role_filtered(self):
        group = DeviceGroup.objects.create(
            name="prod",
            rules=clean_rules(
                {"conditions": [{"field": "tag", "op": "eq", "value": self.tag_a.pk}]}
            ),
        )
        baker.make_recipe("agents.agent", site=self.site3).tags.add(self.tag_a)
        url = f"{base_url}/{group.pk}/agents/"

        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 3)

        user = self.scoped_user(["can_list_agents"], [self.client1])
        self.client.force_authenticate(user=user)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertCountEqual(
            [a["hostname"] for a in r.data], ["WIN-SRV01", "lin-web01"]
        )
        row = next(a for a in r.data if a["hostname"] == "lin-web01")
        self.assertEqual([t["name"] for t in row["tags"]], ["prod", "web"])

        r = self.client.get(f"{url}?detail=false")
        self.assertEqual(len(r.data), 2)
        self.assertEqual(self.client.get(f"{base_url}/999999/agents/").status_code, 404)

    def test_preview(self):
        url = f"{base_url}/preview/"
        rules = self.rules(
            {"field": "client", "op": "eq", "value": self.client1.pk},
            {"field": "plat", "op": "eq", "value": "darwin"},
            how="any",
        )
        r = self.client.post(url, rules, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["count"], 4)
        self.assertCountEqual(
            r.data["agents"], ["MacBook", "NEW-PC", "WIN-SRV01", "lin-web01"]
        )

        baker.make_recipe("agents.agent", site=self.site1, _quantity=30)
        r = self.client.post(url, rules, format="json")
        self.assertEqual(r.data["count"], 34)
        self.assertEqual(len(r.data["agents"]), 25)

        user = self.scoped_user(["can_list_agents"], [self.client2])
        self.client.force_authenticate(user=user)
        r = self.client.post(url, rules, format="json")
        self.assertEqual(r.data, {"count": 1, "agents": ["MacBook"]})

        r = self.client.post(
            url, self.rules({"field": "x", "op": "eq", "value": 1}), format="json"
        )
        self.assertEqual(r.status_code, 400)


class TestBulkGroup(Fleet):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.make_fleet()

    def payload(self, **kwargs):
        data = {
            "mode": "command",
            "target": "group",
            "monType": "all",
            "osType": "all",
            "client": None,
            "site": None,
            "agents": [],
            "cmd": "hostname",
            "shell": "cmd",
            "custom_shell": None,
            "timeout": 30,
            "run_as_user": False,
        }
        data.update(kwargs)
        return data

    @patch("scripts.tasks.bulk_command_task.delay")
    def test_bulk_group_target(self, mock_task):
        online = {
            name: baker.make_recipe(
                "agents.online_agent",
                hostname=name,
                site=site,
                last_seen=djangotime.now(),
            )
            for name, site in (
                ("g1", self.site1),
                ("g2", self.site3),
                ("x1", self.site1),
            )
        }
        group = baker.make("groups.DeviceGroup", name="g", kind=GroupKind.STATIC)
        group.members.set([online["g1"], online["g2"], self.lin])

        r = self.client.post(
            "/agents/actions/bulk/", self.payload(group=group.pk), format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertCountEqual(
            mock_task.call_args.kwargs["agent_pks"], [online["g1"].pk, online["g2"].pk]
        )
        self.assertIn("1 offline agents were skipped", r.data)
        log = AuditLog.objects.get(object_type=AuditObjType.BULK)
        self.assertIn("bulk command on device group: g, sent to 2 agents", log.message)

        # only the members the user may see
        user = self.scoped_user(["can_run_bulk"], [self.client1])
        self.client.force_authenticate(user=user)
        r = self.client.post(
            "/agents/actions/bulk/", self.payload(group=group.pk), format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_task.call_args.kwargs["agent_pks"], [online["g1"].pk])

        # dynamic group
        dyn = DeviceGroup.objects.create(
            name="d",
            rules=clean_rules(
                {"conditions": [{"field": "hostname", "op": "starts", "value": "g"}]}
            ),
        )
        r = self.client.post(
            "/agents/actions/bulk/", self.payload(group=dyn.pk), format="json"
        )
        self.assertEqual(mock_task.call_args.kwargs["agent_pks"], [online["g1"].pk])

        r = self.client.post(
            "/agents/actions/bulk/", self.payload(group="x"), format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            "/agents/actions/bulk/", self.payload(group=999999), format="json"
        )
        self.assertEqual(r.status_code, 404)

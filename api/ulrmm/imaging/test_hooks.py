# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from model_bakery import baker

from deploy import envelope
from logs.models import AuditLog
from scripts.models import Script

from .models import BackupPolicy, Profile
from .service import script_hash
from .test_poll import PollBase


def hook(script, **kw):
    return {
        "script_id": script.pk,
        "phase": "pre-backup",
        "args": ["--all"],
        "env_vars": ["PGPASS=secret"],
        "timeout": 60,
        "on_fail": "abort",
        **kw,
    }


class HookBase(PollBase):
    def setUp(self):
        super().setUp()
        self.script = baker.make(
            Script, name="Dump", shell="bash", script_body="pg_dumpall"
        )

    def put(self, hooks, stepup=True):
        body = {"set": {"hooks": hooks}}
        if not stepup:
            return self.client.put(self.uri, body, format="json")
        with patch("imaging.views.stepup_denied", return_value=None):
            return self.client.put(self.uri, body, format="json")

    def stored(self):
        return Profile.objects.get(agent=self.agent).overrides["hooks"]


class TestDeviceHooks(HookBase):
    def test_keys_and_kept_env_values(self):
        r = self.put([hook(self.script)])
        self.assertEqual(r.status_code, 200, r.data)
        key = self.stored()[0]["key"]
        self.assertRegex(key, r"\A[0-9a-f]{8}\Z")
        shown = r.data["effective"]["fields"]["hooks"]["value"][0]
        self.assertEqual(shown["key"], key)
        self.assertEqual(
            shown["env_vars"], [{"name": "PGPASS", "value": "", "has_value": True}]
        )
        # the masked entry sent back keeps the stored value and needs no hook rights
        kept = hook(self.script, key=key, env_vars=[{"name": "PGPASS"}])
        r = self.put([kept], stepup=False)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(self.stored()[0]["env_vars"], ["PGPASS=secret"])
        r = self.put([hook(self.script, key=key, env_vars=[{"name": "OTHER"}])])
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data["set"]["hooks"], ["Environment value OTHER has no stored value."]
        )
        # an unknown key is a new hook, which has no stored values
        r = self.put([hook(self.script, key="00000000", env_vars=[{"name": "PGPASS"}])])
        self.assertEqual(r.status_code, 400)

    def test_save_needs_stepup_and_script_rights(self):
        r = self.put([hook(self.script)], stepup=False)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.data["stepup"])
        manager = self.create_user_with_roles(["can_manage_images"])
        self.client.force_authenticate(manager)
        self.assertEqual(self.put([hook(self.script)]).status_code, 403)

    def test_pinned_hash_and_suspension_after_edit(self):
        self.put([hook(self.script)])
        self.assertEqual(self.client.get(self.uri).data["hooks_suspended"], [])
        Script.objects.filter(pk=self.script.pk).update(script_body="rm -rf /")
        script = Script.objects.get(pk=self.script.pk)
        current = script_hash(script)
        r = self.client.get(self.uri)
        self.assertEqual(
            r.data["hooks_suspended"],
            [
                {
                    "script_id": script.pk,
                    "name": "Dump",
                    "script_name": "Dump",
                    "sha256": current,
                    "origin": {"level": "device", "id": None},
                }
            ],
        )
        self.identity()
        self.queue()
        with patch(
            "imaging.native.envelope.seal_response", wraps=envelope.seal_response
        ) as seal:
            self.assertEqual(self.poll(protocol=2, seal=True).status_code, 200)
        body = seal.call_args.args[2]["hooks"][0]
        self.assertEqual((body["suspended"], body["code"]), (True, ""))
        self.assertEqual(body["args"], ["--all"])

    def test_confirm_rights_and_hash(self):
        self.put([hook(self.script)])
        Script.objects.filter(pk=self.script.pk).update(script_body="v2")
        current = script_hash(Script.objects.get(pk=self.script.pk))
        url = self.uri + "hooks/confirm/"
        body = {"script_id": self.script.pk, "sha256": current}
        self.assertEqual(self.client.post(url, body, format="json").status_code, 403)
        with patch("imaging.views.stepup_denied", return_value=None):
            r = self.client.post(url, {**body, "sha256": "0" * 64}, format="json")
            self.assertEqual(r.status_code, 409)
            r = self.client.post(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["hooks_suspended"], [])
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Backup hook Dump confirmed at {current[:12]}."
            ).exists()
        )


class TestPolicyHooks(HookBase):
    def policy(self, hooks, method="post", url="/imaging/policies/", **extra):
        body = {
            "name": "Databases",
            "scope": "assigned",
            "config": {"hooks": hooks},
            "agents": [self.agent.agent_id],
            **extra,
        }
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            patch("imaging.tasks.wake_imaging_agent.delay"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            return getattr(self.client, method)(url, body, format="json")

    def test_keep_hooks_on_put_only(self):
        r = self.policy([hook(self.script)])
        self.assertEqual(r.status_code, 201, r.data)
        policy = BackupPolicy.objects.get(pk=r.data["id"])
        pinned, approved = policy.hooks_pinned, policy.hooks_approved_at
        self.assertEqual(self.policy([], keep_hooks=True).status_code, 400)
        # a role without script rights keeps the hooks it cannot see
        manager = self.create_user_with_roles(["can_manage_images"])
        self.client.force_authenticate(manager)
        url = f"/imaging/policies/{policy.pk}/"
        r = self.policy([], method="put", url=url, keep_hooks=True, name="Renamed")
        self.assertEqual(r.status_code, 200, r.data)
        policy.refresh_from_db()
        self.assertEqual(policy.name, "Renamed")
        self.assertEqual(policy.config["hooks"][0]["env_vars"], ["PGPASS=secret"])
        self.assertEqual(
            (policy.hooks_pinned, policy.hooks_approved_at), (pinned, approved)
        )
        r = self.policy([], method="put", url=url)
        self.assertEqual(r.status_code, 403)

    def test_policy_confirm_and_suspended_origin(self):
        r = self.policy([hook(self.script)])
        pk = r.data["id"]
        Script.objects.filter(pk=self.script.pk).update(script_body="v2")
        current = script_hash(Script.objects.get(pk=self.script.pk))
        row = next(
            p for p in self.client.get("/imaging/policies/").data if p["id"] == pk
        )
        self.assertEqual(
            row["hooks_suspended"][0]["origin"], {"level": "assigned", "id": pk}
        )
        self.assertEqual(row["config"]["hooks"][0]["env_vars"][0]["value"], "")
        url = f"/imaging/policies/{pk}/hooks/confirm/"
        body = {"script_id": self.script.pk, "sha256": current}
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.post(url, body, format="json")
        self.assertEqual((r.status_code, r.data["hooks_suspended"]), (200, []))
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Backup hook Dump of policy {pk} confirmed at {current[:12]}."
            ).exists()
        )
        hooks = self.client.get(self.uri).data["hooks_suspended"]
        self.assertEqual(hooks, [])


class TestHookReach(HookBase):
    def test_claim_carries_args_literally_and_skips_other_platforms(self):
        linux = baker.make(
            Script,
            name="Mount",
            shell="bash",
            script_body="mount",
            supported_platforms=["linux"],
        )
        literal = hook(self.script, args=["{{agent.hostname}}"], env_vars=["A=1"])
        self.put([literal, hook(linux, phase="post-backup")])
        self.identity()
        image = self.queue()
        with patch(
            "imaging.native.envelope.seal_response", wraps=envelope.seal_response
        ) as seal:
            self.assertEqual(self.poll(protocol=2, seal=True).status_code, 200)
        hooks = seal.call_args.args[2]["hooks"]
        self.assertEqual([h["name"] for h in hooks], ["Dump"])
        self.assertEqual(hooks[0]["args"], ["{{agent.hostname}}"])
        self.assertEqual(hooks[0]["env_vars"], ["A=1"])
        self.assertEqual(
            (hooks[0]["code"], hooks[0]["suspended"]), ("pg_dumpall", False)
        )
        run = image.runs.get()
        self.assertEqual(
            [(h["script_id"], h["status"]) for h in run.hooks], [(linux.pk, "skipped")]
        )

    def test_reach_change_of_policy_with_hooks_needs_script_rights(self):
        from .models import NativeInventory

        other = baker.make("agents.Agent", plat="windows", goarch="amd64")
        NativeInventory.objects.create(agent=other, capability=self.cap)
        body = {
            "name": "Databases",
            "scope": "assigned",
            "config": {"hooks": [hook(self.script)]},
            "agents": [self.agent.agent_id],
        }
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            self.captureOnCommitCallbacks(execute=True),
        ):
            pk = self.client.post("/imaging/policies/", body, format="json").data["id"]
        url = f"/imaging/policies/{pk}/"
        grown = {
            **body,
            "agents": [self.agent.agent_id, other.agent_id],
            "keep_hooks": True,
        }
        manager = self.create_user_with_roles(["can_manage_images"])
        self.client.force_authenticate(manager)
        self.assertEqual(self.client.put(url, grown, format="json").status_code, 403)
        self.client.force_authenticate(self.john)
        self.assertEqual(self.client.put(url, grown, format="json").status_code, 403)
        before = BackupPolicy.objects.get(pk=pk).hooks_approved_at
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.put(url, grown, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        policy = BackupPolicy.objects.get(pk=pk)
        self.assertGreater(policy.hooks_approved_at, before)
        self.assertEqual(policy.hooks_approved_by, self.john)

    def test_scoped_save_needs_unrestricted_role(self):
        tag = baker.make("groups.Tag", name="db-servers")
        user = self.create_user_with_roles(["can_manage_images", "can_run_scripts"])
        body = {
            "name": "Tagged",
            "scope": "tag",
            "tag": tag.pk,
            "config": {"hooks": [hook(self.script)]},
        }
        url = "/imaging/policies/"
        self.client.force_authenticate(user)
        with patch("imaging.policies.stepup_denied", return_value=None):
            self.assertEqual(
                self.client.post(url, body, format="json").status_code, 201
            )
            user.role.can_view_clients.add(self.agent.site.client)
            body["name"] = "Tagged again"
            self.assertEqual(
                self.client.post(url, body, format="json").status_code, 403
            )


class TestHookReview(HookBase):
    def manager(self, *flags):
        user = self.create_user_with_roles(["can_manage_images", *flags])
        self.client.force_authenticate(user)
        return user

    def test_empty_hooks_list_needs_script_rights(self):
        Profile.objects.filter(agent=self.agent).update(overrides={"hooks": []})
        self.manager()
        r = self.client.put(self.uri, {"reset": ["hooks"]}, format="json")
        self.assertEqual(r.status_code, 403)
        Profile.objects.filter(agent=self.agent).update(overrides={})
        self.assertEqual(self.put([]).status_code, 403)
        tag = baker.make("groups.Tag", name="quiet")
        body = {"name": "No hooks", "scope": "tag", "tag": tag.pk}
        r = self.client.post(
            "/imaging/policies/", {**body, "config": {"hooks": []}}, format="json"
        )
        self.assertEqual(r.status_code, 403)

    def test_keep_hooks_keeps_an_empty_list_and_skips_validation(self):
        gone = baker.make(Script, name="Gone", shell="bash")
        policy = BackupPolicy.objects.create(
            name="Quiet", scope="assigned", config={"hooks": []}, enforced=["hooks"]
        )
        Profile.objects.filter(agent=self.agent).update(policy=policy)
        self.manager()
        body = {
            "name": "Quiet",
            "scope": "assigned",
            "agents": [self.agent.agent_id],
            "config": {"hooks": [hook(gone)]},
            "enforced": ["hooks"],
            "keep_hooks": True,
        }
        gone.delete()
        url = f"/imaging/policies/{policy.pk}/"
        r = self.client.put(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        policy.refresh_from_db()
        self.assertEqual(policy.config, {"hooks": []})

    def test_assigned_policy_gives_back_its_last_device(self):
        policy = BackupPolicy.objects.create(name="One", scope="assigned", config={})
        Profile.objects.filter(agent=self.agent).update(policy=policy)
        body = {"name": "One", "scope": "assigned", "config": {}, "agents": []}
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 400)
        url = f"/imaging/policies/{policy.pk}/"
        r = self.client.put(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIsNone(Profile.objects.get(agent=self.agent).policy)
        self.assertEqual(self.client.delete(url).status_code, 204)

    def test_warnings_carry_hostname_and_are_capped(self):
        other = baker.make("agents.Agent", plat="windows", goarch="amd64")
        from .models import NativeInventory

        NativeInventory.objects.create(agent=other, capability=self.cap)
        body = {
            "name": "Hooks",
            "scope": "assigned",
            "config": {"hooks": [hook(self.script)]},
            "agents": [self.agent.agent_id, other.agent_id],
        }
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            patch("imaging.policies.WARNINGS_SHOWN", 1),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(
            r.data["warnings"],
            [
                {
                    "agent_id": self.agent.agent_id,
                    "hostname": self.agent.hostname,
                    "legacy": True,
                }
            ],
        )
        self.assertEqual(r.data["warnings_more"], 1)
        rows = self.client.get("/imaging/policies/").data
        self.assertTrue(all(row["can_run_scripts"] for row in rows))
        self.manager()
        rows = self.client.get("/imaging/policies/").data
        self.assertFalse(any(row["can_run_scripts"] for row in rows))

    def test_hook_change_by_manager_without_script_right_is_held(self):
        from . import resolver
        from .models import PolicyChangeHold

        tag = baker.make("groups.Tag", name="db")
        BackupPolicy.objects.create(
            name="Tagged hooks",
            scope="tag",
            tag=tag,
            config={"hooks": [{**hook(self.script), "key": "0a0b0c0d"}]},
            hooks_pinned={str(self.script.pk): script_hash(self.script)},
        )
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()
        user = self.manager()
        self.agent.tags.add(tag)
        with self.captureOnCommitCallbacks(execute=True):
            resolver.resolve_device(self.agent, cause="tag", author=user)
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual(
            self.client.get(self.uri).data["effective"]["fields"]["hooks"]["value"], []
        )
        url = f"/imaging/holds/{hold.pk}/confirm/"
        body = {"action": "confirm", "proposed_hash": hold.proposed_hash}
        self.assertEqual(self.client.post(url, body, format="json").status_code, 403)
        self.client.force_authenticate(self.john)
        self.assertEqual(self.client.post(url, body, format="json").status_code, 403)
        with (
            patch("imaging.views.stepup_denied", return_value=None),
            patch("imaging.tasks.wake_imaging_agent.delay"),
        ):
            r = self.client.post(url, body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        hooks = self.client.get(self.uri).data["effective"]["fields"]["hooks"]["value"]
        self.assertEqual([h["script_id"] for h in hooks], [self.script.pk])


class TestHookRule(HookBase):
    def manager(self):
        self.client.force_authenticate(
            self.create_user_with_roles(["can_manage_images"])
        )

    def refused_without_rights(self, method, url, body=None):
        self.manager()
        r = getattr(self.client, method)(url, body, format="json")
        self.assertEqual(r.status_code, 403)
        self.client.force_authenticate(self.john)
        r = getattr(self.client, method)(url, body, format="json")
        self.assertEqual((r.status_code, r.data.get("stepup")), (403, True))
        with patch("imaging.policies.stepup_denied", return_value=None):
            r = getattr(self.client, method)(url, body, format="json")
        self.assertIn(r.status_code, (200, 201, 204), getattr(r, "data", None))

    def tagged(self, **kw):
        tag = baker.make("groups.Tag", name="t")
        return BackupPolicy.objects.create(
            name="Quiet", scope="tag", tag=tag, config={"hooks": []}, **kw
        )

    def test_delete_of_a_policy_with_empty_hooks(self):
        policy = self.tagged()
        self.refused_without_rights("delete", f"/imaging/policies/{policy.pk}/")

    def test_priority_of_a_tag_policy_with_hooks(self):
        policy = self.tagged()
        body = {"name": "Quiet", "scope": "tag", "tag": policy.tag_id, "priority": 5}
        body["config"], body["keep_hooks"] = {}, True
        self.refused_without_rights("put", f"/imaging/policies/{policy.pk}/", body)

    def test_enforced_hooks_on_a_keep_hooks_put(self):
        policy = self.tagged()
        body = {"name": "Quiet", "scope": "tag", "tag": policy.tag_id}
        body.update(config={}, keep_hooks=True, enforced=["hooks"])
        self.refused_without_rights("put", f"/imaging/policies/{policy.pk}/", body)

    def test_detaching_every_device_checks_the_removed_ones(self):
        policy = BackupPolicy.objects.create(
            name="Quiet", scope="assigned", config={"hooks": []}
        )
        Profile.objects.filter(agent=self.agent).update(policy=policy)
        body = {"name": "Quiet", "scope": "assigned", "config": {}, "agents": []}
        body["keep_hooks"] = True
        self.refused_without_rights("put", f"/imaging/policies/{policy.pk}/", body)
        self.assertIsNone(Profile.objects.get(agent=self.agent).policy)

    def test_schedule_edit_with_keep_hooks_stays_a_plain_save(self):
        policy = BackupPolicy.objects.create(
            name="Hooks", scope="assigned", config={"hooks": [hook(self.script)]}
        )
        Profile.objects.filter(agent=self.agent).update(policy=policy)
        self.manager()
        body = {
            "name": "Hooks",
            "scope": "assigned",
            "agents": [self.agent.agent_id],
            "config": {"schedule": {"kind": "daily", "time": "02:00"}, "keep_last": 3},
            "keep_hooks": True,
        }
        r = self.client.put(f"/imaging/policies/{policy.pk}/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        policy.refresh_from_db()
        self.assertEqual(policy.config["keep_last"], 3)
        self.assertEqual(policy.config["hooks"][0]["script_id"], self.script.pk)

    def test_taking_a_device_from_a_policy_with_hooks(self):
        quiet = BackupPolicy.objects.create(
            name="Quiet", scope="assigned", config={"hooks": []}
        )
        Profile.objects.filter(agent=self.agent).update(policy=quiet)
        body = {
            "name": "Other",
            "scope": "assigned",
            "config": {"keep_last": 2},
            "agents": [self.agent.agent_id],
        }
        self.refused_without_rights("post", "/imaging/policies/", body)
        self.assertNotEqual(Profile.objects.get(agent=self.agent).policy, quiet)

    def test_taking_a_device_from_a_policy_without_hooks_is_plain(self):
        plain = BackupPolicy.objects.create(name="Plain", scope="assigned", config={})
        Profile.objects.filter(agent=self.agent).update(policy=plain)
        self.manager()
        body = {
            "name": "Other",
            "scope": "assigned",
            "config": {"keep_last": 2},
            "agents": [self.agent.agent_id],
        }
        r = self.client.post("/imaging/policies/", body, format="json")
        self.assertEqual(r.status_code, 201, r.data)

    def test_policy_list_costs_no_query_per_policy(self):
        from collections import Counter

        from django.core.cache import cache
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        from .service import backup_rows

        tag = baker.make("groups.Tag", name="many")
        devices = [self.agent] + [
            baker.make("agents.Agent", site=self.agent.site) for _ in range(5)
        ]
        for device in devices:
            backup_rows(device)
        free = self.create_user_with_roles(["can_manage_images", "can_run_scripts"])
        bound = self.create_user_with_roles(["can_manage_images"])
        bound.role.can_view_clients.add(self.agent.site.client)

        def count(user):
            self.client.force_authenticate(user)
            out = []
            for _ in range(2):  # the first read warms the caches of the process
                cache.clear()
                with CaptureQueriesContext(connection) as queries:
                    r = self.client.get("/imaging/policies/")
                    self.assertEqual(r.status_code, 200)
                # reads only: savepoints of nested atomic blocks are no table access
                out = [q["sql"][:120] for q in queries if "SAVEPOINT" not in q["sql"]]
            return Counter(out)

        def make(first, n):
            for i in range(first, first + n):
                BackupPolicy.objects.create(
                    name=f"Tag {i}",
                    scope="tag",
                    tag=tag,
                    config={"hooks": [hook(self.script)]},
                )
                policy = BackupPolicy.objects.create(
                    name=f"Assigned {i}", scope="assigned", config={}
                )
                # two devices for each of the first three assigned policies
                Profile.objects.filter(agent__in=devices[2 * i : 2 * i + 2]).update(
                    policy=policy
                )

        make(0, 1)
        one = (count(free), count(bound))
        make(1, 19)
        self.assertEqual((count(free), count(bound)), one)

    def test_reach_of_unresolved_devices(self):
        from groups.models import DeviceGroup

        from . import resolver

        fresh = baker.make("agents.Agent", site=self.agent.site)
        tag = baker.make("groups.Tag", name="fresh")
        tag.agents.add(fresh)
        group = baker.make(DeviceGroup, kind="static", name="fresh")
        group.members.add(fresh)
        for scope, key in (
            ("client", self.agent.site.client),
            ("site", self.agent.site),
            ("tag", tag),
            ("group", group),
        ):
            policy = BackupPolicy(scope=scope, **{scope: key})
            with self.subTest(scope):
                self.assertIn(fresh.pk, resolver.reach(policy))
                ctx = resolver.reach_context()
                self.assertIn(fresh.pk, resolver.reach(policy, ctx=ctx))

    def test_site_move_by_an_agent_editor_is_held(self):
        from clients.models import Site

        from .models import PolicyChangeHold

        site = baker.make(Site, client=self.agent.site.client, name="Annex")
        BackupPolicy.objects.create(
            name="Annex hooks",
            scope="site",
            site=site,
            config={"hooks": [{**hook(self.script), "key": "0a0b0c0d"}]},
            hooks_pinned={str(self.script.pk): script_hash(self.script)},
        )
        user = self.create_user_with_roles(
            ["can_manage_images", "can_edit_agent", "can_list_agents"]
        )
        # the agent routes take only long agent ids
        self.agent.agent_id = "site-move-agent-0123456789"
        self.agent.save(update_fields=["agent_id"])
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"
        self.client.force_authenticate(user)
        with self.captureOnCommitCallbacks(execute=True):
            r = self.client.put(
                f"/agents/{self.agent.agent_id}/", {"site": site.pk}, format="json"
            )
        self.assertEqual(r.status_code, 200, getattr(r, "data", None))
        hold = PolicyChangeHold.objects.get(status="pending")
        self.assertEqual(hold.cause, "site_move")
        hooks = self.client.get(self.uri).data["effective"]["fields"]["hooks"]
        self.assertEqual(hooks["value"], [])


class TestNames(HookBase):
    def test_scope_name_per_level(self):
        from groups.models import DeviceGroup

        client, site = self.agent.site.client, self.agent.site
        tag = baker.make("groups.Tag", name="laptops")
        group = baker.make(DeviceGroup, kind="static", name="servers")
        for scope, key in (
            ("client", client),
            ("site", site),
            ("tag", tag),
            ("group", group),
        ):
            BackupPolicy.objects.create(
                name=scope, scope=scope, config={}, **{scope: key}
            )
        BackupPolicy.objects.create(name="assigned", scope="assigned", config={})
        rows = self.client.get("/imaging/policies/").data
        self.assertEqual(
            {r["name"]: r["scope_name"] for r in rows},
            {
                "Global default": "",
                "client": client.name,
                "site": site.name,
                "tag": "laptops",
                "group": "servers",
                "assigned": "",
            },
        )

    def test_script_name_in_hook_answers(self):
        self.assertEqual(self.put([hook(self.script)]).status_code, 200)
        data = self.client.get(self.uri).data
        self.assertEqual(
            data["effective"]["fields"]["hooks"]["value"][0]["script_name"], "Dump"
        )
        self.assertEqual(data["overrides"]["hooks"][0]["script_name"], "Dump")
        # a save sends the entries back as received
        sent = {
            **self.stored()[0],
            "script_name": "Dump",
            "env_vars": [{"name": "PGPASS"}],
        }
        self.assertEqual(self.put([sent], stepup=False).status_code, 200)
        self.assertNotIn("script_name", self.stored()[0])
        viewer = self.create_user_with_roles(["can_view_images"])
        self.client.force_authenticate(viewer)
        shown = self.client.get(self.uri).data["effective"]["fields"]["hooks"]["value"][
            0
        ]
        self.assertEqual((shown["script_name"], shown["args_count"]), ("Dump", 1))
        self.assertNotIn("args", shown)
        Script.objects.filter(pk=self.script.pk).update(script_body="v2")
        suspended = self.client.get(self.uri).data["hooks_suspended"][0]
        self.assertEqual(suspended["script_name"], "Dump")
        self.client.force_authenticate(self.john)
        policy = BackupPolicy.objects.create(
            name="Hooks", scope="assigned", config={"hooks": [hook(self.script)]}
        )
        row = next(
            r
            for r in self.client.get("/imaging/policies/").data
            if r["id"] == policy.pk
        )
        self.assertEqual(row["config"]["hooks"][0]["script_name"], "Dump")

    def test_script_name_in_a_held_change(self):
        from . import resolver

        tag = baker.make("groups.Tag", name="db")
        BackupPolicy.objects.create(
            name="Tagged hooks",
            scope="tag",
            tag=tag,
            config={"hooks": [{**hook(self.script), "key": "0a0b0c0d"}]},
            hooks_pinned={str(self.script.pk): script_hash(self.script)},
        )
        with self.captureOnCommitCallbacks(execute=True):
            resolver.invalidate()
        user = self.create_user_with_roles(["can_manage_images"])
        self.agent.tags.add(tag)
        resolver.resolve_device(self.agent, cause="tag", author=user)
        changes = self.client.get(self.uri).data["hold"]["changes"]
        hooks = next(c for c in changes if c["field"] == "hooks")
        self.assertEqual(hooks["proposed"][0]["script_name"], "Dump")

    def test_script_name_in_run_rows(self):
        from .models import BackupRun

        other = baker.make(Script, name="Mount", shell="bash")
        image = self.queue()
        result = {"sha256": "", "status": "ok"}
        run = BackupRun.objects.create(
            image=image,
            trigger="manual",
            status="running",
            claimed_hooks=[
                {
                    "phase": "pre-backup",
                    "script_id": self.script.pk,
                    "sha256": "",
                    "script_name": "Dump at claim",
                }
            ],
            hooks=[
                {**result, "phase": "pre-backup", "script_id": self.script.pk},
                {**result, "phase": "post-backup", "script_id": other.pk},
                {**result, "phase": "post-backup", "script_id": 999999},
            ],
        )
        row = self.client.get(f"{self.uri}runs/{run.pk}/").data
        self.assertEqual(
            [h["script_name"] for h in row["hooks"]], ["Dump at claim", "Mount", ""]
        )

    def test_missing_source_names_the_devices(self):
        def post(n):
            devices = [
                baker.make("agents.Agent", plat="windows", site=self.agent.site)
                for _ in range(n)
            ]
            body = {
                "name": f"Batch {n}",
                "scope": "assigned",
                "config": {},
                "agents": [d.agent_id for d in devices],
            }
            r = self.client.post("/imaging/policies/", body, format="json")
            self.assertEqual(r.status_code, 400)
            return str(r.data[0]), sorted(devices, key=lambda d: d.pk)

        text, devices = post(1)
        self.assertEqual(
            text,
            "Review an available native backup source for every selected device: "
            f"{devices[0].hostname}.",
        )
        text, devices = post(12)
        names = ", ".join(d.hostname for d in devices[:10])
        self.assertEqual(
            text,
            "Review an available native backup source for every selected device: "
            f"{names} and 2 more.",
        )


class TestKeptPins(HookBase):
    def setUp(self):
        super().setUp()
        self.other = baker.make(Script, name="Notify", shell="bash", script_body="echo")
        self.added = baker.make(Script, name="Flush", shell="bash", script_body="sync")

    def edit(self):
        pinned = script_hash(self.script)
        Script.objects.filter(pk=self.script.pk).update(script_body="rm -rf /")
        return pinned, script_hash(Script.objects.get(pk=self.script.pk))

    def changed(self, stored):
        # the edited hook as stored, another hook with a new timeout, a new script
        return [
            stored[0],
            {**stored[1], "timeout": 120},
            hook(self.added, phase="post-backup"),
        ]

    def pins(self, pinned):
        return {
            str(self.script.pk): pinned,
            str(self.other.pk): script_hash(self.other),
            str(self.added.pk): script_hash(self.added),
        }

    def save_policy(self, method, url, body):
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            patch("imaging.tasks.wake_imaging_agent.delay"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = getattr(self.client, method)(url, body, format="json")
        self.assertIn(r.status_code, (200, 201), r.data)
        return r

    def suspended(self, pk):
        row = next(
            p for p in self.client.get("/imaging/policies/").data if p["id"] == pk
        )
        return [h["script_id"] for h in row["hooks_suspended"]]

    def test_policy_saves_keep_the_pin_of_an_edited_script(self):
        from .models import NativeInventory

        second = baker.make("agents.Agent", plat="windows", goarch="amd64")
        NativeInventory.objects.create(agent=second, capability=self.cap)
        hooks = [hook(self.script), hook(self.other, phase="post-backup")]
        body = {
            "name": "Databases",
            "scope": "assigned",
            "config": {"hooks": hooks},
            "agents": [self.agent.agent_id],
        }
        pk = self.save_policy("post", "/imaging/policies/", body).data["id"]
        url = f"/imaging/policies/{pk}/"
        pinned, current = self.edit()
        body["agents"].append(second.agent_id)
        self.save_policy("put", url, {**body, "keep_hooks": True})
        policy = BackupPolicy.objects.get(pk=pk)
        self.assertEqual(policy.hooks_pinned[str(self.script.pk)], pinned)
        self.assertEqual(self.suspended(pk), [self.script.pk])
        body["config"] = {"hooks": self.changed(policy.config["hooks"])}
        self.save_policy("put", url, body)
        policy.refresh_from_db()
        self.assertEqual(policy.config["hooks"][1]["timeout"], 120)
        self.assertEqual(policy.hooks_pinned, self.pins(pinned))
        self.assertEqual(self.suspended(pk), [self.script.pk])
        confirm = {"script_id": self.script.pk, "sha256": current}
        with (
            patch("imaging.policies.stepup_denied", return_value=None),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.post(url + "hooks/confirm/", confirm, format="json")
        self.assertEqual((r.status_code, r.data["hooks_suspended"]), (200, []))

    def test_device_save_keeps_the_pin_of_an_edited_script(self):
        self.put([hook(self.script), hook(self.other, phase="post-backup")])
        pinned, current = self.edit()
        self.assertEqual(self.put(self.changed(self.stored())).status_code, 200)
        profile = Profile.objects.get(agent=self.agent)
        self.assertEqual(profile.overrides["hooks"][1]["timeout"], 120)
        self.assertEqual(profile.hooks_pinned, self.pins(pinned))
        suspended = self.client.get(self.uri).data["hooks_suspended"]
        self.assertEqual([h["script_id"] for h in suspended], [self.script.pk])
        confirm = {"script_id": self.script.pk, "sha256": current}
        with patch("imaging.views.stepup_denied", return_value=None):
            r = self.client.post(self.uri + "hooks/confirm/", confirm, format="json")
        self.assertEqual((r.status_code, r.data["hooks_suspended"]), (200, []))

    def test_an_environment_name_set_twice_is_refused(self):
        self.put([hook(self.script, env_vars=["TOKEN=old"])])
        key = self.stored()[0]["key"]
        for env, name in (
            ([{"name": "TOKEN"}, "TOKEN=new"], "TOKEN"),
            (["A=1", "A=2"], "A"),
        ):
            r = self.put([hook(self.script, key=key, env_vars=env)])
            self.assertEqual(r.status_code, 400)
            self.assertEqual(
                r.data["set"]["hooks"][0]["env_vars"],
                [f"{name} is set more than once."],
            )

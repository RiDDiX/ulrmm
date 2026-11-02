# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import json
import string
import sys
import types
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from logs.models import AuditLog, DebugLog
from remote.utils import decrypt_secret, encrypt_secret
from scripts.models import Script
from ulrmm.constants import AuditActionType, ScriptType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from vault.models import HKDF_INFO, Credential

from .models import LapsPolicy, LapsState
from .tasks import laps_rotate_task, new_password, rotate_agent_task

VARIABLES = [
    {"name": "TARGET_USER", "type": "string"},
    {"name": "NEW_PASSWORD", "type": "password"},
    {"name": "CREATE_IF_MISSING", "type": "checkbox"},
]


def library(filename="win_users_laps_rotate.ps1"):
    return baker.make(
        "scripts.Script",
        name="Rotate local admin",
        filename=filename,
        script_type=ScriptType.BUILT_IN,
        shell="powershell",
        variables=VARIABLES,
    )


def env_of(run_script) -> dict:
    return dict(e.split("=", 1) for e in run_script.call_args.kwargs["env_vars"])


def fake_notify():
    module = types.ModuleType("notify.dispatch")
    module.dispatch = MagicMock()
    return module


@override_settings(CACHES=LOCMEM_CACHE)
class LapsBase(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site", name="HQ", client__name="Acme")
        self.other_site = baker.make("clients.Site", name="Far", client__name="Other")
        self.agent = baker.make_recipe(
            "agents.agent", site=self.site, last_seen=djangotime.now()
        )
        self.policy = baker.make(LapsPolicy, site=None, enabled=True)

    def login(self, user, stepup=True):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)


class TestRotation(LapsBase):
    def setUp(self):
        super().setUp()
        self.script = library()

    def test_password(self):
        for length in (14, 24, 64):
            pw = new_password(length)
            self.assertEqual(len(pw), length)
            for group in (string.ascii_lowercase, string.ascii_uppercase):
                self.assertTrue(any(c in group for c in pw))
            self.assertFalse(set(pw) & set("{}:=\"' \\"))

    @patch("agents.models.Agent.run_script")
    def test_success_keeps_password_in_vault(self, run_script):
        run_script.return_value = {"retcode": 0, "stdout": "ok", "stderr": ""}
        self.assertEqual(rotate_agent_task(self.agent.pk, force=True), "ok")

        kwargs = run_script.call_args.kwargs
        self.assertEqual(kwargs["scriptpk"], self.script.pk)
        self.assertTrue(kwargs["wait"] and kwargs["full"])
        env = env_of(run_script)
        self.assertEqual(env["TARGET_USER"], "ulrmm-admin")
        self.assertEqual(env["CREATE_IF_MISSING"], "true")
        self.assertEqual(len(env["NEW_PASSWORD"]), 24)

        state = LapsState.objects.get(agent=self.agent)
        cred = state.credential
        self.assertEqual(cred.agent, self.agent)
        self.assertEqual(cred.name, "Local admin (ulrmm-admin)")
        self.assertEqual(cred.username, "ulrmm-admin")
        self.assertEqual(decrypt_secret(cred.secret, HKDF_INFO), env["NEW_PASSWORD"])
        self.assertEqual(state.last_error, "")
        self.assertAlmostEqual(
            state.next_rotation - state.last_rotation, dt.timedelta(days=30)
        )

        # the next rotation updates the same credential
        rotate_agent_task(self.agent.pk, force=True)
        self.assertEqual(Credential.objects.count(), 1)
        cred.refresh_from_db()
        self.assertEqual(
            decrypt_secret(cred.secret, HKDF_INFO), env_of(run_script)["NEW_PASSWORD"]
        )

        # another account gets its own credential, the old one stays
        self.policy.account = "it-admin"
        self.policy.save()
        rotate_agent_task(self.agent.pk, force=True)
        self.assertEqual(
            sorted(Credential.objects.values_list("username", flat=True)),
            ["it-admin", "ulrmm-admin"],
        )
        # the password never reaches the history or the debug log
        dump = json.dumps(
            list(AuditLog.objects.values()) + list(DebugLog.objects.values()),
            default=str,
        )
        self.assertNotIn(env_of(run_script)["NEW_PASSWORD"], dump)

    @patch("agents.models.Agent.run_script")
    def test_not_due_is_skipped_unless_forced(self, run_script):
        run_script.return_value = {"retcode": 0, "stdout": "", "stderr": ""}
        rotate_agent_task(self.agent.pk)
        self.assertEqual(run_script.call_count, 1)
        self.assertEqual(rotate_agent_task(self.agent.pk), "not due")
        self.assertEqual(run_script.call_count, 1)

    @patch("agents.models.Agent.run_script")
    def test_failure_keeps_old_credential(self, run_script):
        run_script.return_value = {"retcode": 0, "stdout": "", "stderr": ""}
        rotate_agent_task(self.agent.pk, force=True)
        cred = Credential.objects.get()
        old = cred.secret

        notify = fake_notify()

        def failing(**kwargs):
            pw = dict(e.split("=", 1) for e in kwargs["env_vars"])["NEW_PASSWORD"]
            return {"retcode": 1, "stdout": "", "stderr": f"rejected {pw}"}

        run_script.side_effect = failing
        with patch.dict(sys.modules, {"notify.dispatch": notify}):
            rotate_agent_task(self.agent.pk, force=True)
            pw = env_of(run_script)["NEW_PASSWORD"]
            state = LapsState.objects.get(agent=self.agent)
            self.assertIn("exited with 1", state.last_error)
            self.assertIn("********", state.last_error)
            self.assertNotIn(pw, state.last_error)
            self.assertAlmostEqual(
                state.next_rotation - djangotime.now(),
                dt.timedelta(hours=4),
                delta=dt.timedelta(minutes=1),
            )
            cred.refresh_from_db()
            self.assertEqual(cred.secret, old)
            self.assertTrue(DebugLog.objects.filter(agent=self.agent).exists())
            event = notify.dispatch.call_args.args[0]
            self.assertEqual(event["source"], "laps")
            self.assertEqual(event["severity"], "warning")
            self.assertEqual(event["agent"], self.agent)

            # still failing: no second notification
            run_script.side_effect = None
            run_script.return_value = "timeout"
            rotate_agent_task(self.agent.pk, force=True)
            state.refresh_from_db()
            self.assertEqual(state.last_error, "The agent did not answer.")
            notify.dispatch.assert_called_once()

        # without the notify app the failure is still recorded
        with patch.dict(sys.modules, {"notify.dispatch": None}):
            LapsState.objects.update(last_error="")
            rotate_agent_task(self.agent.pk, force=True)
        self.assertEqual(
            LapsState.objects.get().last_error, "The agent did not answer."
        )

    @patch("agents.models.Agent.run_script")
    def test_missing_or_wrong_library_script(self, run_script):
        self.script.delete()
        # a user script with the same file name is not used
        baker.make(
            "scripts.Script",
            filename="win_users_laps_rotate.ps1",
            script_type=ScriptType.USER_DEFINED,
        )
        rotate_agent_task(self.agent.pk, force=True)
        self.assertIn("no rotation script", LapsState.objects.get().last_error)

        # a library script without the variables
        library()
        Script.objects.filter(script_type=ScriptType.BUILT_IN).update(variables=[])
        rotate_agent_task(self.agent.pk, force=True)
        self.assertIn("does not take", LapsState.objects.get().last_error)
        run_script.assert_not_called()

    @patch("laps.tasks.rotate_agent_task.delay")
    def test_beat_picks_due_online_agents(self, delay):
        offline = baker.make_recipe("agents.agent", site=self.site)
        far = baker.make_recipe(
            "agents.agent", site=self.other_site, last_seen=djangotime.now()
        )
        baker.make(LapsPolicy, site=self.other_site, enabled=False)
        mac = baker.make_recipe(
            "agents.agent",
            site=self.site,
            plat="darwin",
            last_seen=djangotime.now(),
        )
        baker.make(
            LapsState, agent=mac, next_rotation=djangotime.now() + dt.timedelta(days=1)
        )

        laps_rotate_task()
        self.assertEqual([c.args[0] for c in delay.call_args_list], [self.agent.pk])
        self.assertNotIn(offline.pk, [c.args[0] for c in delay.call_args_list])
        self.assertNotIn(far.pk, [c.args[0] for c in delay.call_args_list])

        # due again once the date passed
        delay.reset_mock()
        LapsState.objects.filter(agent=mac).update(
            next_rotation=djangotime.now() - dt.timedelta(minutes=1)
        )
        laps_rotate_task()
        self.assertEqual(
            sorted(c.args[0] for c in delay.call_args_list),
            sorted([self.agent.pk, mac.pk]),
        )

        # the global policy off: nothing
        delay.reset_mock()
        LapsPolicy.objects.update(enabled=False)
        laps_rotate_task()
        delay.assert_not_called()


class TestViews(LapsBase):
    def test_policies(self):
        url = "/laps/policies/"
        self.login(self.john, stepup=False)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["global"]["account"], "ulrmm-admin")
        self.assertEqual(r.data["sites"], [])

        data = {"site": self.site.pk, "enabled": True, "account": "it-admin"}
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        grant_console_stepup(self.john)
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["site"], self.site.pk)
        self.assertEqual(r.data["rotate_days"], 30)
        r = self.client.put(url, {**data, "rotate_days": 7}, format="json")
        self.assertEqual(LapsPolicy.objects.get(site=self.site).rotate_days, 7)
        self.assertEqual(LapsPolicy.objects.count(), 2)

        r = self.client.get(url)
        self.assertEqual(r.data["sites"][0]["site_name"], "HQ")
        self.assertEqual(r.data["sites"][0]["client_name"], "Acme")

        for bad in (
            {"account": "bad name"},
            {"account": "Admin"},
            {"account": "_admin"},
            {"account": "it.admin"},
            {"account": "x" * 21},
            {"length": 8},
            {"rotate_days": 0},
            {"site": "1"},
            {"site": 9999},
        ):
            r = self.client.put(url, {**data, **bad}, format="json")
            self.assertEqual(r.status_code, 400, bad)

        r = self.client.put(url, {"site": None, "length": 32}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(LapsPolicy.objects.get(site=None).length, 32)

        r = self.client.delete(f"{url}{self.site.pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(LapsPolicy.objects.filter(site=self.site).exists())

    def test_policy_permissions(self):
        url = "/laps/policies/"
        user = self.create_user_with_roles(["can_edit_core_settings"])
        self.login(user)
        self.check_not_authorized("get", url)
        self.check_not_authorized("put", url, {"site": None})

        user = self.create_user_with_roles(["can_manage_laps"])
        user.role.can_view_sites.set([self.site])
        self.login(user)
        baker.make(LapsPolicy, site=self.other_site)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["sites"], [])
        self.check_not_authorized("put", url, {"site": self.other_site.pk})
        self.check_not_authorized("delete", f"{url}{self.other_site.pk}/")
        self.check_not_authorized("put", url, {"site": None, "enabled": False})
        self.policy.refresh_from_db()
        self.assertTrue(self.policy.enabled)
        r = self.client.put(url, {"site": self.site.pk}, format="json")
        self.assertEqual(r.status_code, 200)

    def test_agent_state(self):
        url = f"/laps/{self.agent.agent_id}/"
        self.login(self.john)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {
                "supported": False,
                "policy": {**r.data["policy"], "scope": "global"},
                "state": None,
                "can_rotate": True,
            },
        )
        library()
        cred = baker.make(Credential, agent=self.agent, name="x", secret="")
        baker.make(LapsState, agent=self.agent, account="ulrmm-admin", credential=cred)
        r = self.client.get(url)
        self.assertTrue(r.data["supported"])
        self.assertEqual(r.data["state"]["credential"], cred.pk)
        self.assertEqual(r.data["state"]["account"], "ulrmm-admin")

        far = self.create_user_with_roles(["can_view_credentials"])
        far.role.can_view_sites.set([self.other_site])
        self.login(far)
        self.check_not_authorized("get", url)
        user = self.create_user_with_roles(["can_view_credentials"])
        user.role.can_view_sites.set([self.site])
        self.login(user)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["can_rotate"])
        self.login(self.create_user_with_roles(["can_list_agents"]))
        self.check_not_authorized("get", url)

    @patch("laps.tasks.rotate_agent_task.delay")
    def test_rotate_now(self, delay):
        url = f"/laps/{self.agent.agent_id}/rotate/"
        user = self.create_user_with_roles(["can_manage_laps"])
        self.login(user, stepup=False)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        grant_console_stepup(user)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)  # no library script
        library()
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        delay.assert_called_once_with(self.agent.pk, username=user.username, force=True)
        log = AuditLog.objects.get(action=AuditActionType.EXEC_SCRIPT)
        self.assertIn("ulrmm-admin", log.message)

        self.agent.last_seen = djangotime.now() - dt.timedelta(days=1)
        self.agent.save()
        self.assertEqual(self.client.post(url).status_code, 400)

        self.policy.enabled = False
        self.policy.save()
        self.assertEqual(self.client.post(url).status_code, 400)

        far = self.create_user_with_roles(["can_manage_laps"])
        far.role.can_view_sites.set([self.other_site])
        self.login(far)
        self.check_not_authorized("post", url)
        self.login(self.create_user_with_roles(["can_manage_credentials"]))
        self.check_not_authorized("post", url)


class TestRevealHook(LapsBase):
    def test_reveal_moves_rotation_forward(self):
        cred = baker.make(
            Credential,
            agent=self.agent,
            name="Local admin (ulrmm-admin)",
            secret=encrypt_secret("pw", HKDF_INFO),
        )
        later = djangotime.now() + dt.timedelta(days=20)
        state = baker.make(
            LapsState, agent=self.agent, credential=cred, next_rotation=later
        )
        self.login(self.john)
        r = self.client.post(f"/vault/credentials/{cred.pk}/reveal/")
        self.assertEqual(r.status_code, 200)
        state.refresh_from_db()
        self.assertAlmostEqual(
            state.next_rotation - djangotime.now(),
            dt.timedelta(hours=4),
            delta=dt.timedelta(minutes=1),
        )

        # an earlier date stays, 0 hours keeps the schedule
        soon = djangotime.now() + dt.timedelta(minutes=30)
        LapsState.objects.update(next_rotation=soon)
        self.client.post(f"/vault/credentials/{cred.pk}/reveal/")
        self.assertEqual(LapsState.objects.get().next_rotation, soon)
        LapsState.objects.update(next_rotation=later)
        LapsPolicy.objects.update(rotate_after_reveal_hours=0)
        self.client.post(f"/vault/credentials/{cred.pk}/reveal/")
        self.assertEqual(LapsState.objects.get().next_rotation, later)

        # any other credential is left alone
        other = baker.make(
            Credential,
            agent=self.agent,
            name="x",
            secret=encrypt_secret("pw", HKDF_INFO),
        )
        LapsPolicy.objects.update(rotate_after_reveal_hours=4)
        self.assertEqual(
            self.client.post(f"/vault/credentials/{other.pk}/reveal/").status_code, 200
        )
        self.assertEqual(LapsState.objects.get().next_rotation, later)

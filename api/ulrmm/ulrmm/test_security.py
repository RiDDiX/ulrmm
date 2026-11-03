# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey, Role, User
from accounts.utils import (
    commit_pending_totp_key,
    get_pending_totp_key,
    set_pending_totp_key,
)
from core.models import CoreSettings
from logs.models import AuditLog
from ulrmm.constants import CORE_SETTINGS_SECRET_FIELDS, AuditObjType
from ulrmm.helpers import (
    get_client_ip,
    get_nats_server_password,
    setup_nats_options,
)
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from winupdate.models import WinUpdatePolicy
from winupdate.serializers import WinUpdatePolicySerializer


class TestMFAEnrolment(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()

    def token_for(self, user):
        _, token = AuthToken.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        return token

    def test_password_only_session_can_only_enrol(self):
        user = User.objects.create_user(username="nototp", password="hunter2x")
        self.token_for(user)

        r = self.client.get("/core/version/")
        self.assertEqual(r.status_code, 401)

        r = self.client.post("/accounts/users/setup_totp/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["totp_key"])
        # nothing is committed before a code proves the authenticator has the key
        self.assertFalse(User.objects.get(pk=user.pk).totp_key)

        # enrolment ends that session, the next one needs the code
        self.assertFalse(AuthToken.objects.filter(user=user).exists())

    def test_enrolled_user_session_works(self):
        user = User.objects.create_user(username="withtotp", password="hunter2x")
        user.totp_key = "AB5RI6YPFTZAS52G"
        user.save()
        self.token_for(user)

        r = self.client.get("/core/version/")
        self.assertEqual(r.status_code, 200)

    def test_websocket_refuses_password_only_session(self):
        # the undecorated function: database_sync_to_async closes the test
        # transaction's connection
        from ulrmm.utils import get_user

        user = User.objects.create_user(username="wsnototp", password="hunter2x")
        _, token = AuthToken.objects.create(user=user)
        ws_user = get_user.func(f"access_token={token}".encode())
        self.assertIsInstance(ws_user, AnonymousUser)

        user.totp_key = "AB5RI6YPFTZAS52G"
        user.save()
        ws_user = get_user.func(f"access_token={token}".encode())
        self.assertEqual(ws_user.pk, user.pk)


@override_settings(CACHES=LOCMEM_CACHE)
class TestPendingTOTPEnrolment(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        # the pending keys and the login throttles live here
        cache.clear()
        self.user = User.objects.create_user(username="enrol", password="hunter2x")

    def start_enrolment(self, user=None):
        # the password only session check creds hands out
        _, token = AuthToken.objects.create(user=user or self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        r = self.client.post("/accounts/users/setup_totp/")
        self.client.credentials()
        self.assertEqual(r.status_code, 200)
        return r.data["totp_key"]

    def login(self, code, username="enrol", password="hunter2x"):
        return self.client.post(
            "/v2/login/",
            {"username": username, "password": password, "twofactor": code},
            format="json",
        )

    def stored_key(self, user=None):
        return User.objects.get(pk=(user or self.user).pk).totp_key

    def test_valid_code_commits_the_key(self):
        key = self.start_enrolment()
        self.assertFalse(self.stored_key())

        r = self.login(pyotp.TOTP(key).now())
        self.assertEqual(r.status_code, 200)
        self.assertIn("token", r.data.keys())
        self.assertIn("expiry", r.data.keys())
        self.assertEqual(self.stored_key(), key)
        self.assertFalse(get_pending_totp_key(self.user))

    def test_wrong_code_keeps_the_key_pending(self):
        key = self.start_enrolment()

        r = self.login("000000")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Bad credentials")
        self.assertFalse(self.stored_key())
        self.assertEqual(get_pending_totp_key(self.user), key)

        # the dialog allows retries
        r = self.login(pyotp.TOTP(key).now())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.stored_key(), key)

    def test_abandoned_enrolment_leaves_no_key(self):
        key = self.start_enrolment()
        # the entry expired, or the cache was cleared
        cache.clear()

        r = self.login(pyotp.TOTP(key).now())
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.stored_key())

        new_key = self.start_enrolment()
        self.assertNotEqual(new_key, key)
        self.assertFalse(self.stored_key())
        self.assertEqual(self.login(pyotp.TOTP(new_key).now()).status_code, 200)

    def test_pending_key_commits_only_once(self):
        key = pyotp.random_base32()
        set_pending_totp_key(self.user, key)

        self.assertTrue(commit_pending_totp_key(self.user, key))
        self.assertEqual(self.stored_key(), key)

        # a replay finds nothing left to enrol with
        User.objects.filter(pk=self.user.pk).update(totp_key="")
        self.user.refresh_from_db()
        self.assertFalse(commit_pending_totp_key(self.user, key))
        self.assertFalse(self.stored_key())

    def test_enrolled_account_ignores_pending_entry(self):
        committed = "AB5RI6YPFTZAS52G"
        self.user.totp_key = committed
        self.user.save()
        other = pyotp.random_base32()
        set_pending_totp_key(self.user, other)

        _, token = AuthToken.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        r = self.client.post("/accounts/users/setup_totp/")
        self.client.credentials()
        self.assertEqual(r.data, False)

        r = self.login(pyotp.TOTP(other).now())
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.stored_key(), committed)

        r = self.login(pyotp.TOTP(committed).now())
        self.assertEqual(r.status_code, 200)

    def test_pending_key_belongs_to_one_account(self):
        key = self.start_enrolment()
        other = User.objects.create_user(username="other", password="hunter2x")

        r = self.login(pyotp.TOTP(key).now(), username="other")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.stored_key(other))
        self.assertEqual(get_pending_totp_key(self.user), key)


class TestNatsServerCredential(ULRMMTestCase):
    @override_settings(NATS_SERVER_PASSWORD="")
    def test_derived_password_is_not_secret_key(self):
        self.assertNotEqual(get_nats_server_password(), settings.SECRET_KEY)
        self.assertEqual(setup_nats_options()["password"], get_nats_server_password())

    @override_settings(NATS_SERVER_PASSWORD="configured-nats-pass")
    @patch("ulrmm.utils.time.sleep")
    @patch("ulrmm.utils.subprocess.run")
    def test_reload_nats_server_user(self, run, sleep):
        from ulrmm.utils import reload_nats

        reload_nats()
        with open(f"{settings.BASE_DIR}/nats-rmm.conf") as f:
            config = json.load(f)

        server = config["authorization"]["users"][0]
        self.assertEqual(server["user"], "ulrmm")
        self.assertEqual(server["password"], "configured-nats-pass")
        self.assertEqual(server["allowed_connection_types"], ["STANDARD"])
        self.assertNotIn(settings.SECRET_KEY, json.dumps(config))


class TestCoreSettingsSecrets(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        core = CoreSettings.objects.first()
        for field in CORE_SETTINGS_SECRET_FIELDS:
            setattr(core, field, f"stored-{field}")
        core.save()

    def test_get_never_returns_secrets(self):
        r = self.client.get("/core/settings/")
        self.assertEqual(r.status_code, 200)
        for field in CORE_SETTINGS_SECRET_FIELDS:
            self.assertNotIn(field, r.data)
            self.assertTrue(r.data[f"{field}_set"])
        self.assertNotIn("stored-", json.dumps(r.data))

    def test_empty_secret_keeps_stored_value(self):
        data = {field: "" for field in CORE_SETTINGS_SECRET_FIELDS}
        data["smtp_host_password"] = "new-password"
        r = self.client.put("/core/settings/", data, format="json")
        self.assertEqual(r.status_code, 200)

        core = CoreSettings.objects.first()
        self.assertEqual(core.smtp_host_password, "new-password")
        self.assertEqual(core.mesh_token, "stored-mesh_token")

    def test_audit_entry_has_no_plaintext_secret(self):
        from core.serializers import CoreSerializer

        audit = json.dumps(CoreSerializer(CoreSettings.objects.first()).data)
        self.assertNotIn("stored-", audit)
        self.assertIn("hmac:", audit)

    def test_clear_flag_removes_only_its_own_secret(self):
        # cleared to the empty value the column allows
        empty = {
            "smtp_host_password": "",
            "twilio_auth_token": None,
            "mesh_token": None,
            "ai_api_key": None,
        }
        self.assertEqual(sorted(empty), sorted(CORE_SETTINGS_SECRET_FIELDS))

        cleared = []
        for field in CORE_SETTINGS_SECRET_FIELDS:
            r = self.client.put(
                "/core/settings/", {f"{field}_clear": True}, format="json"
            )
            self.assertEqual(r.status_code, 200)
            cleared.append(field)

            core = CoreSettings.objects.first()
            for other in CORE_SETTINGS_SECRET_FIELDS:
                self.assertEqual(
                    getattr(core, other),
                    empty[other] if other in cleared else f"stored-{other}",
                )

        r = self.client.get("/core/settings/")
        for field in CORE_SETTINGS_SECRET_FIELDS:
            self.assertFalse(r.data[f"{field}_set"])

    def test_clear_flag_wins_over_a_value_in_the_same_body(self):
        r = self.client.put(
            "/core/settings/",
            {"smtp_host_password": "new-password", "smtp_host_password_clear": True},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(CoreSettings.objects.first().smtp_host_password, "")

    def test_clear_flags_are_write_only(self):
        r = self.client.get("/core/settings/")
        for field in CORE_SETTINGS_SECRET_FIELDS:
            self.assertNotIn(f"{field}_clear", r.data)

    def test_audit_entry_of_a_clear_shows_the_change(self):
        AuditLog.objects.all().delete()
        r = self.client.put(
            "/core/settings/", {"mesh_token_clear": True}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        audit = AuditLog.objects.get(object_type=AuditObjType.CORE)
        self.assertTrue(audit.before_value["mesh_token"].startswith("hmac:"))
        self.assertIsNone(audit.after_value["mesh_token"])
        self.assertNotIn("stored-", json.dumps(audit.before_value))
        self.assertNotIn("_clear", json.dumps(audit.after_value))


class TestPrivilegeEscalation(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.admin = self.create_user_with_roles(
            [
                "can_list_accounts",
                "can_manage_accounts",
                "can_list_roles",
                "can_manage_roles",
                "can_list_api_keys",
                "can_manage_api_keys",
            ]
        )
        self.admin.totp_key = pyotp.random_base32()
        self.admin.save(update_fields=["totp_key"])
        self.client.force_authenticate(user=self.admin)
        self.super_role = baker.make("accounts.Role", is_superuser=True)
        self.superuser = baker.make("accounts.User", role=self.super_role)
        self.plain_user = baker.make("accounts.User")

    def code(self):
        return pyotp.TOTP(self.admin.totp_key).now()

    def test_roles(self):
        r = self.client.post(
            "/accounts/roles/", {"name": "sneaky", "is_superuser": True}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.put(
            f"/accounts/roles/{self.admin.role.pk}/",
            {"name": "mine", "can_manage_clients": True},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.put(
            f"/accounts/roles/{self.super_role.pk}/", {"name": "x"}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        other = baker.make("accounts.Role", name="other")
        r = self.client.put(
            f"/accounts/roles/{other.pk}/",
            {"name": "other", "is_superuser": True},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        # only flags the admin's own role holds can be granted
        r = self.client.put(
            f"/accounts/roles/{other.pk}/",
            {"name": "other2", "can_list_agents": True, "totp_code": self.code()},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("can_list_agents", r.data["detail"])
        self.assertFalse(Role.objects.get(pk=other.pk).can_list_agents)

        r = self.client.put(
            f"/accounts/roles/{other.pk}/",
            {"name": "other2", "can_list_accounts": True, "totp_code": self.code()},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Role.objects.get(pk=other.pk).is_superuser)

    def test_users(self):
        r = self.client.put(
            f"/accounts/{self.superuser.pk}/users/",
            {"email": "x@example.com"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.put(
            f"/accounts/{self.plain_user.pk}/users/",
            {"role": self.super_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        new_role = baker.make("accounts.Role")
        r = self.client.put(
            f"/accounts/{self.admin.pk}/users/",
            {"role": new_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.post(
            "/accounts/users/reset/",
            {"id": self.superuser.pk, "password": "takeover123"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.put(
            "/accounts/users/reset_totp/", {"id": self.superuser.pk}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.post(
            "/accounts/users/reset/",
            {
                "id": self.plain_user.pk,
                "password": "fine12345",
                "totp_code": self.code(),
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)

    def test_api_keys(self):
        r = self.client.post(
            "/accounts/apikeys/",
            {"name": "steal", "user": self.superuser.pk, "expiration": None},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.post(
            "/accounts/apikeys/",
            {"name": "mine", "user": self.admin.pk, "expiration": None},
            format="json",
        )
        self.assertEqual(r.status_code, 200)

        other_key = APIKey.objects.create(
            name="other", key="OTHERKEY", user=self.plain_user
        )
        r = self.client.get("/accounts/apikeys/")
        self.assertEqual({k["name"] for k in r.data}, {"mine", "other"})
        self.assertNotIn("OTHERKEY", json.dumps(r.data))

        r = self.client.put(
            f"/accounts/apikeys/{other_key.pk}/", {"name": "renamed"}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.delete(f"/accounts/apikeys/{other_key.pk}/")
        self.assertEqual(r.status_code, 403)
        self.assertTrue(APIKey.objects.filter(pk=other_key.pk).exists())

        mine = APIKey.objects.get(name="mine")
        r = self.client.delete(f"/accounts/apikeys/{mine.pk}/")
        self.assertEqual(r.status_code, 200)


class TestScopedAccess(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.setup_base_instance()

    def test_audit_log_hides_other_agentless_entries(self):
        user = self.create_user_with_roles(["can_view_auditlogs"])
        user.role.can_view_sites.set([self.site1])
        baker.make("logs.AuditLog", username="someone-else", agent_id=None, _quantity=3)
        baker.make("logs.AuditLog", username=user.username, agent_id=None, _quantity=2)
        self.client.force_authenticate(user=user)

        page = dict(page=1, rowsPerPage=100, sortBy="entry_time", descending=True)
        r = self.client.patch("/logs/audit/", {"pagination": page}, format="json")
        self.assertEqual(r.status_code, 200)
        names = {log["username"] for log in r.data["audit_logs"]}
        self.assertEqual(names, {user.username})

    def test_agent_cannot_move_into_foreign_site(self):
        agent = baker.make_recipe("agents.agent", site=self.site1)
        user = self.create_user_with_roles(["can_edit_agent", "can_list_agents"])
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)

        r = self.client.put(
            f"/agents/{agent.agent_id}/", {"site": self.site3.pk}, format="json"
        )
        self.assertEqual(r.status_code, 403)

    def test_bulk_recovery_needs_superuser(self):
        user = self.create_user_with_roles(["can_recover_agents"])
        self.client.force_authenticate(user=user)
        with patch("agents.views.bulk_recover_agents_task.delay") as delay:
            r = self.client.get("/agents/bulkrecovery/")
            self.assertEqual(r.status_code, 403)
            delay.assert_not_called()


class TestPatchPolicyScope(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.setup_base_instance()
        self.own = baker.make_recipe("agents.agent", site=self.site1)
        self.own_policy = baker.make("winupdate.WinUpdatePolicy", agent=self.own)
        self.foreign = baker.make_recipe("agents.agent", site=self.site3)
        self.foreign_policy = baker.make(
            "winupdate.WinUpdatePolicy", agent=self.foreign
        )

    def scoped_user(self, *perms):
        user = self.create_user_with_roles(list(perms))
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        return user

    def test_agent_edit_cannot_move_the_policy_row(self):
        self.scoped_user("can_edit_agent", "can_manage_patch_policies")

        r = self.client.put(
            f"/agents/{self.own.agent_id}/",
            {
                "winupdatepolicy": [
                    {
                        "agent": self.foreign.pk,
                        "policy": baker.make("automation.Policy").pk,
                        "reboot_after_install": "always",
                    }
                ]
            },
            format="json",
        )

        self.assertEqual(r.status_code, 200)
        self.own_policy.refresh_from_db()
        self.foreign_policy.refresh_from_db()
        self.assertEqual(self.own_policy.agent, self.own)
        self.assertIsNone(self.own_policy.policy)
        self.assertEqual(self.own_policy.reboot_after_install, "always")
        self.assertEqual(self.foreign_policy.reboot_after_install, "inherit")
        self.assertEqual(self.foreign.winupdatepolicy.count(), 1)

    def test_automation_endpoint_refuses_agent_rows(self):
        self.scoped_user("can_manage_automation_policies", "can_manage_patch_policies")
        url = f"/automation/patchpolicy/{self.foreign_policy.pk}/"

        r = self.client.put(
            url, {"run_time_hour": 5, "reboot_after_install": "always"}, format="json"
        )
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.client.delete(url).status_code, 404)

        self.foreign_policy.refresh_from_db()
        self.assertEqual(self.foreign_policy.run_time_hour, 3)
        self.assertEqual(self.foreign_policy.reboot_after_install, "inherit")

        # policy-level rows stay editable
        policy = baker.make("automation.Policy")
        row = baker.make("winupdate.WinUpdatePolicy", policy=policy)
        r = self.client.put(
            f"/automation/patchpolicy/{row.pk}/",
            {"run_time_hour": 5, "agent": self.foreign.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        row.refresh_from_db()
        self.assertEqual((row.run_time_hour, row.agent, row.policy), (5, None, policy))

        # one patch row per policy
        r = self.client.post(
            "/automation/patchpolicy/",
            {"policy": policy.pk, "critical": "approve"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(policy.winupdatepolicy.count(), 1)

        other = baker.make("automation.Policy")
        r = self.client.post(
            "/automation/patchpolicy/",
            {"policy": other.pk, "agent": self.foreign.pk, "critical": "approve"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        new = WinUpdatePolicy.objects.get(critical="approve")
        self.assertEqual((new.policy, new.agent), (other, None))

        self.assertEqual(
            self.client.delete(f"/automation/patchpolicy/{row.pk}/").status_code, 200
        )

    def test_patch_policy_changes_need_the_flag(self):
        user = self.scoped_user("can_edit_agent", "can_manage_automation_policies")
        policy = baker.make("automation.Policy")
        row = baker.make("winupdate.WinUpdatePolicy", policy=policy)

        for method, url, data in (
            ("post", "/automation/patchpolicy/", {"policy": policy.pk}),
            ("put", f"/automation/patchpolicy/{row.pk}/", {"run_time_hour": 5}),
            ("delete", f"/automation/patchpolicy/{row.pk}/", {}),
            ("post", "/automation/patchpolicy/reset/", {"site": self.site1.pk}),
        ):
            r = getattr(self.client, method)(url, data, format="json")
            self.assertEqual(r.status_code, 403, (method, url))

        # the edit form sends the unchanged policy back with every save
        url = f"/agents/{self.own.agent_id}/"
        unchanged = WinUpdatePolicySerializer(self.own_policy).data
        r = self.client.put(
            url, {"description": "a", "winupdatepolicy": [unchanged]}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        changed = {**unchanged, "reboot_after_install": "always"}
        r = self.client.put(
            url, {"description": "b", "winupdatepolicy": [changed]}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.own.refresh_from_db()
        self.own_policy.refresh_from_db()
        self.assertEqual(self.own.description, "a")
        self.assertEqual(self.own_policy.reboot_after_install, "inherit")

        user.role.can_manage_patch_policies = True
        user.role.save()
        r = self.client.put(url, {"winupdatepolicy": [changed]}, format="json")
        self.assertEqual(r.status_code, 200)
        self.own_policy.refresh_from_db()
        self.assertEqual(self.own_policy.reboot_after_install, "always")

    def patch_policy(self):
        policy = baker.make("automation.Policy", active=True)
        baker.make(
            "winupdate.WinUpdatePolicy",
            policy=policy,
            critical="approve",
            reboot_after_install="always",
        )
        return policy

    def test_agent_policy_choice_needs_the_flag(self):
        user = self.scoped_user("can_edit_agent")
        user.role.can_view_sites.add(self.site2)
        agent = baker.make_recipe("agents.workstation_agent", site=self.site1)
        url = f"/agents/{agent.agent_id}/"
        auto = self.patch_policy()
        plain = baker.make("automation.Policy", active=True)

        # no patch settings in it, so the patch policy stays the same
        r = self.client.put(url, {"policy": plain.pk}, format="json")
        self.assertEqual(r.status_code, 200)

        r = self.client.put(url, {"policy": auto.pk}, format="json")
        self.assertEqual(r.status_code, 403)
        agent.refresh_from_db()
        self.assertEqual(agent.policy, plain)

        self.site1.workstation_policy = auto
        self.site1.save()
        for data in (
            {"block_policy_inheritance": True},
            {"monitoring_type": "server"},
            {"site": self.site2.pk},
        ):
            r = self.client.put(url, data, format="json")
            self.assertEqual(r.status_code, 403, data)
        agent.refresh_from_db()
        self.assertEqual(
            (agent.block_policy_inheritance, agent.monitoring_type, agent.site),
            (False, "workstation", self.site1),
        )

        # what the edit form sends on every save
        data = {"site": self.site1.pk, "monitoring_type": "workstation"}
        r = self.client.put(url, {**data, "description": "x"}, format="json")
        self.assertEqual(r.status_code, 200)

        user.role.can_manage_patch_policies = True
        user.role.save()
        r = self.client.put(url, {"block_policy_inheritance": True}, format="json")
        self.assertEqual(r.status_code, 200)
        agent.refresh_from_db()
        self.assertTrue(agent.block_policy_inheritance)

    def test_site_policy_choice_needs_the_flag(self):
        user = self.scoped_user("can_manage_sites")
        user.role.can_view_sites.add(self.site2)
        user.totp_key = pyotp.random_base32()
        user.save(update_fields=["totp_key"])
        agent = baker.make_recipe("agents.workstation_agent", site=self.site1)
        auto = self.patch_policy()
        url = f"/clients/sites/{self.site1.pk}/"

        r = self.client.put(
            url, {"site": {"workstation_policy": auto.pk}}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.site1.refresh_from_db()
        self.assertIsNone(self.site1.workstation_policy)

        r = self.client.put(url, {"site": {"name": "renamed"}}, format="json")
        self.assertEqual(r.status_code, 200)

        user.role.can_manage_patch_policies = True
        user.role.save()
        r = self.client.put(
            url, {"site": {"workstation_policy": auto.pk}}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        # deleting the site moves its agents away from that policy
        user.role.can_manage_patch_policies = False
        user.role.save()
        r = self.client.delete(
            f"{url}?move_to_site={self.site2.pk}",
            {"totp_code": pyotp.TOTP(user.totp_key).now()},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        agent.refresh_from_db()
        self.assertEqual(agent.site, self.site1)

    def test_policies_with_patch_settings_need_the_flag(self):
        user = self.scoped_user("can_manage_automation_policies")
        auto = self.patch_policy()
        plain = baker.make("automation.Policy", active=True)
        url = f"/automation/policies/{auto.pk}/"

        r = self.client.put(url, {"active": False}, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.delete(url).status_code, 403)
        auto.refresh_from_db()
        self.assertTrue(auto.active)

        r = self.client.put(
            f"/automation/policies/{plain.pk}/", {"active": False}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        user.role.can_manage_patch_policies = True
        user.role.save()
        r = self.client.put(url, {"active": False}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.delete(url).status_code, 200)

    @patch("agents.models.Agent.nats_cmd", return_value="ok")
    def test_install_and_approve_need_their_flags(self, nats_cmd):
        user = self.scoped_user("can_manage_winupdates")
        update = baker.make("winupdate.WinUpdate", agent=self.own, action="nothing")
        install = f"/winupdate/{self.own.agent_id}/install/"
        edit = f"/winupdate/{update.pk}/"

        self.assertEqual(self.client.post(install).status_code, 403)
        r = self.client.put(edit, {"action": "approve"}, format="json")
        self.assertEqual(r.status_code, 403)
        nats_cmd.assert_not_called()

        user.role.can_install_patches_now = True
        user.role.can_approve_patches = True
        user.role.save()

        # nothing approved, so nothing is sent
        self.assertEqual(self.client.post(install).status_code, 400)
        nats_cmd.assert_not_called()
        baker.make("winupdate.WinUpdate", agent=self.own, action="approve")
        self.assertEqual(self.client.post(install).status_code, 200)
        nats_cmd.assert_called_once()
        # the scope still applies
        foreign_update = baker.make("winupdate.WinUpdate", agent=self.foreign)
        r = self.client.put(
            f"/winupdate/{foreign_update.pk}/", {"action": "approve"}, format="json"
        )
        self.assertEqual(r.status_code, 403)

        # only the action changes, the row cannot move to another agent
        r = self.client.put(
            edit,
            {"action": "approve", "agent": self.foreign.pk, "installed": True},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        update.refresh_from_db()
        self.assertEqual(
            (update.action, update.agent, update.installed),
            ("approve", self.own, False),
        )

    @patch("agents.views.bulk_check_for_updates_task.delay")
    @patch("agents.views.bulk_install_updates_task.delay")
    def test_bulk_patch_install_needs_the_flag(self, install, scan):
        self.own.last_seen = djangotime.now()
        self.own.save(update_fields=["last_seen"])
        user = self.scoped_user("can_run_bulk")
        data = {
            "mode": "patch",
            "patchMode": "install",
            "target": "all",
            "monType": "all",
            "osType": "all",
        }

        r = self.client.post("/agents/actions/bulk/", data, format="json")
        self.assertEqual(r.status_code, 403)
        install.assert_not_called()

        r = self.client.post(
            "/agents/actions/bulk/", {**data, "patchMode": "scan"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        scan.assert_called_once_with([self.own.pk])

        user.role.can_install_patches_now = True
        user.role.save()
        r = self.client.post("/agents/actions/bulk/", data, format="json")
        self.assertEqual(r.status_code, 200)
        install.assert_called_once_with([self.own.pk])


class TestAgentResultOwnership(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()

    def test_foreign_check_and_task_results_refused(self):
        agent = baker.make_recipe("agents.agent")
        other = baker.make_recipe("agents.agent")
        foreign_check = baker.make_recipe("checks.ping_check", agent=other)
        foreign_task = baker.make("autotasks.AutomatedTask", agent=other)
        self.authenticate_agent(agent)

        r = self.client.patch(
            "/api/v3/checkrunner/",
            {"id": foreign_check.pk, "agent_id": agent.agent_id, "status": "failing"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(foreign_check.checkresults.filter(agent=agent).exists())

        r = self.client.patch(
            f"/api/v3/{foreign_task.pk}/{agent.agent_id}/taskrunner/",
            {"stdout": "x", "stderr": "", "retcode": 0, "execution_time": "1"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)


class TestURLActions(ULRMMTestCase):
    def test_internal_targets(self):
        from core.utils import _is_internal_url

        for url in (
            "http://127.0.0.1:8222/varz",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http:///nohost",
        ):
            self.assertTrue(_is_internal_url(url), url)

        self.assertFalse(_is_internal_url("http://192.168.178.10/hook"))

    def test_keystore_values_need_permission(self):
        self.setup_coresettings()
        self.setup_client()
        user = self.create_user_with_roles(["can_run_urlactions"])
        self.client.force_authenticate(user=user)
        data = {
            "pattern": "https://example.com/?x={{ global.secret }}",
            "rest_body": "{}",
            "rest_headers": "{}",
            "rest_method": "get",
            "run_instance_type": "none",
            "run_instance_id": None,
        }
        with patch("core.views.run_test_url_rest_action") as run:
            r = self.client.post("/core/urlaction/run/test/", data, format="json")
            self.assertEqual(r.status_code, 403)
            run.assert_not_called()


class TestClientIP(ULRMMTestCase):
    def test_forwarded_for_ignored_by_default(self):
        meta = {"REMOTE_ADDR": "203.0.113.7", "HTTP_X_FORWARDED_FOR": "10.9.9.9"}
        self.assertEqual(get_client_ip(meta), "203.0.113.7")

        with override_settings(ULRMM_TRUST_X_FORWARDED_FOR=True):
            self.assertEqual(get_client_ip(meta), "10.9.9.9")


class TestSSOHardening(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_email_login_does_not_take_over_accounts(self):
        self.assertFalse(settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION)
        self.assertFalse(settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT)

    def test_provider_secret_is_write_only(self):
        from allauth.socialaccount.models import SocialApp

        app = SocialApp.objects.create(
            provider="openid_connect",
            provider_id="idp",
            name="idp",
            client_id="cid",
            secret="very-secret",
            settings={"server_url": "https://idp.example.com", "role": None},
        )
        r = self.client.get("/accounts/ssoproviders/")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("very-secret", json.dumps(r.data))
        self.assertTrue(r.data[0]["secret_set"])

        r = self.client.put(
            f"/accounts/ssoproviders/{app.pk}/",
            {
                "client_id": "cid2",
                "secret": "",
                "server_url": "https://idp.example.com",
                "role": None,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual(app.secret, "very-secret")
        self.assertEqual(app.client_id, "cid2")

    def test_provider_secret_can_be_cleared(self):
        from allauth.socialaccount.models import SocialApp

        app = SocialApp.objects.create(
            provider="openid_connect",
            provider_id="idp",
            name="idp",
            client_id="cid",
            secret="very-secret",
            settings={"server_url": "https://idp.example.com", "role": None},
        )
        r = self.client.put(
            f"/accounts/ssoproviders/{app.pk}/",
            {
                "client_id": "cid",
                "secret": "ignored",
                "secret_clear": True,
                "server_url": "https://idp.example.com",
                "role": None,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app.refresh_from_db()
        self.assertEqual(app.secret, "")

        r = self.client.get("/accounts/ssoproviders/")
        self.assertFalse(r.data[0]["secret_set"])
        self.assertNotIn("secret_clear", r.data[0])

    def test_sso_can_be_enabled_without_sponsorship(self):
        r = self.client.post(
            "/accounts/ssoproviders/settings/",
            {"sso_enabled": True, "block_local_user_logon": False},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(CoreSettings.objects.first().sso_enabled)

    def test_superuser_role_needs_a_superuser(self):
        from allauth.socialaccount.models import SocialApp

        admin = self.create_user_with_roles(
            ["can_list_accounts", "can_manage_accounts"]
        )
        self.client.force_authenticate(user=admin)
        super_role = baker.make("accounts.Role", is_superuser=True)
        plain_role = baker.make("accounts.Role")
        body = {
            "name": "own idp",
            "client_id": "cid",
            "secret": "s",
            "server_url": "https://idp.example.com",
        }

        r = self.client.post(
            "/accounts/ssoproviders/",
            {**body, "role": super_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        self.assertFalse(SocialApp.objects.exists())

        r = self.client.post(
            "/accounts/ssoproviders/",
            {**body, "role": plain_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        app = SocialApp.objects.get()

        r = self.client.put(
            f"/accounts/ssoproviders/{app.pk}/",
            {**body, "role": super_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        # provider already has a superuser role
        app.settings = {"server_url": "https://idp.example.com", "role": super_role.pk}
        app.save()
        r = self.client.put(
            f"/accounts/ssoproviders/{app.pk}/",
            {**body, "server_url": "https://evil.example.com", "role": plain_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        r = self.client.delete(f"/accounts/ssoproviders/{app.pk}/")
        self.assertEqual(r.status_code, 403)
        app.refresh_from_db()
        self.assertEqual(app.settings["server_url"], "https://idp.example.com")

        self.client.force_authenticate(user=self.john)
        r = self.client.put(
            f"/accounts/ssoproviders/{app.pk}/",
            {**body, "role": super_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 200)

    def test_provider_with_linked_superuser_needs_a_superuser(self):
        from allauth.socialaccount.models import SocialAccount, SocialApp

        admin = self.create_user_with_roles(
            ["can_list_accounts", "can_manage_accounts"]
        )
        plain_role = baker.make("accounts.Role")
        body = {
            "name": "corp idp",
            "client_id": "cid",
            "secret": "s",
            "server_url": "https://evil.example.com",
            "role": plain_role.pk,
        }
        app = SocialApp.objects.create(
            provider="openid_connect",
            provider_id="corp-idp",
            name="corp idp",
            client_id="cid",
            settings={"server_url": "https://idp.example.com", "role": plain_role.pk},
        )
        # john already signs in through this provider
        SocialAccount.objects.create(user=self.john, provider="corp-idp", uid="sub-1")

        self.client.force_authenticate(user=admin)
        r = self.client.put(f"/accounts/ssoproviders/{app.pk}/", body, format="json")
        self.assertEqual(r.status_code, 403)
        r = self.client.delete(f"/accounts/ssoproviders/{app.pk}/")
        self.assertEqual(r.status_code, 403)
        app.refresh_from_db()
        self.assertEqual(app.settings["server_url"], "https://idp.example.com")

        # recreating the same name keeps the provider id and its links
        app.delete()
        r = self.client.post("/accounts/ssoproviders/", body, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertFalse(SocialApp.objects.exists())

        self.client.force_authenticate(user=self.john)
        r = self.client.post("/accounts/ssoproviders/", body, format="json")
        self.assertEqual(r.status_code, 200)

    def test_sso_settings_need_a_superuser(self):
        admin = self.create_user_with_roles(
            ["can_list_accounts", "can_manage_accounts"]
        )
        self.client.force_authenticate(user=admin)
        r = self.client.get("/accounts/ssoproviders/settings/")
        self.assertEqual(r.status_code, 200)

        r = self.client.post(
            "/accounts/ssoproviders/settings/",
            {"sso_enabled": True, "block_local_user_logon": True},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        core = CoreSettings.objects.first()
        self.assertFalse(core.sso_enabled or core.block_local_user_logon)


class TestBrowserHardening(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_cookies_and_headers(self):
        # session cookie has no Domain, so it stays on the api host
        self.assertIsNone(settings.SESSION_COOKIE_DOMAIN)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)

        r = self.client.get("/core/version/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["X-Frame-Options"], "DENY")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Strict-Transport-Security", r)

    def test_ai_drafts_need_script_rights(self):
        user = self.create_user_with_roles(["can_list_scripts"])
        self.client.force_authenticate(user=user)
        r = self.client.post("/core/ai/generate/", {"prompt": "x"}, format="json")
        self.assertEqual(r.status_code, 403)

        user = self.create_user_with_roles(["can_manage_scripts"])
        self.client.force_authenticate(user=user)
        r = self.client.post("/core/ai/generate/", {"prompt": "x"}, format="json")
        # permission ok, no OpenAI key set
        self.assertEqual(r.status_code, 400)


class TestBrandingAudit(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_branding_change_is_audited(self):
        with patch("ulrmm.middleware.get_debug_info", return_value={}):
            r = self.client.put(
                "/core/branding/edit/", {"product_name": "Audited"}, format="json"
            )
        self.assertEqual(r.status_code, 200)
        entry = AuditLog.objects.filter(object_type=AuditObjType.CORE).last()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.after_value["product_name"], "Audited")


class TestIssuesURL(ULRMMTestCase):
    def test_derived_from_git_remote_without_credentials(self):
        from ulrmm.helpers import get_issues_url

        with override_settings(
            ISSUES_URL="", ULRMM_GIT_URL="https://user:pw@git.example.com/o/r.git"
        ):
            self.assertEqual(get_issues_url(), "https://git.example.com/o/r/issues")

        with override_settings(ISSUES_URL="javascript:alert(1)", ULRMM_GIT_URL=""):
            self.assertEqual(get_issues_url(), "")

        with override_settings(ISSUES_URL="", ULRMM_GIT_URL=""):
            self.assertEqual(get_issues_url(), "")


class TestAgentSelfHeal(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe(
            "agents.agent", plat="linux", goarch="amd64", hostname="heal-host"
        )
        self.url = f"/api/v3/{self.agent.agent_id}/selfheal/"

    def test_current_build_with_checksum(self):
        import hashlib
        import tempfile
        from pathlib import Path

        from ulrmm.agent_ident import agent_artifact_for

        self.authenticate_agent(self.agent)
        with tempfile.TemporaryDirectory() as dist:
            with override_settings(AGENTS_DIST_DIR=dist):
                r = self.client.get(self.url)
                self.assertEqual(r.status_code, 404)

                # the build this agent runs
                name = agent_artifact_for(self.agent, settings.LATEST_AGENT_VER)
                Path(dist, name).write_bytes(b"agent build")
                r = self.client.get(self.url)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["version"], settings.LATEST_AGENT_VER)
        self.assertTrue(r.data["url"].endswith("/" + name))
        self.assertEqual(r.data["sha256"], hashlib.sha256(b"agent build").hexdigest())

    def test_windows_answer_names_the_agent_exe(self):
        import hashlib
        import tempfile
        from pathlib import Path

        from ulrmm.agent_ident import agent_artifact_for

        win = baker.make_recipe("agents.agent", plat="windows", goarch="amd64")
        self.authenticate_agent(win)
        url = f"/api/v3/{win.agent_id}/selfheal/"
        exe = hashlib.sha256(b"agent exe").hexdigest()
        with tempfile.TemporaryDirectory() as dist:
            with override_settings(AGENTS_DIST_DIR=dist):
                name = agent_artifact_for(win, settings.LATEST_AGENT_VER)
                Path(dist, name).write_bytes(b"setup")
                r = self.client.get(url)
                self.assertNotIn("agent_sha256", r.data)

                Path(dist, name + ".agent.sha256").write_text(exe + "\n")
                r = self.client.get(url)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["sha256"], hashlib.sha256(b"setup").hexdigest())
        self.assertEqual(r.data["agent_sha256"], exe)

    def test_unknown_agent_identity_refused(self):
        # self-heal falls back to its own verified copy when the server says no,
        # so refusing here is safer than handing over a foreign build
        self.agent.agent_ident = "someoneelses-agent"
        self.agent.save(update_fields=["agent_ident"])
        self.authenticate_agent(self.agent)

        r = self.client.get(self.url)

        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data,
            "heal-host reports agent identity 'someoneelses-agent', which this "
            "server does not build. Refusing to send it an agent artifact.",
        )

    def test_foreign_agent_and_anonymous_refused(self):
        other = baker.make_recipe("agents.agent", plat="linux", goarch="amd64")
        self.authenticate_agent(other)
        self.assertEqual(self.client.get(self.url).status_code, 404)
        self.assertEqual(
            self.client.post(self.url, {"actions": ["x"]}, format="json").status_code,
            404,
        )

        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 401)

    def test_repair_report_is_logged(self):
        from logs.models import DebugLog

        self.authenticate_agent(self.agent)
        r = self.client.post(self.url, {"actions": "restarted"}, format="json")
        self.assertEqual(r.status_code, 400)

        r = self.client.post(
            self.url, {"actions": ["service was not running: started"]}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        log = DebugLog.objects.get(agent=self.agent)
        self.assertIn("service was not running: started", log.message)
        self.assertEqual(log.log_level, "warning")

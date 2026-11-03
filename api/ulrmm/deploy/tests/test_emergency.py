# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import drop_console_stepup, grant_console_stepup
from deploy import identity, pki, tokens
from deploy.models import AgentCredential, AgentIdentity, CommandKey
from deploy.tests.test_identity import AgentBase, Keys, store_identity
from logs.models import AuditLog
from ulrmm.constants import AuditObjType
from ulrmm.test import LOCMEM_CACHE
from ulrmm.utils import nats_config

PIN_A = "A" * 43 + "="
PIN_B = "B" * 43 + "="


@override_settings(CACHES=LOCMEM_CACHE)
class EmergencyBase(AgentBase):
    def setUp(self):
        super().setUp()
        self.setup_coresettings()
        self.ident = store_identity(self.agent, self.keys)
        self.url = f"/deploy/agents/{self.agent.agent_id}/"
        self.user = self.create_user_with_roles(
            [
                "can_list_agents",
                "can_edit_agent",
                "can_view_core_settings",
                "can_edit_core_settings",
            ]
        )
        self.login(stepup=True)

    def login(self, stepup):
        token, _ = AuthToken.objects.create(user=self.user)
        self.client.force_authenticate(user=self.user, token=token)
        if stepup:
            grant_console_stepup(self.user)
        else:
            drop_console_stepup(self.user)

    def state(self):
        return AgentIdentity.objects.get(agent=self.agent).state

    def nkey_rendered(self) -> bool:
        users = nats_config()["authorization"]["users"]
        return any(u.get("nkey") == self.keys.nkey for u in users)


class TestEmergency(EmergencyBase):
    def test_quarantine_release_reset_block_flow(self):
        cert = self.cert_for()
        self.assertTrue(self.nkey_rendered())
        with self.captureOnCommitCallbacks(execute=True):
            r = self.client.post(self.url + "quarantine/", {"reason": "lost laptop"})
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["identity"]["state"], "quarantined")
        self.assertEqual(r.data["identity"]["reason"], "lost laptop")
        self.reload.assert_called()
        self.forget.assert_called_with(self.agent.agent_id)
        self.assertFalse(self.nkey_rendered())
        cert.refresh_from_db()
        self.assertIsNotNone(cert.revoked_at)
        self.assertIsNotNone(AgentCredential.objects.get(agent=self.agent).revoked_at)
        self.assertEqual(self.event("quarantined").severity, "high")

        r = self.client.post(self.url + "release/")
        self.assertEqual(r.data["identity"]["state"], "active")
        self.assertIsNotNone(r.data["identity"]["release_until"])
        self.assertTrue(self.nkey_rendered())
        # the token stays revoked; the agent gets a new one by its identity
        self.assertIsNotNone(r.data["credential"]["revoked_at"])
        self.assertIsNotNone(self.event("released"))
        # release of an active identity: nothing to do
        self.assertEqual(self.client.post(self.url + "release/").status_code, 409)

        r = self.client.post(self.url + "reset-identity/")
        self.assertEqual(r.data["identity"]["state"], "quarantined")
        self.assertIsNotNone(r.data["identity"]["release_until"])
        # the agent registers new keys with its (revoked) token
        new = Keys()
        self.as_agent()
        r = self.client.post(
            f"/api/v3/{self.agent.agent_id}/identity/",
            new.body(self.agent.agent_id),
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(AgentIdentity.objects.get().kid, new.kid)

        self.login(stepup=True)
        r = self.client.post(self.url + "block/", {"reason": "stolen"})
        self.assertEqual(r.data["identity"]["state"], "blocked")
        self.assertEqual(self.client.post(self.url + "release/").status_code, 409)
        self.assertEqual(
            self.client.post(self.url + "reset-identity/").status_code, 409
        )

    def test_reset_and_block_record_events(self):
        from deploy.models import SecurityEvent

        def last():
            return SecurityEvent.objects.filter(agent=self.agent).latest("pk")

        self.client.post(self.url + "reset-identity/")
        event = last()
        self.assertEqual((event.kind, event.severity), ("rotation_forced", "high"))
        self.assertIn("reset", event.detail)
        self.client.post(self.url + "block/", {"reason": "stolen"})
        event = last()
        self.assertEqual((event.kind, event.severity), ("quarantined", "high"))
        self.assertEqual(event.detail, "blocked: stolen")

    def test_quarantine_without_identity_blocks(self):
        other, token = self.new_agent()
        r = self.client.post(f"/deploy/agents/{other.agent_id}/quarantine/")
        self.assertEqual(r.data["identity"]["state"], "blocked")
        users = nats_config()["authorization"]["users"]
        self.assertFalse(any(u.get("user") == other.agent_id for u in users))

    def test_emergency_needs_stepup(self):
        self.login(stepup=False)
        for action in ("quarantine", "release", "reset-identity", "block"):
            with self.subTest(action=action):
                r = self.client.post(self.url + action + "/")
                self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.assertEqual(self.state(), "active")

    def test_emergency_scope(self):
        self.user = self.create_user_with_roles(["can_list_agents"])
        self.login(stepup=True)
        self.assertEqual(self.client.post(self.url + "quarantine/").status_code, 403)
        self.assertEqual(self.client.get(self.url + "identity/").status_code, 200)
        self.assertEqual(self.state(), "active")

    def test_emergency_audited(self):
        self.client.post(self.url + "quarantine/", {"reason": "x"})
        self.client.post(self.url + "release/")
        messages = list(
            AuditLog.objects.filter(agent_id=self.agent.agent_id, action="modify")
            .order_by("pk")
            .values_list("message", flat=True)
        )
        self.assertEqual(len(messages), 2)
        self.assertIn("quarantined", messages[0])
        self.assertIn("released", messages[1])

    def test_identity_get(self):
        r = self.client.get(self.url + "identity/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["identity"]["kid"], self.keys.kid)
        self.assertNotIn("ed25519", r.data["identity"])
        self.assertEqual(r.data["credential"]["kind"], "legacy")
        self.assertEqual(r.data["sec2_mode"], "optional")


class TestRotate(EmergencyBase):
    url_rotate = "/deploy/security/rotate/"

    def test_rotate_scope_site_sets_pending(self):
        other, _ = self.new_agent()
        other_keys = Keys()
        store_identity(other, other_keys)
        r = self.client.post(
            self.url_rotate,
            {
                "scope": "site",
                "ids": [self.agent.site_id],
                "what": ["cert", "token", "session"],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["agents"], 1)
        self.assertEqual(r.data["counts"], {"cert": 1, "token": 1, "session": 1})
        self.assertEqual(
            AgentIdentity.objects.get(agent=self.agent).rotate_pending,
            ["cert", "token"],
        )
        self.assertEqual(AgentIdentity.objects.get(agent=other).rotate_pending, [])
        self.forget.assert_called_once_with(self.agent.agent_id)
        self.assertIsNotNone(self.event("rotation_forced"))

    def test_rotate_checkin_answer_and_done(self):
        self.client.post(
            self.url_rotate, {"scope": "all", "what": ["token"]}, format="json"
        )
        self.as_agent()
        with patch("asyncio.run"):
            r = self.client.post("/api/v3/checkin/", {}, format="json")
            self.assertEqual(r.data["rotate"], ["token"])
            self.assertIn("now_ms", r.data)
            identity.done_rotation(AgentIdentity.objects.get(), "token")
            r = self.client.post("/api/v3/checkin/", {}, format="json")
        self.assertEqual(r.data["rotate"], [])
        r = self.client.get(f"/api/v3/{self.agent.agent_id}/checkinterval/")
        self.assertEqual(r.data["rotate"], [])
        self.assertIn("check_interval", r.data)

    def test_checkin_without_identity_unchanged(self):
        other, token = self.new_agent()
        self.as_agent(token)
        with patch("asyncio.run"):
            r = self.client.post("/api/v3/checkin/", {}, format="json")
        self.assertEqual(r.data, "ok")
        r = self.client.get(f"/api/v3/{other.agent_id}/checkinterval/")
        self.assertNotIn("rotate", r.data)

    def test_rotate_validation_and_stepup(self):
        bad = [
            {"scope": "planet", "what": ["cert"]},
            {"scope": "all", "what": ["coffee"]},
            {"scope": "agent", "ids": [], "what": ["cert"]},
            {"scope": "site", "ids": ["x"], "what": ["cert"]},
        ]
        for body in bad:
            with self.subTest(body=body):
                r = self.client.post(self.url_rotate, body, format="json")
                self.assertEqual(r.status_code, 400)
        self.login(stepup=False)
        r = self.client.post(
            self.url_rotate, {"scope": "all", "what": ["cert"]}, format="json"
        )
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.assertEqual(AgentIdentity.objects.get().rotate_pending, [])

    def test_command_key_rotate_and_pins_promote_need_stepup(self):
        self.login(stepup=False)
        for path in ("command-key/rotate/", "pins/promote/"):
            with self.subTest(path=path):
                sec = pki.security_settings()
                sec.backup_pins = [PIN_B]
                sec.save()
                with patch("deploy.signing.spki_pins", return_value=[PIN_B]):
                    r = self.client.post(f"/deploy/security/{path}")
                self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.assertFalse(CommandKey.objects.filter(state="next").exists())
        self.assertEqual(pki.security_settings().backup_pins, [PIN_B])

        self.login(stepup=True)
        r = self.client.post("/deploy/security/command-key/rotate/")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["state"], "next")
        self.assertTrue(
            CommandKey.objects.filter(kid=r.data["kid"], state="next").exists()
        )
        self.assertIsNotNone(self.event("command_key_rotated"))

        with patch("deploy.signing.spki_pins", return_value=[PIN_A]):
            r = self.client.post("/deploy/security/pins/promote/")
        self.assertEqual(r.status_code, 400)
        with patch("deploy.signing.spki_pins", return_value=[PIN_B]):
            r = self.client.post("/deploy/security/pins/promote/")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(pki.security_settings().backup_pins, [])


class TestSec2Mode(EmergencyBase):
    url_sec = "/deploy/security/"

    def put(self, **data):
        return self.client.put(self.url_sec, data, format="json")

    def test_get_has_sec2_fields(self):
        r = self.client.get(self.url_sec)
        self.assertEqual(r.data["sec2_mode"], "optional")
        cov = r.data["sec2_coverage"]
        self.assertEqual(
            (cov["agents"], cov["with_identity"], cov["with_family"]), (1, 1, 0)
        )
        self.assertEqual(cov["missing"][0]["agent_id"], self.agent.agent_id)

    def test_required_needs_coverage_or_force(self):
        r = self.put(sec2_mode="required")
        self.assertEqual(r.status_code, 400)
        self.assertIn("sec2_coverage", r.data)
        self.assertEqual(pki.security_settings().sec2_mode, "optional")
        with patch("deploy.mtls_views._sec2_changed") as changed:
            r = self.put(sec2_mode="required", force=True)
        self.assertEqual(r.status_code, 200, r.data)
        changed.assert_called_once_with()
        self.assertEqual(pki.security_settings().sec2_mode, "required")

    def test_required_with_full_coverage(self):
        cred = AgentCredential.objects.get(agent=self.agent)
        tokens.issue_family(cred)
        cred.save()
        # agents not seen for a week do not count
        old = baker.make_recipe("agents.online_agent")
        old.__class__.objects.filter(pk=old.pk).update(
            last_seen=djangotime.now() - dt.timedelta(days=8)
        )
        with patch("deploy.mtls_views._sec2_changed"):
            self.assertEqual(self.put(sec2_mode="required").status_code, 200)

    def test_lowering_needs_stepup_and_reloads(self):
        self.login(stepup=False)
        r = self.put(sec2_mode="off")
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))
        self.login(stepup=True)
        with patch("deploy.envelope.forget") as forget:
            r = self.put(sec2_mode="off")
        self.assertEqual(r.status_code, 200)
        forget.assert_called_with(self.agent.agent_id)
        self.reload.assert_called()
        self.assertTrue(AuditLog.objects.filter(object_type=AuditObjType.CORE).exists())

    def test_pins_list_command_keys(self):
        with patch("deploy.signing.spki_pins", return_value=[PIN_A]):
            pins = self.client.get(self.url_sec).data["pins"]
        key = CommandKey.objects.get(state="current")
        self.assertEqual(pins["cmd"], [{"kid": key.kid, "state": "current"}])
        self.assertEqual(pins["sec2"], "optional")

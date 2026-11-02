# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import tempfile

from cryptography import x509
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from deploy import pki, policy, tokens
from deploy.models import (
    POLICY_FIELDS,
    AgentCredential,
    AgentIdentity,
    AgentSecuritySettings,
    PinSet,
    RotationPolicy,
    SecurityEvent,
)
from deploy.tests.test_mtls import csr_pem
from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

POLICIES = "/deploy/security/policies/"
MATRIX = "/deploy/security/matrix/"
SECURITY = "/deploy/security/"
GLOBAL = {
    "rekey_minutes": 60,
    "rekey_mb": 64,
    "cert_ttl_hours": 180 * 24,
    "renew_pct": 75,
    "offline_grace_days": 30,
    "auto_quarantine": True,
}


@override_settings(CACHES=LOCMEM_CACHE)
class PolicyBase(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_client()
        self.setup_base_instance()
        self.agent = baker.make_recipe("agents.online_agent", site=self.site1)
        self.other = baker.make_recipe("agents.online_agent", site=self.site3)

    def login(self, roles, stepup=False):
        user = self.create_user_with_roles(roles)
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)
        return user


class TestEffective(PolicyBase):
    def test_defaults_and_inheritance(self):
        got = policy.effective(self.agent)
        self.assertEqual(got, {**GLOBAL, "cert_ttl_hours": None})
        RotationPolicy.objects.create(client=self.company1, rekey_minutes=10)
        got = policy.effective(self.agent)
        self.assertEqual((got["rekey_minutes"], got["rekey_mb"]), (10, 64))
        RotationPolicy.objects.create(
            site=self.site1, rekey_minutes=20, auto_quarantine=False
        )
        got = policy.effective(self.agent.agent_id)
        self.assertEqual(got["rekey_minutes"], 20)
        self.assertFalse(got["auto_quarantine"])
        # another client sees only the global values
        self.assertEqual(policy.effective(self.other)["rekey_minutes"], 60)

    def test_cached_until_a_policy_changes(self):
        pki.security_settings().save()
        self.assertEqual(policy.effective(self.agent)["renew_pct"], 75)
        AgentSecuritySettings.objects.filter(pk=1).update(renew_pct=50)
        # a bare update leaves the cache alone, a save drops it
        self.assertEqual(policy.effective(self.agent)["renew_pct"], 75)
        pki.security_settings().save()
        self.assertEqual(policy.effective(self.agent)["renew_pct"], 50)
        row = RotationPolicy.objects.create(client=self.company1, renew_pct=40)
        self.assertEqual(policy.effective(self.agent)["renew_pct"], 40)
        row.delete()
        self.assertEqual(policy.effective(self.agent)["renew_pct"], 50)

    def test_scope_constraints(self):
        from django.db import IntegrityError, transaction

        with self.assertRaises(IntegrityError), transaction.atomic():
            RotationPolicy.objects.create(client=self.company1, site=self.site1)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RotationPolicy.objects.create()
        RotationPolicy.objects.create(site=self.site1)
        with self.assertRaises(IntegrityError), transaction.atomic():
            RotationPolicy.objects.create(site=self.site1)


class TestPolicyUse(PolicyBase):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        override = override_settings(AGENT_CA_DIR=tmp.name)
        override.enable()
        self.addCleanup(override.disable)
        pki.ensure_ca()

    def test_cert_lifetime_from_policy(self):
        issued = pki.issue(self.agent, csr_pem())
        cert = x509.load_pem_x509_certificate(issued["cert"].encode())
        days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        self.assertEqual(days, 180)
        self.assertEqual(issued["renew_pct"], 75)
        RotationPolicy.objects.create(site=self.site1, cert_ttl_hours=2, renew_pct=50)
        issued = pki.issue(self.agent, csr_pem())
        cert = x509.load_pem_x509_certificate(issued["cert"].encode())
        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertEqual(lifetime, dt.timedelta(hours=2) + pki.BACKDATE)
        self.assertEqual(issued["renew_pct"], 50)

    def test_grace_from_policy(self):
        now = djangotime.now()
        baker.make(
            "deploy.AgentCertificate",
            agent=self.agent,
            not_before=now - dt.timedelta(days=10),
            not_after=now - dt.timedelta(days=1),
        )
        self.assertEqual(tokens.grace(self.agent), dt.timedelta(days=30))
        self.assertTrue(tokens.recovery_due(self.agent, None, now))
        RotationPolicy.objects.create(client=self.company1, offline_grace_days=0)
        self.assertEqual(tokens.grace(self.agent), dt.timedelta(0))
        self.assertFalse(tokens.recovery_due(self.agent, None, now))


class TestPoliciesApi(PolicyBase):
    def put(self, **data):
        return self.client.put(POLICIES, data, format="json")

    def test_permissions(self):
        self.check_not_authenticated("get", POLICIES)
        self.login(["can_view_core_settings"])
        self.assertEqual(self.client.get(POLICIES).status_code, 200)
        r = self.put(scope="global", id=None, policy=GLOBAL)
        self.assertEqual(r.status_code, 403)
        self.login(["can_edit_core_settings"])
        r = self.put(scope="global", id=None, policy=GLOBAL)
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))

    def test_get_shape(self):
        self.login(["can_view_core_settings"])
        RotationPolicy.objects.create(site=self.site1, rekey_minutes=15)
        RotationPolicy.objects.create(client=self.company2, auto_quarantine=False)
        r = self.client.get(POLICIES)
        self.assertEqual(r.data["global"], GLOBAL)
        self.assertEqual(r.data["limits"]["rekey_minutes"], [5, 1440])
        self.assertEqual(
            set(r.data["limits"]), set(POLICY_FIELDS) - {"auto_quarantine"}
        )
        overrides = {(o["scope"], o["id"]): o for o in r.data["overrides"]}
        site = overrides[("site", self.site1.pk)]
        self.assertEqual(
            (
                site["name"],
                site["client_name"],
                site["rekey_minutes"],
                site["rekey_mb"],
            ),
            (self.site1.name, self.company1.name, 15, None),
        )
        client = overrides[("client", self.company2.pk)]
        self.assertEqual(
            (client["name"], client["client_name"], client["auto_quarantine"]),
            (self.company2.name, None, False),
        )

    def test_put_global(self):
        self.login(["can_edit_core_settings"], stepup=True)
        before = AuditLog.objects.count()
        r = self.put(scope="global", id=None, policy={**GLOBAL, "rekey_minutes": 4})
        self.assertEqual(r.status_code, 400)
        self.assertIn("rekey_minutes", r.data["policy"])
        r = self.put(scope="global", id=None, policy={"rekey_minutes": 30})
        self.assertEqual(r.status_code, 400)
        self.assertIn("rekey_mb", r.data["policy"])
        r = self.put(
            scope="global",
            id=None,
            policy={**GLOBAL, "rekey_minutes": 30, "cert_ttl_hours": 48},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["global"]["rekey_minutes"], 30)
        self.assertEqual(r.data["global"]["cert_ttl_hours"], 48)
        sec = AgentSecuritySettings.objects.get(pk=1)
        self.assertEqual((sec.rekey_minutes, sec.cert_days), (30, 180))
        self.assertEqual(policy.effective(self.agent)["cert_ttl_hours"], 48)
        self.assertEqual(AuditLog.objects.count(), before + 1)
        self.assertIn("global rotation policy", AuditLog.objects.latest("id").message)

    def test_global_lifetime_follows_days(self):
        self.login(["can_view_core_settings", "can_edit_core_settings"], stepup=True)
        # the GET reply sent back unchanged is accepted and stays on cert_days
        shown = self.client.get(POLICIES).data["global"]
        self.assertEqual(shown["cert_ttl_hours"], 180 * 24)
        r = self.put(scope="global", id=None, policy={**shown, "rekey_minutes": 30})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(AgentSecuritySettings.objects.get(pk=1).cert_ttl_hours)
        cleared = {**shown, "cert_ttl_hours": None}
        r = self.put(scope="global", id=None, policy=cleared)
        self.assertEqual(r.status_code, 200)
        self.put(scope="global", id=None, policy={**shown, "cert_ttl_hours": 48})
        r = self.client.get(SECURITY)
        self.assertEqual(r.data["cert_ttl_hours"], 48)
        # a new lifetime in days replaces the hours again
        r = self.client.put(SECURITY, {"cert_days": 60}, format="json")
        self.assertEqual((r.status_code, r.data["cert_ttl_hours"]), (200, None))
        self.assertIsNone(policy.effective(self.agent)["cert_ttl_hours"])
        shown = self.client.get(POLICIES).data["global"]
        self.assertEqual(shown["cert_ttl_hours"], 60 * 24)

    def test_put_overrides(self):
        self.login(["can_edit_core_settings"], stepup=True)
        r = self.put(scope="client", id=self.company1.pk, policy={"rekey_mb": 5000})
        self.assertEqual(r.status_code, 400)
        self.assertIn("rekey_mb", r.data["policy"])
        r = self.put(scope="client", id=self.company1.pk, policy={"rekey_mb": 8})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data["overrides"]), 1)
        self.assertEqual(r.data["overrides"][0]["rekey_mb"], 8)
        self.assertIsNone(r.data["overrides"][0]["rekey_minutes"])
        self.assertEqual(policy.effective(self.agent)["rekey_mb"], 8)
        # a second put replaces the override
        r = self.put(scope="client", id=self.company1.pk, policy={"renew_pct": 20})
        self.assertEqual(r.data["overrides"][0]["renew_pct"], 20)
        self.assertIsNone(r.data["overrides"][0]["rekey_mb"])
        r = self.put(scope="site", id=self.site1.pk, policy={"auto_quarantine": False})
        self.assertEqual(len(r.data["overrides"]), 2)
        self.assertFalse(policy.effective(self.agent)["auto_quarantine"])
        r = self.put(scope="site", id=self.site1.pk, policy=None)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data["overrides"]), 1)
        self.assertTrue(policy.effective(self.agent)["auto_quarantine"])
        self.assertEqual(self.put(scope="site", id=99999, policy=None).status_code, 404)
        self.assertEqual(self.put(scope="all", id=1, policy=None).status_code, 400)
        self.assertEqual(self.put(scope="site", id="1", policy=None).status_code, 400)


class TestMatrix(PolicyBase):
    def setUp(self):
        super().setUp()
        self.login(["can_view_core_settings"])
        self.now = djangotime.now()

    def cert(self, agent, before_days, after_days, revoked=None):
        return baker.make(
            "deploy.AgentCertificate",
            agent=agent,
            not_before=self.now - dt.timedelta(days=before_days),
            not_after=self.now + dt.timedelta(days=after_days),
            revoked_at=revoked,
        )

    def make(self, hostname):
        return baker.make_recipe(
            "agents.online_agent", site=self.site1, hostname=hostname
        )

    def test_statuses(self):
        self.agent.hostname = "valid"
        self.agent.save()
        self.cert(self.agent, 10, 100)
        self.other.hostname = "none"
        self.other.save()
        renewing = self.make("renewing")
        self.cert(renewing, 80, 20)
        expired = self.make("expired")
        self.cert(expired, 100, -40)
        graced = self.make("graced")
        self.cert(graced, 100, -5)
        revoked = self.make("revoked")
        self.cert(revoked, 10, 100, revoked=self.now - dt.timedelta(days=1))
        quarantined = self.make("quarantined")
        self.cert(quarantined, 10, 100)
        AgentIdentity.objects.create(
            agent=quarantined, state="quarantined", pin_seq=3, rotate_pending=["cert"]
        )
        blocked = self.make("blocked")
        AgentIdentity.objects.create(agent=blocked, state="blocked")
        cloned = self.make("cloned")
        self.cert(cloned, 10, 100)
        SecurityEvent.objects.create(
            kind="token_reuse",
            severity="critical",
            agent=cloned,
            agent_uid=cloned.agent_id,
            first_seen=self.now,
            last_seen=self.now,
        )
        cred_only = self.make("cred-only")
        AgentCredential.objects.create(
            agent=cred_only,
            kind="family",
            access_digest="a" * 64,
            prev_rotated_at=self.now,
        )
        PinSet.objects.create(seq=3)

        r = self.client.get(MATRIX)
        self.assertEqual(r.status_code, 200)
        by_host = {a["hostname"]: a for a in r.data["agents"]}
        self.assertEqual(
            {h: a["status"] for h, a in by_host.items()},
            {
                "valid": "valid",
                "none": "none",
                "renewing": "renewing",
                "expired": "expired",
                "graced": "offline_grace",
                "revoked": "revoked",
                "quarantined": "quarantined",
                "blocked": "blocked",
                "cloned": "clone_alert",
                "cred-only": "none",
            },
        )
        self.assertEqual(r.data["total"], 10)
        self.assertEqual(r.data["pin_seq"], 3)
        self.assertEqual(r.data["counts"]["valid"], 1)
        self.assertEqual(r.data["counts"]["none"], 2)
        self.assertEqual(sum(r.data["counts"].values()), 10)
        valid = by_host["valid"]
        self.assertEqual(valid["client"], self.company1.name)
        self.assertEqual(valid["site"], self.site1.name)
        self.assertEqual(len(valid["fingerprint"]), 64)
        self.assertAlmostEqual(valid["countdown_s"], 100 * 86400, delta=60)
        self.assertEqual((valid["pin_seq"], valid["pin_current"]), (0, False))
        self.assertIsNone(valid["identity_state"])
        self.assertEqual(valid["rotate_pending"], [])
        q = by_host["quarantined"]
        self.assertEqual((q["pin_seq"], q["pin_current"]), (3, True))
        self.assertEqual(q["identity_state"], "quarantined")
        self.assertEqual(q["rotate_pending"], ["cert"])
        self.assertIsNone(by_host["revoked"]["fingerprint"])
        self.assertLess(by_host["expired"]["countdown_s"], 0)
        self.assertIsNotNone(by_host["cred-only"]["rotated_at"])
        # the renewal window and the grace follow the agent's policy
        RotationPolicy.objects.create(
            client=self.company1, renew_pct=90, offline_grace_days=2
        )
        r = self.client.get(MATRIX)
        by_host = {a["hostname"]: a for a in r.data["agents"]}
        self.assertEqual(by_host["renewing"]["status"], "valid")
        self.assertEqual(by_host["graced"]["status"], "expired")

    def test_filters_and_paging(self):
        for name in ("alpha", "beta", "gamma"):
            self.cert(self.make(name), 10, 100)
        self.agent.hostname = "alpaca"
        self.agent.save()
        r = self.client.get(MATRIX, {"q": "alp"})
        self.assertEqual([a["hostname"] for a in r.data["agents"]], ["alpaca", "alpha"])
        self.assertEqual(r.data["total"], 2)
        self.assertEqual(r.data["counts"], {**r.data["counts"], "none": 1, "valid": 1})
        r = self.client.get(MATRIX, {"status": "valid", "limit": 2, "offset": 1})
        self.assertEqual([a["hostname"] for a in r.data["agents"]], ["beta", "gamma"])
        self.assertEqual(r.data["total"], 3)
        self.assertIsNone(r.data["pin_seq"])
        self.assertEqual(self.client.get(MATRIX, {"status": "x"}).status_code, 400)
        self.assertEqual(self.client.get(MATRIX, {"limit": 1001}).status_code, 400)
        self.check_not_authenticated("get", MATRIX)

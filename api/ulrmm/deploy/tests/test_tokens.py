# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import importlib
import json
from io import StringIO
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.apps import apps
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.test import override_settings
from django.utils import timezone as djangotime
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

from deploy import pki, signing, tokens
from deploy.models import (
    AgentCredential,
    AgentIdentity,
    IdentityState,
    SecurityEvent,
)
from deploy.tests.test_identity import AgentBase, b64, now_ms, store_identity
from deploy.tests.test_mtls import csr_pem
from remote.utils import decrypt_secret
from ulrmm.test import LOCMEM_CACHE

PEPPER_A = base64.b64encode(b"a" * 32).decode()
PEPPER_B = base64.b64encode(b"b" * 32).decode()


class TokenBase(AgentBase):
    def setUp(self):
        super().setUp()
        self.ident = store_identity(self.agent, self.keys)
        self.base = f"/api/v3/{self.agent.agent_id}"

    def nonce(self, kind="token"):
        r = self.client.get(f"{self.base}/{kind}/challenge/")
        self.assertEqual(r.status_code, 200)
        return r.data["nonce"]

    def grant_body(self, nonce=None, ts=None, key=None):
        nonce = nonce or self.nonce()
        ts = now_ms() if ts is None else ts
        message = tokens.grant_message(self.agent.agent_id, base64.b64decode(nonce), ts)
        return {
            "nonce": nonce,
            "ts": ts,
            "sig": b64((key or self.keys.ed).sign(message)),
        }

    def grant(self, **kw):
        self.as_agent()
        return self.client.post(
            f"{self.base}/token/grant/", self.grant_body(**kw), format="json"
        )

    def refresh_body(self, refresh, ts=None, key=None):
        ts = now_ms() if ts is None else ts
        message = tokens.refresh_message(self.agent.agent_id, refresh, ts)
        return {
            "refresh": refresh,
            "ts": ts,
            "sig": b64((key or self.keys.ed).sign(message)),
        }

    def refresh(self, refresh, **kw):
        self.client.credentials()
        return self.client.post(
            f"{self.base}/token/refresh/",
            self.refresh_body(refresh, **kw),
            format="json",
        )

    def family(self):
        r = self.grant()
        self.assertEqual(r.status_code, 200, r.data)
        return r.data


@override_settings(CACHES=LOCMEM_CACHE)
class TestAuth(TokenBase):
    def config(self, token=None):
        self.as_agent(token)
        return self.client.get(f"{self.base}/config/")

    def test_legacy_token_authenticates(self):
        self.assertEqual(self.config().status_code, 200)
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual(cred.access_digest, tokens.digest(self.token))
        self.assertNotIn(self.token, cred.access_digest + cred.legacy_nats)
        self.assertEqual(self.config("wrong").status_code, 401)

    def test_auth_digest_lookup_each_pepper(self):
        with override_settings(AGENT_TOKEN_PEPPERS=[PEPPER_A]):
            agent, token = self.new_agent()
            self.assertEqual(
                AgentCredential.objects.get(agent=agent).access_digest,
                tokens.digest(token, b"a" * 32),
            )
        self.base = f"/api/v3/{agent.agent_id}"
        # a new current pepper: digests of the old one still open
        with override_settings(AGENT_TOKEN_PEPPERS=[PEPPER_B, PEPPER_A]):
            self.assertEqual(self.config(token).status_code, 200)
        with override_settings(AGENT_TOKEN_PEPPERS=[PEPPER_B]):
            self.assertEqual(self.config(token).status_code, 401)
        # the SECRET_KEY derived pepper stays last on the list
        self.base = f"/api/v3/{self.agent.agent_id}"
        with override_settings(AGENT_TOKEN_PEPPERS=[PEPPER_B]):
            self.assertEqual(self.config().status_code, 200)

    def test_bad_pepper_config(self):
        for value in (["!!"], [base64.b64encode(b"x").decode()]):
            with override_settings(AGENT_TOKEN_PEPPERS=value), self.assertRaises(
                Exception
            ):
                tokens.peppers()

    def test_access_expired_401_refresh_hint(self):
        body = self.family()
        AgentCredential.objects.filter(agent=self.agent).update(
            access_expires=djangotime.now() - dt.timedelta(seconds=1)
        )
        r = self.config(body["access"])
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json(), {"detail": "token expired", "refresh": True})

    def test_revoked_401(self):
        AgentCredential.objects.filter(agent=self.agent).update(
            revoked_at=djangotime.now()
        )
        r = self.config()
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token revoked"))

    def test_quarantined_403(self):
        AgentIdentity.objects.filter(pk=self.ident.pk).update(
            state=IdentityState.QUARANTINED
        )
        r = self.config()
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json(), {"detail": "quarantined"})
        AgentIdentity.objects.filter(pk=self.ident.pk).update(
            release_until=djangotime.now() + dt.timedelta(hours=1)
        )
        r = self.config()
        self.assertEqual(r.json(), {"detail": "quarantined", "new_identity": True})

    def test_drf_token_only_without_credential(self):
        user = self.agent.user
        key = Token.objects.create(user=user).key
        self.assertEqual(self.config(key).status_code, 401)
        AgentCredential.objects.filter(agent=self.agent).delete()
        self.assertEqual(self.config(key).status_code, 200)

    def test_legacy_migration_copies_and_deletes_drf_tokens(self):
        migration = importlib.import_module("deploy.migrations.0007_legacy_credentials")
        other, _ = self.new_agent()
        AgentCredential.objects.filter(agent=other).delete()
        key = Token.objects.create(user=other.user).key
        dashboard = Token.objects.create(user=self.create_user_with_roles([]))
        migration.forwards(apps, None)
        cred = AgentCredential.objects.get(agent=other)
        self.assertEqual(
            (cred.kind, cred.access_digest), ("legacy", tokens.digest(key))
        )
        self.assertEqual(decrypt_secret(cred.legacy_nats, tokens.LEGACY_NATS_INFO), key)
        self.assertFalse(Token.objects.filter(user=other.user).exists())
        self.assertTrue(Token.objects.filter(pk=dashboard.pk).exists())
        self.base = f"/api/v3/{other.agent_id}"
        self.assertEqual(self.config(key).status_code, 200)
        migration.backwards(apps, None)
        self.assertEqual(Token.objects.get(user=other.user).key, key)


@override_settings(CACHES=LOCMEM_CACHE)
class TestGrant(TokenBase):
    def test_grant_requires_identity_sig_and_nonce(self):
        # a signature of another key
        r = self.grant(key=Ed25519PrivateKey.generate())
        self.assertEqual((r.status_code, r.data["detail"]), (400, "signature"))
        # a nonce the server never gave out
        r = self.grant(nonce=b64(b"n" * 32))
        self.assertEqual((r.status_code, r.data["detail"]), (400, "nonce invalid"))
        # a nonce is single use
        body = self.grant_body()
        url = f"{self.base}/token/grant/"
        self.assertEqual(self.client.post(url, body, format="json").status_code, 200)
        r = self.client.post(url, body, format="json")
        self.assertEqual((r.status_code, r.data["detail"]), (400, "nonce invalid"))
        r = self.grant(ts=now_ms() - 60_000)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "clock"))
        self.assertAlmostEqual(r.data["now_ms"], now_ms(), delta=5000)

    def test_grant_without_identity_403(self):
        AgentIdentity.objects.all().delete()
        r = self.grant()
        self.assertEqual(r.status_code, 403)

    def test_grant_without_token_needs_release_window(self):
        self.client.credentials()
        url = f"{self.base}/token/grant/"
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token required"))
        AgentIdentity.objects.filter(pk=self.ident.pk).update(
            release_until=djangotime.now() + dt.timedelta(hours=1)
        )
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual(r.status_code, 200)

    def test_grant_with_family_token_409(self):
        body = self.family()
        before = AgentCredential.objects.get(agent=self.agent)
        self.as_agent(body["access"])
        r = self.client.post(
            f"{self.base}/token/grant/", self.grant_body(), format="json"
        )
        self.assertEqual(
            (r.status_code, r.data["detail"]), (409, "token family exists")
        )
        self.assertEqual(self.event("token_reuse").severity, "high")
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual(
            (cred.refresh_digest, cred.generation, cred.family),
            (before.refresh_digest, 1, before.family),
        )
        # the history reuse detection relies on is kept
        self.assertEqual(self.refresh(body["refresh"]).status_code, 200)
        self.assertEqual(AgentIdentity.objects.get().state, "active")

    def test_grant_release_window_opens_one_grant(self):
        self.client.credentials()
        AgentIdentity.objects.filter(pk=self.ident.pk).update(
            release_until=djangotime.now() + dt.timedelta(hours=1)
        )
        url = f"{self.base}/token/grant/"
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(AgentIdentity.objects.get().release_until)
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token required"))

    def test_restore_release_window_command(self):
        # the restored database knows only an older generation of the family
        first = self.family()
        self.refresh(self.refresh(first["refresh"]).data["refresh"])
        self.assertEqual(
            AgentCredential.objects.get(agent=self.agent).refresh_history,
            [tokens.digest(first["refresh"])],
        )
        newer = "n" * 64
        r = self.refresh(newer)
        self.assertEqual((r.status_code, r.data["detail"]), (401, "unknown token"))
        url = f"{self.base}/token/grant/"
        self.as_agent("a" * 43)
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token required"))
        with self.assertRaises(CommandError):
            call_command("open_release_window")
        call_command("open_release_window", "--all-active", stdout=StringIO())
        self.assertGreater(AgentIdentity.objects.get().release_until, djangotime.now())
        self.assertEqual(self.event("released").severity, "warning")
        # the agent sends its newer access token, which the database does not know
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual(r.status_code, 200, r.data)
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual((cred.generation, cred.refresh_history), (1, []))
        self.assertIn(
            "release window",
            SecurityEvent.objects.filter(kind="released", agent=self.agent)
            .get()
            .detail,
        )
        r = self.client.post(url, self.grant_body(), format="json")
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token required"))

    def test_release_window_command_skips_quarantined(self):
        AgentIdentity.objects.filter(pk=self.ident.pk).update(
            state=IdentityState.QUARANTINED
        )
        out = StringIO()
        call_command("open_release_window", "--all-active", stdout=out)
        self.assertIn("for 0 identities", out.getvalue())
        self.assertIsNone(AgentIdentity.objects.get().release_until)

    def test_grant_clears_legacy_nats_and_reloads(self):
        with self.captureOnCommitCallbacks(execute=True):
            body = self.family()
        self.reload.assert_called_once_with()
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual(
            (cred.kind, cred.generation, cred.legacy_nats), ("family", 1, "")
        )
        self.assertEqual(cred.access_digest, tokens.digest(body["access"]))
        self.assertEqual(cred.refresh_digest, tokens.digest(body["refresh"]))
        self.assertIsNotNone(cred.family)
        # the legacy token is gone, the access token works
        self.as_agent()
        self.assertEqual(self.client.get(f"{self.base}/config/").status_code, 401)
        self.as_agent(body["access"])
        self.assertEqual(self.client.get(f"{self.base}/config/").status_code, 200)

    def test_grant_answers_when_the_nats_reload_fails(self):
        self.reload.side_effect = OSError("read-only file system")
        with self.assertLogs("ulrmm", "ERROR") as logs:
            with self.captureOnCommitCallbacks(execute=True):
                body = self.family()
        self.reload.assert_called_once_with()
        self.assertIn("after a token grant", logs.output[0])
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual((cred.kind, cred.legacy_nats), ("family", ""))
        self.assertEqual(cred.access_digest, tokens.digest(body["access"]))
        self.assertEqual(cred.refresh_digest, tokens.digest(body["refresh"]))


@override_settings(CACHES=LOCMEM_CACHE)
class TestRefresh(TokenBase):
    def test_refresh_rotates_generation(self):
        first = self.family()
        r = self.refresh(first["refresh"])
        self.assertEqual(r.status_code, 200, r.data)
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual(cred.generation, 2)
        self.assertEqual(cred.prev_refresh_digest, tokens.digest(first["refresh"]))
        self.assertNotEqual(r.data["refresh"], first["refresh"])
        r2 = self.refresh(r.data["refresh"])
        self.assertEqual(AgentCredential.objects.get(agent=self.agent).generation, 3)
        self.assertEqual(r2.status_code, 200)

    def test_refresh_needs_identity_signature(self):
        first = self.family()
        r = self.refresh(first["refresh"], key=Ed25519PrivateKey.generate())
        self.assertEqual(r.status_code, 401)
        self.assertEqual(AgentCredential.objects.get(agent=self.agent).generation, 1)

    def test_refresh_expired_and_unknown(self):
        first = self.family()
        self.assertEqual(self.refresh("x" * 40).status_code, 401)
        AgentCredential.objects.filter(agent=self.agent).update(
            refresh_expires=djangotime.now()
        )
        r = self.refresh(first["refresh"])
        self.assertEqual((r.status_code, r.data["detail"]), (401, "token expired"))

    def test_refresh_retry_within_60s_same_pair(self):
        first = self.family()
        second = self.refresh(first["refresh"]).data
        again = self.refresh(first["refresh"])
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.data["refresh"], second["refresh"])
        self.assertEqual(AgentCredential.objects.get(agent=self.agent).generation, 2)
        self.assertEqual(AgentIdentity.objects.get().state, "active")

    def test_refresh_retry_after_5_min_same_pair(self):
        # the agent retries a lost answer at its next heartbeat
        first = self.family()
        second = self.refresh(first["refresh"]).data
        AgentCredential.objects.filter(agent=self.agent).update(
            prev_rotated_at=djangotime.now() - dt.timedelta(minutes=5, seconds=30)
        )
        again = self.refresh(first["refresh"])
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.data["refresh"], second["refresh"])
        self.assertEqual(AgentIdentity.objects.get().state, "active")
        AgentCredential.objects.filter(agent=self.agent).update(
            prev_rotated_at=djangotime.now() - dt.timedelta(minutes=16)
        )
        with patch("deploy.identity.quarantine") as quarantine:
            r = self.refresh(first["refresh"])
        self.assertEqual(r.status_code, 403)
        quarantine.assert_called_once()

    def test_refresh_reuse_without_auto_quarantine(self):
        sec = pki.security_settings()
        sec.auto_quarantine = False
        sec.save()
        first = self.family()
        self.assertEqual(self.refresh(first["refresh"]).status_code, 200)
        AgentCredential.objects.filter(agent=self.agent).update(
            prev_rotated_at=djangotime.now() - dt.timedelta(minutes=16)
        )
        r = self.refresh(first["refresh"])
        self.assertEqual((r.status_code, r.data), (403, {"detail": "token reuse"}))
        self.assertEqual(AgentIdentity.objects.get().state, "active")
        self.assertTrue(
            SecurityEvent.objects.filter(
                kind="token_reuse", agent_uid=self.agent.agent_id
            ).exists()
        )
        self.assertFalse(SecurityEvent.objects.filter(kind="quarantined").exists())

    def use(self, access):
        self.as_agent(access)
        self.assertEqual(self.client.get(f"{self.base}/config/").status_code, 200)

    def test_first_use_of_access_token_recorded(self):
        first = self.family()
        self.assertIsNone(AgentCredential.objects.get(agent=self.agent).access_used_at)
        self.use(first["access"])
        used = AgentCredential.objects.get(agent=self.agent).access_used_at
        self.assertIsNotNone(used)
        self.use(first["access"])
        self.assertEqual(
            AgentCredential.objects.get(agent=self.agent).access_used_at, used
        )
        self.refresh(first["refresh"])
        self.assertIsNone(AgentCredential.objects.get(agent=self.agent).access_used_at)

    def test_refresh_retry_after_new_access_used_is_reuse(self):
        # two copies in lockstep: the second one asks after the first one
        # already works with the new pair
        first = self.family()
        second = self.refresh(first["refresh"]).data
        self.use(second["access"])
        with self.captureOnCommitCallbacks(execute=True):
            r = self.refresh(first["refresh"])
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        self.assertIn("generation 1 used again", self.event("token_reuse").detail)
        self.assertEqual(AgentIdentity.objects.get().state, "quarantined")

    def test_refresh_retry_carries_fresh_now_ms(self):
        first = self.family()
        second = self.refresh(first["refresh"]).data
        later = second["now_ms"] + 20_000
        with patch.object(tokens, "now_ms", return_value=later):
            again = self.refresh(first["refresh"], ts=later)
        self.assertEqual(again.status_code, 200, again.data)
        self.assertEqual(again.data["refresh"], second["refresh"])
        self.assertEqual(again.data["now_ms"], later)

    def test_refresh_reuse_checked_before_clock(self):
        first = self.family()
        second = self.refresh(first["refresh"]).data
        third = self.refresh(second["refresh"]).data
        skewed = now_ms() - 60_000
        # the current token and a retry still need the clock
        for token in (third["refresh"], second["refresh"]):
            r = self.refresh(token, ts=skewed)
            self.assertEqual((r.status_code, r.data["detail"]), (400, "clock"))
            self.assertAlmostEqual(r.data["now_ms"], now_ms(), delta=5000)
        self.assertEqual(AgentIdentity.objects.get().state, "active")
        # a token from the history is reuse whatever its clock says
        with self.captureOnCommitCallbacks(execute=True):
            r = self.refresh(first["refresh"], ts=skewed)
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        self.assertEqual(AgentIdentity.objects.get().state, "quarantined")

    def test_refresh_prev_after_window_reuse_with_bad_clock(self):
        first = self.family()
        self.refresh(first["refresh"])
        AgentCredential.objects.filter(agent=self.agent).update(
            prev_rotated_at=djangotime.now() - dt.timedelta(minutes=16)
        )
        with patch("deploy.identity.quarantine") as quarantine:
            r = self.refresh(first["refresh"], ts=now_ms() + 120_000)
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        quarantine.assert_called_once()

    def test_refresh_reuse_of_older_generations(self):
        # a clone that fell several generations behind counts as reuse
        tokens_of = {1: self.family()["refresh"]}
        for gen in range(2, 22):
            r = self.refresh(tokens_of[gen - 1])
            self.assertEqual(r.status_code, 200, r.data)
            tokens_of[gen] = r.data["refresh"]
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual((cred.generation, len(cred.refresh_history)), (21, 16))
        # generations 4 to 19 are kept, 20 is prev_refresh_digest
        r = self.refresh(tokens_of[3])
        self.assertEqual((r.status_code, r.data["detail"]), (401, "unknown token"))
        self.assertIsNone(self.event("token_reuse"))
        with self.captureOnCommitCallbacks(execute=True):
            r = self.refresh(tokens_of[4])
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        self.assertIn("generation 4 used again", self.event("token_reuse").detail)
        self.assertEqual(AgentIdentity.objects.get().state, "quarantined")

    def test_refresh_reuse_two_generations_back_no_retry(self):
        first = self.family()
        second = self.refresh(first["refresh"]).data
        self.refresh(second["refresh"])
        with patch("deploy.identity.quarantine") as quarantine:
            r = self.refresh(first["refresh"])
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        quarantine.assert_called_once()

    def test_refresh_reuse_quarantines_and_disconnects(self):
        first = self.family()
        self.refresh(first["refresh"])
        cert = self.cert_for()
        with patch.object(tokens, "RETRY_SECONDS", 0), self.captureOnCommitCallbacks(
            execute=True
        ):
            r = self.refresh(first["refresh"])
        self.assertEqual((r.status_code, r.data["detail"]), (403, "token reuse"))
        event = self.event("token_reuse")
        self.assertEqual(event.severity, "critical")
        self.assertIn("generation 1", event.detail)
        ident = AgentIdentity.objects.get()
        self.assertEqual(
            (ident.state, ident.reason), ("quarantined", "refresh token reused")
        )
        self.assertIsNotNone(AgentCredential.objects.get(agent=self.agent).revoked_at)
        cert.refresh_from_db()
        self.assertIsNotNone(cert.revoked_at)
        self.reload.assert_called()
        self.forget.assert_called_with(self.agent.agent_id)


@override_settings(CACHES=LOCMEM_CACHE)
class TestRecover(TokenBase):
    def recover_body(self, nonce=None, csr=None, key=None, agent_id=None, ts=None):
        nonce = nonce or self.nonce("recover")
        csr = csr or csr_pem()
        ts = now_ms() if ts is None else ts
        message = tokens.recover_message(
            agent_id or self.agent.agent_id, base64.b64decode(nonce), ts, csr
        )
        return {
            "nonce": nonce,
            "ts": ts,
            "csr": csr,
            "sig": b64((key or self.keys.ed).sign(message)),
        }

    def recover(self, **kw):
        self.client.credentials()
        return self.client.post(
            f"{self.base}/recover/", self.recover_body(**kw), format="json"
        )

    def expire_cert(self, days=5):
        cert = self.cert_for()
        cert.not_after = djangotime.now() - dt.timedelta(days=days)
        cert.save()
        return cert

    def test_recover_within_grace(self):
        self.expire_cert()
        r = self.recover()
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn("cert", r.data)
        self.assertIn("refresh", r.data)
        self.assertTrue(pki_active(self.agent))
        cred = AgentCredential.objects.get(agent=self.agent)
        self.assertEqual(cred.kind, "family")
        self.assertIsNotNone(self.event("grace_recovery"))
        self.as_agent(r.data["access"])
        self.assertEqual(self.client.get(f"{self.base}/config/").status_code, 200)

    def test_recover_tokens_expired_within_grace(self):
        self.family()
        past = djangotime.now() - dt.timedelta(days=1)
        AgentCredential.objects.filter(agent=self.agent).update(
            access_expires=past, refresh_expires=past
        )
        self.assertEqual(self.recover().status_code, 200)
        self.assertEqual(AgentCredential.objects.get(agent=self.agent).generation, 2)

    def test_recover_needs_expiry_and_grace(self):
        self.cert_for()
        self.assertEqual(self.recover().status_code, 403)
        AgentCredential.objects.all().delete()
        self.agent.certificates.all().delete()
        self.expire_cert(days=31)
        r = self.recover()
        self.assertEqual(
            (r.status_code, r.data["detail"]), (403, "recovery not allowed")
        )

    def test_recover_clock_answer_carries_now_ms(self):
        self.expire_cert()
        r = self.recover(ts=now_ms() + 60_000)
        self.assertEqual((r.status_code, r.data["detail"]), (400, "clock"))
        self.assertAlmostEqual(r.data["now_ms"], now_ms(), delta=5000)

    def test_recover_bad_signature(self):
        self.expire_cert()
        r = self.recover(key=Ed25519PrivateKey.generate())
        self.assertEqual((r.status_code, r.data["detail"]), (400, "signature"))

    def test_recover_after_revoke_403(self):
        cert = self.expire_cert()
        cert.revoked_at = cert.not_after - dt.timedelta(days=1)
        cert.save()
        self.assertEqual(self.recover().status_code, 403)

    def test_recover_after_quarantine_403(self):
        self.expire_cert()
        AgentIdentity.objects.update(state=IdentityState.QUARANTINED)
        r = self.recover()
        self.assertEqual(
            (r.status_code, r.data["detail"]), (403, "recovery not allowed")
        )

    def test_recover_unknown_id_same_shape(self):
        unknown = "x" * 30
        self.client.credentials()
        r = self.client.get(f"/api/v3/{unknown}/recover/challenge/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.data), {"nonce", "now_ms"})
        body = self.recover_body(nonce=r.data["nonce"], agent_id=unknown)
        r = self.client.post(f"/api/v3/{unknown}/recover/", body, format="json")
        self.assertEqual(
            (r.status_code, r.data["detail"]), (403, "recovery not allowed")
        )

    def test_recover_challenge_throttled(self):
        self.client.credentials()
        for _ in range(10):
            self.client.get(f"{self.base}/recover/challenge/")
        r = self.client.get(f"{self.base}/recover/challenge/")
        self.assertEqual(r.status_code, 429)


def pki_active(agent) -> bool:
    from deploy import pki

    return pki.active_certs().filter(agent=agent).exists()


@override_settings(CACHES=LOCMEM_CACHE)
class TestAgentEndpoints(TokenBase):
    def test_cert_sealed_on_request_and_rotation_done(self):
        AgentIdentity.objects.filter(pk=self.ident.pk).update(rotate_pending=["cert"])
        self.as_agent()
        url = f"{self.base}/cert/"
        with patch("deploy.envelope.seal_response", return_value=Response("x")) as seal:
            r = self.client.post(url, {"csr": csr_pem()}, format="json")
            self.assertEqual(r.status_code, 200)
            self.assertIn("cert", r.data)
            seal.assert_not_called()
            r = self.client.post(
                url, {"csr": csr_pem()}, format="json", HTTP_X_ULRMM_SEAL="1"
            )
        self.assertEqual(r.data, "x")
        agent, _, data = seal.call_args.args
        self.assertEqual(agent.agent_id, self.agent.agent_id)
        self.assertIn("cert", data)
        self.assertEqual(AgentIdentity.objects.get().rotate_pending, [])

    def test_selfheal_sealed_on_request(self):
        self.as_agent()
        url = f"{self.base}/selfheal/"
        with patch("agents.utils.get_agent_url", return_value="https://x/a"), patch(
            "agents.utils.get_agent_artifact_sha256", return_value="ab" * 32
        ), patch("deploy.envelope.seal_response", return_value=Response("x")) as seal:
            data = self.client.get(url).data
            self.assertEqual(data["sha256"], "ab" * 32)
            self.assertEqual(self.client.get(url, HTTP_X_ULRMM_SEAL="1").data, "x")
        self.assertEqual(seal.call_args.args[2]["url"], "https://x/a")
        self.assertEqual(seal.call_args.args[2]["update_sig"], data["update_sig"])
        # the same signed document do_update sends; verify() is for enrollment
        # tokens, so check the JWS and its claims directly
        h, c, sig = data["update_sig"].split(".")
        unb64 = lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))  # noqa
        signing.signing_key().public_key().verify(unb64(sig), f"{h}.{c}".encode())
        self.assertEqual(json.loads(unb64(h))["typ"], signing.UPDATE_TYP)
        claims = json.loads(unb64(c))
        self.assertEqual(
            {k: claims[k] for k in ("agent", "url", "version", "sha256")},
            {
                "agent": self.agent.agent_id,
                "url": "https://x/a",
                "version": data["version"],
                "sha256": "ab" * 32,
            },
        )
        with override_settings(ENROLL_SIGNING_KEY=""), patch(
            "agents.utils.get_agent_url", return_value="https://x/a"
        ), patch("agents.utils.get_agent_artifact_sha256", return_value="ab" * 32):
            data = self.client.get(url).data
        self.assertNotIn("update_sig", data)
        self.assertEqual(data["sha256"], "ab" * 32)

    def test_update_reverted_event(self):
        self.as_agent()
        url = f"{self.base}/security-event/"
        r = self.client.post(
            url, {"kind": "update_reverted", "detail": "d"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.event("update_reverted").severity, "high")

    def test_agent_reported_r2_events(self):
        self.as_agent()
        url = f"{self.base}/security-event/"
        for kind in (
            "identity_unreadable",
            "unsigned_command",
            "envelope_refused",
            "clock_skew",
        ):
            with self.subTest(kind=kind):
                r = self.client.post(url, {"kind": kind, "detail": "d"}, format="json")
                self.assertEqual(r.status_code, 200)
                self.assertIsNotNone(self.event(kind))
        r = self.client.post(url, {"kind": "token_reuse"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_token_challenge_id_check_and_ip_throttle(self):
        from apiv3 import views

        self.client.credentials()
        with patch.object(views.TokenIpThrottle, "rate", "2/hour"):
            codes = [
                self.client.get(f"/api/v3/{'r' * 30}{i}/token/challenge/").status_code
                for i in range(3)
            ]
        # a new made-up id each time still meets the address limit
        self.assertEqual(codes, [200, 200, 429])
        cache.clear()
        r = self.client.get("/api/v3/not-an-id!/token/challenge/")
        self.assertEqual(r.status_code, 404)

    def test_grant_with_token_of_other_agent_404(self):
        other, token = self.new_agent()
        self.as_agent(token)
        r = self.client.post(
            f"{self.base}/token/grant/", self.grant_body(), format="json"
        )
        self.assertEqual(r.status_code, 404)

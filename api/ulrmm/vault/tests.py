# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey
from accounts.utils import grant_console_stepup
from reporting.utils import (
    InvalidDBOperationException,
    build_queryset,
    env,
    resolve_model,
)
from logs.models import AuditLog
from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.utils import is_credential_model

from .models import HKDF_INFO, MAX_BODY_BYTES, Credential, Document

base_url = "/vault"
SECRET = "correct horse battery staple"


class VaultMixin:
    def setup_vault(self):
        self.authenticate()
        self.setup_coresettings()
        self.client1 = baker.make("clients.Client", name="Acme")
        self.client2 = baker.make("clients.Client", name="Other")
        self.site1 = baker.make("clients.Site", client=self.client1, name="HQ")
        self.site2 = baker.make("clients.Site", client=self.client1, name="Branch")
        self.site3 = baker.make("clients.Site", client=self.client2, name="Far")
        self.agent1 = baker.make_recipe("agents.agent", site=self.site1)
        self.agent2 = baker.make_recipe("agents.agent", site=self.site3)

    def scope_data(self, scope):
        return {
            "client": {"client": self.client1.pk},
            "site": {"site": self.site1.pk},
            "agent": {"agent": self.agent1.agent_id},
        }[scope]

    def listing_url(self, scope):
        return {
            "client": f"{base_url}/clients/{self.client1.pk}/",
            "site": f"{base_url}/sites/{self.site1.pk}/",
            "agent": f"{base_url}/agents/{self.agent1.agent_id}/",
        }[scope]

    def cred(self, secret=SECRET, **kwargs):
        kwargs.setdefault("name", "admin")
        return baker.make(
            "vault.Credential", secret=encrypt_secret(secret, HKDF_INFO), **kwargs
        )


class TestVaultItems(VaultMixin, ULRMMTestCase):
    def setUp(self):
        self.setup_vault()

    def test_documents_each_scope(self):
        for scope in ("client", "site", "agent"):
            with self.subTest(scope=scope):
                data = {"title": "Runbook", "body": "line 1\nline 2", "pinned": True}
                r = self.client.post(
                    f"{base_url}/documents/",
                    {**data, **self.scope_data(scope)},
                    format="json",
                )
                self.assertEqual(r.status_code, 200, r.data)
                pk = r.data["id"]
                self.assertEqual(r.data["body"], "line 1\nline 2")
                self.assertIsNone(r.data["inherited"])
                self.assertEqual(r.data["created_by"], "john")

                r = self.client.get(self.listing_url(scope))
                self.assertEqual(r.status_code, 200)
                own = [d for d in r.data["documents"] if d["id"] == pk]
                self.assertEqual(len(own), 1)
                self.assertIsNone(own[0]["inherited"])

                r = self.client.put(
                    f"{base_url}/documents/{pk}/", {"title": "Changed"}, format="json"
                )
                self.assertEqual(r.status_code, 200, r.data)
                self.assertEqual(Document.objects.get(pk=pk).title, "Changed")
                self.assertEqual(Document.objects.get(pk=pk).body, "line 1\nline 2")

                r = self.client.delete(f"{base_url}/documents/{pk}/")
                self.assertEqual(r.status_code, 200)
                self.assertFalse(Document.objects.filter(pk=pk).exists())

        self.assertEqual(
            self.client.delete(f"{base_url}/documents/9999/").status_code, 404
        )
        # the log records the change. the text itself is not in the log
        logs = AuditLog.objects.filter(object_type=AuditObjType.DOCUMENT)
        self.assertEqual(logs.filter(action=AuditActionType.ADD).count(), 3)
        self.assertEqual(logs.filter(action=AuditActionType.MODIFY).count(), 3)
        self.assertEqual(logs.filter(action=AuditActionType.DELETE).count(), 3)
        dump = json.dumps(list(logs.values("before_value", "after_value", "message")))
        self.assertNotIn("line 1", dump)
        self.assertIn("hmac:", dump)

    def test_credentials_each_scope(self):
        for scope in ("client", "site", "agent"):
            with self.subTest(scope=scope):
                data = {
                    "name": "router",
                    "username": "admin",
                    "secret": SECRET,
                    "url": "https://192.168.1.1:8443/",
                    "notes": "local admin",
                }
                r = self.client.post(
                    f"{base_url}/credentials/",
                    {**data, **self.scope_data(scope)},
                    format="json",
                )
                self.assertEqual(r.status_code, 200, r.data)
                self.assertNotIn("secret", r.data)
                self.assertIs(r.data["secret_set"], True)
                pk = r.data["id"]
                cred = Credential.objects.get(pk=pk)
                self.assertEqual(cred.scope, scope)
                self.assertNotEqual(cred.secret, SECRET)
                self.assertEqual(decrypt_secret(cred.secret, HKDF_INFO), SECRET)

                r = self.client.get(self.listing_url(scope))
                self.assertEqual(r.status_code, 200)
                own = [c for c in r.data["credentials"] if c["id"] == pk]
                self.assertEqual(own[0]["username"], "admin")
                self.assertNotIn("secret", own[0])
                self.assertNotIn(SECRET, json.dumps(r.data))
                self.assertNotIn(cred.secret, json.dumps(r.data))

                r = self.client.put(
                    f"{base_url}/credentials/{pk}/", {"name": "fw"}, format="json"
                )
                self.assertEqual(r.status_code, 200, r.data)
                self.assertNotIn("secret", r.data)

                r = self.client.delete(f"{base_url}/credentials/{pk}/")
                self.assertEqual(r.status_code, 200)
                self.assertFalse(Credential.objects.filter(pk=pk).exists())

    def test_exactly_one_scope(self):
        for scope in ({}, {"client": self.client1.pk, "site": self.site1.pk}):
            for kind, data in (
                ("documents", {"title": "t"}),
                ("credentials", {"name": "n"}),
            ):
                r = self.client.post(
                    f"{base_url}/{kind}/", {**data, **scope}, format="json"
                )
                self.assertEqual(r.status_code, 400, (kind, scope))

        with transaction.atomic(), self.assertRaises(IntegrityError):
            Credential.objects.create(name="x", client=self.client1, site=self.site1)
        with transaction.atomic(), self.assertRaises(IntegrityError):
            Document.objects.create(title="x")

        # the scope of an item is fixed, sending it back unchanged is fine
        doc = baker.make("vault.Document", title="t", site=self.site1)
        r = self.client.put(
            f"{base_url}/documents/{doc.pk}/",
            {"site": self.site2.pk, "title": "u"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.put(
            f"{base_url}/documents/{doc.pk}/",
            {"client": None, "site": self.site1.pk, "agent": None, "title": "u"},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        cred = self.cred(agent=self.agent1)
        r = self.client.put(
            f"{base_url}/credentials/{cred.pk}/",
            {"agent": self.agent2.agent_id},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_inheritance_in_listings(self):
        baker.make("vault.Document", title="client doc", client=self.client1)
        baker.make("vault.Document", title="site doc", site=self.site1)
        baker.make("vault.Document", title="device doc", agent=self.agent1)
        baker.make("vault.Document", title="pinned doc", agent=self.agent1, pinned=True)
        # not related to agent1
        baker.make("vault.Document", title="other site", site=self.site2)
        baker.make("vault.Document", title="other client", client=self.client2)
        baker.make("vault.Document", title="other device", agent=self.agent2)
        self.cred(name="client cred", client=self.client1)
        self.cred(name="site cred", site=self.site1)
        self.cred(name="device cred", agent=self.agent1)
        self.cred(name="other cred", site=self.site3)

        def rows(r, key, field):
            return [(i[field], i["inherited"]) for i in r.data[key]]

        r = self.client.get(f"{base_url}/agents/{self.agent1.agent_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            rows(r, "documents", "title"),
            [
                ("pinned doc", None),
                ("device doc", None),
                ("site doc", "site"),
                ("client doc", "client"),
            ],
        )
        self.assertEqual(
            rows(r, "credentials", "name"),
            [("device cred", None), ("site cred", "site"), ("client cred", "client")],
        )
        self.assertEqual(r.data["documents"][0]["agent"], self.agent1.agent_id)

        r = self.client.get(f"{base_url}/sites/{self.site1.pk}/")
        self.assertEqual(
            rows(r, "documents", "title"),
            [("site doc", None), ("client doc", "client")],
        )
        r = self.client.get(f"{base_url}/clients/{self.client1.pk}/")
        self.assertEqual(rows(r, "documents", "title"), [("client doc", None)])
        self.assertEqual(rows(r, "credentials", "name"), [("client cred", None)])

        self.assertEqual(self.client.get(f"{base_url}/agents/nope/").status_code, 404)
        self.assertEqual(self.client.get(f"{base_url}/sites/9999/").status_code, 404)
        self.check_not_authenticated("get", f"{base_url}/clients/{self.client1.pk}/")

    def test_secret_write_only_and_kept_on_empty(self):
        r = self.client.post(
            f"{base_url}/credentials/",
            {"name": "nas", "secret": SECRET, "site": self.site1.pk},
            format="json",
        )
        pk = r.data["id"]
        token = Credential.objects.get(pk=pk).secret

        for data in ({"secret": ""}, {"notes": "rack 2"}, {"username": "root"}):
            r = self.client.put(f"{base_url}/credentials/{pk}/", data, format="json")
            self.assertEqual(r.status_code, 200, r.data)
            self.assertEqual(Credential.objects.get(pk=pk).secret, token)

        r = self.client.put(
            f"{base_url}/credentials/{pk}/", {"secret": " new secret "}, format="json"
        )
        new_token = Credential.objects.get(pk=pk).secret
        self.assertNotEqual(new_token, token)
        self.assertEqual(decrypt_secret(new_token, HKDF_INFO), " new secret ")

        logs = AuditLog.objects.filter(object_type=AuditObjType.CREDENTIAL)
        # add, notes, username, new secret; the empty secret changed nothing
        self.assertEqual(logs.count(), 4)
        dump = json.dumps(list(logs.values("before_value", "after_value", "message")))
        for value in (SECRET, "new secret", token, new_token):
            self.assertNotIn(value, dump)
        self.assertIn("hmac:", dump)
        changed = logs.filter(action=AuditActionType.MODIFY).last()
        self.assertNotEqual(
            changed.before_value["secret"], changed.after_value["secret"]
        )
        self.assertTrue(changed.after_value["secret"].startswith("hmac:"))

        # without a secret it is just metadata
        r = self.client.post(
            f"{base_url}/credentials/",
            {"name": "no secret", "client": self.client1.pk},
            format="json",
        )
        self.assertIs(r.data["secret_set"], False)

    def test_secret_clear(self):
        cred = self.cred(name="nas", site=self.site1)
        url = f"{base_url}/credentials/{cred.pk}/"
        r = self.client.put(url, {"secret_clear": True}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIs(r.data["secret_set"], False)
        self.assertNotIn("secret_clear", r.data)
        self.assertEqual(Credential.objects.get(pk=cred.pk).secret, "")
        log = AuditLog.objects.get(
            object_type=AuditObjType.CREDENTIAL, action=AuditActionType.MODIFY
        )
        self.assertTrue(log.before_value["secret"].startswith("hmac:"))
        self.assertIsNone(log.after_value["secret"])

        # a secret sent along wins
        r = self.client.put(url, {"secret_clear": True, "secret": "x"}, format="json")
        self.assertIs(r.data["secret_set"], True)
        cred.refresh_from_db()
        self.assertEqual(decrypt_secret(cred.secret, HKDF_INFO), "x")

    def test_validation(self):
        url = f"{base_url}/credentials/"
        site = {"site": self.site1.pk}
        for bad in ("javascript:alert(1)", "https://a b", "ftp://x", "x" * 501):
            r = self.client.post(url, {"name": "n", "url": bad, **site}, format="json")
            self.assertEqual(r.status_code, 400, bad)
        r = self.client.post(url, {"name": "n" * 81, **site}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            url, {"name": "n", "notes": "x" * 2001, **site}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            url, {"name": "n", "secret": "x" * 4097, **site}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("x" * 100, json.dumps(r.data))
        self.assertFalse(Credential.objects.exists())

    def test_document_size_limit(self):
        url = f"{base_url}/documents/"
        site = {"site": self.site1.pk}
        r = self.client.post(
            url, {"title": "max", "body": "a" * MAX_BODY_BYTES, **site}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        r = self.client.post(
            url,
            {"title": "over", "body": "a" * (MAX_BODY_BYTES + 1), **site},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        # counted in bytes, not characters
        r = self.client.post(
            url,
            {"title": "umlauts", "body": "ä" * (MAX_BODY_BYTES // 2 + 1), **site},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(url, {"title": "t" * 121, **site}, format="json")
        self.assertEqual(r.status_code, 400)
        doc = Document.objects.get()
        r = self.client.put(
            f"{base_url}/documents/{doc.pk}/",
            {"body": "b" * (MAX_BODY_BYTES + 1)},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(Document.objects.get().title, "max")

    def test_reporting_refuses_credentials(self):
        cred = self.cred(agent=self.agent1)
        self.assertTrue(is_credential_model(cred))
        self.assertFalse(env.is_safe_attribute(cred, "name", cred.name))
        for data_source in (
            {"model": "Agent", "only": ["vault_credentials__secret"]},
            {"model": "Site", "values": ["vault_credentials__name"]},
            {
                "model": "Client",
                "filter": {"vault_credentials__secret__startswith": "g"},
            },
        ):
            with self.subTest(data_source=data_source), self.assertRaises(
                InvalidDBOperationException
            ):
                build_queryset(data_source=resolve_model(data_source=data_source))


CAN = (
    "view_documents",
    "view_credentials",
    "manage_credentials",
    "manage_documents",
)


def can_dict(read=False, view=False, creds=False, docs=False):
    return dict(zip(CAN, (read, view, creds, docs)))


class TestVaultPermissions(VaultMixin, ULRMMTestCase):
    def setUp(self):
        self.setup_vault()

    def test_flags(self):
        doc = baker.make("vault.Document", title="d", site=self.site1)
        cred = self.cred(site=self.site1)
        listing = f"{base_url}/sites/{self.site1.pk}/"

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("get", listing)
        self.check_not_authorized(
            "post", f"{base_url}/documents/", {"title": "x", "site": self.site1.pk}
        )
        self.check_not_authorized(
            "put", f"{base_url}/documents/{doc.pk}/", {"title": "x"}
        )
        self.check_not_authorized("delete", f"{base_url}/documents/{doc.pk}/")
        self.check_not_authorized(
            "post", f"{base_url}/credentials/", {"name": "x", "site": self.site1.pk}
        )
        self.check_not_authorized(
            "put", f"{base_url}/credentials/{cred.pk}/", {"name": "x"}
        )
        self.check_not_authorized("delete", f"{base_url}/credentials/{cred.pk}/")
        self.check_not_authorized("post", f"{base_url}/credentials/{cred.pk}/reveal/")

        # documents and credentials each need their own flag
        user = self.create_user_with_roles(["can_list_agents"])
        self.client.force_authenticate(user=user)
        r = self.client.get(listing)
        self.assertEqual([d["id"] for d in r.data["documents"]], [doc.pk])
        self.assertEqual(r.data["credentials"], [])
        self.assertEqual(r.data["can"], can_dict(read=True))

        user = self.create_user_with_roles(["can_view_credentials"])
        self.client.force_authenticate(user=user)
        r = self.client.get(listing)
        self.assertEqual(r.data["documents"], [])
        self.assertEqual([c["id"] for c in r.data["credentials"]], [cred.pk])
        self.assertEqual(r.data["can"], can_dict(view=True))
        self.check_not_authorized(
            "put", f"{base_url}/credentials/{cred.pk}/", {"name": "x"}
        )

        user = self.create_user_with_roles(["can_list_agents", "can_manage_notes"])
        self.client.force_authenticate(user=user)
        r = self.client.get(listing)
        self.assertEqual(r.data["can"], can_dict(read=True, docs=True))
        self.client.force_authenticate(user=self.john)
        r = self.client.get(listing)
        self.assertEqual(r.data["can"], dict.fromkeys(CAN, True))

        user = self.create_user_with_roles(["can_manage_notes"])
        self.client.force_authenticate(user=user)
        r = self.client.post(
            f"{base_url}/documents/",
            {"title": "x", "site": self.site1.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.check_not_authorized(
            "post", f"{base_url}/credentials/", {"name": "x", "site": self.site1.pk}
        )

        user = self.create_user_with_roles(["can_manage_credentials"])
        self.client.force_authenticate(user=user)
        r = self.client.put(
            f"{base_url}/credentials/{cred.pk}/", {"name": "y"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.check_not_authorized(
            "put", f"{base_url}/documents/{doc.pk}/", {"title": "x"}
        )

    def test_scope(self):
        flags = [
            "can_list_agents",
            "can_view_credentials",
            "can_manage_notes",
            "can_manage_credentials",
        ]
        user = self.create_user_with_roles(flags)
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)

        # the device, its site and its client. the client row is read-only
        everything = dict.fromkeys(CAN, True)
        for url, can in (
            (f"{base_url}/agents/{self.agent1.agent_id}/", everything),
            (f"{base_url}/sites/{self.site1.pk}/", everything),
            (f"{base_url}/clients/{self.client1.pk}/", can_dict(True, True)),
        ):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            self.assertEqual(r.data["can"], can, url)
        for url in (
            f"{base_url}/agents/{self.agent2.agent_id}/",
            f"{base_url}/sites/{self.site2.pk}/",
            f"{base_url}/sites/{self.site3.pk}/",
            f"{base_url}/clients/{self.client2.pk}/",
        ):
            self.check_not_authorized("get", url)

        # writes land on the user's site and device. the client stays read-only
        for data in ({"site": self.site1.pk}, {"agent": self.agent1.agent_id}):
            r = self.client.post(
                f"{base_url}/documents/", {"title": "x", **data}, format="json"
            )
            self.assertEqual(r.status_code, 200, data)
        for data in (
            {"client": self.client1.pk},
            {"site": self.site2.pk},
            {"agent": self.agent2.agent_id},
        ):
            self.check_not_authorized(
                "post", f"{base_url}/documents/", {"title": "x", **data}
            )
            self.check_not_authorized(
                "post", f"{base_url}/credentials/", {"name": "x", **data}
            )

        inherited = baker.make("vault.Document", title="c", client=self.client1)
        foreign = self.cred(site=self.site3)
        self.check_not_authorized(
            "put", f"{base_url}/documents/{inherited.pk}/", {"title": "x"}
        )
        self.check_not_authorized("delete", f"{base_url}/documents/{inherited.pk}/")
        self.check_not_authorized(
            "put", f"{base_url}/credentials/{foreign.pk}/", {"name": "x"}
        )
        self.check_not_authorized("delete", f"{base_url}/credentials/{foreign.pk}/")
        self.assertTrue(Document.objects.filter(pk=inherited.pk, title="c").exists())
        self.assertTrue(Credential.objects.filter(pk=foreign.pk).exists())


@override_settings(CACHES=LOCMEM_CACHE)
class TestReveal(VaultMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_vault()
        self.user = self.create_user_with_roles(["can_view_credentials"])
        self.user.role.can_view_clients.set([self.client1])
        self.cred_in = self.cred(name="switch", agent=self.agent1)
        self.cred_out = self.cred(name="foreign", agent=self.agent2)

    def reveals(self):
        return AuditLog.objects.filter(
            object_type=AuditObjType.CREDENTIAL, action=AuditActionType.VIEW
        )

    def reveal(self, cred):
        return self.client.post(f"{base_url}/credentials/{cred.pk}/reveal/")

    def login(self, user, stepup=True):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)

    def test_needs_stepup_and_a_dashboard_token(self):
        # no dashboard token
        self.client.force_authenticate(user=self.user)
        grant_console_stepup(self.user)
        r = self.reveal(self.cred_in)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        # an api key is no step-up
        APIKey.objects.create(name="key", key="userskey", user=self.user)
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_X_API_KEY="userskey")
        r = self.reveal(self.cred_in)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.client.credentials()

        # dashboard token without step-up
        cache.clear()
        self.login(self.user, stepup=False)
        r = self.reveal(self.cred_in)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        self.assertNotIn(SECRET, json.dumps(r.data))
        self.assertFalse(self.reveals().exists())

    def test_flag_and_scope(self):
        user = self.create_user_with_roles(
            ["can_list_agents", "can_manage_credentials"]
        )
        self.login(user)
        r = self.reveal(self.cred_in)
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("stepup", r.data)

        self.login(self.user)
        r = self.reveal(self.cred_out)
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("stepup", r.data)
        self.assertEqual(
            self.client.post(f"{base_url}/credentials/9999/reveal/").status_code, 404
        )
        self.assertFalse(self.reveals().exists())

    def test_reveal_is_audited(self):
        self.login(self.user)
        r = self.reveal(self.cred_in)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"secret": SECRET})
        self.assertEqual(r["Cache-Control"], "no-store")

        log = self.reveals().get()
        self.assertEqual(log.action, AuditActionType.VIEW)
        self.assertEqual(log.username, self.user.username)
        self.assertEqual(log.agent_id, self.agent1.agent_id)
        self.assertIn("switch", log.message)
        self.assertIn(self.agent1.hostname, log.message)
        self.assertEqual(log.after_value["name"], "switch")
        self.assertEqual(log.after_value["scope"], "agent")
        self.assertEqual(log.after_value["agent"], self.agent1.agent_id)
        dump = json.dumps([log.message, log.after_value, log.before_value])
        self.assertNotIn(SECRET, dump)
        self.assertNotIn(self.cred_in.secret, dump)

        # inherited from the client of an allowed device
        client_cred = self.cred(name="domain admin", client=self.client1)
        r = self.reveal(client_cred)
        self.assertEqual(r.status_code, 200)
        log = self.reveals().last()
        self.assertIn("client Acme", log.message)
        self.assertIsNone(log.agent_id)

    def test_unreadable_and_empty(self):
        self.login(self.user)
        broken = baker.make(
            "vault.Credential", name="old", site=self.site1, secret="gAAAA-bad"
        )
        r = self.reveal(broken)
        self.assertEqual(r.status_code, 400)
        empty = baker.make("vault.Credential", name="none", site=self.site1)
        self.assertEqual(self.reveal(empty).status_code, 400)
        self.assertFalse(self.reveals().exists())

    def test_reveal_throttled_per_user(self):
        self.login(self.user)
        codes = [self.reveal(self.cred_in).status_code for _ in range(31)]
        self.assertEqual(codes, [200] * 30 + [429])
        self.assertEqual(self.reveals().count(), 30)

        other = self.create_user_with_roles(["can_view_credentials"])
        other.role.can_view_clients.set([self.client1])
        self.login(other)
        self.assertEqual(self.reveal(self.cred_in).status_code, 200)

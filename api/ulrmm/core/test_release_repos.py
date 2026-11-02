# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest import mock

from django.db import connection
from django.test import override_settings
from knox.models import AuthToken

from accounts.utils import grant_console_stepup
from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

from . import releases
from .models import ReleaseRepo

URL = "/core/server/update/repos/"
ALPHA = {
    "name": "alpha",
    "repo_url": "https://github.com/RiDDiX/ulrmm-alpha",
    "token": "github_pat_sponsor",
}


LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM_CACHE)
class TestReleaseRepos(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def login(self, stepup=True):
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        if stepup:
            grant_console_stepup(self.john)

    def test_writes_need_the_stepup(self):
        self.login(stepup=False)
        r = self.client.post(URL, ALPHA, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        repo = ReleaseRepo.objects.create(name="x", repo_url=ALPHA["repo_url"])
        for call in (self.client.put, self.client.delete):
            r = call(f"{URL}{repo.pk}/", {"enabled": False}, format="json")
            self.assertEqual(r.status_code, 403)
        self.assertTrue(ReleaseRepo.objects.get(pk=repo.pk).enabled)

    def test_add_list_change_remove(self):
        self.login()
        with mock.patch.object(releases, "forget_status") as forget:
            r = self.client.post(URL, ALPHA, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        forget.assert_called_once()
        self.assertEqual(r.data["kind"], "github")
        self.assertEqual(
            r.data["api"], "https://api.github.com/repos/RiDDiX/ulrmm-alpha/releases"
        )
        self.assertIs(r.data["has_token"], True)
        self.assertNotIn("token", r.data)
        pk = r.data["id"]

        r = self.client.get(URL)
        self.assertEqual([x["name"] for x in r.data], ["alpha"])
        self.assertNotIn("github_pat_sponsor", str(r.data))

        # no token in the body keeps the stored one
        r = self.client.put(f"{URL}{pk}/", {"enabled": False}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(ReleaseRepo.objects.get(pk=pk).token, "github_pat_sponsor")
        # an empty one removes it
        r = self.client.put(f"{URL}{pk}/", {"token": ""}, format="json")
        self.assertIs(r.data["has_token"], False)

        r = self.client.delete(f"{URL}{pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(ReleaseRepo.objects.exists())
        logs = AuditLog.objects.filter(message__contains="release repository alpha")
        self.assertEqual(logs.count(), 4)
        self.assertNotIn("github_pat_sponsor", str(list(logs.values())))

    def test_token_is_encrypted_at_rest(self):
        self.login()
        self.client.post(URL, ALPHA, format="json")
        with connection.cursor() as c:
            c.execute("SELECT token FROM core_releaserepo")
            raw = c.fetchone()[0]
        self.assertNotIn("github_pat_sponsor", raw)
        self.assertTrue(raw.startswith("gAAAAA"))

    def test_token_does_not_follow_a_new_url(self):
        self.login()
        pk = self.client.post(URL, ALPHA, format="json").data["id"]
        other = "https://evil.example/o/r"
        r = self.client.put(f"{URL}{pk}/", {"repo_url": other}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertTrue(r.data.startswith("Token:"), r.data)
        self.assertEqual(ReleaseRepo.objects.get(pk=pk).repo_url, ALPHA["repo_url"])
        # the same repository spelled differently keeps the token
        same = ALPHA["repo_url"] + ".git"
        r = self.client.put(f"{URL}{pk}/", {"repo_url": same}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIs(r.data["has_token"], True)
        for token in ("new-token", ""):
            body = {"repo_url": other, "token": token}
            r = self.client.put(f"{URL}{pk}/", body, format="json")
            self.assertEqual(r.status_code, 200, r.data)
            other = "https://evil.example/o/r2"

    def test_name_is_fixed_after_creation(self):
        self.login()
        pk = self.client.post(URL, ALPHA, format="json").data["id"]
        r = self.client.put(f"{URL}{pk}/", {"name": "beta"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(ReleaseRepo.objects.get(pk=pk).name, "alpha")

    @override_settings(ULRMM_RELEASE_SOURCES=None, ULRMM_RELEASE_GITEA_TOKEN="t")
    def test_a_database_error_leaves_the_built_in_sources(self):
        from django.db import DatabaseError

        with mock.patch.object(
            ReleaseRepo.objects, "filter", side_effect=DatabaseError("gone")
        ):
            names = [s.name for s in releases.sources()]
        self.assertEqual(names, ["github", "gitea"])

    def test_validation(self):
        self.login()
        for body in (
            {**ALPHA, "name": "github"},
            # taken even while the Gitea source is off (no token)
            {**ALPHA, "name": "gitea"},
            {**ALPHA, "name": "git"},
            {**ALPHA, "name": "Alpha"},
            {**ALPHA, "name": "a b"},
            {**ALPHA, "repo_url": "http://github.com/a/b"},
            {**ALPHA, "repo_url": "https://github.com/onlyowner"},
            {**ALPHA, "token": "two words"},
            {**ALPHA, "token": "line\nbreak"},
        ):
            r = self.client.post(URL, body, format="json")
            self.assertEqual(r.status_code, 400, body)
            self.assertIsInstance(r.data, str)
        self.assertFalse(ReleaseRepo.objects.exists())

    def test_names_are_unique_and_count_is_capped(self):
        self.login()
        self.client.post(URL, ALPHA, format="json")
        self.assertEqual(self.client.post(URL, ALPHA, format="json").status_code, 400)
        for i in range(releases.MAX_REPOS - 1):
            ReleaseRepo.objects.create(name=f"r{i}", repo_url=ALPHA["repo_url"])
        r = self.client.post(URL, {**ALPHA, "name": "one-more"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_role_without_server_updates_is_refused(self):
        user = self.create_user_with_roles([])
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        grant_console_stepup(user)
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.assertEqual(self.client.post(URL, ALPHA, format="json").status_code, 403)

    def test_enabled_repos_feed_the_sources(self):
        ReleaseRepo.objects.create(name="alpha", repo_url=ALPHA["repo_url"], token="t")
        ReleaseRepo.objects.create(
            name="off", repo_url="https://git.example.org/a/b", enabled=False
        )
        names = [s.name for s in releases.sources()]
        self.assertEqual(names[-1], "alpha")
        self.assertNotIn("off", names)
        alpha = releases.sources()[-1]
        self.assertEqual(
            (alpha.kind, alpha.token, alpha.available), ("github", "t", True)
        )

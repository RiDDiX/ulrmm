# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import hashlib
import io
import json
import shutil
import tempfile
import time
from pathlib import Path
from unittest import mock

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.cache import cache
from django.core.management import call_command
from django.test import SimpleTestCase, override_settings

from deploy import tasks

from . import releases

V = "2.27.10.2026"
GH = "https://gh.test/releases"
GT = "https://gt.test/api/v1/releases"
SOURCES = [{"name": "github", "api": GH}, {"name": "gitea", "api": GT}]
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class Resp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}

    def json(self):
        return json.loads(self.content)

    def iter_content(self, n):
        for i in range(0, len(self.content), n):
            yield self.content[i : i + n]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@override_settings(
    CACHES=LOCMEM,
    ULRMM_RELEASE_SOURCES=SOURCES,
    ULRMM_RELEASE_GITHUB_TOKEN="",
    ULRMM_RELEASE_GITEA_TOKEN="gtok",
)
class ReleaseBase(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.routes = {}
        self.calls = []
        self.repos = []
        for p in (
            mock.patch.object(
                releases, "RELEASE_PUBKEY_B64", base64.b64encode(pub).decode()
            ),
            mock.patch.object(tasks, "_check_host"),
            mock.patch.object(releases.requests, "get", side_effect=self.get),
            mock.patch.object(
                releases, "_repo_sources", side_effect=lambda: list(self.repos)
            ),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.server = b"server tree " * 4000
        self.web = b"web spa " * 3000
        self.publish("gh.test", GH)
        self.publish("gt.test", GT)

    def get(self, url, **kw):
        self.calls.append((url, kw))
        r = self.routes.get(url)
        if r is None:
            return Resp(404, b"not here")
        if isinstance(r, Exception):
            raise r
        if callable(r) and not isinstance(r, Resp):
            return r()
        return r

    def manifest(self, server=None, web=None, version=V):
        server = self.server if server is None else server
        web = self.web if web is None else web
        srv, spa = releases.asset_names(version)
        return {
            "v": 1,
            "product": "ulrmm",
            "version": version,
            "created": "2026-10-27T10:00:00+00:00",
            "commit": "a" * 40,
            "web_commit": "b" * 40,
            "assets": [
                {"name": srv, "sha256": sha(server), "size": len(server)},
                {"name": spa, "sha256": sha(web), "size": len(web)},
            ],
        }

    def sign(self, manifest_bytes: bytes) -> str:
        return base64.b64encode(self.key.sign(manifest_bytes)).decode()

    def publish(self, host, api, manifest=None, sig=None, files=None, version=V):
        """Route the release API and its assets for one host."""
        mb = json.dumps(manifest or self.manifest(version=version)).encode()
        srv, spa = releases.asset_names(version)
        files = files or {srv: self.server, spa: self.web}
        files = dict(files)
        files[f"ulrmm-{version}.manifest.json"] = mb
        files[f"ulrmm-{version}.manifest.sig"] = (sig or self.sign(mb)).encode()
        assets = []
        for name, body in files.items():
            url = f"https://{host}/dl/{name}"
            self.routes[url] = Resp(200, body)
            assets.append(
                {"name": name, "browser_download_url": url, "size": len(body)}
            )
        body = json.dumps({"tag_name": f"v{version}", "assets": assets}).encode()
        self.routes[f"{api}/latest"] = Resp(200, body)
        self.routes[f"{api}/tags/v{version}"] = Resp(200, body)
        return mb


class TestDiscover(ReleaseBase):
    def test_github_first(self):
        name, rel = releases.discover()
        self.assertEqual(name, "github")
        self.assertEqual(rel["version"], V)
        gh_call = next(kw for u, kw in self.calls if u.startswith(GH))
        self.assertNotIn("Authorization", gh_call["headers"])

    @override_settings(ULRMM_RELEASE_GITHUB_TOKEN="ghtok")
    def test_private_github_uses_the_asset_api(self):
        # a private repository hands assets out through the API url only
        body = json.loads(self.routes[f"{GH}/latest"].content)
        for a in body["assets"]:
            api = f"https://gh.test/assets/{a['name']}"
            a["url"] = api
            self.routes[api] = self.routes.pop(a["browser_download_url"])
        self.routes[f"{GH}/latest"] = Resp(200, json.dumps(body).encode())
        name, rel = releases.discover()
        self.assertEqual(name, "github")
        asset_calls = [
            kw for u, kw in self.calls if u.startswith("https://gh.test/assets/")
        ]
        self.assertEqual(len(asset_calls), 2)
        for kw in asset_calls:
            self.assertEqual(kw["headers"]["Accept"], "application/octet-stream")
            self.assertEqual(kw["headers"]["Authorization"], "Bearer ghtok")
        api_call = [kw for u, kw in self.calls if u == f"{GH}/latest"][0]
        self.assertEqual(api_call["headers"]["Accept"], "application/json")

    def test_github_down_then_gitea(self):
        self.routes[f"{GH}/latest"] = Resp(503, b"")
        lines = []
        name, rel = releases.discover(log=lines.append)
        self.assertEqual(name, "gitea")
        self.assertEqual(lines, ["source github: HTTP 503", f"source gitea: ok {V}"])
        gitea_calls = [kw for url, kw in self.calls if url.startswith(GT)]
        self.assertEqual(gitea_calls[0]["headers"]["Authorization"], "token gtok")

    def test_connection_error_and_bad_json_fall_through(self):
        self.routes[f"{GH}/latest"] = requests.ConnectTimeout("slow")
        self.assertEqual(releases.discover()[0], "gitea")
        self.routes[f"{GH}/latest"] = Resp(200, b"<html>")
        self.assertEqual(releases.discover()[0], "gitea")

    def test_bad_github_signature_falls_through_to_gitea(self):
        other = Ed25519PrivateKey.generate()
        mb = json.dumps(self.manifest()).encode()
        self.publish("gh.test", GH, sig=base64.b64encode(other.sign(mb)).decode())
        lines = []
        self.assertEqual(releases.discover(log=lines.append)[0], "gitea")
        self.assertIn("signature", lines[0])

    @override_settings(ULRMM_RELEASE_GITEA_TOKEN="")
    def test_gitea_without_token_is_unavailable(self):
        self.routes[f"{GH}/latest"] = Resp(500, b"")
        lines = []
        with self.assertRaises(releases.ReleaseError):
            releases.discover(log=lines.append)
        self.assertEqual(lines[1], "source gitea: unavailable (no token)")
        self.assertFalse([u for u, _ in self.calls if u.startswith(GT)])

    def test_pinned_version_and_tag_mismatch(self):
        self.assertEqual(releases.discover(V)[1]["version"], V)
        self.routes[f"{GH}/tags/v{V}"] = Resp(
            200, json.dumps({"tag_name": "v1.01.01.2026", "assets": []}).encode()
        )
        self.routes[f"{GT}/tags/v{V}"] = Resp(404, b"")
        with self.assertRaises(releases.ReleaseError):
            releases.discover(V)
        with self.assertRaises(releases.ReleaseError):
            releases.discover("../x")

    def test_redirect_drops_auth_on_other_host_and_stays_https(self):
        self.routes[f"{GT}/latest"] = Resp(
            302, b"", {"Location": "https://cdn.test/latest"}
        )
        self.routes["https://cdn.test/latest"] = self.routes[f"{GH}/latest"]
        self.routes[f"{GH}/latest"] = Resp(500, b"")
        releases.discover()
        cdn = [kw for u, kw in self.calls if u == "https://cdn.test/latest"]
        self.assertNotIn("Authorization", cdn[0]["headers"])
        for _, kw in self.calls:
            self.assertFalse(kw["allow_redirects"])
            self.assertEqual(kw["timeout"], releases.API_TIMEOUT)
            self.assertIn("stream", kw)
        self.routes[f"{GT}/latest"] = Resp(
            302, b"", {"Location": "http://cdn.test/latest"}
        )
        with self.assertRaises(releases.ReleaseError):
            releases.discover()

    def test_oversized_manifest_asset_falls_through(self):
        self.routes[f"https://gh.test/dl/ulrmm-{V}.manifest.json"] = Resp(
            200, b"{" * ((1 << 20) + 1)
        )
        lines = []
        self.assertEqual(releases.discover(log=lines.append)[0], "gitea")
        self.assertEqual(lines[0], "source github: asset too large")

    def test_oversized_release_json_falls_through(self):
        self.routes[f"{GH}/latest"] = Resp(200, b"{" * ((1 << 20) + 1))
        lines = []
        self.assertEqual(releases.discover(log=lines.append)[0], "gitea")
        self.assertEqual(lines[0], "source github: release JSON too large")

    def test_private_source_host_allowed_other_hops_checked(self):
        def check(hostname):
            raise ValueError("the host resolves to a private address")

        with mock.patch.object(tasks, "_check_host", side_effect=check) as m:
            # gh.test is a configured source, so it is not checked at all
            self.assertEqual(releases.discover()[0], "github")
            m.assert_not_called()
            self.routes[f"{GH}/latest"] = Resp(
                302, b"", {"Location": "https://cdn.test/latest"}
            )
            self.routes[f"{GT}/latest"] = Resp(500, b"")
            lines = []
            with self.assertRaises(releases.ReleaseError):
                releases.discover(log=lines.append)
        self.assertEqual(
            lines[0],
            "source github: blocked: the host resolves to a private address",
        )
        m.assert_called_once_with("cdn.test")


AL = "https://alpha.test/api/v1/repos/riddix/ulrmm-alpha/releases"
V2 = "1.28.10.2026"


class TestRepoSources(ReleaseBase):
    """Repositories added in the Update Center."""

    def alpha(self, token=""):
        self.repos.append(
            releases.ReleaseSource("alpha", AL, token, "gitea", needs_token=False)
        )

    def test_newest_release_wins(self):
        self.alpha()
        self.publish("alpha.test", AL, version=V2)
        name, rel = releases.discover()
        self.assertEqual((name, rel["version"]), ("alpha", V2))

    def test_tie_keeps_the_first_source(self):
        self.alpha()
        self.publish("alpha.test", AL)
        name, _ = releases.discover()
        self.assertEqual(name, "github")

    def test_older_alpha_does_not_win(self):
        self.alpha()
        self.publish("alpha.test", AL, version="9.26.10.2026")
        self.assertEqual(releases.discover()[0], "github")

    def test_pinned_version_comes_from_the_first_source_that_has_it(self):
        self.alpha()
        self.publish("alpha.test", AL)
        self.publish("alpha.test", AL, version=V2)
        self.assertEqual(releases.discover(V)[0], "github")
        self.assertEqual(releases.discover(V2)[0], "alpha")

    def test_added_gitea_repo_works_without_token_and_sends_one(self):
        self.alpha()
        self.publish("alpha.test", AL, version=V2)
        releases.discover()
        alpha_calls = [kw for u, kw in self.calls if u.startswith(AL)]
        self.assertNotIn("Authorization", alpha_calls[0]["headers"])
        self.calls.clear()
        self.repos.clear()
        self.alpha("sponsor-tok")
        releases.discover()
        alpha_calls = [kw for u, kw in self.calls if u.startswith(AL)]
        self.assertEqual(
            alpha_calls[0]["headers"]["Authorization"], "token sponsor-tok"
        )

    def test_added_repo_host_gets_the_public_address_check(self):
        self.alpha()
        self.assertNotIn("alpha.test", releases._source_hosts())
        checked = []
        with mock.patch.object(tasks, "_check_host", side_effect=checked.append):
            self.publish("alpha.test", AL, version=V2)
            releases.discover()
        self.assertIn("alpha.test", checked)
        self.assertNotIn("gh.test", checked)
        with override_settings(ULRMM_RELEASE_TRUSTED_HOSTS=["Alpha.test"]):
            self.assertIn("alpha.test", releases._source_hosts())

    def test_token_only_goes_to_the_repo_api_host(self):
        # a Forgejo release may point an attachment at any https host
        self.alpha("sponsor-tok")
        mb = self.publish("alpha.test", AL, version=V2)
        body = json.loads(self.routes[f"{AL}/latest"].content)
        for a in body["assets"]:
            moved = a["browser_download_url"].replace("alpha.test", "cdn.test")
            self.routes[moved] = self.routes.pop(a["browser_download_url"])
            a["browser_download_url"] = moved
        self.routes[f"{AL}/latest"] = Resp(200, json.dumps(body).encode())
        name, rel = releases.discover()
        self.assertEqual((name, rel["manifest_bytes"]), ("alpha", mb))
        for url, kw in self.calls:
            if url.startswith("https://cdn.test/"):
                self.assertNotIn("Authorization", kw["headers"])
            if url.startswith(AL):
                self.assertEqual(kw["headers"]["Authorization"], "token sponsor-tok")

    def test_a_hanging_source_does_not_hold_the_others(self):
        self.alpha()

        def hang():
            time.sleep(3)
            return Resp(503, b"")

        self.routes[f"{AL}/latest"] = hang
        lines = []
        started = time.monotonic()
        with mock.patch.object(releases, "SOURCE_BUDGET", 0.2):
            name, _ = releases.discover(log=lines.append)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(name, "github")
        self.assertEqual(lines[-1], "source alpha: no answer in time")

    def test_download_uses_the_source_that_answered(self):
        self.alpha("sponsor-tok")
        self.publish("alpha.test", AL, version=V2)
        name, rel = releases.discover()
        self.repos.clear()  # removed between discover and download
        path = releases.download_and_verify(rel, self.tmp)
        self.assertTrue((path / releases.asset_names(V2)[0]).exists())
        rel.pop("_source")
        with self.assertRaises(releases.ReleaseError):
            releases.download_and_verify(rel, self.tmp)

    def test_bad_alpha_signature_is_skipped(self):
        self.alpha()
        self.publish(
            "alpha.test", AL, version=V2, sig=base64.b64encode(b"x" * 64).decode()
        )
        self.assertEqual(releases.discover()[0], "github")

    def test_status_reports_the_newest_source(self):
        self.alpha()
        self.publish("alpha.test", AL, version=V2)
        st = releases.sources_status(refresh=True)
        self.assertEqual((st["active"], st["latest"]), ("alpha", V2))
        self.assertEqual(
            [r["name"] for r in st["sources"]], ["github", "gitea", "alpha"]
        )


class TestRepoApi(SimpleTestCase):
    def test_github_and_gitea_urls(self):
        self.assertEqual(
            releases.repo_api("https://github.com/RiDDiX/ulrmm-alpha"),
            ("github", "https://api.github.com/repos/RiDDiX/ulrmm-alpha/releases"),
        )
        self.assertEqual(
            releases.repo_api(" https://Git.Example.org:3000/me/rmm.git/ "),
            ("gitea", "https://git.example.org:3000/api/v1/repos/me/rmm/releases"),
        )

    def test_rejects(self):
        for bad in (
            "",
            "http://github.com/a/b",
            "https://github.com/a",
            "https://github.com/a/b/c",
            "https://user:pw@github.com/a/b",
            "https://github.com/a/b?x=1",
            "https://github.com/a/b#x",
            "https://github.com/a b/c",
            "github.com/a/b",
            "https://host/../x",
            "https://host/a/..",
        ):
            with self.assertRaises(ValueError, msg=bad):
                releases.repo_api(bad)

    def test_url_host_refuses_urls_two_parsers_read_differently(self):
        self.assertEqual(tasks.url_host("https://Api.GitHub.com/x"), "api.github.com")
        self.assertEqual(tasks.url_host("https://[::1]:8443/x"), "::1")
        for bad in (
            "https://evil.example\\@api.github.com/x",
            "https://127.0.0.1:6379\\@git.riddix.de/a",
        ):
            with self.assertRaises(ValueError, msg=bad):
                tasks.url_host(bad)

    def test_version_key_orders_by_date_then_number(self):
        vs = ["2.27.10.2026", "1.28.10.2026", "10.27.10.2026", "3.01.11.2025"]
        self.assertEqual(
            sorted(vs, key=releases.version_key),
            ["3.01.11.2025", "2.27.10.2026", "10.27.10.2026", "1.28.10.2026"],
        )


class TestManifest(ReleaseBase):
    def test_good_signature(self):
        mb = json.dumps(self.manifest()).encode()
        self.assertEqual(releases.verify_manifest(mb, self.sign(mb))["version"], V)
        self.assertEqual(len(releases.key_id()), 16)

    def test_one_flipped_byte_fails(self):
        mb = json.dumps(self.manifest()).encode()
        sig = self.sign(mb)
        bad = mb[:-3] + bytes([mb[-3] ^ 1]) + mb[-2:]
        with self.assertRaises(releases.ReleaseError):
            releases.verify_manifest(bad, sig)
        with self.assertRaises(releases.ReleaseError):
            releases.verify_manifest(mb, "not base64!")

    def test_shape_is_checked(self):
        for broken in (
            {**self.manifest(), "product": "other"},
            {**self.manifest(), "version": "x/../y"},
            {**self.manifest(), "assets": self.manifest()["assets"][:1]},
            {**self.manifest(), "assets": [{"name": "a", "sha256": "0", "size": 1}]},
        ):
            mb = json.dumps(broken).encode()
            with self.assertRaises(releases.ReleaseError):
                releases.verify_manifest(mb, self.sign(mb))


class TestDownload(ReleaseBase):
    def test_download_verifies_and_reports_progress(self):
        _, rel = releases.discover()
        seen = []
        path = releases.download_and_verify(
            rel, self.tmp / "release", lambda *a: seen.append(a)
        )
        self.assertEqual(path, self.tmp / "release" / V)
        srv, spa = releases.asset_names(V)
        self.assertEqual((path / srv).read_bytes(), self.server)
        self.assertEqual((path / spa).read_bytes(), self.web)
        self.assertEqual((path / "manifest.json").read_bytes(), rel["manifest_bytes"])
        self.assertEqual((path / "manifest.sig").read_text().strip(), rel["sig"])
        total = len(self.server) + len(self.web)
        self.assertEqual(seen[0], ("download", 0, total))
        self.assertEqual(seen[-1], ("verify", total, total))

    def test_sha_mismatch_removes_dir(self):
        srv, spa = releases.asset_names(V)
        self.publish("gh.test", GH, files={srv: self.server, spa: b"x" * len(self.web)})
        _, rel = releases.discover()
        with self.assertRaisesRegex(releases.ReleaseError, "sha256"):
            releases.download_and_verify(rel, self.tmp / "release")
        self.assertFalse((self.tmp / "release" / V).exists())

    def test_size_mismatch_fails(self):
        srv, spa = releases.asset_names(V)
        self.publish("gh.test", GH, files={srv: self.server, spa: self.web + b"!"})
        _, rel = releases.discover()
        with self.assertRaisesRegex(releases.ReleaseError, "size"):
            releases.download_and_verify(rel, self.tmp / "release")
        self.assertFalse((self.tmp / "release" / V).exists())

    def test_missing_tarball_asset_fails(self):
        srv, spa = releases.asset_names(V)
        # the release lists only the server tarball, the manifest both
        self.publish("gh.test", GH, files={srv: self.server})
        lines = []
        self.assertEqual(releases.discover(log=lines.append)[0], "gitea")
        self.assertEqual(lines[0], f"source github: release lacks {spa}")
        self.publish("gt.test", GT, files={srv: self.server})
        with self.assertRaisesRegex(releases.ReleaseError, f"lacks {spa}"):
            releases.discover()

    def test_stream_past_manifest_size_aborts(self):
        srv, spa = releases.asset_names(V)
        self.publish(
            "gh.test",
            GH,
            manifest=self.manifest(),
            files={srv: self.server, spa: self.web + b"x" * (2 * releases.CHUNK)},
        )
        _, rel = releases.discover()
        seen = []
        with self.assertRaisesRegex(releases.ReleaseError, "exceeds the manifest"):
            releases.download_and_verify(
                rel, self.tmp / "release", lambda *a: seen.append(a)
            )
        self.assertFalse((self.tmp / "release" / V).exists())
        # the stream stops at the first chunk past the manifest size
        self.assertLessEqual(seen[-1][1], len(self.server) + len(self.web))

    def test_content_length_past_manifest_size_aborts_early(self):
        srv, spa = releases.asset_names(V)
        _, rel = releases.discover()
        self.routes[f"https://gh.test/dl/{spa}"] = Resp(
            200, self.web, {"Content-Length": str(len(self.web) + 1)}
        )
        with self.assertRaisesRegex(releases.ReleaseError, "Content-Length"):
            releases.download_and_verify(rel, self.tmp / "release")
        self.assertFalse((self.tmp / "release" / V).exists())


class TestProgress(ReleaseBase):
    def test_writer_throttles_and_formats(self):
        path = self.tmp / "update.progress.json"
        cb = releases.progress_writer(path, "github", V)
        cb("download", 0, 100)
        first = json.loads(path.read_text())
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o644")
        self.assertEqual(
            {k: first[k] for k in ("phase", "percent", "bytes", "total", "source")},
            {
                "phase": "download",
                "percent": 0,
                "bytes": 0,
                "total": 100,
                "source": "github",
            },
        )
        cb("download", 50, 100)
        self.assertEqual(json.loads(path.read_text())["bytes"], 0)
        cb("verify", 100, 100)
        data = json.loads(path.read_text())
        self.assertEqual((data["phase"], data["percent"]), ("verify", 100))
        self.assertFalse(path.with_name(path.name + ".tmp").exists())
        self.assertIn("updated_at", data)
        # the final write at 100 percent is never throttled
        cb("verify", 100, 100, "verified")
        self.assertEqual(json.loads(path.read_text())["message"], "verified")
        with mock.patch.object(time, "monotonic", return_value=time.monotonic() + 1):
            cb("verify", 100, 100)


class TestCommand(ReleaseBase):
    def run_cmd(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        call_command(
            "fetch_release",
            dest=str(self.tmp / "release"),
            progress=str(self.tmp / "update.progress.json"),
            stdout=out,
            stderr=err,
            **kw,
        )
        return out.getvalue(), err.getvalue()

    def test_ok(self):
        (self.tmp / "release" / "1.01.01.2026").mkdir(parents=True)
        out, err = self.run_cmd()
        self.assertEqual(out.strip().splitlines()[-1], str(self.tmp / "release" / V))
        self.assertIn(f"source github: ok {V}", err)
        current = self.tmp / "release" / "current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(current.resolve(), (self.tmp / "release" / V).resolve())
        self.assertFalse((self.tmp / "release" / "1.01.01.2026").exists())
        prog = json.loads((self.tmp / "update.progress.json").read_text())
        self.assertEqual((prog["phase"], prog["percent"]), ("verify", 100))
        self.assertEqual(prog["message"], "verified")

    def test_every_source_failed_exits_3(self):
        self.routes[f"{GH}/latest"] = Resp(503, b"")
        self.routes[f"{GT}/latest"] = requests.ConnectionError("down")
        with self.assertRaises(SystemExit) as cm:
            self.run_cmd()
        self.assertEqual(cm.exception.code, 3)
        prog = json.loads((self.tmp / "update.progress.json").read_text())
        self.assertEqual(prog["phase"], "failed")

    def test_missing_tarball_everywhere_exits_3(self):
        srv, _ = releases.asset_names(V)
        self.publish("gh.test", GH, files={srv: self.server})
        self.publish("gt.test", GT, files={srv: self.server})
        with self.assertRaises(SystemExit) as cm:
            self.run_cmd()
        self.assertEqual(cm.exception.code, 3)

    def test_verification_failed_exits_2(self):
        srv, spa = releases.asset_names(V)
        self.publish("gh.test", GH, files={srv: b"tampered", spa: self.web})
        with self.assertRaises(SystemExit) as cm:
            self.run_cmd()
        self.assertEqual(cm.exception.code, 2)
        self.assertFalse((self.tmp / "release" / V).exists())


class TestSourcesStatus(ReleaseBase):
    def test_status_cached_and_refreshed(self):
        self.routes[f"{GH}/latest"] = Resp(503, b"")
        s = releases.sources_status()
        self.assertEqual((s["active"], s["latest"]), ("gitea", V))
        self.assertEqual(s["key_id"], releases.key_id())
        gh, gt = s["sources"]
        self.assertEqual(
            (gh["ok"], gh["status"], gh["error"]), (False, 503, "HTTP 503")
        )
        self.assertEqual((gt["ok"], gt["status"], gt["latest"]), (True, 200, V))
        self.publish("gh.test", GH)
        self.assertEqual(releases.sources_status()["active"], "gitea")
        self.assertEqual(releases.sources_status(refresh=True)["active"], "github")
        cache.set(releases.SOURCES_CACHE_KEY + "_inflight", 1, 60)
        self.assertEqual(releases.sources_status(refresh=True)["active"], "github")


@override_settings(
    CACHES=LOCMEM, ULRMM_RELEASE_SOURCES=None, ULRMM_RELEASE_TRUSTED_HOSTS=[]
)
class BuiltinSourceTest(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.urls = []
        for p in (
            mock.patch.object(releases.requests, "get", side_effect=self.get),
            mock.patch.object(releases, "_repo_sources", return_value=[]),
            mock.patch.object(tasks, "_check_host"),
        ):
            p.start()
            self.addCleanup(p.stop)

    def get(self, url, **kw):
        self.urls.append(url)
        return Resp(404, b"")

    def names(self):
        return [s.name for s in releases.sources()]

    @override_settings(ULRMM_RELEASE_GITEA_TOKEN="")
    def test_without_gitea_token_only_github(self):
        self.assertEqual(self.names(), ["github"])
        self.assertEqual(releases._source_hosts(), {"api.github.com"})
        with self.assertRaises(releases.ReleaseError):
            releases.discover()
        releases.sources_status(refresh=True)
        self.assertTrue(self.urls)
        self.assertFalse([u for u in self.urls if "git.riddix.de" in u])

    @override_settings(ULRMM_RELEASE_GITEA_TOKEN="gtok")
    def test_with_gitea_token_both_as_before(self):
        self.assertEqual(releases.builtin_sources(), releases.DEFAULT_SOURCES)
        self.assertEqual(self.names(), ["github", "gitea"])
        self.assertEqual(releases._source_hosts(), {"api.github.com", "git.riddix.de"})
        releases.sources_status(refresh=True)
        self.assertTrue([u for u in self.urls if "git.riddix.de" in u])

    @override_settings(ULRMM_RELEASE_GITEA_TOKEN="", ULRMM_RELEASE_SOURCES=SOURCES)
    def test_local_settings_list_wins(self):
        self.assertEqual(self.names(), ["github", "gitea"])
        self.assertEqual(releases._source_hosts(), {"gh.test", "gt.test"})

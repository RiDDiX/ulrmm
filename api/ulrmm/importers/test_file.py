# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Import from an export file: riddix/scripts/ulrmm_export.py writes it,
sources/file.py reads it."""

import gzip
import importlib.util
import io
import json
import os
import tempfile
import threading
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import DebugLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import engine, migrate
from .models import ImportedDevice, ImportSource, RemoveState
from .sources import SourceError, file, validate
from .sources.base import Source
from .sources.upstream import Upstream
from .tasks import BUSY, fetch_task, lock_id, remove_task
from .test_sources import Recorded
from .tests import SNAPSHOT, FakeSource
from .views import NO_INSTALL, NO_REMOVE, OLD_FILE

BASE = "/importers/sources"
SCRIPT = Path(__file__).resolve().parents[3] / "riddix/scripts/ulrmm_export.py"
DC = "/agents/DEMOAGENT00xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxCONTOSO-DC01/"
ORIGIN = "https://old.example"
NO_NETWORK = patch(
    "requests.Session.request", side_effect=AssertionError("network used")
)


def _exporter():
    spec = importlib.util.spec_from_file_location("ulrmm_export", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ex = _exporter()


def recorded():
    rec = Recorded("upstream")
    # inventory the exporter leaves out
    rec.answers[DC] = {**rec.answers[DC], "inventory": "x" * 5000}
    return rec


def exporter_get(rec):
    def get(path, params=None):
        try:
            return rec(None, "GET", path, params=params)
        except SourceError:
            raise ex.NotFound(path)

    return get


@lru_cache
def sealed() -> tuple:
    answers = ex.collect(exporter_get(recorded()))
    return answers, *ex.seal(answers, ORIGIN)


def seal_raw(made) -> tuple:
    """A file of any JSON, sealed the way the exporter seals."""
    secret, nonce = os.urandom(20), os.urandom(12)
    header = ex.MAGIC + bytes([ex.FORMAT])
    plain = gzip.compress(json.dumps(made).encode())
    body = ex.AESGCM(ex._aes_key(secret)).encrypt(nonce, plain, header)
    return header + nonce + body, ex.base64.b32encode(secret).decode()


def live(rec=None) -> dict:
    rec = rec or recorded()
    with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
        return validate(Upstream("https://old", True, {}, {"api_key": "K"}).fetch())


class TestFile(SimpleTestCase):
    def test_file_equals_live_read(self):
        answers, data, key = sealed()
        with NO_NETWORK:
            self.assertEqual(file.read(data, key, "upstream"), (live(), ORIGIN))
        # every answer fetch() asked for is in the file
        rec = recorded()
        with patch.object(Source, "call", lambda s, *a, **k: rec(s, *a, **k)):
            Upstream("https://old", True, {}, {"api_key": "K"}).fetch()
        for _, path, kwargs in rec.calls:
            query = ex.answer_key(path, kwargs.get("params"))
            if query in rec.answers or path in rec.answers:
                self.assertIn(query, answers)
        self.assertNotIn("inventory", answers[DC])
        self.assertIn("hostname", answers[DC])

    def test_key_spelling(self):
        _, data, key = sealed()
        loose = " ".join(key.lower().split("-"))
        self.assertTrue(file.read(data, loose, "upstream")[0]["clients"])

    def test_refusals(self):
        _, data, key = sealed()
        other = ex.seal({}, ORIGIN)[1]
        for blob, k, message in (
            (b"garbage", key, file.NOT_OURS),
            (data[:8] + b"\x00" + data[9:], key, "older exporter"),
            (data[:8] + b"\x02" + data[9:], key, "newer exporter"),
            (data, other, file.BAD_KEY),
            (data, "not base32!", file.BAD_KEY),
            (data[:15], key, file.BAD_KEY),
        ):
            with self.assertRaisesMessage(SourceError, message):
                file.read(blob, k, "upstream")

    def test_size_limits(self):
        _, data, key = sealed()
        with patch.object(file, "MAX_FILE", 100):
            with self.assertRaisesMessage(SourceError, "larger than"):
                file.read(data, key, "upstream")
        with patch.object(file, "MAX_PLAIN", 1000):
            with self.assertRaisesMessage(SourceError, "unpacks to more than"):
                file.read(data, key, "upstream")

    def test_shape_and_kind(self):
        good = {"kind": "upstream", "origin": ORIGIN, "answers": {}}
        for made in (
            [],
            {**good, "answers": []},
            {"kind": "upstream", "answers": {}},
            {**good, "origin": "http://old.example"},
            {**good, "origin": "https://u@old.example"},
            {**good, "origin": "https://old.example/" + "a" * 255},
        ):
            data, key = seal_raw(made)
            with self.assertRaisesMessage(SourceError, file.NOT_OURS):
                file.read(data, key, "upstream")
        data, key = ex.seal({}, ORIGIN, kind="ninjaone")
        with self.assertRaisesMessage(SourceError, "NinjaOne, the source"):
            file.read(data, key, "upstream")
        with self.assertRaisesMessage(SourceError, "cannot be imported from a file"):
            file.read(data, key, "ninjaone")
        # a missing answer ends the replay like a live 404
        data, key = ex.seal({}, ORIGIN)
        with self.assertRaisesMessage(SourceError, "The file cannot be used: "):
            file.read(data, key, "upstream")

    def test_repeated_ids_do_not_multiply(self):
        site = {"id": 1, "name": "s"}
        data, key = seal_raw(
            {
                "kind": "upstream",
                "origin": ORIGIN,
                "answers": {
                    "/core/customfields/": [],
                    "/clients/": [{"id": 1, "name": "c", "sites": [site] * 300}],
                    "/agents/notes/": [],
                    "/agents/?site=1": [
                        {"agent_id": f"a{i}", "hostname": f"h{i}"} for i in range(300)
                    ],
                },
            }
        )
        get = Upstream._get
        with patch.object(Upstream, "_get", autospec=True, side_effect=get) as spy:
            with self.assertRaisesMessage(
                SourceError, "The file cannot be used: /agents/ answered 404"
            ):
                file.read(data, key, "upstream")
        # each answer once: the second ask for the same site ends the replay
        self.assertEqual(spy.call_count, 5)


class TestExporter(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_redirect_refused(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("X-API-KEY")))
                self.send_response(302)
                self.send_header("Location", "/elsewhere/")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        get = ex.http_get(f"http://127.0.0.1:{server.server_port}", "K")
        with self.assertRaisesMessage(ex.ExportError, "redirect"):
            get("/clients/")
        self.assertEqual(seen, [("/clients/", "K")])

    def test_short_body(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"[1, 2")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        get = ex.http_get(f"http://127.0.0.1:{server.server_port}", "K")
        with self.assertRaisesMessage(ex.ExportError, "IncompleteRead"):
            get("/clients/")

    def test_https_only_and_no_key_in_argv(self):
        out = os.path.join(self.dir.name, "x.bin")
        with (
            patch.dict(os.environ, {"ULRMM_EXPORT_API_KEY": "K"}),
            patch.object(ex, "http_get", side_effect=AssertionError("requested")),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            for url in (
                "http://old.example",
                "https://u:p@old.example",
                "https://old.example/?a=1",
                "https://old.example/#x",
                "https://old_example",
            ):
                self.assertEqual(ex.main([url, "-o", out]), 1, url)
            # a bad target fails before any request
            bad = os.path.join(self.dir.name, "missing", "x.bin")
            self.assertEqual(ex.main(["https://old.example", "-o", bad]), 1)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(
            ex.origin("https://API.Old.Example:8443/api/"),
            "https://api.old.example:8443/api",
        )
        for spelling in (
            "https://old.example/",
            "https://old.example:443",
            "https://Old.Example.:443/",
        ):
            self.assertEqual(ex.origin(spelling), ORIGIN, spelling)
        self.assertEqual(ex.origin("https://old.example:8443"), ORIGIN + ":8443")
        with self.assertRaises(ValueError):
            ex.origin("https://.")
        with self.assertRaises(SystemExit):
            ex.main(["https://old.example", "--api-key", "K"])

    def test_file_mode_and_no_overwrite(self):
        out = os.path.join(self.dir.name, "x.bin")
        ex.write_new(out, b"one")
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ex.write_new(out, b"two")
        with patch.dict(os.environ, {"ULRMM_EXPORT_API_KEY": "K"}):
            self.assertEqual(ex.main(["https://old.example", "-o", out]), 1)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"one")
        # a failed write leaves no part of a file
        half = os.path.join(self.dir.name, "half.bin")
        with self.assertRaises(TypeError):
            ex.write_new(half, "not bytes")
        self.assertFalse(os.path.exists(half))
        with patch.object(ex, "write_new", side_effect=OSError(28, "No space left")):
            self.assertEqual(self.export(recorded()), (1, False))
        self.assertIn("nothing was written", str(self.printed.call_args_list[-1]))

    def export(self, rec) -> tuple:
        out = os.path.join(self.dir.name, "e.bin")
        with (
            patch.dict(os.environ, {"ULRMM_EXPORT_API_KEY": "K"}),
            patch.object(ex, "http_get", return_value=exporter_get(rec)),
            patch("builtins.print") as self.printed,
        ):
            rc = ex.main(["https://old.example", "-o", out])
        return rc, os.path.exists(out)

    def test_limits_mirror_the_import(self):
        self.assertEqual((ex.MAX_FILE, ex.MAX_PLAIN), (file.MAX_FILE, file.MAX_PLAIN))
        self.assertEqual(self.export(recorded()), (0, True))
        os.remove(os.path.join(self.dir.name, "e.bin"))
        for name in ("MAX_FILE", "MAX_PLAIN"):
            with patch.object(ex, name, 1000):
                self.assertEqual(self.export(recorded()), (1, False), name)

    def test_unexpected_answers(self):
        rec = recorded()
        rec.answers["/checks/"] = {"detail": "nope"}
        self.assertEqual(self.export(rec), (1, False))
        rec = recorded()
        rec.answers["/scripts/1/"] = "gone"
        rec.answers[DC] = ["junk"]
        answers = ex.collect(exporter_get(rec))
        self.assertNotIn(DC, answers)
        # the import skips it, but its fetch asks for it
        self.assertEqual(answers["/scripts/1/"], "gone")
        with self.assertRaisesMessage(ex.ExportError, "/tasks/ gave an unexpected"):
            rec.answers["/tasks/"] = None
            ex.collect(exporter_get(rec))


def _file_source(**kw) -> ImportSource:
    return baker.make(
        ImportSource, kind="upstream", name="old", url="", from_file=True, **kw
    )


@override_settings(CACHES=LOCMEM_CACHE)
class TestFileViews(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()

    def upload(self, src, data=None, key=None):
        if isinstance(data, tuple):
            data, key = data
        _, sealed_data, sealed_key = sealed()
        body = {
            "file": SimpleUploadedFile("x.bin", sealed_data if data is None else data),
            "key": sealed_key if key is None else key,
        }
        return self.client.post(f"{BASE}/{src.pk}/upload/", body, format="multipart")

    def test_superuser_only(self):
        src = _file_source()
        self.client.force_authenticate(
            user=self.create_user_with_roles(["can_manage_integrations"])
        )
        self.check_not_authorized("post", f"{BASE}/{src.pk}/upload/")

    def test_upload_then_import_without_network(self):
        src = _file_source(created={"roles": [7]})
        base = f"{BASE}/{src.pk}"
        r = self.client.get(f"{base}/plan/")
        self.assertEqual(
            (r.status_code, r.data), (400, "Upload the export file first.")
        )
        with NO_NETWORK:
            r = self.upload(src)
            self.assertEqual(r.status_code, 200, r.data)
            self.assertTrue(r.data["from_file"])
            src.refresh_from_db()
            self.assertEqual(src.snapshot, live())
            self.assertEqual(src.url, ORIGIN, "bound to its server")
            self.assertEqual(src.created, {"roles": [7]})
            self.assertEqual(self.client.get(f"{base}/plan/").status_code, 200)
            r = self.client.post(
                f"{base}/import/",
                {"parts": ["custom_fields", "clients", "devices", "scripts"]},
                format="json",
            )
            self.assertEqual(r.status_code, 200)
        self.assertEqual(src.devices.count(), 6)

        ImportSource.objects.filter(pk=src.pk).update(snapshot={"version": 0})
        r = self.client.get(f"{base}/plan/")
        self.assertEqual((r.status_code, r.data), (400, OLD_FILE))
        created = ImportSource.objects.get(pk=src.pk).created
        self.assertEqual(self.upload(src).status_code, 200)
        src.refresh_from_db()
        self.assertEqual(src.snapshot, live())
        self.assertEqual(src.created, created, "an upload never forgets")

        r = self.client.put(
            f"{base}/",
            {"kind": "upstream", "name": "renamed", "from_file": True, "url": ""},
            format="json",
        )
        self.assertEqual((r.status_code, r.data["url"]), (200, ORIGIN))
        before = ImportSource.objects.get(pk=src.pk)
        r = self.upload(src, ex.seal(sealed()[0], "https://other.example"))
        self.assertEqual(
            (r.status_code, r.data),
            (
                400,
                "This file is an export of https://other.example. This source "
                f"holds {ORIGIN}. For another server add a new source; for the "
                f"same server export it again with the address {ORIGIN}.",
            ),
        )
        row = ImportSource.objects.get(pk=src.pk)
        self.assertEqual(
            (row.snapshot, row.last_fetch, row.created, row.url),
            (before.snapshot, before.last_fetch, before.created, ORIGIN),
        )

    def test_without_reporting_module(self):
        rec = recorded()
        for path in ex.REPORTING:
            del rec.answers[path]
        answers = ex.collect(exporter_get(rec))
        self.assertFalse([k for k in answers if k.startswith("/reporting/")])
        src = _file_source()
        with NO_NETWORK:
            r = self.upload(src, ex.seal(answers, ORIGIN))
        self.assertEqual(r.status_code, 200, r.data)
        src.refresh_from_db()
        self.assertEqual(src.snapshot, live(rec))
        self.assertEqual(src.snapshot["report_templates"], [])

    def test_source_deleted_during_upload(self):
        src = _file_source()

        def read(*args):
            ImportSource.objects.filter(pk=src.pk).delete()
            return live(), ORIGIN

        with patch.object(file, "read", side_effect=read):
            self.assertEqual(self.upload(src).status_code, 404)

    def test_refused_uploads_leave_the_row(self):
        then = djangotime.now()
        src = _file_source(snapshot={"version": 1}, last_fetch=then, created={"a": 1})
        _, data, key = sealed()
        flips = [0, 8, 9, 20, len(data) // 2, len(data) - 1]
        for blob, k in [
            *((data[:i] + bytes([data[i] ^ 1]) + data[i + 1 :], key) for i in flips),
            (data[:-10], key),
            (data, ex.seal({}, ORIGIN)[1]),
        ]:
            r = self.upload(src, blob, k)
            self.assertEqual(r.status_code, 400)
            row = ImportSource.objects.get(pk=src.pk)
            self.assertEqual(
                (row.snapshot, row.last_fetch, row.created, row.last_error),
                ({"version": 1}, then, {"a": 1}, ""),
            )
        self.assertEqual(self.upload(src, data, "").status_code, 400)
        with patch.object(file, "MAX_FILE", 10), patch.object(file, "read") as read:
            r = self.upload(src)
        read.assert_not_called()
        self.assertEqual(
            (r.status_code, r.data), (400, "The file is larger than 0 MB.")
        )
        with patch.object(file, "read", side_effect=KeyError("text-of-the-file")):
            r = self.upload(src)
        self.assertEqual((r.status_code, r.data), (400, "unexpected error: KeyError"))
        logged = list(DebugLog.objects.values_list("message", flat=True))
        self.assertTrue(any("KeyError" in m for m in logged), logged)
        self.assertFalse(any("text-of-the-file" in m for m in logged))

    def test_live_source_and_lock(self):
        live_src = baker.make(ImportSource, kind="upstream", url="https://old.example")
        r = self.upload(live_src)
        self.assertEqual(
            (r.status_code, r.data),
            (400, "This source is read from its server, not from a file."),
        )
        src = _file_source()
        cache.add(lock_id(src.pk), "someone")
        r = self.upload(src)
        self.assertEqual((r.status_code, r.data), (409, BUSY))
        self.assertIsNone(ImportSource.objects.get(pk=src.pk).last_fetch)

    def test_no_server_refusals(self):
        src = _file_source()
        base = f"{BASE}/{src.pk}"
        # held: a refusal comes before the lock check
        cache.add(lock_id(src.pk), "someone")
        with (
            patch("importers.views.fetch_task.delay") as fetch_delay,
            patch("importers.views.migrate_task.delay") as migrate_delay,
            patch("importers.views.verify_fresh_totp") as totp,
        ):
            r = self.client.post(f"{base}/fetch/")
            self.assertEqual(
                (r.status_code, r.data),
                (
                    400,
                    "This source has no server to read. Upload the export file instead.",
                ),
            )
            for remove_old in (False, True):
                body = {"devices": [1], "remove_old": remove_old, "totp_code": "1"}
                r = self.client.post(f"{base}/migrate/", body, format="json")
                self.assertEqual((r.status_code, r.data), (400, NO_INSTALL))
            body = {"devices": [1], "totp_code": "1"}
            r = self.client.post(f"{base}/remove/", body, format="json")
            self.assertEqual((r.status_code, r.data), (400, NO_REMOVE))
            fetch_delay.assert_not_called()
            migrate_delay.assert_not_called()
            totp.assert_not_called()

    def test_tasks_never_reach_out(self):
        src = _file_source()
        baker.make(
            ImportedDevice, source=src, ref="d1", remove_state=RemoveState.WAITING_THERE
        )
        with patch("importers.tasks.for_source") as for_source:
            self.assertEqual(fetch_task(src.pk), "ok")
            remove_task()
            for_source.assert_not_called()

    def test_send_pushes_nothing(self):
        src = _file_source(snapshot=validate(SNAPSHOT), last_fetch=djangotime.now())
        engine.run(src, ["custom_fields", "clients", "devices"])
        FakeSource.pushed = []
        ids = list(src.devices.values_list("pk", flat=True))
        fake = FakeSource("https://x", True, {}, {})
        with patch("importers.migrate.for_source", return_value=fake):
            with self.assertRaisesMessage(migrate.MigrateError, "cannot run"):
                migrate.send(src, ids)
        self.assertEqual(FakeSource.pushed, [])

    def test_serializer(self):
        r = self.client.post(
            f"{BASE}/",
            {"kind": "upstream", "name": "f", "from_file": True},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["url"], "")
        for k, v in (
            ("from_file", True),
            ("push_plats", []),
            ("removes_agent", False),
            ("secret_names", []),
            ("secrets_set", []),
            ("parts", list(Upstream.PARTS)),
        ):
            self.assertEqual(r.data[k], v, k)
        url = f"{BASE}/{r.data['id']}/"
        r = self.client.put(url, {"from_file": False}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.put(url, {"name": "g"}, format="json")
        self.assertEqual((r.status_code, r.data["name"]), (200, "g"))
        for body in (
            {
                "kind": "upstream",
                "name": "f",
                "from_file": True,
                "secrets": {"api_key": "K"},
            },
            {"kind": "ninjaone", "name": "f", "from_file": True},
            {"kind": "upstream", "name": "f"},
        ):
            self.assertEqual(
                self.client.post(f"{BASE}/", body, format="json").status_code, 400, body
            )
        self.assertEqual(ImportSource.objects.count(), 1)
        r = self.client.post(
            f"{BASE}/",
            {"kind": "upstream", "name": "s", "url": "https://old.example"},
            format="json",
        )
        self.assertEqual((r.status_code, r.data["from_file"]), (201, False))
        self.assertEqual(r.data["push_plats"], list(Upstream.PUSH_PLATS))

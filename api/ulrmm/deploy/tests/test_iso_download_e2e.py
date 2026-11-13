# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import requests
from django.core.cache import cache

from deploy import iso, iso_layout, tasks
from deploy.models import BaseIso
from deploy.tests.test_iso_views import INFO, IsoTestCase, layout

BODY = random.Random(7).randbytes(3 * 1024 * 1024)
SHA = hashlib.sha256(BODY).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = self.server.body
        etag = '"%s"' % hashlib.sha256(body).hexdigest()[:16]
        rng = self.headers.get("Range")
        self.server.ranges.append(rng)
        start = 0
        if rng and self.headers.get("If-Range", etag) == etag:
            start = int(rng.split("=")[1].rstrip("-"))
            sent = start + self.server.skew
            self.send_response(206)
            self.send_header(
                "Content-Range", f"bytes {sent}-{len(body) - 1}/{len(body)}"
            )
            start = sent
        else:
            self.send_response(200)
        self.send_header("ETag", etag)
        self.send_header("Content-Length", str(len(body) - start))
        self.end_headers()
        for i in range(start, len(body), 256 * 1024):
            self.wfile.write(body[i : i + 256 * 1024])


class DownloadE2E(IsoTestCase):
    def setUp(self):
        super().setUp()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.srv.ranges = []
        self.srv.body = BODY
        self.srv.skew = 0
        t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"https://127.0.0.1:{self.srv.server_port}/win.iso"
        self.hook = None
        real_get = requests.get

        # The task insists on https and a public host; the local server is
        # plain http on loopback, so only the host check and the scheme of
        # the outgoing request are rewritten here.
        def get(url, ip, headers):
            r = real_get(
                url.replace("https://", "http://", 1),
                stream=True,
                timeout=30,
                headers=headers,
                allow_redirects=False,
            )
            orig = r.iter_content

            def chunks(n):
                for i, c in enumerate(orig(n), 1):
                    if self.hook and i > 1:
                        self.hook(i)
                    yield c

            r.iter_content = chunks
            return r

        for p in (
            mock.patch.object(tasks, "_check_host"),
            mock.patch.object(tasks, "_fetch", side_effect=get),
            mock.patch.object(iso, "inspect", return_value=INFO),
        ):
            p.start()
            self.addCleanup(p.stop)

    def start(self, sha=SHA):
        r = self.client.post(
            "/deploy/iso/library/", {"url": self.url, "sha256": sha}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        row = BaseIso.objects.get(pk=r.data["id"])
        self.assertEqual(row.status, "downloading")
        tasks.download_base_iso.delay.assert_called_with(row.pk)
        self.dest = os.path.join(self.dir, row.filename)
        self.part = self.dest + ".part"
        self.addCleanup(cache.delete, f"iso:dl:lock:{row.pk}")
        return row

    def progress(self, pk):
        r = self.client.get("/deploy/iso/library/progress/")
        return {x["id"]: x for x in r.data}[pk]


class TestIsoDownload(DownloadE2E):
    def test_progress_is_real_bytes(self):
        row = self.start()
        seen = []

        def hook(i):
            if i != 2:
                return
            time.sleep(0.7)  # progress reports are rate limited to 0.5 s
            seen.append(self.progress(row.pk))
            seen.append((os.path.exists(self.part), os.path.exists(self.dest)))

        self.hook = hook
        self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        p, (part, dest) = seen
        self.assertEqual(p["status"], "downloading")
        self.assertEqual(p["totalBytes"], len(BODY))
        self.assertTrue(0 < p["downloadedBytes"] < p["totalBytes"])
        self.assertEqual(
            p["progressPercent"], round(p["downloadedBytes"] / p["totalBytes"] * 100, 1)
        )
        self.assertTrue(part)
        self.assertFalse(dest)
        self.assertFalse(os.path.exists(self.part))
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), BODY)
        row.refresh_from_db()
        self.assertEqual((row.status, row.sha256), ("ready", SHA))
        rec = tasks.dl_progress(row.pk)
        self.assertEqual((rec["status"], rec["progressPercent"]), ("ready", 100.0))

    def test_single_flight(self):
        row = self.start()
        self.assertTrue(cache.add(f"iso:dl:lock:{row.pk}", 1, 60))
        self.assertEqual(tasks.download_base_iso(row.pk), "busy")
        self.assertFalse(os.path.exists(self.part))
        again = self.client.post(
            "/deploy/iso/library/", {"url": self.url, "sha256": SHA}, format="json"
        )
        self.assertEqual(again.data["id"], row.pk)
        self.assertEqual(BaseIso.objects.filter(source_url=self.url).count(), 1)

    def test_sha_mismatch(self):
        row = self.start("0" * 64)
        self.assertEqual(tasks.download_base_iso(row.pk), "error")
        row.refresh_from_db()
        self.assertEqual(row.status, "error")
        self.assertIn("SHA-256", row.error)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.part))

    def test_resume_uses_range(self):
        row = self.start()
        with open(self.part, "wb") as f:
            f.write(BODY[: 1024 * 1024])
        with open(self.part + ".validator", "w") as f:
            f.write('"%s"' % SHA[:16])
        self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        self.assertEqual(self.srv.ranges, ["bytes=1048576-"])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), BODY)
        self.assertFalse(os.path.exists(self.part))
        self.assertFalse(os.path.exists(self.part + ".validator"))

    def test_changed_file_is_not_spliced(self):
        row = self.start("")
        self.hook = lambda i: tasks.dl_cancel(row.pk)
        self.assertEqual(tasks.download_base_iso(row.pk), "cancelled")
        self.assertTrue(os.path.exists(self.part + ".validator"))
        self.hook = None
        new = random.Random(8).randbytes(len(BODY))
        self.srv.body = new
        self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        self.assertTrue(self.srv.ranges[1].startswith("bytes="))
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), new)
        row.refresh_from_db()
        self.assertEqual(row.sha256, hashlib.sha256(new).hexdigest())

    def test_replaced_part_is_gone_before_the_first_write(self):
        row = self.start("")
        with open(self.part, "wb") as f:
            f.write(BODY[: 1024 * 1024])
        with open(self.part + ".validator", "w") as f:
            f.write('"%s"' % SHA[:16])
        new = random.Random(8).randbytes(len(BODY))
        self.srv.body = new
        # fails after the 200 answer, before any byte is written
        with mock.patch.object(tasks, "MAX_DOWNLOAD", len(new) - 1):
            self.assertEqual(tasks.download_base_iso(row.pk), "error")
        self.assertEqual(self.srv.ranges, ["bytes=1048576-"])
        self.assertFalse(os.path.exists(self.part))
        self.assertTrue(os.path.exists(self.part + ".validator"))

    def test_part_without_validator_starts_clean(self):
        row = self.start("")
        with open(self.part, "wb") as f:
            f.write(b"x" * 1024)
        self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        self.assertEqual(self.srv.ranges, [None])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), BODY)

    def test_wrong_range_start_starts_clean(self):
        row = self.start("")
        with open(self.part, "wb") as f:
            f.write(BODY[: 1024 * 1024])
        with open(self.part + ".validator", "w") as f:
            f.write('"%s"' % SHA[:16])
        self.srv.skew = 512
        self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        self.assertEqual(self.srv.ranges, ["bytes=1048576-", None])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), BODY)

    def test_cancel_keeps_the_part(self):
        row = self.start()
        self.hook = lambda i: tasks.dl_cancel(row.pk)
        self.assertEqual(tasks.download_base_iso(row.pk), "cancelled")
        self.assertTrue(os.path.exists(self.part))
        self.assertFalse(os.path.exists(self.dest))
        row.refresh_from_db()
        self.assertEqual((row.status, row.error), ("error", "cancelled"))

    def test_then_build_the_full_iso(self):
        for p in (
            mock.patch.object(
                iso_layout, "agent_payload", return_value=("a.exe", b"M")
            ),
            mock.patch.object(iso_layout, "seed", return_value=layout()),
            mock.patch.object(iso_layout, "full", return_value=layout("WIN11")),
        ):
            p.start()
            self.addCleanup(p.stop)
        base = self.start()
        self.assertEqual(tasks.download_base_iso(base.pk), "ready")
        body = {**self.body, "profile": {}, "base": base.pk}
        with mock.patch.object(tasks.build_iso_task, "delay") as delay:
            r = self.client.post("/deploy/iso/build/", body, format="json")
        self.assertEqual(r.status_code, 200)
        job = r.data["job"]
        self.addCleanup(cache.delete, f"iso:job:{job}")

        def inject(src, out, files, *, edits=None, progress=None):
            self.assertEqual(src, self.dest)
            progress(5, 10)
            out.write(b"IMAGE")
            return {"sha256": hashlib.sha256(b"IMAGE").hexdigest(), "size": 5}

        with mock.patch.object(iso, "inject", side_effect=inject):
            self.assertEqual(
                tasks.build_iso_task(job, delay.call_args.args[1], "john"), "done"
            )
        status = self.client.get(f"/deploy/iso/jobs/{job}/")
        self.assertEqual(status.data["state"], "done")
        built = BaseIso.objects.get(pk=status.data["iso"])
        self.assertEqual((built.kind, built.status), ("built", "ready"))

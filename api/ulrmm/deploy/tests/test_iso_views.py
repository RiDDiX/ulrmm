# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.core.cache import cache
from django.test.utils import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from deploy import checksums, iso, iso_layout, signing, tasks, windows
from deploy.models import BaseIso
from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

INFO = {
    "label": "WIN11",
    "size": 4096,
    "bios": True,
    "efi": True,
    "udf": True,
    "os": "windows",
}


def layout(label="ULRMM"):
    return SimpleNamespace(
        label=label,
        files=[("autounattend.xml", b"<x/>"), ("a.exe", b"MZ" * 8)],
        edits={},
        notes=["a note"],
    )


class IsoTestCase(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_base_instance()
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site1,
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": False},
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        over = override_settings(ISO_DIR=self.dir, CACHES=LOCMEM_CACHE)
        over.enable()
        self.addCleanup(over.disable)
        for p in (
            mock.patch.object(windows, "_agent_install_ps1", return_value="# a\n"),
            mock.patch.object(signing, "dist_pubkey_ok", return_value=True),
            mock.patch.object(tasks.inspect_base_iso, "delay"),
            mock.patch.object(tasks.download_base_iso, "delay"),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.body = {"deployment": self.deployment.pk, "target": "win11-pro"}

    def put(self, name, data=b"iso"):
        with open(os.path.join(self.dir, name), "wb") as f:
            f.write(data)

    def ready(self, **kw):
        kw = {"filename": "w.iso", "os": "windows", "status": "ready", **kw}
        return baker.make("deploy.BaseIso", name="w", **kw)


class TestLibrary(IsoTestCase):
    def test_register_rejects_bad_names(self):
        self.put("ok.iso")
        for name in ("../x.iso", "/etc/passwd", "a/b.iso", "gone.iso", "ok.txt", 5):
            r = self.client.post("/deploy/iso/library/", {"filename": name})
            self.assertEqual(r.status_code, 400, name)
        self.assertEqual(BaseIso.objects.count(), 0)

    def test_register_rejects_non_https_url(self):
        for url in (
            "http://x.test/a.iso",
            "ftp://x.test/a.iso",
            "https:///a.iso",
            # urllib3 would connect to internal.lan, urlparse sees example.com
            "https://internal.lan\\@example.com/x.iso",
        ):
            r = self.client.post("/deploy/iso/library/", {"url": url})
            self.assertEqual(r.status_code, 400, url)

    def test_register_file_and_duplicate(self):
        self.put("ok.iso")
        r = self.client.post("/deploy/iso/library/", {"filename": "ok.iso"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["filename"], "ok.iso")
        self.assertEqual(r.data["status"], "inspecting")
        tasks.inspect_base_iso.delay.assert_called_once_with(r.data["id"])
        again = self.client.post("/deploy/iso/library/", {"filename": "ok.iso"})
        self.assertEqual(again.status_code, 400)

    def test_register_url_names_the_file(self):
        r = self.client.post(
            "/deploy/iso/library/", {"url": "https://x.test/p/debian%20x.iso?a=1"}
        )
        self.assertEqual(r.data["filename"], "debian-x.iso")
        self.assertEqual(r.data["status"], "downloading")
        tasks.download_base_iso.delay.assert_called_once_with(r.data["id"])
        r = self.client.post("/deploy/iso/library/", {"url": "https://x.test/get"})
        self.assertRegex(r.data["filename"], r"^download-\d+\.iso$")

    def test_url_dedup_and_error_reuse(self):
        url = "https://x.test/d.iso"
        a = self.client.post("/deploy/iso/library/", {"url": url})
        b = self.client.post("/deploy/iso/library/", {"url": url})
        self.assertEqual(a.data["id"], b.data["id"])
        self.assertEqual(BaseIso.objects.count(), 1)
        BaseIso.objects.update(status="error", error="boom")
        c = self.client.post("/deploy/iso/library/", {"url": url})
        self.assertEqual(c.data["id"], a.data["id"])
        self.assertEqual((c.data["status"], c.data["error"]), ("downloading", ""))

    def test_sha256_stored_lowercase_and_validated(self):
        url = "https://x.test/d.iso"
        bad = self.client.post("/deploy/iso/library/", {"url": url, "sha256": "zz"})
        self.assertEqual(bad.status_code, 400)
        r = self.client.post(
            "/deploy/iso/library/", {"url": url, "sha256": "AB" * 32, "target": "t1"}
        )
        self.assertEqual(r.data["expected_sha256"], "ab" * 32)
        self.assertEqual(r.data["target"], "t1")

    def test_sha256_url_parsing(self):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.iter_content.return_value = [f"{'cd' * 32}  d.iso\n".encode()]
        with mock.patch.object(checksums.requests, "get", return_value=resp):
            r = self.client.post(
                "/deploy/iso/library/",
                {"url": "https://x.test/d.iso", "sha256_url": "https://x.test/SUMS"},
            )
            self.assertEqual(r.data["expected_sha256"], "cd" * 32)
            bad = self.client.post(
                "/deploy/iso/library/",
                {"url": "https://x.test/e.iso", "sha256_url": "https://x.test/SUMS"},
            )
        self.assertEqual(bad.status_code, 400)

    def test_progress_endpoint(self):
        row = baker.make(
            "deploy.BaseIso", name="d", filename="d.iso", status="downloading"
        )
        idle = self.client.get("/deploy/iso/library/progress/")
        self.assertEqual(idle.data[0]["progressPercent"], 0)
        tasks.dl_set(row.pk, status="downloading", progressPercent=42.0)
        r = self.client.get("/deploy/iso/library/progress/")
        self.assertEqual(r.data[0]["id"], row.pk)
        self.assertEqual(r.data[0]["progressPercent"], 42.0)
        self.assertEqual(r.data[0]["filename"], "d.iso")

    def test_cancel_and_retry(self):
        row = baker.make(
            "deploy.BaseIso",
            name="d",
            filename="d.iso",
            status="downloading",
            source_url="https://x.test/d.iso",
        )
        with mock.patch.object(tasks, "dl_cancel") as cancel:
            r = self.client.post(f"/deploy/iso/library/{row.pk}/cancel/")
        self.assertEqual(r.status_code, 200)
        cancel.assert_called_once_with(row.pk)
        self.assertEqual(
            self.client.post(f"/deploy/iso/library/{row.pk}/retry/").status_code, 400
        )
        row.status, row.error = "error", "x"
        row.save()
        self.assertEqual(
            self.client.post(f"/deploy/iso/library/{row.pk}/cancel/").status_code, 400
        )
        r = self.client.post(f"/deploy/iso/library/{row.pk}/retry/")
        self.assertEqual((r.data["status"], r.data["error"]), ("downloading", ""))
        tasks.download_base_iso.delay.assert_called_with(row.pk)

    def test_scan_verify_list_delete(self):
        self.put("a.iso")
        self.put("b.iso")
        self.put("notes.txt")
        r = self.client.post("/deploy/iso/library/scan/")
        self.assertEqual([x["filename"] for x in r.data], ["a.iso", "b.iso"])
        self.assertEqual(self.client.post("/deploy/iso/library/scan/").data, [])
        row = BaseIso.objects.get(filename="a.iso")
        BaseIso.objects.filter(pk=row.pk).update(status="error", error="bad")
        r = self.client.post(f"/deploy/iso/library/{row.pk}/verify/")
        self.assertEqual(r.data["status"], "inspecting")
        self.assertEqual(r.data["error"], "")
        self.assertEqual(len(self.client.get("/deploy/iso/library/").data), 2)
        r = self.client.delete(f"/deploy/iso/library/{row.pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "a.iso")))
        self.assertFalse(BaseIso.objects.filter(pk=row.pk).exists())
        self.assertEqual(
            self.client.delete("/deploy/iso/library/9999/").status_code, 404
        )

    def test_needs_the_manage_flag(self):
        user = self.create_user_with_roles(["can_list_deployments"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get("/deploy/iso/library/").status_code, 200)
        for url in ("library/", "library/scan/", "plan/", "seed/", "build/"):
            r = self.client.post(f"/deploy/iso/{url}", self.body, format="json")
            self.assertEqual(r.status_code, 403, url)
        self.assertEqual(self.client.delete("/deploy/iso/library/1/").status_code, 403)


class TestLibraryTasks(IsoTestCase):
    def test_inspect_fills_the_row(self):
        self.put("w.iso")
        row = baker.make("deploy.BaseIso", name="w", filename="w.iso")
        with (
            mock.patch.object(iso, "sha256_of", return_value="ab" * 32),
            mock.patch.object(iso, "inspect", return_value=INFO),
        ):
            self.assertEqual(tasks.inspect_base_iso(row.pk), "ready")
        row.refresh_from_db()
        self.assertEqual((row.status, row.os, row.label), ("ready", "windows", "WIN11"))
        self.assertEqual((row.sha256, row.size), ("ab" * 32, 4096))
        self.assertTrue(row.bios and row.efi and row.udf)

    def test_inspect_error_is_kept(self):
        row = baker.make("deploy.BaseIso", name="w", filename="w.iso")
        with mock.patch.object(iso, "sha256_of", side_effect=iso.IsoError("not iso")):
            tasks.inspect_base_iso(row.pk)
        row.refresh_from_db()
        self.assertEqual((row.status, row.error), ("error", "not iso"))

    def test_download_streams_and_inspects(self):
        row = baker.make(
            "deploy.BaseIso",
            name="d",
            filename="d.iso",
            source_url="https://x.test/d.iso",
            status="downloading",
        )
        resp = mock.MagicMock(headers={}, history=[], url="https://x.test/d.iso")
        resp.__enter__.return_value = resp
        resp.iter_content.return_value = [b"ab", b"cd"]
        with (
            mock.patch.object(tasks, "_check_host"),
            mock.patch.object(tasks.requests, "get", return_value=resp),
            mock.patch.object(iso, "sha256_of", return_value="cd" * 32),
            mock.patch.object(iso, "inspect", return_value=INFO),
        ):
            self.assertEqual(tasks.download_base_iso(row.pk), "ready")
        with open(os.path.join(self.dir, "d.iso"), "rb") as f:
            self.assertEqual(f.read(), b"abcd")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "d.iso.part")))

    def test_download_over_the_cap_removes_the_part_file(self):
        row = baker.make(
            "deploy.BaseIso",
            name="d",
            filename="d.iso",
            source_url="https://x.test/d.iso",
            status="downloading",
        )
        resp = mock.MagicMock(headers={}, history=[], url="https://x.test/d.iso")
        resp.__enter__.return_value = resp
        resp.iter_content.return_value = [b"abcd"]
        with (
            mock.patch.object(tasks, "_check_host"),
            mock.patch.object(tasks.requests, "get", return_value=resp),
            mock.patch.object(tasks, "MAX_DOWNLOAD", 3),
        ):
            self.assertEqual(tasks.download_base_iso(row.pk), "error")
        row.refresh_from_db()
        self.assertEqual(row.status, "error")
        self.assertEqual(os.listdir(self.dir), [])

    def test_prune_removes_old_jobs_only(self):
        jobs = os.path.join(self.dir, "jobs")
        os.makedirs(jobs)
        for name in ("old.iso", "new.iso"):
            open(os.path.join(jobs, name), "wb").close()
        old = os.path.join(jobs, "old.iso")
        os.utime(old, (1, 1))
        stale = os.path.join(tasks.iso_uploads_dir(), "a" * 32 + ".part")
        open(stale, "wb").close()
        os.utime(stale, (1, 1))
        self.assertEqual(tasks.prune_iso_jobs(), 2)
        self.assertEqual(os.listdir(jobs), ["new.iso"])
        self.assertFalse(os.path.exists(stale))


class TestIsoUploads(IsoTestCase):
    def setUp(self):
        super().setUp()
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        grant_console_stepup(self.john)

    def start(self, filename="new.iso", size=6):
        body = {"filename": filename, "size": size}
        return self.client.post("/deploy/iso/uploads/", body, format="json")

    def chunk(self, uid, data, start=0):
        return self.client.put(
            f"/deploy/iso/uploads/{uid}/",
            data,
            content_type="application/octet-stream",
            HTTP_CONTENT_RANGE=f"bytes {start}-{start + len(data) - 1}/6",
        )

    def finish(self, uid):
        return self.client.post(f"/deploy/iso/uploads/{uid}/finish/")

    def test_flow_registers_and_inspects(self):
        r = self.start()
        self.assertEqual(r.status_code, 201, r.data)
        uid = r.data["id"]
        self.assertEqual(self.chunk(uid, b"abc").data, {"received": 3})
        self.assertEqual(self.chunk(uid, b"abc").status_code, 409)
        self.assertEqual(
            self.client.get(f"/deploy/iso/uploads/{uid}/").data["received"], 3
        )
        self.assertEqual(self.chunk(uid, b"def", 3).data, {"received": 6})
        r = self.finish(uid)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual((r.data["filename"], r.data["kind"]), ("new.iso", "base"))
        tasks.inspect_base_iso.delay.assert_called_once_with(r.data["id"])
        with open(os.path.join(self.dir, "new.iso"), "rb") as f:
            self.assertEqual(f.read(), b"abcdef")
        self.assertEqual(os.listdir(tasks.iso_uploads_dir()), [])
        self.assertIn(
            "uploaded base image new.iso", AuditLog.objects.latest("id").message
        )

    def test_refusals(self):
        for name in ("../x.iso", "a/b.iso", ".x.iso", "x.img", 5):
            self.assertEqual(self.start(name).status_code, 400, name)
        self.put("taken.iso")
        self.assertEqual(self.start("taken.iso").status_code, 400)
        self.assertEqual(self.start(size=tasks.MAX_DOWNLOAD + 1).status_code, 400)
        uid = self.start().data["id"]
        self.chunk(uid, b"abc")
        r = self.finish(uid)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not complete", r.data)
        self.chunk(uid, b"def", 3)
        self.put("new.iso")
        self.assertEqual(self.finish(uid).status_code, 400)
        self.assertEqual(BaseIso.objects.count(), 0)
        self.assertEqual(
            self.client.delete(f"/deploy/iso/uploads/{uid}/").status_code, 200
        )
        self.assertEqual(os.listdir(tasks.iso_uploads_dir()), [])

    def test_needs_stepup(self):
        self.client.force_authenticate(user=self.john)
        r = self.start()
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))


class TestIsoDownload(IsoTestCase):
    def link(self, row):
        return self.client.post(f"/deploy/iso/library/{row.pk}/link/")

    def test_link_and_download(self):
        self.put("w.iso", b"IMAGE")
        row = self.ready(sha256="ab" * 32)
        r = self.link(row)
        self.assertEqual(r.status_code, 200)
        token = r.data["url"].rstrip("/").rsplit("/", 1)[1]
        self.assertIn("downloaded image w", AuditLog.objects.latest("id").message)
        self.client.force_authenticate(user=None)
        url = f"/deploy/iso/download/{token}/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["X-Accel-Redirect"], "/private/iso/w.iso")
        self.assertEqual(r["Content-Disposition"], 'attachment; filename="w.iso"')
        self.assertEqual((r["X-Sha256"], r["Cache-Control"]), ("ab" * 32, "no-store"))
        with override_settings(DEBUG=True):
            r = self.client.get(url)
            self.assertEqual(b"".join(r.streaming_content), b"IMAGE")
        self.assertEqual(self.client.get(url[:-2] + "x/").status_code, 404)
        BaseIso.objects.filter(pk=row.pk).update(status="inspecting")
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_built_link_needs_stepup(self):
        self.put("b.iso")
        r = self.link(self.ready(filename="b.iso", kind="built"))
        self.assertEqual((r.status_code, r.data["stepup"]), (403, True))

    def test_link_needs_a_ready_row(self):
        self.put("w.iso")
        row = self.ready(status="inspecting")
        self.assertEqual(self.link(row).status_code, 400)


class TestIsoBuilds(IsoTestCase):
    def mocks(self):
        for p in (
            mock.patch.object(
                iso_layout, "agent_payload", return_value=("a.exe", b"M")
            ),
            mock.patch.object(iso_layout, "seed", return_value=layout()),
            mock.patch.object(iso_layout, "full", return_value=layout("WIN11")),
        ):
            p.start()
            self.addCleanup(p.stop)

    def test_plan_seed_and_full(self):
        self.mocks()
        r = self.client.post("/deploy/iso/plan/", self.body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["label"], "ULRMM")
        self.assertEqual(r.data["files"], ["autounattend.xml", "a.exe"])
        self.assertEqual(r.data["notes"], ["a note"])
        self.assertEqual(r.data["agent"], "a.exe")
        # an agent the layout leaves out is not announced
        with mock.patch.object(
            iso_layout, "agent_payload", return_value=("b.exe", b"")
        ):
            r = self.client.post("/deploy/iso/plan/", self.body, format="json")
        self.assertIsNone(r.data["agent"])
        self.assertEqual(r.data["size_hint"], 4 + 16)
        body = {**self.body, "mode": "full", "base": None}
        self.assertEqual(
            self.client.post("/deploy/iso/plan/", body, format="json").status_code, 400
        )
        base = self.ready()
        body["base"] = base.pk
        r = self.client.post("/deploy/iso/plan/", body, format="json")
        self.assertEqual(r.data["label"], "WIN11")
        self.assertEqual(iso_layout.full.call_args.args[4]["os"], "windows")

    def test_seed_streams_the_bytes_with_headers_and_audit(self):
        self.mocks()
        blob = bytes(range(256)) * 1000
        before = AuditLog.objects.count()
        with mock.patch.object(iso, "seed_iso", return_value=blob) as seed:
            r = self.client.post("/deploy/iso/seed/", self.body, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(seed.call_args.args[0], "ULRMM")
        self.assertEqual(r["Content-Type"], "application/x-iso9660-image")
        self.assertEqual(r["Content-Length"], str(len(blob)))
        self.assertEqual(r["X-Volume-Label"], "ULRMM")
        self.assertIn("-seed.iso", r["Content-Disposition"])
        self.assertTrue(r["Content-Disposition"].startswith("attachment"))
        got = b"".join(r.streaming_content)
        self.assertEqual(got, blob)
        self.assertEqual(r["X-Sha256"], hashlib.sha256(got).hexdigest())
        self.assertEqual(AuditLog.objects.count(), before + 1)
        self.assertIn(
            "built a win11-pro seed ISO", AuditLog.objects.latest("id").message
        )

    def test_build_checks_the_base(self):
        self.mocks()
        for base in (None, 999):
            body = {**self.body, "base": base}
            r = self.client.post("/deploy/iso/build/", body, format="json")
            self.assertEqual(r.status_code, 400)
        linux = self.ready(filename="l.iso", os="debian")
        body = {**self.body, "base": linux.pk}
        r = self.client.post("/deploy/iso/build/", body, format="json")
        self.assertEqual(r.status_code, 400)
        busy = self.ready(filename="b.iso", status="inspecting")
        body = {**self.body, "base": busy.pk}
        r = self.client.post("/deploy/iso/build/", body, format="json")
        self.assertEqual(r.status_code, 400)
        built = self.ready(filename="x.iso", kind="built")
        body = {**self.body, "base": built.pk}
        r = self.client.post("/deploy/iso/build/", body, format="json")
        self.assertEqual(r.status_code, 400)

    def test_build_job_lifecycle(self):
        self.mocks()
        base = self.ready()
        self.put("w.iso", b"base")
        before = AuditLog.objects.count()
        body = {**self.body, "profile": {}, "base": base.pk}
        with mock.patch.object(tasks.build_iso_task, "delay") as delay:
            r = self.client.post("/deploy/iso/build/", body, format="json")
        self.assertEqual(r.status_code, 200)
        job = r.data["job"]
        self.addCleanup(cache.delete, f"iso:job:{job}")
        self.assertRegex(job, r"^[0-9a-f]{32}$")
        self.assertEqual(delay.call_args.args[0], job)
        self.assertEqual(delay.call_args.args[2], "john")
        self.assertIn(
            "started a win11-pro ISO build", AuditLog.objects.latest("id").message
        )
        self.assertEqual(AuditLog.objects.count(), before + 1)
        status = self.client.get(f"/deploy/iso/jobs/{job}/")
        self.assertEqual((status.data["state"], status.data["iso"]), ("queued", None))

        def inject(src, out, files, *, edits=None, progress=None):
            progress(5, 10)
            out.write(b"IMAGE")
            return {"sha256": hashlib.sha256(b"IMAGE").hexdigest(), "size": 5}

        with (
            mock.patch.object(iso, "inspect", return_value=INFO),
            mock.patch.object(iso, "inject", side_effect=inject),
        ):
            self.assertEqual(
                tasks.build_iso_task(job, delay.call_args.args[1], "john"), "done"
            )
        self.assertEqual(iso_layout.full.call_args.kwargs["base"], INFO)
        status = self.client.get(f"/deploy/iso/jobs/{job}/")
        self.assertEqual(status.data["state"], "done")
        self.assertEqual(status.data["pct"], 100)
        self.assertEqual(status.data["notes"], ["a note"])
        self.assertEqual(status.data["label"], "WIN11")
        self.assertNotIn("path", status.data)
        self.assertNotIn("user", status.data)
        self.assertRegex(status.data["name"], r"^win11-pro-.+\.iso$")
        # the image moved into the library as a built row
        row = BaseIso.objects.get(pk=status.data["iso"])
        self.assertEqual((row.filename, row.status), (status.data["name"], "ready"))
        self.assertEqual(
            (row.kind, row.built_by, row.target), ("built", "john", "win11-pro")
        )
        self.assertEqual(row.sha256, hashlib.sha256(b"IMAGE").hexdigest())
        path = os.path.join(self.dir, row.filename)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"IMAGE")
        self.assertEqual(os.listdir(os.path.join(self.dir, "jobs")), [])
        listed = {x["id"]: x for x in self.client.get("/deploy/iso/library/").data}
        self.assertEqual(listed[row.pk]["kind"], "built")
        self.assertEqual(listed[base.pk]["kind"], "base")
        # another user may not read it
        other = self.create_user_with_roles(["can_list_deployments"])
        self.client.force_authenticate(user=other)
        self.assertEqual(self.client.get(f"/deploy/iso/jobs/{job}/").status_code, 403)
        self.client.force_authenticate(user=self.john)
        self.assertEqual(
            self.client.delete(f"/deploy/iso/jobs/{job}/").status_code, 200
        )
        self.assertFalse(os.path.exists(path))
        self.assertFalse(BaseIso.objects.filter(pk=row.pk).exists())
        self.assertEqual(self.client.get(f"/deploy/iso/jobs/{job}/").status_code, 404)

    def test_build_failure_is_recorded(self):
        self.mocks()
        base = self.ready()
        self.put("w.iso")
        job = "a" * 32
        self.addCleanup(cache.delete, f"iso:job:{job}")
        body = {**self.body, "base": base.pk}
        with (
            mock.patch.object(iso, "inspect", return_value=INFO),
            mock.patch.object(iso, "inject", side_effect=iso.IsoError("no space")),
        ):
            self.assertEqual(tasks.build_iso_task(job, body, "john"), "error")
        rec = cache.get(f"iso:job:{job}")
        self.assertEqual((rec["state"], rec["error"]), ("error", "no space"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "jobs", f"{job}.iso")))

    def test_bad_job_ids_are_404(self):
        for job in ("../etc", "A" * 32, "b" * 31, "c" * 32):
            self.assertEqual(
                self.client.get(f"/deploy/iso/jobs/{job}/").status_code, 404
            )

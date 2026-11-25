# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import gzip
from datetime import timedelta
from hashlib import sha256
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

from django.utils import timezone
from model_bakery import baker
from rest_framework.test import APIClient

from alerts.models import Alert
from logs.models import AuditLog

from .blocks import BATCH_GAP, BLOCK
from .models import (
    BackupRun,
    Image,
    ImagePart,
    ImageStatus,
    StorageTarget,
    Transfer,
)
from .native import REPLACED_RUN
from .runs import STALE
from .tasks import imaging_tick, verify_image
from .test_poll import PollBase


class RunBase(PollBase):
    def claim(self):
        image = self.queue()
        r = self.poll()
        self.assertEqual(r.status_code, 200, getattr(r, "data", None))
        self.grant = r.data
        self.run = BackupRun.objects.get(image=image, status="running")
        return image

    def op(self, op, body=None, method="patch", **extra):
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + self.grant["token"])
        return getattr(client, method)(
            urlsplit(self.grant["url"]).path + op,
            body if body is not None else {},
            format="json",
            secure=True,
            HTTP_HOST="api.example.com",
            **extra,
        )

    def claim_sealed(self):
        from deploy import envelope

        self.identity()
        image = self.queue()
        with patch(
            "imaging.native.envelope.seal_response", wraps=envelope.seal_response
        ) as seal:
            r = self.poll(protocol=2, seal=True)
        self.assertEqual(r.status_code, 200)
        self.grant = seal.call_args.args[2]
        self.run = BackupRun.objects.get(image=image, status="running")
        return image

    def progress(self, **body):
        return self.op("progress/", {"run": str(self.run.id), **body})

    def settle(self, **body):
        with self.captureOnCommitCallbacks(execute=True):
            return self.progress(**body)


class TestProgress(RunBase):
    def test_progress_only_run_required(self):
        self.claim()
        r = self.progress()
        self.assertEqual((r.status_code, r.data), (200, {"cancel": False}))
        r = self.op("progress/", {"run": "6c4a4d1e-3d3c-4d0e-9c6e-6a3f5c0e1b2a"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.op("progress/", method="post").status_code, 409)

    def test_progress_accepts_step_scan_and_pause(self):
        self.claim()
        counters = {"bytes_read": 5, "rate": 3, "eta": None, "expected_bytes": None}
        r = self.progress(state="paused", step="scan", pause_reason="network")
        self.assertEqual(r.status_code, 200)
        r = self.progress(counters=counters)
        self.run.refresh_from_db()
        self.assertEqual(
            (self.run.status, self.run.step, self.run.pause_reason),
            ("paused", "scan", "network"),
        )
        self.assertEqual(self.run.counters, counters)
        self.assertEqual(self.progress(counters={"rate": -1}).status_code, 400)

    def test_progress_caps_and_log_start(self):
        self.claim()
        for n in range(32):
            lines = [f"{n}-{i}" for i in range(64)]
            self.assertEqual(self.progress(log=lines).status_code, 200)
        self.run.refresh_from_db()
        self.assertEqual((len(self.run.log), self.run.log_start), (2000, 48))
        self.assertEqual(self.run.log[0], "0-48")
        self.assertEqual(self.progress(log=["x"] * 65).status_code, 400)
        self.assertEqual(self.progress(log=["x" * 513]).status_code, 400)
        self.assertEqual(
            self.progress(warnings=[{"code": "other", "detail": "w"}] * 65).status_code,
            400,
        )
        url = f"{self.uri}runs/{self.run.id}/?log_from=2040"
        r = self.client.get(url)
        self.assertEqual((r.data["log_start"], len(r.data["log"])), (2040, 8))
        self.assertEqual(r.data["log"][0], "31-56")
        big = "x" * (300 * 1024)
        self.assertEqual(self.progress(log=[big]).status_code, 413)

    def test_progress_after_seal_adds_only_log_hooks_warnings(self):
        image = self.claim()
        image.status = ImageStatus.VERIFYING
        image.save(update_fields=["status"])
        r = self.progress(state="paused", step="cleanup", log=["late"])
        self.assertEqual(r.status_code, 200)
        self.run.refresh_from_db()
        self.assertEqual((self.run.status, self.run.step), ("running", "snapshot"))
        self.assertEqual(self.run.log, ["late"])
        final = {"status": "failed", "reason": "no"}
        self.assertEqual(
            self.progress(final=final).data["detail"], "This run has ended."
        )
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, "running")

    def test_final_failed_interrupted_cancelled(self):
        image = self.claim()
        r = self.settle(final={"status": "failed", "reason": "Capture failed: x"})
        self.assertEqual(r.status_code, 200)
        image.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual((self.run.status, image.status), ("failed", "failed"))
        state = self.state()
        self.assertEqual(state.consecutive_failures, 1)
        self.assertIn("run_failed", state.alerts)
        # every final expires the grant
        r = self.progress(final={"status": "failed", "reason": "again"})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(
            AuditLog.objects.filter(
                message=f"Backup run {self.run.id} failed: Capture failed: x."
            ).exists()
        )

        image = self.claim()
        self.settle(final={"status": "interrupted", "reason": "The network was lost."})
        image.refresh_from_db()
        self.run.refresh_from_db()
        self.assertEqual((self.run.status, image.status), ("interrupted", "waiting"))
        self.assertFalse(
            Transfer.objects.filter(image=image, expires_at__gt=timezone.now()).exists()
        )
        self.assertEqual(self.state().consecutive_interruptions, 1)

        r = self.poll()
        self.assertEqual(r.status_code, 200)
        self.grant = r.data
        self.run = BackupRun.objects.get(image=image, status="running")
        BackupRun.objects.filter(pk=self.run.pk).update(cancel_requested=True)
        self.settle(
            final={"status": "cancelled", "reason": "Cancelled from the dashboard."}
        )
        image.refresh_from_db()
        self.assertEqual(image.reason, "Backup cancelled by the agent.")
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "cancelled")
        self.assertEqual(self.state().consecutive_interruptions, 1)

    def test_three_interruptions_alert(self):
        image = self.queue()
        for _ in range(3):
            r = self.poll()
            self.assertEqual(r.status_code, 200)
            self.grant = r.data
            self.run = BackupRun.objects.get(image=image, status="running")
            self.settle(final={"status": "interrupted", "reason": "Paused."})
        alerts = Alert.objects.filter(agent=self.agent, alert_type="backup")
        self.assertEqual(
            list(alerts.values_list("message", flat=True)),
            ["Backup runs were interrupted three times in a row."],
        )

    def test_final_takes_image_lock(self):
        from . import views

        self.claim()
        with patch("imaging.views._lock_image", wraps=views._lock_image) as lock:
            self.progress(log=["a"])
            lock.assert_not_called()
            self.progress(final={"status": "failed", "reason": "x"})
            lock.assert_called_once()

    def test_progress_renews_grant_while_live(self):
        self.claim()
        grant = Transfer.objects.get(pk=self.grant["claim"])
        soon = timezone.now() + timedelta(minutes=5)
        Transfer.objects.filter(pk=grant.pk).update(expires_at=soon)
        self.assertEqual(self.progress(log=["hook running"]).status_code, 200)
        grant.refresh_from_db()
        self.assertGreater(grant.expires_at, timezone.now() + timedelta(minutes=50))
        # an ended run renews nothing
        BackupRun.objects.filter(pk=self.run.pk).update(status="failed")
        Transfer.objects.filter(pk=grant.pk).update(expires_at=soon)
        self.assertEqual(self.progress(log=["late"]).status_code, 200)
        grant.refresh_from_db()
        self.assertEqual(grant.expires_at, soon)

    def test_hook_results_stored_once_and_audited(self):
        from . import resolver
        from .models import Profile

        script = baker.make("scripts.Script", name="Dump", shell="bash")
        stranger = baker.make("scripts.Script", name="Other", shell="bash")
        hooks = [
            {
                "script_id": script.pk,
                "phase": "pre-backup",
                "args": [],
                "env_vars": [],
                "timeout": 60,
                "on_fail": "abort",
            }
        ]
        Profile.objects.filter(agent=self.agent).update(overrides={"hooks": hooks})
        resolver.resolve_device(self.agent, cause="device")
        self.poll(protocol=2)
        self.claim_sealed()
        result = {
            "phase": "pre-backup",
            "script_id": script.pk,
            "sha256": "a" * 64,
            "status": "ok",
            "exit_code": 0,
            "duration_ms": 12,
            "stdout": "done",
            "stderr": "",
        }
        foreign = {**result, "script_id": stranger.pk}
        for _ in range(2):
            self.assertEqual(self.progress(hooks=[result, foreign]).status_code, 200)
        self.run.refresh_from_db()
        self.assertEqual(self.run.hooks, [result])
        audits = AuditLog.objects.filter(message__startswith="Backup hook Dump")
        self.assertEqual(audits.count(), 1)
        self.assertIn(f"ok in pre-backup for run {self.run.id}", audits.get().message)


class TestRunStates(RunBase):
    def test_reclaim_interrupts_open_run(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(
            updated_at=timezone.now() - timedelta(hours=2)
        )
        with self.captureOnCommitCallbacks(execute=True):
            r = self.poll()
        self.assertEqual(r.status_code, 200)
        old = BackupRun.objects.get(pk=self.run.pk)
        self.assertEqual((old.status, old.reason), ("interrupted", REPLACED_RUN))
        self.assertEqual(BackupRun.objects.filter(status="running").count(), 1)

    def test_sealing_failure_counts_the_replaced_run_once(self):
        from django.http import HttpResponse

        self.identity()
        image = self.queue()
        run = BackupRun.objects.create(
            image=image, trigger="manual", status="running", agent_protocol=2
        )
        before = self.state().consecutive_interruptions
        with (
            patch("imaging.native.envelope.seal_response", return_value=HttpResponse()),
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.poll(protocol=2, seal=True)
        self.assertEqual(r.status_code, 204)
        self.assertFalse(Transfer.objects.exists())
        self.assertEqual(BackupRun.objects.get(pk=run.pk).status, "interrupted")
        deferred = BackupRun.objects.get(image=image, status="deferred")
        self.assertEqual(deferred.deferred_reason, "sealing")
        self.assertEqual(self.state().consecutive_interruptions, before + 1)

    def test_reporting_protocol2_run_is_not_claimed_again(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(
            updated_at=timezone.now() - timedelta(hours=2)
        )
        BackupRun.objects.filter(pk=self.run.pk).update(agent_protocol=2)
        self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "running")

    def test_seal_moves_the_run_to_verify(self):
        from .service import set_status

        image = self.claim()
        set_status(image, ImageStatus.VERIFYING, "Verifying.")
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).step, "verify")

    def test_smart_abort_blocks_the_claim(self):
        from .test_poll import agent_check

        self.identity()
        image = self.queue()
        failed = agent_check("failed", id="smart.source", blocking=False, detail="sda")
        self.save_smart("abort")
        r = self.poll(protocol=2, seal=True, checks=[failed])
        self.assertEqual(r.status_code, 204)
        image.refresh_from_db()
        self.assertEqual(image.reason, "sda")
        self.save_smart("warn")
        r = self.poll(protocol=2, seal=True, checks=[failed])
        self.assertEqual(r.status_code, 200)

    def save_smart(self, level):
        from . import resolver
        from .models import Profile

        Profile.objects.filter(agent=self.agent).update(overrides={"smart": level})
        resolver.resolve_device(self.agent, cause="device")

    def test_stale_protocol2_run_uses_claim_pause_column(self):
        image = self.claim()
        runs = BackupRun.objects.filter(pk=self.run.pk)
        runs.update(
            agent_protocol=2,
            pause_max_minutes=30,
            updated_at=timezone.now() - timedelta(minutes=40),
        )
        imaging_tick()
        self.assertEqual(runs.get().status, "running")
        runs.update(pause_max_minutes=0)
        with self.captureOnCommitCallbacks(execute=True):
            imaging_tick()
        run = runs.get()
        image.refresh_from_db()
        self.assertEqual((run.status, run.reason), ("interrupted", STALE))
        self.assertEqual(image.status, "waiting")
        self.assertFalse(
            Transfer.objects.filter(image=image, expires_at__gt=timezone.now()).exists()
        )

    def test_stale_rule_keys_on_point_status(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFYING)
        BackupRun.objects.filter(pk=self.run.pk).update(
            agent_protocol=2, updated_at=timezone.now() - timedelta(hours=5)
        )
        with patch("imaging.tasks.verify_image.delay"):
            imaging_tick()
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "running")

    def test_tick_never_ends_legacy_run_or_expires_its_transfer(self):
        image = self.claim()
        BackupRun.objects.filter(pk=self.run.pk).update(
            updated_at=timezone.now() - timedelta(hours=5)
        )
        imaging_tick()
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "running")
        self.assertTrue(
            Transfer.objects.filter(image=image, expires_at__gt=timezone.now()).exists()
        )

    def test_server_side_point_failure_ends_run_failed(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(
            status=ImageStatus.UPLOADING,
            updated_at=timezone.now() - timedelta(days=2),
        )
        with self.captureOnCommitCallbacks(execute=True):
            imaging_tick()
        run = BackupRun.objects.get(pk=self.run.pk)
        self.assertEqual(
            (run.status, run.reason), ("failed", "Incomplete upload expired.")
        )
        self.assertEqual(self.state().consecutive_failures, 1)

    def test_seal_and_verification_end_the_run(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFYING)
        with (
            patch("imaging.tasks.verify_point", return_value=True),
            self.captureOnCommitCallbacks(execute=True),
        ):
            verify_image(str(image.pk))
        run = BackupRun.objects.get(pk=self.run.pk)
        self.assertEqual(run.status, "succeeded")
        state = self.state()
        image.refresh_from_db()
        self.assertEqual(state.last_success_at, image.verified_at)
        success = state.last_success_at
        # a recheck that fails changes no run and no success time
        with (
            patch("imaging.tasks.verify_point", return_value=False),
            self.captureOnCommitCallbacks(execute=True),
        ):
            verify_image(str(image.pk), recheck=True)
        state = self.state()
        self.assertEqual(state.last_success_at, success)
        self.assertIn("verify_failed", state.alerts)
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "succeeded")

    def test_target_run_limit(self):
        target = StorageTarget.objects.get(is_default=True)
        StorageTarget.objects.filter(pk=target.pk).update(max_runs=1)
        other = baker.make("agents.Agent", plat="windows", goarch="amd64")
        busy = baker.make(
            Image,
            agent=other,
            target=target,
            native={"method": "windows-wbadmin-tar-v1"},
            status=ImageStatus.UPLOADING,
            destination=target.name,
            network_mode="internet",
            compression="gzip",
            compression_level=6,
        )
        run = BackupRun.objects.create(image=busy, trigger="manual", status="running")
        image = self.queue()
        self.assertEqual(self.poll().status_code, 204)
        image.refresh_from_db()
        self.assertEqual(
            image.reason, f"Waiting: 1 backups already run on target {target.name}."
        )
        self.assertEqual(
            BackupRun.objects.get(image=image).deferred_reason, "target_busy"
        )
        # a quiet legacy run past the idle limit frees its slot
        Image.objects.filter(pk=busy.pk).update(
            updated_at=timezone.now() - timedelta(minutes=10)
        )
        self.assertEqual(run.agent_protocol, 0)
        self.assertEqual(self.poll().status_code, 200)

    def test_manual_request_returns_open_point(self):
        first = self.queue()
        self.assertEqual(self.queue(), first)

    def test_log_cleared_after_30_days(self):
        self.claim()
        old = timezone.now() - timedelta(days=31)
        BackupRun.objects.filter(pk=self.run.pk).update(
            status="failed", ended_at=old, updated_at=old, log=["a"]
        )
        imaging_tick()
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).log, [])


class TestCancel(RunBase):
    def test_cancel_legacy_discards_server_side(self):
        image = self.claim()
        r = self.client.post(f"{self.uri}runs/{self.run.id}/cancel/", {}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            set(r.data),
            {
                "id",
                "image",
                "trigger",
                "status",
                "step",
                "deferred_reason",
                "reason",
                "pause_reason",
                "counters",
                "warnings",
                "hooks",
                "output_hidden",
                "cancel_requested",
                "cancelled_by",
                "created_at",
                "started_at",
                "ended_at",
            },
        )
        self.assertEqual(
            (r.data["status"], r.data["cancelled_by"]), ("cancelled", "john")
        )
        image.refresh_from_db()
        self.assertEqual((image.status, image.reason), ("failed", "Capture discarded."))
        r = self.client.post(f"{self.uri}runs/{self.run.id}/cancel/", {}, format="json")
        self.assertEqual(
            (r.status_code, r.data["detail"]), (409, "This run has ended.")
        )

    def test_cancel_flag_in_patch_answer(self):
        self.claim()
        self.poll(protocol=2)
        self.agent.last_seen = timezone.now()
        self.agent.save(update_fields=["last_seen"])
        with (
            patch("agents.models.Agent.nats_cmd", new_callable=AsyncMock) as nats,
            self.captureOnCommitCallbacks(execute=True),
        ):
            r = self.client.post(
                f"{self.uri}runs/{self.run.id}/cancel/", {}, format="json"
            )
        self.assertEqual((r.status_code, r.data["status"]), (200, "running"))
        self.assertTrue(r.data["cancel_requested"])
        nats.assert_awaited_once_with(
            {"func": "imagingcancel", "payload": {"run": str(self.run.id)}}, wait=False
        )
        self.assertEqual(self.progress().data, {"cancel": True})
        self.settle(
            final={"status": "cancelled", "reason": "Cancelled from the dashboard."}
        )
        image = Image.objects.get(pk=self.run.image_id)
        self.assertEqual(image.reason, "Backup cancelled by john.")

    def test_cancel_refused_while_verifying(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFYING)
        r = self.client.post(f"{self.uri}runs/{self.run.id}/cancel/", {}, format="json")
        self.assertEqual(r.data["detail"], "The backup is sealed and being verified.")


class TestParts(RunBase):
    def put_part(self, data, index):
        url = f"part/?i={index}&size={len(data)}&sha256={sha256(data).hexdigest()}"
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + self.grant["token"])
        return client.put(
            urlsplit(self.grant["url"]).path + url,
            gzip.compress(data),
            content_type="application/octet-stream",
            secure=True,
            HTTP_HOST="api.example.com",
        )

    def entry(self, i, data):
        return {"i": i, "size": len(data), "id": sha256(data).hexdigest()}

    def test_parts_batch(self):
        image = self.claim()
        known = b"A" * BLOCK
        self.assertEqual(
            self.op("parts/", {"parts": [self.entry(0, known)]}, "post").status_code,
            409,
        )
        self.assertEqual(self.op("begin/", method="post").status_code, 204)
        self.assertEqual(self.put_part(known, 0).status_code, 204)
        self.assertEqual(self.op("begin/", method="post").status_code, 204)
        grant = Transfer.objects.get(pk=self.grant["claim"])
        Transfer.objects.filter(pk=grant.pk).update(
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        batch = [self.entry(0, known), self.entry(1, known), self.entry(2, b"new")]
        r = self.op("parts/", {"parts": batch}, "post")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data, {"attached": 2, "missing": [2], "offset": 2 * BLOCK})
        self.assertEqual(ImagePart.objects.filter(image=image).count(), 2)
        grant.refresh_from_db()
        self.assertGreater(grant.expires_at, timezone.now() + timedelta(minutes=50))
        r = self.op("parts/", {"parts": [self.entry(0, known)]}, "post")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.data, {"detail": BATCH_GAP, "offset": 2 * BLOCK})
        gap = [self.entry(2, known), self.entry(4, known)]
        self.assertEqual(self.op("parts/", {"parts": gap}, "post").status_code, 400)
        self.assertEqual(self.op("parts/", {"parts": []}, "post").status_code, 400)
        many = [self.entry(2 + i, known) for i in range(513)]
        self.assertEqual(self.op("parts/", {"parts": many}, "post").status_code, 400)


class TestRunReview(RunBase):
    def cancel(self):
        return self.client.post(
            f"{self.uri}runs/{self.run.id}/cancel/", {}, format="json"
        )

    def test_cancel_discards_only_open_points(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFIED)
        r = self.cancel()
        self.assertEqual(r.status_code, 409)
        self.assertEqual(Image.objects.get(pk=image.pk).status, "verified")

    def test_failed_point_ends_its_deferred_row(self):
        from .service import set_status

        self.identity()
        image = self.queue()
        self.assertEqual(self.poll(protocol=2).status_code, 204)
        run = BackupRun.objects.get(image=image)
        self.assertEqual(run.status, "deferred")
        set_status(image, ImageStatus.FAILED, "The backup source changed.")
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.reason), ("failed", "The backup source changed.")
        )

    def test_defer_of_a_quiet_run_expires_its_grant(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(
            updated_at=timezone.now() - timedelta(hours=2)
        )
        with patch("imaging.native.window", return_value=(False, None)):
            self.assertEqual(self.poll().status_code, 204)
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "interrupted")
        self.assertFalse(
            Transfer.objects.filter(image=image, expires_at__gt=timezone.now()).exists()
        )

    def test_unrequested_cancel_counts_as_failure(self):
        image = self.claim()
        self.settle(final={"status": "cancelled", "reason": "Disk full."})
        run = BackupRun.objects.get(pk=self.run.pk)
        self.assertEqual((run.status, run.reason), ("failed", "Disk full."))
        image.refresh_from_db()
        self.assertEqual(image.reason, "Disk full.")
        self.assertEqual(self.state().consecutive_failures, 1)
        self.assertFalse(
            Transfer.objects.filter(image=image, expires_at__gt=timezone.now()).exists()
        )

    def test_cancel_keeps_the_stale_clock_and_ends_a_stale_run(self):
        image = self.claim()
        self.poll(protocol=2)
        old = timezone.now() - timedelta(minutes=50)
        runs = BackupRun.objects.filter(pk=self.run.pk)
        runs.update(agent_protocol=2, updated_at=old)
        self.agent.last_seen = timezone.now()
        self.agent.save(update_fields=["last_seen"])
        with patch("agents.models.Agent.nats_cmd", new_callable=AsyncMock):
            self.assertEqual(self.cancel().status_code, 200)
        self.assertEqual(runs.get().updated_at, old)
        with self.captureOnCommitCallbacks(execute=True):
            imaging_tick()
        self.assertEqual(runs.get().status, "cancelled")
        image.refresh_from_db()
        self.assertEqual(
            (image.status, image.reason), ("failed", "Backup cancelled by john.")
        )

    def test_ended_runs_per_point_are_bounded(self):
        image = self.queue()
        for _ in range(23):
            r = self.poll()
            self.assertEqual(r.status_code, 200)
            self.grant = r.data
            self.run = BackupRun.objects.get(image=image, status="running")
            self.progress(final={"status": "interrupted", "reason": "x"})
        self.assertEqual(BackupRun.objects.filter(image=image).count(), 20)

    def test_parts_body_cap(self):
        self.claim()
        self.assertEqual(self.op("begin/", method="post").status_code, 204)
        entry = {"i": 0, "size": 1, "id": "a" * 64, "pad": "x" * (130 * 1024)}
        r = self.op("parts/", {"parts": [entry]}, "post")
        self.assertEqual(r.status_code, 413)

    def test_hook_output_only_for_script_users(self):
        self.claim()
        result = {
            "phase": "pre-backup",
            "script_id": 1,
            "sha256": "",
            "status": "ok",
            "stdout": "secret output",
            "stderr": "",
        }
        BackupRun.objects.filter(pk=self.run.pk).update(hooks=[result])
        url = f"{self.uri}runs/{self.run.id}/"
        row = self.client.get(url).data
        self.assertEqual(
            (row["output_hidden"], row["hooks"][0]["stdout"]), (False, "secret output")
        )
        viewer = self.create_user_with_roles(["can_view_images"])
        self.client.force_authenticate(viewer)
        for row in (
            self.client.get(url).data,
            self.client.get(self.uri).data["runs"][0],
        ):
            self.assertTrue(row["output_hidden"])
            self.assertNotIn("stdout", row["hooks"][0])
            self.assertNotIn("stderr", row["hooks"][0])

    def test_hook_results_only_for_carried_hooks(self):
        self.claim()
        BackupRun.objects.filter(pk=self.run.pk).update(
            claimed_hooks=[{"phase": "pre-backup", "script_id": 7, "sha256": ""}]
        )
        result = {"phase": "pre-backup", "script_id": 7, "sha256": "", "status": "ok"}
        other = {**result, "phase": "post-backup"}
        self.assertEqual(self.progress(hooks=[result, other]).status_code, 200)
        stored = BackupRun.objects.get(pk=self.run.pk).hooks
        self.assertEqual(
            [(h["phase"], h["script_id"]) for h in stored], [("pre-backup", 7)]
        )


class TestQuietEnds(RunBase):
    def requested(self):
        image = self.claim()
        BackupRun.objects.filter(pk=self.run.pk).update(
            cancel_requested=True, cancelled_by=self.john
        )
        Image.objects.filter(pk=image.pk).update(
            updated_at=timezone.now() - timedelta(hours=2)
        )
        return image

    def assert_cancelled(self, image):
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "cancelled")
        image.refresh_from_db()
        self.assertEqual(
            (image.status, image.reason), ("failed", "Backup cancelled by john.")
        )
        self.assertFalse(BackupRun.objects.filter(status="running").exists())

    def test_reclaim_keeps_a_requested_cancel(self):
        image = self.requested()
        self.assertEqual(self.poll().status_code, 204)
        self.assert_cancelled(image)

    def test_deferral_keeps_a_requested_cancel(self):
        image = self.requested()
        with patch("imaging.native.window", return_value=(False, None)):
            self.assertEqual(self.poll().status_code, 204)
        self.assert_cancelled(image)

    def test_final_interrupted_keeps_a_requested_cancel(self):
        image = self.requested()
        self.progress(final={"status": "interrupted", "reason": "The agent stopped."})
        self.assert_cancelled(image)

    def test_failure_report_keeps_a_requested_cancel(self):
        image = self.requested()
        r = self.poll(
            image_id=str(image.id), failure="capture", claim=self.grant["claim"]
        )
        self.assertEqual(r.status_code, 204)
        self.assert_cancelled(image)


class TestReviewGaps(RunBase):
    def stale_usage(self):
        from .models import DeviceBackupState, Profile

        target = Profile.objects.get(agent=self.agent).target_id
        DeviceBackupState.objects.filter(agent=self.agent).update(
            usage={str(target): 999}
        )

    def usage(self):
        return sum(self.state().usage.values())

    def test_discard_expiry_replacement_and_watch_recompute_usage(self):
        from .service import queue_capture
        from .tasks import imaging_watch

        image = self.queue()
        self.stale_usage()
        with self.captureOnCommitCallbacks(execute=True):
            r = self.client.post(
                f"{self.uri}images/{image.pk}/cancel/", {}, format="json"
            )
        self.assertEqual((r.status_code, self.usage()), (204, 0))

        image = self.queue()
        Image.objects.filter(pk=image.pk).update(
            status=ImageStatus.UPLOADING, updated_at=timezone.now() - timedelta(days=2)
        )
        self.stale_usage()
        with self.captureOnCommitCallbacks(execute=True):
            imaging_tick()
        self.assertEqual(self.usage(), 0)

        point = self.schedule_point()
        self.stale_usage()
        profile = point.agent.profile
        with self.captureOnCommitCallbacks(execute=True):
            self.assertIsNotNone(
                queue_capture(profile, "imaging scheduler", trigger="schedule")
            )
        self.assertEqual(self.usage(), 0)

        self.claim()
        self.stale_usage()
        with self.captureOnCommitCallbacks(execute=True):
            self.progress(final={"status": "failed", "reason": "Capture failed: x"})
        self.assertEqual(self.usage(), 0)

        self.stale_usage()
        state = self.state()
        state.alerts = {"quota_high": 0}
        state.save(update_fields=["alerts"])
        imaging_watch()
        self.assertEqual(self.usage(), 0)

    def test_failed_run_keeps_blocks_and_the_next_run_reuses_them(self):
        from django.conf import settings
        from pathlib import Path

        from .blocks import _namespace
        from .models import ImageBlock, ImagePart

        image = self.claim()
        self.assertEqual(self.op("begin/", method="post").status_code, 204)
        image.refresh_from_db()
        data = b"kept block"
        block = ImageBlock.objects.create(
            namespace=_namespace(image),
            destination=image.destination,
            digest=sha256(data).hexdigest(),
            size=len(data),
            stored_size=4,
            created_at=timezone.now() - timedelta(days=3),
        )
        folder = Path(settings.ULRMM_IMAGING_ROOT, image.destination)
        folder.mkdir(mode=0o700, exist_ok=True)
        stored = folder / str(block.pk)
        stored.write_bytes(b"gzip")
        stored.chmod(0o600)
        ImagePart.objects.create(image=image, index=0, block=block)
        self.progress(final={"status": "failed", "reason": "Capture failed: x"})
        imaging_tick()
        self.assertTrue(ImageBlock.objects.filter(pk=block.pk).exists())
        self.claim()
        self.assertEqual(self.op("begin/", method="post").status_code, 204)
        entry = {"i": 0, "size": len(data), "id": sha256(data).hexdigest()}
        r = self.op("parts/", {"parts": [entry]}, "post")
        self.assertEqual((r.status_code, r.data["attached"]), (200, 1), r.data)

    def test_settle_keeps_the_just_verified_point(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFYING)
        with (
            patch("imaging.tasks.verify_point", return_value=True),
            patch("imaging.tasks.prune_device") as prune,
            self.captureOnCommitCallbacks(execute=True),
        ):
            verify_image(str(image.pk))
        self.assertEqual(prune.call_args.kwargs, {"keep": {image.pk}})

    def test_deferred_row_of_a_verified_point_ends(self):
        image = self.claim()
        Image.objects.filter(pk=image.pk).update(status=ImageStatus.VERIFYING)
        deferred = BackupRun.objects.create(image=image, trigger="manual")
        with (
            patch("imaging.tasks.verify_point", return_value=True),
            self.captureOnCommitCallbacks(execute=True),
        ):
            verify_image(str(image.pk))
        deferred.refresh_from_db()
        self.assertEqual(deferred.status, "cancelled")
        self.assertEqual(BackupRun.objects.get(pk=self.run.pk).status, "succeeded")

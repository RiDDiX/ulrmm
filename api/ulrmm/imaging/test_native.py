# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os
import shutil
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit
import gzip

from django.test import override_settings
from django.utils import timezone
from model_bakery import baker
from rest_framework.test import APIClient

from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase
from .blocks import BLOCK
from . import resolver
from .models import (
    MODE_CHANGED,
    NATIVE_RECEIVING_REASON,
    BackupPolicy,
    Image,
    ImageBlock,
    ImageStatus,
    Profile,
    StorageTarget,
    Transfer,
)
from .service import NO_INTERNAL
from .storage import MARKER, NO_SPACE, OTHER_STORE
from .tasks import imaging_tick, verify_image
from .tests import other_disk


class NativeBackupTests(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.agent = baker.make(
            "agents.Agent",
            agent_id="test-native-agent",
            plat="windows",
            goarch="amd64",
            time_zone="UTC",
        )
        self.fleet = StorageTarget.objects.create(name="fleet")
        self.agent_user = self.authenticate_agent(self.agent)
        self.worker = self.client
        self.client = APIClient()
        self.client.force_authenticate(self.john)
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(
            override_settings(
                ULRMM_IMAGING_ROOT=str(self.root),
                ULRMM_IMAGING_PUBLIC_ORIGIN="https://api.example.com",
                ULRMM_IMAGING_RESERVE_BYTES=0,
                ALLOWED_HOSTS=["api.example.com", "testserver"],
            )
        )
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"
        self.poll = f"/api/v3/{self.agent.agent_id}/imaging/"
        self.cap = dict(
            method="windows-wbadmin-tar-v1",
            ready=True,
            scope="Critical volumes",
            recovery="WinRE",
            reason="Ready",
            encryption="unencrypted source",
            source_id="gpt-test",
            device_uuid="90cb53c8-01ea-444d-b1f1-23abcd127ace",
            boot_mode="uefi",
            size=512 * 1024**2,
            sector_size=512,
        )
        self.config = dict(
            name="Office",
            scope="assigned",
            config=dict(
                timezone="UTC",
                target=self.fleet.pk,
                network_mode="internet",
                compression="gzip",
                compression_level=6,
                schedule={"kind": "daily", "time": "12:30"},
            ),
            agents=[self.agent.agent_id],
        )
        self.assertEqual(
            self.worker_post(
                self.poll, {"capability": self.cap}, format="json"
            ).status_code,
            204,
        )
        self.transport = {"secure": True, "HTTP_HOST": "api.example.com"}

    def post_policy(self, body=None, url="/imaging/policies/", method="post"):
        with (
            patch("imaging.tasks.wake_imaging_agent.delay"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            send = getattr(self.client, method)
            return send(url, body or self.config, format="json")

    def worker_post(self, *args, **kwargs):
        return self.worker.post(*args, secure=True, **kwargs)

    def issue(self, data):
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + data["token"])
        return client, urlsplit(data["url"]).path

    def claim(self):
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        grant = self.worker_post(self.poll, {"capability": self.cap}, format="json")
        self.assertEqual(grant.status_code, 200, grant.data)
        client, path = self.issue(grant.data)
        return response.data["id"], client, path

    def part(self, client, path, data, index=0):
        url = (
            path + f"part/?i={index}&size={len(data)}&sha256={sha256(data).hexdigest()}"
        )
        return client.put(
            url,
            gzip.compress(data),
            content_type="application/octet-stream",
            **self.transport,
        )

    def point(self, blocks):
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        image_id = response.data["id"]
        grant = self.worker_post(self.poll, {"capability": self.cap}, format="json")
        self.assertEqual(grant.status_code, 200, grant.data)
        client, path = self.issue(grant.data)
        self.assertEqual(
            self.worker_post(
                self.poll, {"capability": self.cap}, format="json"
            ).status_code,
            204,
        )
        self.assertEqual(
            client.post(
                path + "begin/", {}, format="json", **self.transport
            ).status_code,
            204,
        )
        needed = []
        for index, raw in enumerate(blocks):
            url = (
                path
                + f"part/?i={index}&size={len(raw)}&sha256={sha256(raw).hexdigest()}"
            )
            res = client.post(url, {}, format="json", **self.transport)
            if res.status_code == 404:
                needed.append(index)
                res = client.put(
                    url,
                    gzip.compress(raw),
                    content_type="application/octet-stream",
                    **self.transport,
                )
            self.assertEqual(res.status_code, 204, res.content)
        raw = b"".join(blocks)
        response = client.post(
            path + "seal/",
            {"size": len(raw), "sha256": sha256(raw).hexdigest()},
            format="json",
            **self.transport,
        )
        self.assertEqual(response.status_code, 202, response.data)
        verify_image(image_id)
        image = Image.objects.get(pk=image_id)
        self.assertEqual(image.status, ImageStatus.VERIFIED)
        self.assertEqual(
            client.post(
                path + "begin/", {}, format="json", **self.transport
            ).status_code,
            409,
        )
        self.assertEqual(
            client.get(path + "data/?offset=0", **self.transport).status_code, 409
        )
        return image, needed

    def test_duplicate_manual_capture_wakes_agent_once_after_commit(self):
        self.post_policy()
        with (
            patch("imaging.tasks.wake_imaging_agent.delay") as wake,
            self.captureOnCommitCallbacks(execute=True),
        ):
            first = self.client.post(self.uri + "capture/", {}, format="json")
            second = self.client.post(self.uri + "capture/", {}, format="json")
            self.assertEqual(first.status_code, 202, first.data)
            self.assertEqual(second.data["id"], first.data["id"])
            wake.assert_not_called()
        wake.assert_called_once_with(self.agent.agent_id)

    def test_crashed_upload_can_be_reclaimed_after_one_idle_poll_interval(self):
        self.post_policy()
        image_id = self.client.post(self.uri + "capture/", {}, format="json").data["id"]
        report = {"capability": self.cap}
        first = self.worker_post(self.poll, report, format="json").data
        old_client, path = self.issue(first)
        point = Image.objects.filter(pk=image_id)
        stale = timezone.now() - timedelta(minutes=6)
        point.update(updated_at=stale)
        self.assertEqual(
            self.worker_post(self.poll, report, format="json").status_code, 204
        )
        self.assertEqual(
            old_client.post(
                path + "begin/", {}, format="json", **self.transport
            ).status_code,
            204,
        )
        self.assertEqual(
            self.worker_post(self.poll, report, format="json").status_code, 204
        )
        point.update(updated_at=stale)
        resumed = self.worker_post(self.poll, report, format="json")
        self.assertEqual(resumed.status_code, 200, resumed.data)
        self.assertNotEqual(resumed.data["claim"], first["claim"])
        self.assertEqual(
            old_client.post(
                path + "begin/", {}, format="json", **self.transport
            ).status_code,
            403,
        )

    def test_two_independent_maps_and_damaged_dependency(self):
        response = self.post_policy()
        self.assertEqual(response.status_code, 201, response.data)
        common = b"A" * BLOCK
        first, needed = self.point([common, b"old"])
        self.assertEqual(needed, [0, 1])
        second, needed = self.point([common, b"new"])
        self.assertEqual(needed, [1])
        self.assertEqual(ImageBlock.objects.count(), 3)
        self.assertLess(second.new_bytes, second.size)
        for image, ending in [(first, b"old"), (second, b"new")]:
            confirmation = {
                "device_uuid": self.cap["device_uuid"],
                "disk_id": "gpt-spare",
                "target_agent_id": self.agent.agent_id,
                "confirmed": True,
                "raw_size": self.cap["size"],
                "sector_size": 512,
            }
            url = self.uri + f"images/{image.pk}/restore-access/"
            self.assertEqual(
                self.client.post(url, confirmation, format="json").status_code, 403
            )
            with patch("imaging.views.stepup_denied", return_value=None):
                # Windows Recovery would recreate the source partitions on it
                for unfit in (
                    {"raw_size": self.cap["size"] - 512},
                    {"sector_size": 4096},
                    {"raw_size": None},
                ):
                    bad = {k: v for k, v in {**confirmation, **unfit}.items() if v}
                    self.assertEqual(
                        self.client.post(url, bad, format="json").status_code, 400
                    )
                response = self.client.post(url, confirmation, format="json")
            self.assertEqual(response.status_code, 201, response.data)
            cli, path = self.issue(response.data)
            self.assertEqual(
                cli.get(path + f"data/?offset={BLOCK}", **self.transport).content,
                ending,
            )
        bad = second.parts.get(index=1).block
        (self.root / "fleet" / str(bad.id)).write_bytes(b"damaged")
        self.assertEqual(
            cli.get(path + f"data/?offset={BLOCK}", **self.transport).status_code, 409
        )
        second.refresh_from_db()
        self.assertEqual(second.status, ImageStatus.FAILED)
        verify_image(first.pk, recheck=True)
        first.refresh_from_db()
        self.assertEqual(first.status, ImageStatus.VERIFIED)

        # A fresh upload can recover from a broken stored dependency without
        # replacing any old point's blob, or inheriting its corruption.
        third, needed = self.point([common, b"new"])
        self.assertEqual(needed, [1])
        self.assertNotEqual(third.parts.get(index=1).block_id, bad.pk)
        self.assertEqual((self.root / "fleet" / str(bad.pk)).read_bytes(), b"damaged")

        shared = first.parts.get(index=0).block_id
        (self.root / "fleet" / str(shared)).unlink()
        with self.captureOnCommitCallbacks(execute=True):
            verify_image(first.pk, recheck=True)
        self.assertEqual(
            Image.objects.filter(
                pk__in=(first.pk, third.pk), status=ImageStatus.FAILED
            ).count(),
            2,
        )

    @override_settings(ULRMM_IMAGING_ENCRYPTED_DESTINATIONS=["fleet"])
    def test_policy_preview_uses_the_requested_destination(self):
        response = self.post_policy()
        self.assertEqual(response.status_code, 201, response.data)
        current = self.client.get(self.uri)
        self.assertIn("encryption confirmed", current.data["at_rest"])

        preview = self.client.get(self.uri, {"destination": "new-folder"})
        self.assertEqual(preview.status_code, 200, preview.data)
        self.assertEqual(preview.data["destination"], "new-folder")
        self.assertIn("unconfirmed", preview.data["at_rest"])
        self.assertEqual(
            preview.data["storage"], {"configured": True, "internal": False}
        )
        self.assertNotIn("images", preview.data)
        self.assertEqual(Profile.objects.get(agent=self.agent).destination, "fleet")

        invalid = self.client.get(self.uri, {"destination": "../fleet"})
        self.assertEqual(invalid.status_code, 400)
        self.client.force_authenticate(self.create_user_with_roles([]))
        denied = self.client.get(self.uri, {"destination": "fleet"})
        self.assertEqual(denied.status_code, 403)

    def test_policy_internal_mode_needs_the_internal_listener(self):
        internal = {
            **self.config,
            "config": {**self.config["config"], "network_mode": "internal"},
        }
        refused = self.post_policy(internal)
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.json(), {"config": {"network_mode": [NO_INTERNAL]}})
        self.assertFalse(BackupPolicy.objects.filter(scope="assigned").exists())
        created = self.post_policy()
        self.assertEqual(created.status_code, 201, created.data)
        update = f"/imaging/policies/{created.data['id']}/"
        refused = self.post_policy(internal, update, "put")
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.json(), {"config": {"network_mode": [NO_INTERNAL]}})
        self.assertEqual(Profile.objects.get(agent=self.agent).network_mode, "internet")
        with override_settings(
            ULRMM_IMAGING_INTERNAL_ORIGIN="https://private.example.test",
            ULRMM_IMAGING_INTERNAL_CIDRS=["10.40.0.0/16"],
        ):
            response = self.post_policy(internal, update, "put")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(Profile.objects.get(agent=self.agent).network_mode, "internal")

    def test_reserve_refuses_block_before_writing(self):
        self.post_policy()
        point_id, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        reserve = 10 * 1024**3
        volume = SimpleNamespace(f_bavail=reserve, f_frsize=1)
        with (
            override_settings(ULRMM_IMAGING_RESERVE_BYTES=reserve),
            patch("os.statvfs", return_value=volume),
        ):
            full = self.part(cli, path, b"block data")
        self.assertEqual(full.status_code, 507)
        self.assertEqual(full.json()["detail"], NO_SPACE)
        self.assertFalse(ImageBlock.objects.exists())
        files = [p.name for p in self.root.rglob("*") if p.is_file()]
        self.assertEqual([f for f in files if f != MARKER], [])
        point = Image.objects.get(pk=point_id)
        self.assertEqual((point.offset, point.reason), (0, NO_SPACE))
        self.assertEqual(point.status, ImageStatus.UPLOADING)
        self.assertEqual(self.part(cli, path, b"block data").status_code, 204)

    def test_failure_report_keeps_the_free_space_reason(self):
        self.post_policy()
        point_id, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        with patch("os.statvfs", return_value=SimpleNamespace(f_bavail=0, f_frsize=1)):
            self.assertEqual(self.part(cli, path, b"block data").status_code, 507)
        claim = Transfer.objects.get(image_id=point_id, direction="capture").id
        report = {
            "capability": self.cap,
            "failure": "upload",
            "image_id": str(point_id),
            "claim": str(claim),
        }
        self.assertEqual(
            self.worker_post(self.poll, report, format="json").status_code, 204
        )
        self.assertEqual(Image.objects.get(pk=point_id).reason, NO_SPACE)
        self.assertFalse(
            Transfer.objects.filter(pk=claim, expires_at__gt=timezone.now()).exists()
        )

    def test_failure_report_keeps_the_store_reason(self):
        self.post_policy()
        point_id, _, _ = self.claim()
        Image.objects.filter(pk=point_id).update(reason=OTHER_STORE)
        claim = Transfer.objects.get(image_id=point_id, direction="capture").id
        report = {
            "capability": self.cap,
            "failure": "upload",
            "image_id": str(point_id),
            "claim": str(claim),
        }
        self.worker_post(self.poll, report, format="json")
        self.assertEqual(Image.objects.get(pk=point_id).reason, OTHER_STORE)

    def test_unmounted_store_with_its_marker_takes_no_blocks(self):
        self.setup_coresettings()
        self.post_policy()
        first, _ = self.point([b"A" * BLOCK, b"old"])
        _, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        # the folder under the mount point, from before the disk was mounted
        under = Path(self.enterContext(TemporaryDirectory()))
        shutil.copy(self.root / MARKER, under / MARKER)
        (under / "fleet").mkdir(mode=0o700)
        probe = path + f"part/?i=1&size=3&sha256={sha256(b'old').hexdigest()}"
        with (
            override_settings(ULRMM_IMAGING_ROOT=str(under)),
            other_disk(under),
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.assertEqual(self.part(cli, path, b"N" * BLOCK).status_code, 503)
            self.assertEqual(
                cli.post(probe, {}, format="json", **self.transport).status_code, 503
            )
        self.assertEqual(sorted(p.name for p in under.rglob("*")), [MARKER, "fleet"])
        first.refresh_from_db()
        self.assertEqual(first.status, ImageStatus.VERIFIED)
        self.assertEqual(self.part(cli, path, b"N" * BLOCK).status_code, 204)

    def test_unreadable_block_fails_the_restore(self):
        self.post_policy()
        image, _ = self.point([b"old"])
        block = image.parts.get().block
        os.link(self.root / "fleet" / str(block.pk), self.root / "link")
        confirmation = {
            "device_uuid": self.cap["device_uuid"],
            "disk_id": "gpt-spare",
            "target_agent_id": self.agent.agent_id,
            "confirmed": True,
            "raw_size": self.cap["size"],
            "sector_size": 512,
        }
        with patch("imaging.views.stepup_denied", return_value=None):
            response = self.client.post(
                self.uri + f"images/{image.pk}/restore-access/",
                confirmation,
                format="json",
            )
        self.assertEqual(response.status_code, 201, response.data)
        cli, path = self.issue(response.data)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(
                cli.get(path + "data/?offset=0", **self.transport).status_code, 409
            )
        image.refresh_from_db()
        block.refresh_from_db()
        self.assertEqual(image.status, ImageStatus.FAILED)
        self.assertTrue(block.namespace.startswith("corrupt/"))

    def test_new_profile_uses_internet_without_the_internal_listener(self):
        self.assertEqual(
            self.client.get(self.uri).data["config"]["network_mode"], "internet"
        )
        with override_settings(
            ULRMM_IMAGING_INTERNAL_ORIGIN="https://private.example.test",
            ULRMM_IMAGING_INTERNAL_CIDRS=["10.40.0.0/16"],
        ):
            # the builtin default is internet; internal is chosen per policy
            self.assertEqual(
                self.client.get(self.uri).data["config"]["network_mode"], "internet"
            )
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(Profile.objects.get(agent=self.agent).network_mode, "internet")
        self.assertEqual(
            Image.objects.get(pk=response.data["id"]).network_mode, "internet"
        )

    def test_internal_profile_waits_for_the_internal_listener(self):
        Profile.objects.filter(agent=self.agent).update(
            operator=self.john,
            overrides={
                "network_mode": "internal",
                "schedule": {"kind": "daily", "time": "12:30"},
            },
        )
        profile, _ = resolver.resolve_device(self.agent, cause="device")
        Profile.objects.filter(pk=profile.pk).update(
            next_run=timezone.now() - timedelta(minutes=1)
        )
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"detail": NO_INTERNAL})
        imaging_tick()
        self.assertFalse(Image.objects.exists())
        self.assertTrue(AuditLog.objects.filter(message__contains=NO_INTERNAL).exists())
        self.assertGreater(Profile.objects.get(pk=profile.pk).next_run, timezone.now())

    def test_policy_bulk_rolls_back_if_device_is_outside_scope(self):
        self.client.force_authenticate(self.create_user_with_roles([]))
        res = self.post_policy()
        self.assertEqual(res.status_code, 403)
        self.assertFalse(Profile.objects.filter(policy__isnull=False).exists())

    def test_agent_cannot_report_another_machine(self):
        other = baker.make(
            "agents.Agent", agent_id="other-native-agent", plat="windows"
        )
        res = self.worker_post(
            f"/api/v3/{other.agent_id}/imaging/",
            {"capability": self.cap},
            format="json",
        )
        self.assertEqual(res.status_code, 404)

    def test_interruption_full_store_and_resume_preserve_previous_point(self):
        import errno

        self.post_policy()
        first, _ = self.point([b"first capture"])
        point_id = self.client.post(self.uri + "capture/", {}, format="json").data["id"]
        grant = self.worker_post(
            self.poll, {"capability": self.cap}, format="json"
        ).data
        cli, path = self.issue(grant)
        cli.post(path + "begin/", {}, format="json", **self.transport)
        data = b"changed capture"
        part = path + f"part/?i=0&size={len(data)}&sha256={sha256(data).hexdigest()}"
        with patch(
            "imaging.blocks.image_file",
            side_effect=OSError(errno.ENOSPC, "test volume full"),
        ):
            full = cli.put(
                part,
                gzip.compress(data),
                content_type="application/octet-stream",
                **self.transport,
            )
        self.assertEqual(full.status_code, 507)
        point = Image.objects.get(pk=point_id)
        self.assertEqual(point.offset, 0)
        self.assertEqual(point.status, ImageStatus.UPLOADING)
        self.assertEqual(
            cli.put(
                part,
                gzip.compress(data),
                content_type="application/octet-stream",
                **self.transport,
            ).status_code,
            204,
        )
        point.refresh_from_db()
        self.assertEqual(point.reason, NATIVE_RECEIVING_REASON)
        transferred = point.new_bytes
        self.assertGreater(transferred, 0)
        cli.post(path + "begin/", {}, format="json", **self.transport)
        self.assertEqual(
            cli.post(part, {}, format="json", **self.transport).status_code, 204
        )
        point.refresh_from_db()
        self.assertEqual(point.new_bytes, transferred)
        self.assertEqual(
            self.client.post(
                self.uri + f"images/{point_id}/cancel/", {}, format="json"
            ).status_code,
            204,
        )
        first.refresh_from_db()
        self.assertEqual(first.status, ImageStatus.VERIFIED)

    def test_source_encryption_change_requires_review_and_only_own_verified_status_is_visible(
        self,
    ):
        self.post_policy()
        queued = self.client.post(self.uri + "capture/", {}, format="json").data["id"]
        self.assertEqual(
            self.worker_post(
                self.poll,
                {
                    "capability": {
                        **self.cap,
                        "encryption": "Different volume encryption",
                    }
                },
                format="json",
            ).status_code,
            204,
        )
        self.assertIn("source changed", Image.objects.get(pk=queued).reason)
        lookup = self.poll + "?point=" + queued
        self.assertEqual(self.worker.get(lookup).status_code, 403)
        self.assertEqual(
            self.worker.get(lookup, secure=True).data, {"status": "failed"}
        )
        other = baker.make("agents.Agent", agent_id="other-receipt", plat="windows")
        self.assertEqual(
            self.worker.get(
                f"/api/v3/{other.agent_id}/imaging/?point={queued}", secure=True
            ).status_code,
            404,
        )

    def test_claim_slides_with_committed_blocks(self):
        self.post_policy()
        _, cli, path = self.claim()
        claim = Transfer.objects.get()
        self.assertEqual(claim.renew_until - claim.expires_at, timedelta(days=6))
        Transfer.objects.update(expires_at=timezone.now() + timedelta(minutes=1))
        cli.post(path + "begin/", {}, format="json", **self.transport)
        self.assertEqual(self.part(cli, path, b"block").status_code, 204)
        claim.refresh_from_db()
        self.assertGreater(claim.expires_at, timezone.now() + timedelta(minutes=59))

    def test_mode_change_stops_capture_and_fails_the_point(self):
        self.post_policy()
        image_id, cli, path = self.claim()
        Profile.objects.update(network_mode="internal")
        self.assertEqual(
            cli.post(path + "begin/", {}, format="json", **self.transport).status_code,
            403,
        )
        report = {"capability": self.cap}
        self.assertEqual(
            self.worker_post(self.poll, report, format="json").status_code, 204
        )
        point = Image.objects.get(pk=image_id)
        self.assertEqual(
            (point.status, point.reason), (ImageStatus.FAILED, MODE_CHANGED)
        )

    def test_manual_point_without_operator_fails_and_scheduler_needs_none(self):
        self.post_policy()
        image_id = self.client.post(self.uri + "capture/", {}, format="json").data["id"]
        Image.objects.filter(pk=image_id).update(operator=None)
        report = {"capability": self.cap}
        self.assertEqual(
            self.worker_post(self.poll, report, format="json").status_code, 204
        )
        self.assertEqual(Image.objects.get(pk=image_id).status, ImageStatus.FAILED)
        Profile.objects.update(
            operator=None, next_run=timezone.now() - timedelta(minutes=1)
        )
        imaging_tick()
        point = Image.objects.exclude(pk=image_id).get()
        self.assertEqual((point.trigger, point.operator), ("schedule", None))
        grant = self.worker_post(self.poll, report, format="json")
        self.assertEqual(grant.status_code, 200, grant.data)
        self.assertEqual(Transfer.objects.get(image=point).authority, "policy")

    def test_parts_beyond_the_approved_source_are_refused(self):
        self.post_policy()
        image_id, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        point = Image.objects.filter(pk=image_id)
        point.update(new_bytes=2 * self.cap["size"] + 1)
        self.assertEqual(self.part(cli, path, b"12345").status_code, 400)
        reason = "Upload exceeded the approved source size."
        self.assertEqual(
            (point.get().status, point.get().reason), (ImageStatus.FAILED, reason)
        )
        self.assertTrue(AuditLog.objects.filter(message__contains=reason).exists())
        offline = {**self.cap, "method": "linux-offline-disk-v1"}
        uploading = dict(status=ImageStatus.UPLOADING, new_bytes=0)
        point.update(native={**offline, "size": 4}, **uploading)
        self.assertEqual(self.part(cli, path, b"12345").status_code, 400)
        point.update(native={**offline, "size": 5}, **uploading)
        self.assertEqual(self.part(cli, path, b"12345").status_code, 204)

    def test_restarted_map_gives_its_blocks_a_fresh_grace(self):
        self.post_policy()
        _, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        self.assertEqual(self.part(cli, path, b"block").status_code, 204)
        ImageBlock.objects.update(created_at=timezone.now() - timedelta(days=2))
        cli.post(path + "begin/", {}, format="json", **self.transport)
        imaging_tick()
        self.assertEqual(ImageBlock.objects.count(), 1)

    def test_dedup_trusts_length_and_verification_retires_damaged_block(self):
        self.post_policy()
        first, _ = self.point([b"old"])
        bad = first.parts.get().block
        (self.root / "fleet" / str(bad.pk)).write_bytes(bytes(bad.stored_size))
        image_id, cli, path = self.claim()
        cli.post(path + "begin/", {}, format="json", **self.transport)
        probe = path + f"part/?i=0&size=3&sha256={sha256(b'old').hexdigest()}"
        self.assertEqual(
            cli.post(probe, {}, format="json", **self.transport).status_code, 204
        )
        seal = {"size": 3, "sha256": sha256(b"old").hexdigest()}
        self.assertEqual(
            cli.post(path + "seal/", seal, format="json", **self.transport).status_code,
            202,
        )
        with self.captureOnCommitCallbacks(execute=True):
            verify_image(image_id)
        self.assertEqual(Image.objects.get(pk=image_id).status, ImageStatus.FAILED)
        first.refresh_from_db()
        self.assertEqual(first.status, ImageStatus.FAILED)
        bad.refresh_from_db()
        self.assertTrue(bad.namespace.startswith("corrupt/"))
        self.assertEqual(self.point([b"old"])[1], [0])

    def test_policy_delete_only_without_devices(self):
        pk = self.post_policy().data["id"]
        uri = f"/imaging/policies/{pk}/"
        self.assertEqual(self.client.delete(uri).status_code, 409)
        Profile.objects.update(policy=None)
        self.assertEqual(self.client.delete(uri).status_code, 204)
        self.assertFalse(BackupPolicy.objects.filter(scope="assigned").exists())

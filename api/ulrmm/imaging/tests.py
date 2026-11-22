# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import errno
import gzip
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.db import OperationalError
from django.db.models.query import QuerySet
from django.test import override_settings
from django.utils import timezone
from model_bakery import baker
from rest_framework.test import APIClient

from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

from .models import (
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    Pairing,
    Profile,
    Transfer,
)
from .storage import UnconfirmedStorage, _local_disk
from .tasks import DEVICE_DELETED, imaging_tick, verify_image

IDENTITY = {
    "device_uuid": "74bdac69-aa34-4056-93ea-4c692264d3df",
    "disk_id": "wwn-0x123456789",
}
INT = {"HTTP_HOST": "private.example.test", "ULRMM_IMAGING_INTERNAL_PEER": "10.40.2.3"}
PUBLIC = {"HTTP_HOST": "api.example.com"}


class ImagingTests(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.agent = baker.make("agents.Agent", plat="linux", goarch="amd64")
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"
        self.root = self.enterContext(TemporaryDirectory())
        self.enterContext(
            override_settings(
                ULRMM_IMAGING_ROOT=self.root,
                ULRMM_IMAGING_PUBLIC_ORIGIN="https://api.example.com",
                ULRMM_IMAGING_INTERNAL_ORIGIN="https://private.example.test",
                ULRMM_IMAGING_INTERNAL_CIDRS=["10.40.0.0/16"],
                ULRMM_IMAGING_INTERNAL_STORAGE_CONFIRMED=True,
                ALLOWED_HOSTS=["testserver", "api.example.com", "private.example.test"],
            )
        )

    def _config(self, **overrides):
        data = {
            "destination": "fleet",
            "compression": "gzip",
            "compression_level": 6,
            "network_mode": "internet",
            "schedule_time": None,
            "timezone": "UTC",
            **overrides,
        }
        return self.client.put(self.uri, data, format="json")

    def _queue(self):
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202)
        return response.json()["id"]

    def _issue(self, image, direction, data=IDENTITY, status=201):
        response = self.client.post(
            self.uri + f"images/{image}/{direction}-access/", data, format="json"
        )
        self.assertEqual(response.status_code, status, response.content)
        if status != 201:
            return response
        body = response.json()
        url = body["url"].split("/", 3)[3]
        return "/" + url, APIClient(HTTP_AUTHORIZATION="Bearer " + body["token"])

    def _manifest(self, url, client, path, *, size=1024):
        return client.post(
            url + "manifest/",
            {
                "raw_size": size,
                "sector_size": 512,
                "architecture": "x86_64",
                "boot_mode": "uefi",
                "disk_id": IDENTITY["disk_id"],
            },
            secure=True,
            format="json",
            **path,
        )

    def _verified(self, raw=b"A" * 512):
        image = self._queue()
        checksum = sha256(raw).hexdigest()
        Image.objects.filter(pk=image).update(
            status=ImageStatus.VERIFIED,
            reason="",
            raw_size=len(raw),
            size=len(raw),
            raw_sha256=checksum,
            sha256=checksum,
            verified_at=timezone.now(),
        )
        output = Path(self.root, "fleet")
        output.mkdir(mode=0o700, exist_ok=True)
        (output / image).write_bytes(raw)
        (output / image).chmod(0o600)
        return image

    def _restore(self, image):
        confirmation = {
            **IDENTITY,
            "confirmed": True,
            "target_agent_id": self.agent.agent_id,
        }
        with patch("imaging.views.stepup_denied", return_value=None):
            return self._issue(image, "restore", confirmation)

    def _chunk(self, url, client, path, data, offset=0):
        return client.put(
            url + f"data/?offset={offset}",
            data,
            content_type="application/octet-stream",
            secure=True,
            **path,
        )

    def test_capture_integrity_restore_binding_and_scope(self):
        self.assertEqual(self._config().status_code, 200)
        image_id = self._queue()
        self.assertEqual(self._queue(), image_id)
        url, capture = self._issue(image_id, "capture")
        self.assertEqual(self._manifest(url, capture, PUBLIC).status_code, 204)
        raw = b"R" * 1024
        payload = gzip.compress(raw)
        self.assertEqual(
            self._chunk(url, capture, PUBLIC, payload[:7]).status_code, 204
        )
        self.assertEqual(
            self._chunk(url, capture, PUBLIC, payload[7:]).json()["offset"], 7
        )
        self.assertEqual(
            self._chunk(url, capture, PUBLIC, payload[7:], 7).status_code, 204
        )
        hashes = {
            "size": len(payload),
            "sha256": sha256(payload).hexdigest(),
            "raw_sha256": sha256(raw).hexdigest(),
        }
        self.assertEqual(
            capture.post(
                url + "complete/",
                hashes,
                secure=True,
                format="json",
                **PUBLIC,
            ).status_code,
            202,
        )
        self.assertEqual(
            self.client.get(self.uri).json()["images"][0]["status"], "verifying"
        )
        verify_image(image_id)
        self.assertEqual(Image.objects.get(pk=image_id).status, ImageStatus.VERIFIED)
        target = baker.make("agents.Agent", plat="linux", goarch="amd64")
        confirmation = {
            "confirmed": True,
            "target_agent_id": target.agent_id,
            **IDENTITY,
        }
        self.assertTrue(
            self._issue(image_id, "restore", confirmation, status=403).json()["stepup"]
        )
        with patch("imaging.views.stepup_denied", return_value=None):
            url, restore = self._issue(image_id, "restore", confirmation)
        meta = restore.get(url, secure=True, **PUBLIC).json()
        self.assertEqual(meta["agent_id"], target.agent_id)
        self.assertEqual(meta["device_uuid"], IDENTITY["device_uuid"])
        self.assertEqual(meta["disk_id"], IDENTITY["disk_id"])
        self.assertEqual(
            restore.get(url + "data/?offset=0", secure=True, **PUBLIC).content, payload
        )
        self.assertEqual(
            self._chunk(url, restore, PUBLIC, b"forbidden").status_code, 409
        )
        completion = {"raw_sha256": hashes["raw_sha256"]}
        for _ in range(2):
            self.assertEqual(
                restore.post(
                    url + "complete/", completion, secure=True, format="json", **PUBLIC
                ).status_code,
                204,
            )
        self.assertEqual(
            restore.get(url + "data/?offset=0", secure=True, **PUBLIC).status_code, 409
        )
        self.assertEqual(
            AuditLog.objects.filter(message__contains="successful read-back").count(), 1
        )

    @patch("imaging.storage._local_disk")
    def test_internal_ingress_blocks_forged_headers_and_changed_path(self, _disk):
        self.assertEqual(self._config(network_mode="internal").status_code, 200)
        image_id = self._queue()
        url, capture = self._issue(image_id, "capture")
        internal_host = {
            "HTTP_HOST": INT["HTTP_HOST"],
            "HTTP_X_FORWARDED_FOR": INT["ULRMM_IMAGING_INTERNAL_PEER"],
            "HTTP_ULRMM_IMAGING_INTERNAL_PEER": INT["ULRMM_IMAGING_INTERNAL_PEER"],
        }
        self.assertEqual(
            capture.get(url, secure=True, **internal_host).status_code, 403
        )
        self.assertEqual(self._manifest(url, capture, INT).status_code, 204)
        self.assertEqual(self._chunk(url, capture, INT, b"first").status_code, 204)
        self.assertEqual(
            self._chunk(url, capture, internal_host, b"second", 5).status_code, 403
        )
        image = Image.objects.get(pk=image_id)
        self.assertEqual(image.offset, 5)
        self.assertIn("internal", image.reason)
        self.assertEqual(self._chunk(url, capture, INT, b"second", 5).status_code, 204)

    def test_storage_full_and_corrupt_payload(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._queue()
        url, capture = self._issue(image, "capture")
        self.assertEqual(self._manifest(url, capture, PUBLIC).status_code, 204)
        data = bytes(1024)
        with patch(
            "imaging.views.image_file", side_effect=OSError(errno.ENOSPC, "full")
        ):
            self.assertEqual(self._chunk(url, capture, PUBLIC, data).status_code, 507)
        self.assertEqual(Image.objects.get(pk=image).offset, 0)
        self.assertEqual(self._chunk(url, capture, PUBLIC, data).status_code, 204)
        body = {"size": len(data), "sha256": "0" * 64, "raw_sha256": "0" * 64}
        self.assertEqual(
            capture.post(
                url + "complete/",
                body,
                secure=True,
                format="json",
                **PUBLIC,
            ).status_code,
            202,
        )
        verify_image(image)
        self.assertEqual(Image.objects.get(pk=image).status, ImageStatus.FAILED)

    def test_storage_rejects_unsafe_destination_and_cancels_partial(self):
        self.assertEqual(self._config(destination="../other").status_code, 400)
        self.assertEqual(self._config().status_code, 200)
        image = self._queue()
        url, capture = self._issue(image, "capture")
        self.assertEqual(self._manifest(url, capture, PUBLIC).status_code, 204)
        with TemporaryDirectory() as outside:
            dest = Path(self.root, "fleet")
            dest.symlink_to(outside, target_is_directory=True)
            self.assertEqual(
                self._chunk(url, capture, PUBLIC, b"part").status_code, 503
            )
            self.assertEqual(list(Path(outside).iterdir()), [])
            dest.unlink()
        self.assertEqual(self._chunk(url, capture, PUBLIC, b"part").status_code, 204)
        self.assertEqual(
            self.client.post(self.uri + f"images/{image}/cancel/").status_code, 204
        )
        self.assertFalse(Path(self.root, "fleet", image).exists())
        self.assertEqual(capture.get(url, secure=True, **PUBLIC).status_code, 403)

    def test_grant_rejects_wrong_disk_and_expired_credentials(self):
        self.assertEqual(self._config().status_code, 200)
        image = self._queue()
        url, capture = self._issue(image, "capture")
        self._issue(
            image, "capture", {**IDENTITY, "disk_id": "wwn-different"}, status=409
        )
        Transfer.objects.filter(image_id=image).update(expires_at=timezone.now())
        self.assertEqual(capture.get(url, secure=True, **PUBLIC).status_code, 403)

    def test_scheduler_daily_timezone_coalesces_without_an_online_agent(self):
        with patch(
            "imaging.views.timezone.now",
            return_value=datetime(2026, 3, 28, 10, tzinfo=UTC),
        ):
            self.assertEqual(
                self._config(
                    timezone="Europe/Berlin", schedule_time="02:30"
                ).status_code,
                200,
            )
        profile = Profile.objects.get(agent=self.agent)
        self.assertEqual(profile.next_run, datetime(2026, 3, 29, 1, 30, tzinfo=UTC))
        now = profile.next_run + timedelta(minutes=1)
        with patch("imaging.tasks.timezone.now", return_value=now):
            imaging_tick()
            imaging_tick()
        self.assertEqual(Image.objects.filter(agent=self.agent).count(), 1)
        profile.refresh_from_db()
        self.assertEqual(profile.next_run, datetime(2026, 3, 30, 0, 30, tzinfo=UTC))

    def test_role_separation_scope_and_revocation(self):
        self.assertEqual(self._config().status_code, 200)
        user = self.create_user_with_roles(["can_manage_images"])
        user.role.can_view_sites.add(self.agent.site)
        self.client.force_authenticate(user=user)
        image = self._queue()
        self.assertFalse(self.client.get(self.uri).json()["can_restore"])
        self._issue(image, "restore", status=403)
        url, capture = self._issue(image, "capture")
        other = baker.make("agents.Agent", plat="linux")
        self.assertEqual(
            self.client.get(f"/imaging/agents/{other.agent_id}/").status_code, 403
        )
        user.role.can_manage_images = False
        user.role.save()
        self.assertEqual(capture.get(url, secure=True, **PUBLIC).status_code, 403)

    def test_pairing_polls_idempotently_and_revokes_derived_grants(self):
        self.assertEqual(self._config(schedule_time="02:30").status_code, 200)
        response = self.client.post(self.uri + "pair/", IDENTITY, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        url = "/" + body["url"].split("/", 3)[3]
        recovery = APIClient(HTTP_AUTHORIZATION="Bearer " + body["token"])
        self.assertEqual(recovery.get(url, secure=True, **PUBLIC).status_code, 204)
        profile = Profile.objects.get(agent=self.agent)
        now = profile.next_run + timedelta(minutes=1)
        with patch("imaging.tasks.timezone.now", return_value=now):
            imaging_tick()
        first = recovery.get(url, secure=True, **PUBLIC)
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(recovery.get(url, secure=True, **PUBLIC).json(), first.json())
        self.assertEqual(Transfer.objects.count(), 1)
        expiry = Pairing.objects.get().expires_at
        self.assertEqual(Transfer.objects.get().expires_at, expiry)
        Transfer.objects.update(expires_at=timezone.now() + timedelta(minutes=1))
        self.assertEqual(recovery.get(url, secure=True, **PUBLIC).status_code, 200)
        self.assertGreater(
            Transfer.objects.get().expires_at, timezone.now() + timedelta(minutes=59)
        )
        grant = first.json()
        path = "/" + grant["url"].split("/", 3)[3]
        capture = APIClient(HTTP_AUTHORIZATION="Bearer " + grant["token"])
        self.assertEqual(
            capture.get(path, secure=True, **PUBLIC).json()["direction"], "capture"
        )
        self.assertEqual(recovery.get(path, secure=True, **PUBLIC).status_code, 403)
        self.assertEqual(self.client.delete(self.uri + "pair/").status_code, 204)
        self.assertEqual(capture.get(path, secure=True, **PUBLIC).status_code, 403)
        self.assertEqual(recovery.get(url, secure=True, **PUBLIC).status_code, 403)

    def test_internal_requires_local_storage_confirmation(self):
        self.assertEqual(self._config(network_mode="internal").status_code, 200)
        image = self._queue()
        url, capture = self._issue(image, "capture")
        with self.settings(ULRMM_IMAGING_INTERNAL_STORAGE_CONFIRMED=False):
            self.assertEqual(capture.get(url, secure=True, **INT).status_code, 503)
            self.assertEqual(self._chunk(url, capture, INT, b"bytes").status_code, 503)
        self.assertEqual(Image.objects.get(pk=image).offset, 0)
        self.assertIn("local disk", Image.objects.get(pk=image).reason)

    def test_mount_check_rejects_remote_filesystems_at_the_open_fd(self):
        fdinfo = "pos:\t0\nmnt_id:\t37\n"
        local = "36 25 8:1 / / rw - ext4 /dev/sda1 rw"
        remote = "37 36 0:55 / /images rw - nfs4 server:/exports rw"
        with patch(
            "imaging.storage.Path.read_text",
            side_effect=[fdinfo, local + "\n" + remote],
        ):
            with self.assertRaises(UnconfirmedStorage):
                _local_disk(10)
        with patch(
            "imaging.storage.Path.read_text",
            side_effect=[fdinfo, local + "\n" + local.replace("36 ", "37 ", 1)],
        ):
            _local_disk(10)

    def test_restore_role_requires_scope_on_both_devices(self):
        self.assertEqual(self._config().status_code, 200)
        image_id = self._queue()
        Image.objects.filter(pk=image_id).update(status=ImageStatus.VERIFIED)
        user = self.create_user_with_roles(["can_restore_images"])
        user.role.can_view_sites.add(self.agent.site)
        target = baker.make("agents.Agent", plat="linux", goarch="amd64")
        body = {**IDENTITY, "confirmed": True, "target_agent_id": target.agent_id}
        self.client.force_authenticate(user=user)
        state = self.client.get(self.uri).json()
        self.assertTrue(state["can_restore"])
        self.assertFalse(state["can_manage"])
        self.assertEqual(state["storage"], {"configured": True})
        with patch("imaging.views.stepup_denied", return_value=None):
            self._issue(image_id, "restore", body, status=403)

    def test_restore_corruption_report_rechecks_even_with_another_capture_pending(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        verified = self._queue()
        raw = b"A" * 512
        checksum = sha256(raw).hexdigest()
        Image.objects.filter(pk=verified).update(
            status=ImageStatus.VERIFIED,
            raw_size=len(raw),
            size=len(raw),
            raw_sha256=checksum,
            sha256=checksum,
            verified_at=timezone.now(),
        )
        output = Path(self.root, "fleet")
        output.mkdir(mode=0o700)
        damaged = output / verified
        damaged.write_bytes(b"B" + raw[1:])
        damaged.chmod(0o600)
        active = self._queue()
        self.assertNotEqual(active, verified)
        confirmation = {
            **IDENTITY,
            "confirmed": True,
            "target_agent_id": self.agent.agent_id,
        }
        with patch("imaging.views.stepup_denied", return_value=None):
            url, restore = self._issue(verified, "restore", confirmation)
        with (
            patch("imaging.views.verify_image.delay") as verify_later,
            self.captureOnCommitCallbacks(execute=True),
        ):
            report = restore.post(
                url + "integrity-failed/", {}, format="json", secure=True, **PUBLIC
            )
        self.assertEqual(report.status_code, 204)
        verify_later.assert_called_once_with(verified, recheck=True)
        verify_image(verified, recheck=True)
        self.assertEqual(Image.objects.get(pk=verified).status, ImageStatus.FAILED)
        self.assertEqual(Image.objects.get(pk=active).status, ImageStatus.WAITING)
        self.assertEqual(restore.get(url, secure=True, **PUBLIC).status_code, 403)

    def test_restore_grant_slides_with_downloads_up_to_its_limit(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        url, restore = self._restore(image)
        grant = Transfer.objects.get(image_id=image)
        self.assertEqual(
            grant.renew_until - grant.expires_at, timedelta(days=7, hours=-2)
        )
        soon = timezone.now() + timedelta(minutes=1)
        Transfer.objects.filter(pk=grant.pk).update(expires_at=soon)
        data = url + "data/?offset=0"
        self.assertEqual(restore.get(data, secure=True, **PUBLIC).status_code, 200)
        grant.refresh_from_db()
        # the only chunk is the last one: disk write and read-back still follow
        self.assertGreater(grant.expires_at, timezone.now() + timedelta(hours=23))
        Transfer.objects.filter(pk=grant.pk).update(expires_at=soon, renew_until=soon)
        self.assertEqual(restore.get(data, secure=True, **PUBLIC).status_code, 200)
        grant.refresh_from_db()
        self.assertEqual(grant.expires_at, soon)

    def test_delete_point_needs_stepup_and_no_running_restore(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        waiting = self._queue()
        uri = self.uri + f"images/{image}/"
        self.assertTrue(self.client.delete(uri).json()["stepup"])
        self._restore(image)
        with patch("imaging.views.stepup_denied", return_value=None):
            self.assertEqual(
                self.client.delete(self.uri + f"images/{waiting}/").status_code, 409
            )
            self.assertEqual(self.client.delete(uri).status_code, 409)
            # a failed point serves no data, so its open grant does not hold it
            Image.objects.filter(pk=image).update(status=ImageStatus.FAILED)
            self.assertEqual(self.client.delete(uri).status_code, 204)
        self.assertFalse(Image.objects.filter(pk=image).exists())
        self.assertFalse(Path(self.root, "fleet", image).exists())
        restored = self._verified()
        self._restore(restored)
        with patch("imaging.views.stepup_denied", return_value=None):
            uri = self.uri + f"images/{restored}/"
            self.assertEqual(self.client.delete(uri).status_code, 409)
            # a finished restore keeps its grant for a repeated report, not the point
            Transfer.objects.filter(image_id=restored).update(
                completed_at=timezone.now()
            )
            self.assertEqual(self.client.delete(uri).status_code, 204)

    def test_locked_verification_answers_conflict_at_once(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        with patch.object(
            QuerySet, "select_for_update", side_effect=OperationalError("locked")
        ) as select:
            response = self.client.post(self.uri + f"images/{image}/cancel/")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"], "The image is being verified. Retry shortly."
        )
        select.assert_called_once_with(nowait=True)

    def test_recheck_behind_a_short_lock_runs_once_more(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        with (
            patch.object(
                QuerySet, "select_for_update", return_value=Image.objects.none()
            ),
            patch("imaging.tasks.verify_image.apply_async") as later,
        ):
            verify_image(image, recheck=True)
            verify_image(image, recheck=True, retried=True)
        later.assert_called_once_with(
            (image,), {"recheck": True, "retried": True}, countdown=60
        )

    def test_scheduler_queues_paired_offline_point_without_operator(self):
        self.assertEqual(self._config(schedule_time="02:30").status_code, 200)
        self.assertEqual(
            self.client.post(self.uri + "pair/", IDENTITY, format="json").status_code,
            201,
        )
        Profile.objects.update(operator=None)
        now = Profile.objects.get().next_run + timedelta(minutes=1)
        with patch("imaging.tasks.timezone.now", return_value=now):
            imaging_tick()
        self.assertEqual(Image.objects.get().status, ImageStatus.WAITING)

    def test_recheck_storage_error_keeps_verified_text_and_retries(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        with (
            patch("imaging.tasks.verify", side_effect=OSError("gone")),
            patch("imaging.tasks.verify_image.apply_async") as later,
            self.captureOnCommitCallbacks(execute=True),
        ):
            verify_image(image, recheck=True)
        point = Image.objects.get(pk=image)
        self.assertEqual((point.status, point.reason), (ImageStatus.VERIFIED, ""))
        later.assert_called_once_with((image,), {"recheck": True}, countdown=300)

    def test_keep_last_removes_oldest_verified_points_only(self):
        self.assertEqual(self._config(compression="none", keep_last=2).status_code, 200)
        points = [self._verified() for _ in range(4)]
        start = timezone.now() - timedelta(days=10)
        for day, image in enumerate(points):
            Image.objects.filter(pk=image).update(
                created_at=start + timedelta(days=day)
            )
        self._restore(points[0])
        imaging_tick()
        self.assertEqual(
            {str(pk) for pk in Image.objects.values_list("pk", flat=True)},
            {points[0], points[2], points[3]},
        )
        self.assertFalse(Path(self.root, "fleet", points[1]).exists())
        Transfer.objects.filter(image_id=points[0]).update(completed_at=timezone.now())
        imaging_tick()
        self.assertFalse(Image.objects.filter(pk=points[0]).exists())

    def test_points_of_a_deleted_device_are_removed_after_30_days(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        Image.objects.filter(pk=image).update(agent=None)
        imaging_tick()
        self.assertEqual(Image.objects.get(pk=image).reason, DEVICE_DELETED)
        later = timezone.now() + timedelta(days=31)
        with patch("imaging.tasks.timezone.now", return_value=later):
            imaging_tick()
        self.assertFalse(Image.objects.filter(pk=image).exists())
        self.assertTrue(
            AuditLog.objects.filter(message__contains="of a deleted device").exists()
        )

    def test_block_sweep_removes_old_orphans_in_one_tick(self):
        old = timezone.now() - timedelta(days=2)
        block = dict(
            namespace="n",
            destination="fleet",
            size=1,
            stored_size=1,
            created_at=old,
            network_mode="internet",
        )
        folder = Path(self.root, "fleet")
        folder.mkdir(mode=0o700)
        orphan = ImageBlock.objects.create(digest="a" * 64, **block)
        (folder / str(orphan.pk)).write_bytes(b"x")
        ImageBlock.objects.bulk_create(
            ImageBlock(digest=f"{i:064x}", **block) for i in range(150)
        )
        kept = ImageBlock.objects.create(digest="b" * 64, **block)
        image = baker.make(
            Image, agent=self.agent, status=ImageStatus.FAILED, destination="fleet"
        )
        ImagePart.objects.create(image=image, index=0, block=kept)
        imaging_tick()
        self.assertEqual(
            list(ImageBlock.objects.values_list("pk", flat=True)), [kept.pk]
        )
        self.assertFalse((folder / str(orphan.pk)).exists())

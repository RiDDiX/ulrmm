# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import errno
import grp
import gzip
import importlib.util
import os
import pwd
import shutil
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.db import OperationalError
from django.db.models.query import QuerySet
from django.test import override_settings
from django.utils import timezone
from model_bakery import baker
from rest_framework.test import APIClient

from core.models import CoreSettings
from core.serializers import CoreSettingsSerializer
from core.utils import get_core_settings
from logs.models import AuditLog
from ulrmm.settings import imaging_public_origin
from ulrmm.test import ULRMMTestCase

from .models import (
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    Pairing,
    Profile,
    StorageTarget,
    Transfer,
)
from . import storage
from .service import NO_INTERNAL
from .storage import (
    OTHER_STORE,
    MARKER,
    NO_SPACE,
    TEMP_PATHS,
    UnconfirmedStorage,
    _local_disk,
    directory,
    imaging_root,
)
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
        self.agent = baker.make(
            "agents.Agent", plat="linux", goarch="amd64", time_zone="UTC"
        )
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"
        self.root = self.enterContext(TemporaryDirectory())
        self.enterContext(
            override_settings(
                ULRMM_IMAGING_ROOT=self.root,
                ULRMM_IMAGING_PUBLIC_ORIGIN="https://api.example.com",
                ULRMM_IMAGING_INTERNAL_ORIGIN="https://private.example.test",
                ULRMM_IMAGING_INTERNAL_CIDRS=["10.40.0.0/16"],
                ULRMM_IMAGING_INTERNAL_STORAGE_CONFIRMED=True,
                ULRMM_IMAGING_RESERVE_BYTES=0,
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
        name = data.pop("destination")
        at = data.pop("schedule_time")
        target = StorageTarget.objects.filter(name=name).first()
        if target is None and storage.DESTINATION.fullmatch(name):
            target = StorageTarget.objects.create(name=name)
        data["target"] = target.pk if target else 0
        data["schedule"] = {"kind": "daily", "time": at} if at else {"kind": "none"}
        return self.client.put(self.uri, {"set": data}, format="json")

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

    def test_reserve_refuses_chunk_before_writing(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._queue()
        url, capture = self._issue(image, "capture")
        self.assertEqual(self._manifest(url, capture, PUBLIC).status_code, 204)
        reserve = 10 * 1024**3
        volume = SimpleNamespace(f_bavail=reserve + 1000, f_frsize=1)
        with (
            override_settings(ULRMM_IMAGING_RESERVE_BYTES=reserve),
            patch("os.statvfs", return_value=volume),
        ):
            full = self._chunk(url, capture, PUBLIC, bytes(1024))
            self.assertEqual(full.status_code, 507)
            self.assertEqual(full.json()["detail"], NO_SPACE)
            self.assertFalse(Path(self.root, "fleet", image).exists())
            stored = Image.objects.get(pk=image)
            self.assertEqual((stored.offset, stored.reason), (0, NO_SPACE))
            self.assertEqual(
                self._chunk(url, capture, PUBLIC, bytes(512)).status_code, 204
            )

    def test_storage_details_only_for_managers(self):
        with patch("os.statvfs", return_value=SimpleNamespace(f_bavail=5, f_frsize=8)):
            storage = self.client.get(self.uri).json()["storage"]
        self.assertEqual(
            storage,
            {
                "configured": True,
                "internal": True,
                "problem": "",
                "location": self.root,
                "free_bytes": 40,
                "reserve_bytes": 0,
            },
        )
        missing = self.root + "/missing"
        with override_settings(ULRMM_IMAGING_ROOT=missing):
            self.assertEqual(
                self.client.get(self.uri).json()["storage"],
                {
                    "configured": False,
                    "internal": True,
                    "problem": "",
                    "location": missing,
                    "free_bytes": None,
                    "reserve_bytes": 0,
                },
            )
        viewer = self.create_user_with_roles(["can_view_images"])
        viewer.role.can_view_sites.add(self.agent.site)
        self.client.force_authenticate(user=viewer)
        self.assertEqual(
            self.client.get(self.uri).json()["storage"],
            {"configured": True, "internal": True},
        )
        with override_settings(ULRMM_IMAGING_INTERNAL_CIDRS=[]):
            self.assertFalse(self.client.get(self.uri).json()["storage"]["internal"])

    def test_internal_mode_needs_the_internal_listener(self):
        for missing in (
            {"ULRMM_IMAGING_INTERNAL_CIDRS": []},
            {"ULRMM_IMAGING_INTERNAL_ORIGIN": ""},
        ):
            with override_settings(**missing):
                response = self._config(network_mode="internal")
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"set": {"network_mode": [NO_INTERNAL]}})
        self.assertFalse(Profile.objects.exists())
        self.assertEqual(self._config(network_mode="internal").status_code, 200)

    def test_public_origin_defaults_to_the_first_plain_host(self):
        hosts = ["*", ".example.com", "", "api.example.com", "rmm.example.com"]
        self.assertEqual(imaging_public_origin(hosts), "https://api.example.com")
        self.assertEqual(imaging_public_origin(["*", ".example.com"]), "")
        self.assertEqual(
            imaging_public_origin(hosts, 8443), "https://api.example.com:8443"
        )

    def _settings(self, **local):
        module = ModuleType("ulrmm.local_settings")
        module.ALLOWED_HOSTS = ["api.example.com"]
        module.CORS_ORIGIN_WHITELIST = ["https://rmm.example.com"]
        vars(module).update(local)
        path = Path(settings.BASE_DIR) / "ulrmm" / "settings.py"
        spec = importlib.util.spec_from_file_location("ulrmm.settings_copy", path)
        conf = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"ulrmm.local_settings": module}):
            spec.loader.exec_module(conf)
        return conf.ULRMM_IMAGING_PUBLIC_ORIGIN

    def test_settings_derive_the_public_origin_only_standalone(self):
        self.assertEqual(self._settings(), "https://api.example.com")
        self.assertEqual(
            self._settings(ULRMM_BACKEND_PORT=8443), "https://api.example.com:8443"
        )
        internal = "https://private.example.test"
        self.assertEqual(self._settings(ULRMM_IMAGING_INTERNAL_ORIGIN=internal), "")
        chosen = "https://images.example.com"
        self.assertEqual(self._settings(ULRMM_IMAGING_PUBLIC_ORIGIN=chosen), chosen)

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
            "imaging.resolver.timezone.now",
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
        # the new point's created_at sets the spacing floor, so it follows the clock
        with patch("django.utils.timezone.now", return_value=now):
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
        self.assertEqual(state["storage"], {"configured": True, "internal": True})
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

    def test_unreadable_file_fails_the_point_instead_of_waiting(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        bad_sector = OSError(errno.EIO, "Input/output error")
        image = self._verified()
        with patch("hashlib.file_digest", side_effect=bad_sector):
            verify_image(image, recheck=True)
        self.assertEqual(Image.objects.get(pk=image).status, ImageStatus.FAILED)
        image = self._verified()
        os.link(Path(self.root, "fleet", image), Path(self.root, "link"))
        verify_image(image, recheck=True)
        self.assertEqual(Image.objects.get(pk=image).status, ImageStatus.FAILED)

    def test_a_disk_that_stops_answering_keeps_the_point_waiting(self):
        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        with (
            patch("hashlib.file_digest", side_effect=OSError(errno.EIO, "I/O error")),
            patch("imaging.storage._answers", return_value=False),
        ):
            verify_image(image, recheck=True)
        self.assertEqual(Image.objects.get(pk=image).status, ImageStatus.VERIFIED)

    def test_a_passing_read_error_is_read_again(self):
        import hashlib

        self.assertEqual(self._config(compression="none").status_code, 200)
        image = self._verified()
        real, errors = hashlib.file_digest, [OSError(errno.EIO, "I/O error")]

        def digest(*args, **kwargs):
            if errors:
                raise errors.pop()
            return real(*args, **kwargs)

        with patch("hashlib.file_digest", side_effect=digest):
            verify_image(image, recheck=True)
        self.assertEqual(Image.objects.get(pk=image).status, ImageStatus.VERIFIED)

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


KEYS = ["absolute", "allowed", "exists", "directory", "owner", "mode", "content"]


def other_disk(*folders):
    """Gives folders another file system id, as a disk mounted there has."""
    real = storage._fsid

    def fsid(fd):
        where = os.readlink(f"/proc/self/fd/{fd}")
        if any(where == str(f) or where.startswith(f"{f}/") for f in folders):
            return "other-disk"
        return real(fd)

    return patch("imaging.storage._fsid", side_effect=fsid)


class StorageRootTests(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.base = self.enterContext(TemporaryDirectory())
        self.default = self._folder("default")
        self.enterContext(
            override_settings(
                ULRMM_IMAGING_ROOT=self.default, ULRMM_IMAGING_RESERVE_BYTES=0
            )
        )
        # the test folders live in /tmp
        self.enterContext(patch("imaging.storage.TEMP_PATHS", ()))
        self.user = pwd.getpwuid(os.geteuid()).pw_name
        self.group = grp.getgrgid(os.getegid()).gr_name

    def _folder(self, name, mode=0o700):
        path = os.path.join(self.base, name)
        os.mkdir(path)
        os.chmod(path, mode)
        return path

    def _check(self, path):
        response = self.client.get("/imaging/storage/", {"path": path})
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual([c["key"] for c in data["checks"]], KEYS)
        return next((c["key"] for c in data["checks"] if not c["ok"]), None), data

    def _put(self, path):
        with patch("imaging.views.stepup_denied", return_value=None):
            return self.client.put("/imaging/storage/", {"path": path}, format="json")

    def _start_new(self, path):
        with patch("imaging.views.stepup_denied", return_value=None):
            return self.client.put(
                "/imaging/storage/", {"path": path, "start_new": True}, format="json"
            )

    def _point(self, **fields):
        return baker.make(
            "imaging.Image",
            destination="fleet",
            network_mode="internet",
            compression="none",
            compression_level=0,
            **fields,
        )

    def _stored(self, root, row, data="x"):
        os.makedirs(os.path.join(root, "fleet"), 0o700, exist_ok=True)
        Path(root, "fleet", str(row.id)).write_text(data)

    def test_reports_the_current_store_and_marks_it(self):
        response = self.client.get("/imaging/storage/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        data = response.json()
        self.assertTrue(all(c["ok"] for c in data["checks"]), data["checks"])
        self.assertEqual(
            {k: data[k] for k in data if k not in ("checks", "free_bytes")},
            {
                "path": self.default,
                "current": self.default,
                "source": "server",
                "server_default": self.default,
                "configured": True,
                "problem": "",
                "older_copy": False,
                "ok": True,
                "can_start_new": False,
                "fix": "",
                "total_bytes": os.statvfs(self.default).f_blocks
                * os.statvfs(self.default).f_frsize,
                "reserve_bytes": 0,
                "service_user": self.user,
                "service_group": self.group,
                "points": 0,
                "docker": False,
            },
        )
        self.assertIsInstance(data["free_bytes"], int)
        marker = Path(self.default, MARKER)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        with override_settings(ULRMM_DOCKER=True):
            self.assertTrue(self.client.get("/imaging/storage/").json()["docker"])
        self.assertNotIn("imaging_root", self.client.get("/core/settings/").json())

    def test_each_check_names_the_failing_rule(self):
        link = os.path.join(self.base, "etc")
        os.symlink("/etc", link)
        file = os.path.join(self.base, "file")
        Path(file).write_text("x")
        alias = os.path.join(self.base, "alias")
        os.symlink(self.default, alias)
        missing = os.path.join(self.base, "missing")
        shared = self._folder("shared", 0o750)
        full = self._folder("full")
        Path(full, "data").write_text("x")
        foreign = self._folder("foreign", 0o755)
        Path(foreign, "data").write_text("x")
        child = os.path.join(self.default, "fleet")
        os.mkdir(child, 0o700)
        create = f"sudo install -d -m 0700 -o {self.user} -g {self.group}"
        cases = {
            "relative/images": ("absolute", ""),
            "/srv/images\0x": ("absolute", ""),
            self.default + "/": ("absolute", ""),
            self.base + "/./x": ("absolute", ""),
            "/": ("allowed", ""),
            "/mnt": ("allowed", ""),
            "/srv": ("allowed", ""),
            child: ("allowed", ""),
            self.base: ("allowed", ""),
            "/etc/images": ("allowed", ""),
            "/var/lib/postgresql/images": ("allowed", ""),
            "/opt/ulrmm-web": ("allowed", ""),
            link + "/images": ("allowed", ""),
            str(settings.BASE_DIR): ("allowed", ""),
            missing: (
                "exists",
                f"sudo install -d -m 0700 -o {self.user} -g {self.group} {missing}",
            ),
            file: ("directory", ""),
            alias: ("directory", ""),
            shared: (
                "mode",
                f"sudo chown {self.user}:{self.group} {shared} "
                f"&& sudo chmod 0700 {shared}",
            ),
            full: ("content", f"{create} {full}/rmmimages"),
            foreign: ("mode", f"{create} {foreign}/rmmimages"),
            self._folder("empty"): (None, ""),
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                failed, data = self._check(path)
                self.assertEqual((failed, data["fix"]), expected)
                self.assertEqual(data["ok"], failed is None)
                self.assertEqual(data["path"], path)
                self.assertEqual(data["current"], self.default)
        other = self._folder("other")
        with patch("imaging.storage.os.geteuid", return_value=os.geteuid() + 1):
            failed, data = self._check(other)
        self.assertEqual(failed, "owner")
        owner = f"{data['service_user']}:{data['service_group']}"
        self.assertEqual(
            data["fix"], f"sudo chown {owner} {other} && sudo chmod 0700 {other}"
        )

    def test_content_needs_a_copy_while_points_are_stored(self):
        empty = self._folder("empty")
        fresh = self._folder("fresh")
        os.mkdir(os.path.join(fresh, "lost+found"))
        marked = self._folder("marked")
        Path(marked, MARKER).touch()
        full = self._folder("full")
        Path(full, "data").write_text("x")
        self._point(status=ImageStatus.WAITING, offset=0)
        for path, failed in ((empty, None), (fresh, None), (marked, None)):
            self.assertEqual(self._check(path)[0], failed)
        self.assertEqual(self._check(full)[0], "content")
        point = self._point(status=ImageStatus.UPLOADING, offset=1)
        block = baker.make(
            "imaging.ImageBlock",
            destination="fleet",
            namespace="n",
            size=1,
            stored_size=1,
        )
        copy = self._folder("copy")
        os.mkdir(os.path.join(copy, "fleet"))
        Path(copy, "fleet", str(point.id)).write_text("x")
        # a marker alone, or a copy without the newest data, is not the store
        for path in (empty, fresh, full, marked, copy):
            failed, data = self._check(path)
            self.assertEqual(failed, "content")
            self.assertEqual(data["points"], 1)
            self.assertEqual(data["fix"], f"sudo rsync -a {self.default}/ {path}/")
        Path(copy, "fleet", str(block.id)).write_text("x")
        self.assertEqual(self._check(copy)[0], None)
        self.assertEqual(self._check(self.default)[0], None)
        response = self._put(marked)
        self.assertEqual(response.status_code, 400)
        self.assertIn("newest backup data", response.json()["path"][0])
        self.assertEqual(self._put(copy).status_code, 200)

    def test_moved_disk_is_found_when_the_old_path_is_gone(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=512, size=1)
        moved = self._folder("moved")
        os.mkdir(os.path.join(moved, "fleet"))
        Path(moved, "fleet", str(point.id)).write_text("x")
        empty = self._folder("empty")
        with override_settings(ULRMM_IMAGING_ROOT=os.path.join(self.base, "gone")):
            failed, data = self._check(empty)
            self.assertEqual(
                (failed, data["fix"], data["configured"]), ("content", "", False)
            )
            self.assertIn("cannot be read", data["checks"][-1]["text"])
            self.assertEqual(self._check(moved)[0], None)
            self.assertEqual(self._put(moved).status_code, 200)
        self.assertEqual(imaging_root(), moved)

    def test_reset_refuses_a_default_without_the_points(self):
        dash = self._folder("dash")
        self.assertEqual(self._put(dash).status_code, 200)
        point = self._point(status=ImageStatus.VERIFIED, offset=512)
        os.mkdir(os.path.join(dash, "fleet"))
        Path(dash, "fleet", str(point.id)).write_text("x")
        # the installer leaves the default folder with only its marker
        self.assertTrue(Path(self.default, MARKER).exists())
        response = self._put("")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(imaging_root(), dash)

    def test_unmounted_store_keeps_points_waiting(self):
        points = []
        for n in range(2):
            point = self._point(status=ImageStatus.VERIFIED, offset=512, size=1)
            os.makedirs(os.path.join(self.default, "fleet"), 0o700, exist_ok=True)
            Path(self.default, "fleet", str(point.id)).write_text(str(n))
            points.append(point)
        self.assertTrue(self._check(self.default)[1]["configured"])
        # the folder under the mount point: same marker, none of the data
        under = self._folder("under")
        shutil.copy(Path(self.default, MARKER), Path(under, MARKER))
        for root in (under, os.path.join(self.base, "gone")):
            with (
                self.subTest(root=root),
                override_settings(ULRMM_IMAGING_ROOT=root),
                other_disk(under),
            ):
                verify_image(str(points[0].id), recheck=True)
                points[0].refresh_from_db()
                self.assertEqual(points[0].status, ImageStatus.VERIFIED)
        other = self._folder("other")
        Path(other, MARKER).write_text("another-store\n")
        with override_settings(ULRMM_IMAGING_ROOT=other):
            data = self.client.get("/imaging/storage/").json()
            self.assertEqual(
                (data["configured"], data["problem"]), (False, OTHER_STORE)
            )
        # with the rest of the store present a missing file is real data loss
        os.unlink(os.path.join(self.default, "fleet", str(points[0].id)))
        verify_image(str(points[0].id), recheck=True)
        points[0].refresh_from_db()
        self.assertEqual(points[0].status, ImageStatus.FAILED)

    def test_an_empty_mount_point_is_not_the_unmounted_store(self):
        for _ in range(2):
            self._stored(
                self.default, self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
            )
        self.assertTrue(self._check(self.default)[1]["configured"])
        under = self._folder("under", 0o755)
        with override_settings(ULRMM_IMAGING_ROOT=under):
            failed, data = self._check(under)
            self.assertEqual(
                (failed, data["fix"], data["configured"]), ("mode", "", False)
            )
            os.chmod(under, 0o700)
            self.assertEqual(self._check(under)[0], "content")
            self.assertEqual(self._put(under).status_code, 400)
        self.assertFalse(Path(under, MARKER).exists())

    def test_a_truncated_copy_is_not_the_store(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=10, size=10)
        self._stored(self.default, point, "0123456789")
        self.assertTrue(self._check(self.default)[1]["configured"])
        copy = self._folder("copy")
        self._stored(copy, point, "0")
        self.assertEqual(self._check(copy)[0], "content")
        self._stored(copy, point, "0123456789")
        self.assertEqual(self._check(copy)[0], None)

    def test_failed_points_hold_no_store_data(self):
        self._point(status=ImageStatus.FAILED, offset=512)
        data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (True, ""))
        self.assertTrue(Path(self.default, MARKER).exists())
        with override_settings(ULRMM_IMAGING_ROOT=os.path.join(self.base, "gone")):
            self.assertEqual(self.client.get("/imaging/storage/").json()["problem"], "")

    def test_orphan_blocks_keep_the_store_where_it_is(self):
        block = baker.make(
            "imaging.ImageBlock",
            destination="fleet",
            namespace="n",
            size=1,
            stored_size=1,
        )
        self._stored(self.default, block)
        self.assertTrue(self._check(self.default)[1]["configured"])
        empty = self._folder("empty")
        failed, data = self._check(empty)
        self.assertEqual((failed, data["points"]), ("content", 0))
        self.assertEqual(self._put(empty).status_code, 400)

    def test_start_new_needs_an_unreachable_store(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
        self._stored(self.default, point)
        fresh = self._folder("fresh")
        failed, data = self._check(fresh)
        self.assertEqual((failed, data["can_start_new"]), ("content", False))
        self.assertEqual(self._start_new(fresh).status_code, 400)
        point.refresh_from_db()
        self.assertEqual(point.status, ImageStatus.VERIFIED)

    def test_a_renumbered_or_copied_disk_with_the_newest_data_is_the_store(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
        self._stored(self.default, point)
        self.assertTrue(self._check(self.default)[1]["configured"])
        # xfs takes its id from the device number, which can change at boot
        with other_disk(self.default):
            data = self.client.get("/imaging/storage/").json()
            self.assertEqual((data["configured"], data["problem"]), (True, ""))
        self.assertEqual(CoreSettings.objects.get().imaging_store_fs, "other-disk")

    def test_an_older_copy_waits_until_it_is_taken_on_purpose(self):
        points = [
            self._point(status=ImageStatus.VERIFIED, offset=1, size=1) for _ in range(4)
        ]
        for n, point in enumerate(points):
            Image.objects.filter(pk=point.pk).update(
                created_at=timezone.now() - timedelta(minutes=10 - n)
            )
            self._stored(self.default, point)
        self.assertTrue(self._check(self.default)[1]["configured"])
        mirror = self._folder("mirror")
        shutil.copy(Path(self.default, MARKER), Path(mirror, MARKER))
        self._stored(mirror, points[0])
        # last week's mirror at the store's place: none of the newest data
        with override_settings(ULRMM_IMAGING_ROOT=mirror), other_disk(mirror):
            data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (False, OTHER_STORE))
        # the disk is lost: the admin takes the mirror on purpose
        shutil.rmtree(self.default)
        failed, data = self._check(mirror)
        self.assertEqual((failed, data["older_copy"]), (None, True))
        self.assertEqual(self._put(mirror).status_code, 200)
        entry = AuditLog.objects.filter(object_type="coresettings").latest("id")
        self.assertIn("older copy", entry.message)

    def test_a_store_on_nfs_is_not_its_empty_mount_point(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
        nfs = self._folder("nfs")
        self._stored(nfs, point)
        real = os.statvfs

        def statvfs(target):
            info = real(target)
            where = (
                os.readlink(f"/proc/self/fd/{target}")
                if isinstance(target, int)
                else str(target)
            )
            if where != nfs and not where.startswith(nfs + "/"):
                return info
            # NFS and FUSE report no file system id
            return SimpleNamespace(
                f_fsid=0,
                f_bavail=info.f_bavail,
                f_frsize=info.f_frsize,
                f_blocks=info.f_blocks,
            )

        with patch("imaging.storage.os.statvfs", side_effect=statvfs):
            self.assertEqual(self._put(nfs).status_code, 200)
        self.assertEqual(CoreSettings.objects.get().imaging_store_fs, "0")
        # NFS not mounted at boot: the folder under it got the marker earlier
        under = self._folder("under")
        shutil.copy(Path(nfs, MARKER), Path(under, MARKER))
        CoreSettings.objects.update(imaging_root=under)
        data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (False, OTHER_STORE))

    def test_an_old_store_is_not_its_empty_mount_point(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
        self.assertEqual(CoreSettings.objects.get().imaging_store_id, "")
        data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (False, OTHER_STORE))
        self.assertFalse(Path(self.default, MARKER).exists())
        self._stored(self.default, point)
        data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (True, ""))

    def test_another_servers_store_is_not_taken_over(self):
        theirs = self._folder("theirs")
        Path(theirs, MARKER).write_text("another-server\n")
        os.mkdir(os.path.join(theirs, "fleet"), 0o700)
        Path(theirs, "fleet", "x").write_text("x")
        self.assertEqual(self._check(theirs)[0], "content")
        with override_settings(ULRMM_IMAGING_ROOT=theirs):
            data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (False, OTHER_STORE))
        self.assertEqual(Path(theirs, MARKER).read_text(), "another-server\n")

    def test_the_probe_tells_a_lost_disk_from_a_full_one(self):
        fd = os.open(self.default, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertTrue(storage._answers(fd))
        self.assertEqual(os.listdir(self.default), [])
        for code, answers in (
            (errno.ENOSPC, True),
            (errno.EDQUOT, True),
            (errno.EIO, False),
            (errno.EROFS, False),
        ):
            with (
                self.subTest(code=code),
                patch("imaging.storage.os.open", side_effect=OSError(code, "x")),
            ):
                self.assertEqual(storage._answers(fd), answers)

    def test_first_claim_of_an_old_store_tolerates_one_damaged_file(self):
        points = [
            self._point(status=ImageStatus.VERIFIED, offset=1, size=1) for _ in range(3)
        ]
        for point in points[1:]:
            self._stored(self.default, point)
        self.assertEqual(CoreSettings.objects.get().imaging_store_id, "")
        self.assertFalse(Path(self.default, MARKER).exists())
        data = self.client.get("/imaging/storage/").json()
        self.assertEqual((data["configured"], data["problem"]), (True, ""))

    def test_wrong_mode_on_the_store_still_gets_its_command(self):
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1)
        self._stored(self.default, point)
        os.chmod(self.default, 0o755)
        failed, data = self._check(self.default)
        self.assertEqual(failed, "mode")
        self.assertEqual(
            data["fix"],
            f"sudo chown {self.user}:{self.group} {self.default} "
            f"&& sudo chmod 0700 {self.default}",
        )

    def test_a_new_store_replaces_a_dead_disk_and_retires_its_points(self):
        agent = baker.make("agents.Agent", plat="linux")
        point = self._point(status=ImageStatus.VERIFIED, offset=1, size=1, agent=agent)
        self._stored(self.default, point)
        native = self._point(status=ImageStatus.VERIFIED, native={}, agent=agent)
        block = baker.make(
            "imaging.ImageBlock",
            destination="fleet",
            namespace="n",
            size=1,
            stored_size=1,
        )
        self._stored(self.default, block)
        ImagePart.objects.create(image=native, index=0, block=block)
        failed = self._point(status=ImageStatus.FAILED, offset=1, reason="old")
        waiting = self._point(status=ImageStatus.WAITING, agent=agent)
        grant = baker.make(
            Transfer,
            image=point,
            user=self.john,
            direction="restore",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertTrue(self._check(self.default)[1]["configured"])
        store = CoreSettings.objects.get().imaging_store_id
        shutil.rmtree(self.default)
        fresh = self._folder("fresh")
        failed_check, data = self._check(fresh)
        self.assertEqual((failed_check, data["can_start_new"]), ("content", True))
        self.assertEqual(self._put(fresh).status_code, 400)
        full = self._folder("full")
        Path(full, "data").write_text("x")
        self.assertFalse(self._check(full)[1]["can_start_new"])
        refused = self._start_new(full)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("empty folder", refused.json()["path"][0])

        response = self._start_new(fresh)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual(
            (data["current"], data["configured"], data["can_start_new"]),
            (fresh, True, False),
        )
        for row in (point, native):
            row.refresh_from_db()
            self.assertEqual(
                (row.status, row.reason),
                (
                    ImageStatus.FAILED,
                    "The store that held this point was replaced in Global Settings.",
                ),
            )
        failed.refresh_from_db()
        waiting.refresh_from_db()
        self.assertEqual((failed.reason, waiting.status), ("old", ImageStatus.WAITING))
        grant.refresh_from_db()
        self.assertLessEqual(grant.expires_at, timezone.now())
        self.assertFalse(ImagePart.objects.exists() or ImageBlock.objects.exists())
        new_store = CoreSettings.objects.get().imaging_store_id
        self.assertNotEqual(new_store, store)
        self.assertEqual(Path(fresh, MARKER).read_text().strip(), new_store)
        entry = AuditLog.objects.get(object_type="coresettings")
        self.assertIn("2 stored points retired", entry.message)
        with patch("imaging.views.stepup_denied", return_value=None):
            response = self.client.delete(
                f"/imaging/agents/{agent.agent_id}/images/{point.id}/"
            )
        self.assertEqual(response.status_code, 204)

    def test_temporary_and_nested_folders_are_refused(self):
        with patch("imaging.storage.TEMP_PATHS", TEMP_PATHS):
            for path in ("/tmp/x", "/var/tmp/x"):
                with self.subTest(path=path):
                    self.assertEqual(self._check(path)[0], "allowed")
        failed, data = self._check(os.path.join(self.default, "fleet"))
        self.assertEqual(failed, "allowed")
        self.assertIn("inside the current store", data["checks"][1]["text"])

    def test_unencodable_path_is_refused(self):
        with patch("imaging.views.stepup_denied", return_value=None):
            response = self.client.put(
                "/imaging/storage/",
                data='{"path": "/mnt/\\ud800x"}',
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("absolute path", response.json()["path"][0])

    def test_save_moves_the_store_at_once_and_resets(self):
        new = self._folder("new")
        get_core_settings()
        self.assertEqual(imaging_root(), self.default)
        response = self._put(new)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual(
            (data["path"], data["current"], data["source"], data["configured"]),
            (new, new, "dashboard", True),
        )
        self.assertEqual(imaging_root(), new)
        self.assertEqual(CoreSettings.objects.get().imaging_root, new)
        self.assertEqual(Path(new, MARKER).stat().st_mode & 0o777, 0o600)
        with directory() as root:
            self.assertEqual(os.fstat(root).st_ino, os.stat(new).st_ino)
        entry = AuditLog.objects.get(object_type="coresettings")
        self.assertEqual(entry.username, self.john.username)
        self.assertEqual(entry.before_value, {"imaging_root": self.default})
        self.assertEqual(entry.after_value, {"imaging_root": new})
        self.assertIn(f"from {self.default} to {new}", entry.message)

        for path, text in (
            ("relative", "absolute path"),
            (os.path.join(self.base, "missing"), "must exist"),
            (None, "Enter a folder path."),
        ):
            refused = self._put(path)
            self.assertEqual(refused.status_code, 400)
            self.assertIn(text, refused.json()["path"][0])
        self.assertEqual(imaging_root(), new)

        response = self._put("")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            (response.json()["current"], response.json()["source"]),
            (self.default, "server"),
        )
        self.assertEqual(CoreSettings.objects.get().imaging_root, "")
        self.assertEqual(imaging_root(), self.default)
        self.assertEqual(AuditLog.objects.filter(object_type="coresettings").count(), 2)

    def test_save_needs_step_up_and_settings_rights(self):
        new = self._folder("new")
        response = self.client.put("/imaging/storage/", {"path": new}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {
                "detail": "Confirm with a two-factor code first. "
                "Moving the system image storage needs it.",
                "stepup": True,
            },
        )
        self.assertEqual(CoreSettings.objects.get().imaging_root, "")
        self.assertFalse(Path(new, MARKER).exists())
        self.client.force_authenticate(
            self.create_user_with_roles(["can_view_core_settings"])
        )
        self.assertEqual(self.client.get("/imaging/storage/").status_code, 403)
        self.assertEqual(self._put(new).status_code, 403)
        self.client.force_authenticate(
            self.create_user_with_roles(["can_edit_core_settings"])
        )
        self.assertEqual(self.client.get("/imaging/storage/").status_code, 200)
        self.assertEqual(self._put(new).status_code, 200)

    def test_global_settings_cannot_set_the_store(self):
        core = CoreSettings.objects.get()
        serializer = CoreSettingsSerializer(
            core, data={"imaging_root": "/tmp"}, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        self.assertEqual(CoreSettings.objects.get().imaging_root, "")

    def test_first_use_marks_the_store(self):
        marker = Path(self.default, MARKER)
        self.assertFalse(marker.exists())
        with directory():
            pass
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        store = CoreSettings.objects.get().imaging_store_id
        self.assertEqual(len(store), 32)
        self.assertEqual(marker.read_text().strip(), store)

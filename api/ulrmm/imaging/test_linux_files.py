# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import copy
from datetime import timedelta
import gzip
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

from django.test import override_settings
from django.utils import timezone
from model_bakery import baker
from rest_framework.test import APIClient

from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase
from .blocks import BLOCK
from .models import (
    LINUX_OFFLINE_METHOD,
    BackupPolicy,
    Image,
    ImageStatus,
    NativeInventory,
    Pairing,
    Profile,
    Transfer,
)
from .service import capability
from .storage import OTHER_STORE, StoreUnavailable
from .tasks import imaging_tick, verify_image

ROOT = "0b6f3d0e-6f1c-4a51-9d0e-2b8a7c1d4e5f"
ESP = "abcd-1234"
FRIGATE = "5d1c9a7b-3e2f-4c8d-a6b5-9e0f1d2c3b4a"
CAP = {
    "method": "linux-files-v1",
    "ready": True,
    "scope": "Debian GNU/Linux 13 (trixie). Live file backup of the system disk file systems: /, /boot/efi.",
    "recovery": "Boot ULRMM Linux recovery media in UEFI mode and restore onto a blank disk with the same logical sector size that holds the recorded partitions. Extra volumes are not part of the disk restore. Keep the original disk detached: the restored disk carries the same UUIDs.",
    "reason": "Ready for a live backup.",
    "encryption": "unencrypted source",
    "source_id": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456",
    "device_uuid": "90cb53c8-01ea-444d-b1f1-23abcd127ace",
    "boot_mode": "uefi",
    "size": 1000204886016,
    "sector_size": 512,
    "min_target_size": 1000204157440,
    "volumes": [
        {
            "id": ROOT,
            "mount": "/",
            "fs": "ext4",
            "kind": "system",
            "disk": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456",
            "size": 999666221056,
            "used": 41231686041,
            "consistency": "live",
            "reason": "",
        },
        {
            "id": ESP,
            "mount": "/boot/efi",
            "fs": "vfat",
            "kind": "system",
            "disk": "nvme-Samsung_SSD_980_1TB_S64ANS0T123456",
            "size": 536870912,
            "used": 6291456,
            "consistency": "live",
            "reason": "",
        },
        {
            "id": FRIGATE,
            "mount": "/media/frigate",
            "fs": "ext4",
            "kind": "extra",
            "disk": "ata-WDC_WD40PURZ-85AKKY0_WD-WX12345678",
            "size": 4000785960960,
            "used": 2899102924800,
            "consistency": "live",
            "reason": "",
        },
        {
            "id": "",
            "mount": "/mnt/backups",
            "fs": "cifs",
            "kind": "network",
            "disk": "",
            "size": 0,
            "used": 0,
            "consistency": "",
            "reason": "Network storage is not backed up.",
        },
    ],
}
CONFIG = {
    "destination": "fleet",
    "compression": "gzip",
    "compression_level": 6,
    "network_mode": "internet",
    "schedule_time": None,
    "timezone": "UTC",
}
REPORT = {
    "entries": 3,
    "changed": 0,
    "vanished": 0,
    "skipped": 0,
    "reappended": 0,
    "padding_bytes": 0,
}
SYNTAX = "Use absolute mount paths such as /media/data or drive letters such as D:."
GONE = "Selected volume /media/frigate is not mounted."


def block_list(blocks):
    return sha256(b"".join(sha256(b).digest() for b in blocks)).hexdigest()


class LinuxFilesTests(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.agent = baker.make(
            "agents.Agent", agent_id="test-files-agent", plat="linux", goarch="amd64"
        )
        self.authenticate_agent(self.agent)
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
        self.transport = {"secure": True, "HTTP_HOST": "api.example.com"}
        self.cap = copy.deepcopy(CAP)
        self.assertEqual(self.report().status_code, 204)

    def report(self, cap=None):
        return self.worker.post(
            self.poll, {"capability": cap or self.cap}, format="json", secure=True
        )

    def save(self, volumes=()):
        return self.client.put(
            self.uri, {**CONFIG, "volumes": list(volumes)}, format="json"
        )

    def capture(self):
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        return response.data["id"]

    def queue(self, volumes=()):
        self.assertEqual(self.save(volumes).status_code, 200)
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        return response.data["id"]

    def claim(self, volumes=()):
        image_id = self.queue(volumes)
        grant = self.report()
        self.assertEqual(grant.status_code, 200, grant.data)
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + grant.data["token"])
        path = urlsplit(grant.data["url"]).path
        begin = client.post(path + "begin/", {}, format="json", **self.transport)
        self.assertEqual(begin.status_code, 204)
        return image_id, client, path

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

    def seal(self, client, path, size, digest, **extra):
        body = {
            "size": size,
            "sha256": digest,
            "index": {"offset": 0, "size": size},
            "report": REPORT,
            **extra,
        }
        return client.post(path + "seal/", body, format="json", **self.transport)

    def point(self, blocks, volumes=()):
        image_id, client, path = self.claim(volumes)
        for index, data in enumerate(blocks):
            self.assertEqual(self.part(client, path, data, index).status_code, 204)
        size = sum(map(len, blocks))
        sealed = self.seal(client, path, size, block_list(blocks))
        self.assertEqual(sealed.status_code, 202, sealed.data)
        verify_image(image_id)
        image = Image.objects.get(pk=image_id)
        self.assertEqual(image.status, ImageStatus.VERIFIED, image.reason)
        return image

    def test_report_is_stored_with_volumes_and_checked(self):
        stored = NativeInventory.objects.get(agent=self.agent).capability
        self.assertEqual(stored["volumes"], CAP["volumes"])
        self.assertEqual(stored["min_target_size"], CAP["min_target_size"])
        twin = copy.deepcopy(CAP)
        twin["volumes"][2]["id"] = ROOT
        no_system = {**CAP, "volumes": CAP["volumes"][2:]}
        flood = {**CAP, "volumes": CAP["volumes"][:1] * 65}
        for cap, text in (
            (twin, "Volume IDs must be unique."),
            (no_system, "A ready provider must identify"),
            ({**CAP, "min_target_size": 0}, "A ready provider must identify"),
            ({**CAP, "min_target_size": CAP["size"] + 1}, "A ready provider"),
            (flood, "no more than 64"),
        ):
            response = self.report(cap)
            self.assertEqual(response.status_code, 400)
            self.assertIn(text, str(response.data))
        # network and unsupported volumes may share an empty id
        shared = copy.deepcopy(CAP)
        shared["volumes"].append({**CAP["volumes"][3], "mount": "/mnt/nfs"})
        self.assertEqual(self.report(shared).status_code, 204)
        type(self.agent).objects.filter(pk=self.agent.pk).update(plat="windows")
        response = self.report()
        self.assertEqual(response.status_code, 400)
        self.assertIn("belongs to a different platform", str(response.data))

    def test_files_method_needs_ready_and_offline_does_not(self):
        self.assertTrue(capability(self.agent)["supported"])
        waiting = {**CAP, "ready": False, "reason": "Live Linux backup requires UEFI."}
        self.assertEqual(self.report(waiting).status_code, 204)
        self.assertFalse(capability(self.agent)["supported"])
        offline = {
            k: v
            for k, v in CAP.items()
            if k not in ("volumes", "min_target_size", "ready")
        }
        offline.update(method="linux-offline-disk-v1", ready=False)
        self.assertEqual(self.report(offline).status_code, 204)
        result = capability(self.agent)
        self.assertTrue(result["supported"])
        self.assertEqual(
            (result["native"]["volumes"], result["native"]["min_target_size"]),
            ([], 0),
        )

    def test_device_saves_only_offered_extra_volumes(self):
        response = self.save(["/media/frigate"])
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["config"]["volumes"], ["/media/frigate"])
        self.assertEqual(Profile.objects.get().volumes, ["/media/frigate"])
        for selector in ("/boot/efi", "/mnt/backups", "/media/other"):
            response = self.save(["/media/frigate", selector])
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.json(),
                {"volumes": [f"{selector} is not an extra volume on this device."]},
            )
        for bad in (
            ["media"],
            ["/"],
            ["/media/frigate/"],
            ["/media/../frigate"],
            ["d:"],
            ["/media/\x01"],
            ["/media/frigate", "/media/frigate"],
            ["/x"] * 33,
        ):
            response = self.save(bad)
            self.assertEqual(response.status_code, 400)
            self.assertIn("volumes", response.json())
        self.assertIn(SYNTAX, str(self.save(["media"]).data))
        self.assertEqual(Profile.objects.get().volumes, ["/media/frigate"])
        # a report without volumes accepts no selection
        offline = {k: v for k, v in CAP.items() if k != "volumes"}
        offline.update(method="linux-offline-disk-v1", min_target_size=0)
        self.assertEqual(self.report(offline).status_code, 204)
        self.assertEqual(self.save(["/media/frigate"]).status_code, 400)
        self.assertEqual(self.save().status_code, 200)

    def test_policy_volumes_and_warnings(self):
        windows = baker.make("agents.Agent", agent_id="test-files-win", plat="windows")
        NativeInventory.objects.create(
            agent=windows,
            capability={
                **{k: v for k, v in CAP.items() if k != "volumes"},
                "method": "windows-wbadmin-tar-v1",
                "volumes": [],
                "min_target_size": 0,
            },
        )
        selectors = ["/media/frigate", "/media/old", "/mnt/backups"]
        policy = {
            "name": "Fleet",
            "config": {**CONFIG, "volumes": selectors},
            "agents": [self.agent.agent_id, windows.agent_id],
        }
        response = self.client.post("/imaging/policies/", policy, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            response.data["warnings"],
            [
                {
                    "agent_id": self.agent.agent_id,
                    "unmatched": ["/media/old"],
                    "unusable": ["/mnt/backups"],
                }
            ],
        )
        self.assertEqual(Profile.objects.get(agent=self.agent).volumes, selectors)
        pk = response.data["id"]
        policy["config"]["volumes"] = ["/media/frigate"]
        response = self.client.put(f"/imaging/policies/{pk}/", policy, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["warnings"], [])
        policy["config"]["volumes"] = ["media"]
        response = self.client.put(f"/imaging/policies/{pk}/", policy, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertIn(SYNTAX, str(response.data))
        BackupPolicy.objects.create(name="Old", config=CONFIG)
        listed = {p["name"]: p for p in self.client.get("/imaging/policies/").data}
        self.assertEqual(listed["Old"]["config"]["volumes"], [])
        self.assertEqual(listed["Fleet"]["config"]["volumes"], ["/media/frigate"])

    def test_queue_resolves_the_selection(self):
        self.save()
        Profile.objects.update(
            volumes=["/media/frigate", "/boot/efi", "/mnt/backups", "/media/old"],
            policy=BackupPolicy.objects.create(name="Fleet", config=CONFIG),
        )
        image = Image.objects.get(
            pk=self.client.post(self.uri + "capture/", {}, format="json").data["id"]
        )
        self.assertEqual(image.status, ImageStatus.WAITING)
        native = image.native
        self.assertEqual(native["include"], [ROOT, ESP, FRIGATE])
        self.assertEqual(native["missing"], ["/mnt/backups", "/media/old"])
        self.assertEqual(
            native["stream_limit"], 999666221056 + 536870912 + 4000785960960
        )
        self.assertEqual(native["min_target_size"], 1000204157440)
        Image.objects.update(status=ImageStatus.FAILED)
        native = Image.objects.get(pk=self.queue()).native
        self.assertEqual(
            (native["include"], native["missing"], native["stream_limit"]),
            ([ROOT, ESP], [], 999666221056 + 536870912),
        )

    def test_missing_device_volume_fails_at_queue(self):
        older = self.point([b"old"])
        self.assertEqual(self.save(["/media/frigate"]).status_code, 200)
        gone = {**CAP, "volumes": CAP["volumes"][:2]}
        self.assertEqual(self.report(gone).status_code, 204)
        response = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        image = Image.objects.get(pk=response.data["id"])
        self.assertEqual((image.status, image.reason), (ImageStatus.FAILED, GONE))
        self.assertEqual(image.native["missing"], ["/media/frigate"])
        Profile.objects.update(keep_last=1)
        imaging_tick()
        older.refresh_from_db()
        self.assertEqual(older.status, ImageStatus.VERIFIED)

        # still mounted, but no longer a volume the live backup can read
        reformatted = copy.deepcopy(CAP)
        reformatted["volumes"][2].update(
            fs="btrfs", kind="unsupported", reason="btrfs is not supported yet."
        )
        self.assertEqual(self.report(reformatted).status_code, 204)
        Profile.objects.update(volumes=["/media/frigate"])
        image = Image.objects.get(pk=self.capture())
        self.assertEqual(
            (image.status, image.reason),
            (
                ImageStatus.FAILED,
                "Selected volume /media/frigate cannot be backed up: "
                "btrfs is not supported yet.",
            ),
        )
        # the offline fallback holds the system disk only
        offline = {
            **CAP,
            "method": LINUX_OFFLINE_METHOD,
            "volumes": [],
            "ready": False,
            "reason": "Live backup unavailable: no DMI UUID.",
        }
        self.assertEqual(self.report(offline).status_code, 204)
        image = Image.objects.get(pk=self.capture())
        self.assertEqual(
            (image.status, image.reason, image.native["missing"]),
            (
                ImageStatus.FAILED,
                "Selected volumes need the live backup. "
                "Live backup unavailable: no DMI UUID.",
                ["/media/frigate"],
            ),
        )
        # an agent reason may be longer than the point's reason field
        offline["reason"] = "Live backup unavailable: " + "x" * 300
        self.assertEqual(self.report(offline).status_code, 204)
        self.assertEqual(len(Image.objects.get(pk=self.capture()).reason), 255)

        # a policy's selection does not fail the offline point, it is shown as missing
        Profile.objects.update(
            policy=BackupPolicy.objects.create(name="Fleet", config=CONFIG)
        )
        image = Image.objects.get(pk=self.capture())
        self.assertEqual(
            (image.status, image.native["missing"]),
            (ImageStatus.WAITING, ["/media/frigate"]),
        )

    def test_paired_offline_capture_fails_with_selected_volumes(self):
        self.assertEqual(self.save(["/media/frigate"]).status_code, 200)
        baker.make(
            Pairing,
            agent=self.agent,
            user=self.john,
            network_mode=CONFIG["network_mode"],
            expires_at=timezone.now() + timedelta(days=1),
        )
        image = Image.objects.get(pk=self.capture())
        self.assertEqual(
            (image.status, image.reason, image.native),
            (
                ImageStatus.FAILED,
                "Selected volumes need the live backup. "
                "Unpair offline capture or untick the volumes.",
                None,
            ),
        )
        Profile.objects.update(volumes=[])
        image = Image.objects.get(pk=self.capture())
        self.assertEqual((image.status, image.native), (ImageStatus.WAITING, None))

    def test_missing_pinned_volume_fails_the_point_only(self):
        older = self.point([b"old"], ["/media/frigate"])
        moved = copy.deepcopy(CAP)
        moved["volumes"][2]["mount"] = "/media/other"
        unmounted = copy.deepcopy(CAP)
        unmounted["volumes"][2].update(kind="unmounted", reason="Not mounted.")
        gone = {**CAP, "volumes": CAP["volumes"][:2]}
        for cap in (gone, moved, unmounted):
            image_id = self.queue(["/media/frigate"])
            self.assertEqual(self.report(cap).status_code, 204)
            image = Image.objects.get(pk=image_id)
            self.assertEqual((image.status, image.reason), (ImageStatus.FAILED, GONE))
            self.assertFalse(Transfer.objects.filter(image=image).exists())
            self.report()
        # failed points never count for keep-last
        Profile.objects.update(keep_last=1)
        imaging_tick()
        older.refresh_from_db()
        self.assertEqual(older.status, ImageStatus.VERIFIED)

    def test_upload_bound_follows_the_stream_limit(self):
        image_id, client, path = self.claim()
        point = Image.objects.filter(pk=image_id)
        native = point.get().native
        uploading = dict(status=ImageStatus.UPLOADING)
        failed = "Upload exceeded the approved source size."
        point.update(native={**native, "size": 4, "stream_limit": 100}, new_bytes=201)
        self.assertEqual(self.part(client, path, b"12345").status_code, 400)
        self.assertEqual(point.get().reason, failed)
        without = {k: v for k, v in native.items() if k != "stream_limit"}
        point.update(native={**without, "size": 4}, new_bytes=9, **uploading)
        self.assertEqual(self.part(client, path, b"12345").status_code, 400)
        # the stream may pass the system disk size
        point.update(
            native={**native, "size": 4, "stream_limit": 100}, new_bytes=0, **uploading
        )
        self.assertEqual(self.part(client, path, b"12345").status_code, 204)

    def test_seal_needs_index_and_report_and_verifies_the_block_list(self):
        blocks = [b"A" * BLOCK, b"tail"]
        image_id, client, path = self.claim()
        for index, data in enumerate(blocks):
            self.assertEqual(self.part(client, path, data, index).status_code, 204)
        size = BLOCK + 4
        digest = sha256(b"".join(blocks)).hexdigest()
        for extra, text in (
            ({"index": None}, "The stream index location is invalid."),
            ({"index": {"offset": -1, "size": 4}}, "index location"),
            ({"index": {"offset": 0, "size": 0}}, "index location"),
            ({"index": {"offset": 1, "size": size}}, "index location"),
            ({"index": {"offset": True, "size": 4}}, "index location"),
            ({"index": {"offset": 0, "size": 4, "x": 1}}, "index location"),
            ({"report": {**REPORT, "changed": -1}}, "The stream report is invalid."),
            ({"report": {**REPORT, "changed": "1"}}, "stream report"),
            ({"report": {**REPORT, "extra": 1}}, "stream report"),
            ({"report": {"entries": 1}}, "stream report"),
        ):
            response = self.seal(client, path, size, digest, **extra)
            self.assertEqual(response.status_code, 400)
            self.assertIn(text, str(response.data))
        # a whole-stream digest is not the sealed format of this method
        self.assertEqual(self.seal(client, path, size, digest).status_code, 202)
        verify_image(image_id)
        self.assertEqual(Image.objects.get(pk=image_id).status, ImageStatus.FAILED)
        image = self.point(blocks)
        self.assertEqual(image.raw_sha256, block_list(blocks))
        self.assertEqual(image.native["index"], {"offset": 0, "size": size})
        self.assertEqual(image.native["report"], REPORT)

    def test_restore_step_up_comes_before_the_image_lock(self):
        image = self.point([b"x"])
        url = self.uri + f"images/{image.pk}/restore-access/"
        with patch("imaging.views._lock_image") as lock:
            response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertTrue(response.json()["stepup"])
        lock.assert_not_called()

    def test_new_live_profile_uses_gzip_level_one(self):
        self.assertEqual(
            self.client.get(self.uri).data["config"]["compression_level"], 1
        )
        offline = {**CAP, "method": LINUX_OFFLINE_METHOD, "volumes": [], "ready": False}
        self.assertEqual(self.report(offline).status_code, 204)
        self.assertEqual(
            self.client.get(self.uri).data["config"]["compression_level"], 6
        )

    def test_first_capture_creates_a_level_one_live_profile(self):
        image = Image.objects.get(pk=self.capture())
        self.assertEqual(
            (
                image.compression_level,
                Profile.objects.get(agent=self.agent).compression_level,
            ),
            (1, 1),
        )

    def test_restore_grant_checks_target_and_stored_blocks(self):
        image = self.point([b"A" * BLOCK, b"tail"])
        url = self.uri + f"images/{image.pk}/restore-access/"
        confirmation = {
            "device_uuid": CAP["device_uuid"],
            "disk_id": "nvme-Target_Disk",
            "target_agent_id": self.agent.agent_id,
            "confirmed": True,
            "raw_size": CAP["min_target_size"],
            "sector_size": 512,
        }
        small = "The target disk must be at least as large as the recorded partitions and use the source sector size."
        with patch("imaging.views.stepup_denied", return_value=None):
            for unfit in (
                {"raw_size": CAP["min_target_size"] - 1},
                {"sector_size": 4096},
                {"raw_size": None},
            ):
                body = {k: v for k, v in {**confirmation, **unfit}.items() if v}
                response = self.client.post(url, body, format="json")
                self.assertEqual(response.status_code, 400)
                self.assertIn(small, str(response.data))
            with patch(
                "imaging.blocks.stored", side_effect=StoreUnavailable(OTHER_STORE)
            ):
                response = self.client.post(url, confirmation, format="json")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json(), {"detail": OTHER_STORE})
            response = self.client.post(url, confirmation, format="json")
            self.assertEqual(response.status_code, 201, response.data)
            (self.root / "fleet" / str(image.parts.get(index=1).block_id)).unlink()
            response = self.client.post(url, confirmation, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertIn("missing from the image store", response.json()["detail"])
        image.refresh_from_db()
        self.assertEqual(image.status, ImageStatus.VERIFIED)

    def test_recheck_queues_a_full_check_of_verified_points(self):
        image = self.point([b"old"])
        url = self.uri + f"images/{image.pk}/recheck/"
        with (
            patch("imaging.tasks.verify_image.delay") as delay,
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.assertEqual(self.client.post(url, {}, format="json").status_code, 202)
        delay.assert_called_once_with(str(image.pk), recheck=True)
        self.assertTrue(
            AuditLog.objects.filter(message__contains="check requested").exists()
        )
        self.client.force_authenticate(
            self.create_user_with_roles(["can_restore_images"])
        )
        self.assertEqual(self.client.post(url, {}, format="json").status_code, 202)
        self.client.force_authenticate(self.create_user_with_roles([]))
        self.assertEqual(self.client.post(url, {}, format="json").status_code, 403)
        self.client.force_authenticate(self.john)
        Image.objects.update(status=ImageStatus.FAILED)
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(), {"detail": "Only verified points can be checked again."}
        )

    def test_live_point_keeps_the_operator_check(self):
        image_id = self.queue()
        Image.objects.filter(pk=image_id).update(operator=None)
        self.assertEqual(self.report().status_code, 204)
        image = Image.objects.get(pk=image_id)
        self.assertEqual(image.status, ImageStatus.FAILED)
        self.assertIn("no longer has imaging access", image.reason)

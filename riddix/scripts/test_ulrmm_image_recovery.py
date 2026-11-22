import contextlib
import gzip
import hashlib
import http.client
import io
import json
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import ulrmm_image_recovery as recovery


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class LocalTransfer:
    def __init__(self, **manifest):
        self.manifest = manifest
        self.data = bytearray()
        self.completed = None
        self.reported = False

    def request(self, method, endpoint="", payload=None, limit=None, committed=None):
        if not endpoint:
            return json.dumps(self.manifest)
        if endpoint == "manifest/":
            self.manifest.update(payload)
        elif endpoint == "integrity-failed/":
            self.reported = True
        elif endpoint == "complete/":
            self.completed = payload
        else:
            # The same rules as the server's data endpoint.
            offset = int(endpoint.split("=")[-1])
            if method == "GET":
                if not 0 <= offset < len(self.data):
                    raise recovery.RecoveryError("GET returned HTTP 416")
                native = "native" in self.manifest
                size = recovery.NATIVE_CHUNK if native else recovery.CHUNK
                chunk = self.data[offset : offset + size]
                if len(chunk) > limit:
                    raise recovery.RecoveryError("Server response exceeds the limit")
                return chunk
            if offset != len(self.data):
                raise recovery.RecoveryError("PUT returned HTTP 409")
            if not 0 < len(payload) <= recovery.CHUNK:
                raise recovery.RecoveryError("PUT returned HTTP 413")
            self.data.extend(payload)


class RecoveryTest(unittest.TestCase):
    geometry = {"raw_size": 8192, "sector_size": 512, "disk_id": "virtio-disposable"}
    host = {
        "architecture": "x86_64",
        "boot_mode": "bios",
        "device_uuid": "8992796e-04dd-468e-8fcb-881a2358c877",
    }
    data = bytes(range(256)) * 32

    def image(self, compression):
        stored = self.data if compression == "none" else gzip.compress(self.data)
        transfer = LocalTransfer(
            **self.geometry,
            **self.host,
            agent_id="test-agent",
            image_id=2,
            network_mode="internet",
            compression=compression,
            size=len(stored),
            sha256=sha256(stored),
            raw_sha256=sha256(self.data),
        )
        transfer.data.extend(stored)
        return transfer

    def test_native_restore_uses_raw_chunks_and_raw_hash(self):
        data = b"A" * recovery.NATIVE_CHUNK + b"B" * 512
        manifest = {
            "native": {
                "method": recovery.NATIVE_METHOD,
                "size": len(data),
                "sector_size": 512,
                "boot_mode": "uefi",
            },
            "compression": "none",
            "size": len(data),
            "raw_size": len(data),
            "sha256": "0" * 64,
            "raw_sha256": sha256(data),
        }
        transfer = LocalTransfer(**manifest)
        transfer.data.extend(data)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile(
            dir=directory
        ) as staged, mock.patch.object(
            transfer, "request", wraps=transfer.request
        ) as request:
            disk = recovery.disk_restore_manifest(manifest)
            recovery.stage_restore(transfer, disk, staged, directory)
            self.assertEqual(staged.read(), data)
            self.assertEqual(disk["sector_size"], 512)
            self.assertEqual(disk["boot_mode"], "uefi")
            self.assertEqual(
                request.call_args_list,
                [
                    mock.call("GET", "data/?offset=0", limit=recovery.NATIVE_CHUNK),
                    mock.call("GET", "data/?offset=2097152", limit=512),
                ],
            )

    def test_capture_pairing_requires_same_origin_and_network(self):
        url = "https://api.example.test/imaging/transfers/00000000-0000-4000-8000-000000000001/"
        args = SimpleNamespace(
            poll_url=url + "poll/",
            network_mode="internal",
            interface="wg0",
            ca_file=None,
        )
        grant = {"url": url, "network_mode": "internal", "token": "scoped-token"}
        with mock.patch.object(recovery, "Transfer") as pairing:
            call = pairing.return_value.request
            call.return_value = b""
            self.assertIsNone(recovery.poll_capture(args, "pair-secret"))
            call.return_value = json.dumps(grant)
            self.assertEqual(recovery.poll_capture(args, "pair-secret"), grant)
            for change in (
                {"url": url.replace("api.", "elsewhere.")},
                {"network_mode": "internet"},
            ):
                call.return_value = json.dumps(grant | change)
                with self.assertRaises(recovery.RecoveryError):
                    recovery.poll_capture(args, "pair-secret")

    def test_resume_upload_recreates_gzip_prefix_and_verifies_hashes(self):
        # 8192 bytes uncompressed are whole 64-byte chunks with nothing left over
        for compression in ("none", "gzip"):
            transfer = LocalTransfer(
                offset=0, compression=compression, compression_level=3
            )
            geometry = self.geometry | self.host
            with mock.patch.object(recovery, "CHUNK", 64):
                recovery.capture(
                    transfer, transfer.manifest, io.BytesIO(self.data), geometry
                )
                expected = bytes(transfer.data)
                expected_result = transfer.completed
                del transfer.data[94:]
                transfer.manifest["offset"] = 94
                transfer.completed = None
                recovery.capture(
                    transfer, transfer.manifest, io.BytesIO(self.data), geometry
                )
            self.assertEqual(transfer.data, expected)
            self.assertEqual(transfer.completed, expected_result)
            self.assertEqual(transfer.completed["raw_sha256"], sha256(self.data))
            self.assertEqual(transfer.completed["sha256"], sha256(expected))

    def test_restore_verifies_and_rechecks_target_before_writing(self):
        for compression in ("none", "gzip"):
            transfer = self.image(compression)
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / "disposable.raw"
                target.write_bytes(bytes(self.geometry["raw_size"]))
                args = SimpleNamespace(
                    staging_dir=folder, disk_id=self.geometry["disk_id"]
                )
                open_modes = []

                @contextlib.contextmanager
                def disk(disk_id, writable=False):
                    self.assertEqual(disk_id, self.geometry["disk_id"])
                    open_modes.append(writable)
                    with target.open("r+b" if writable else "rb") as stream:
                        yield stream, self.geometry

                recovery.restore(
                    transfer,
                    dict(transfer.manifest),
                    args,
                    self.host,
                    disk,
                    lambda: True,
                )
                self.assertEqual(open_modes, [False, True])
                self.assertEqual(target.read_bytes(), self.data)
                self.assertEqual(transfer.completed, {"raw_sha256": sha256(self.data)})

    def test_corrupt_or_incompatible_restore_never_opens_writable_target(self):
        for kind, message in [
            ("corrupt", "SHA-256"),
            ("too small", "raw_size"),
            ("mismatch", "sector_size"),
            ("wrong device", "device_uuid"),
            ("unconfirmed", "confirmation"),
        ]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                transfer = self.image("gzip")
                if kind == "corrupt":
                    transfer.data[0] ^= 1
                if kind == "too small":
                    transfer.manifest["raw_size"] *= 2
                if kind == "mismatch":
                    transfer.manifest["sector_size"] = 4096
                if kind == "wrong device":
                    transfer.manifest["device_uuid"] = (
                        "17846dd6-9e98-4435-875c-f65fd35d5afa"
                    )
                args = SimpleNamespace(
                    staging_dir=folder, disk_id=self.geometry["disk_id"]
                )

                @contextlib.contextmanager
                def disk(disk_id, writable=False):
                    self.assertFalse(writable)
                    yield None, self.geometry

                with self.assertRaisesRegex(recovery.RecoveryError, message):
                    recovery.restore(
                        transfer,
                        dict(transfer.manifest),
                        args,
                        self.host,
                        disk,
                        lambda: False,
                    )
                self.assertIsNone(transfer.completed)
                self.assertEqual(transfer.reported, kind == "corrupt")

    def test_source_requires_clean_linux_root_and_local_boot_partitions(self):
        root = {
            "name": "/dev/vda1",
            "type": "part",
            "fstype": "ext4",
            "uuid": "root",
            "partuuid": "root-part",
            "parttype": "linux-guid",
            "label": "cloudimg-rootfs",
            "partlabel": "primary",
        }
        efi = {
            "name": "/dev/vda2",
            "type": "part",
            "fstype": "vfat",
            "uuid": "EFI",
            "partuuid": "efi-part",
            "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "label": "UEFI",
            "partlabel": "primary",
        }
        swaps = [
            {"name": f"/dev/vda{n}", "type": "part", "fstype": "swap", "uuid": f"s{n}"}
            for n in (3, 4)
        ]
        parts = {
            "blockdevices": [
                {
                    "type": "disk",
                    "fstype": None,
                    "pttype": "gpt",
                    "children": [root, efi, *swaps],
                }
            ]
        }
        root_fstab = "UUID=root / ext4 defaults 0 1\n"
        clean = "Filesystem state:         clean\n"
        efi_fstab = "UUID=EFI /boot/efi vfat defaults 0 2\n"
        installer_fstab = (
            "/dev/disk/by-uuid/root / ext4 defaults 0 1\n"
            "/dev/disk/by-uuid/efi /boot/efi vfat umask=0077 0 1\n"
            "/swap.img none swap sw 0 0\n"
        )
        for fstab, header, error in [
            (root_fstab + efi_fstab, clean, None),
            (installer_fstab, clean, None),
            (
                root_fstab
                + efi_fstab
                + "/dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0\n",
                clean,
                None,
            ),
            (
                root_fstab
                + efi_fstab
                + "UUID=s3 none swap sw 0 0\nUUID=s4 none swap sw 0 0\n",
                clean,
                None,
            ),
            (
                "LABEL=cloudimg-rootfs / ext4 defaults 0 1\n"
                "LABEL=UEFI /boot/efi vfat umask=0077 0 1\n",
                clean,
                None,
            ),
            # both partitions carry this GPT name
            (
                root_fstab + "PARTLABEL=primary /boot/efi vfat umask=0077 0 1\n",
                clean,
                "outside",
            ),
            (root_fstab + efi_fstab + "/dev/vdb1 none swap sw 0 0\n", clean, "outside"),
            # systemd automounts these despite noauto
            (
                root_fstab
                + efi_fstab
                + "UUID=otherdisk /home ext4 noauto,x-systemd.automount 0 2\n",
                clean,
                "outside",
            ),
            (
                root_fstab
                + "UUID=EFI /boot/efi vfat noauto,x-systemd.automount,umask=0077 0 2\n",
                clean,
                None,
            ),
            # labels are case-sensitive, this one names another disk
            (
                root_fstab + "LABEL=uefi /boot/efi vfat umask=0077 0 1\n",
                clean,
                "outside",
            ),
            (root_fstab, clean, "EFI"),
            (
                root_fstab + "PARTUUID=external /boot ext4 defaults 0 2\n",
                clean,
                "outside",
            ),
            (
                root_fstab + efi_fstab,
                clean + "Filesystem features: needs_recovery\n",
                "cleanly",
            ),
        ]:
            with mock.patch.object(
                recovery,
                "inspect",
                side_effect=[json.dumps(parts), header, "ID=debian\n", fstab],
            ):
                if error:
                    with self.assertRaisesRegex(recovery.RecoveryError, error):
                        recovery.verify_source("/dev/vda", "uefi")
                else:
                    recovery.verify_source("/dev/vda", "uefi")

    def test_wrong_interface_never_creates_socket(self):
        link = [{"linkinfo": {"info_kind": "ether"}, "ifindex": 2, "flags": ["UP"]}]
        connection = recovery.BoundHTTPSConnection("server", interface="eth0")
        with mock.patch.object(
            recovery.subprocess,
            "run",
            return_value=SimpleNamespace(stdout=json.dumps(link)),
        ), mock.patch.object(
            socket, "if_nametoindex", return_value=2
        ), mock.patch.object(
            socket, "socket"
        ) as create:
            with self.assertRaisesRegex(recovery.RecoveryError, "Waiting"):
                connection.connect_bound(("server", 443), 1, None)
        create.assert_not_called()

    def test_failed_chunk_stops_remaining_upload_and_completion(self):
        transfer = mock.Mock()
        transfer.request.side_effect = [None, recovery.RecoveryError("Forbidden path")]
        manifest = {"offset": 0, "compression": "gzip", "compression_level": 0}
        with mock.patch.object(recovery, "CHUNK", 64):
            with self.assertRaisesRegex(recovery.RecoveryError, "Forbidden path"):
                recovery.capture(
                    transfer, manifest, io.BytesIO(self.data), self.geometry | self.host
                )
        self.assertEqual(
            [call.args[0] for call in transfer.request.call_args_list], ["POST", "PUT"]
        )

    def test_request_retries_transient_errors_and_lost_put_replies(self):
        url = "https://api.example.test/imaging/transfers/00000000-0000-4000-8000-000000000001/"
        transfer = recovery.Transfer(url, "token")

        def reply(body, size=None):
            response = mock.MagicMock(status=200)
            response.__enter__.return_value = response
            response.read.return_value = body
            response.headers = {
                "Content-Length": str(len(body) if size is None else size)
            }
            return response

        def error(code):
            return urllib.error.HTTPError(url, code, "error", {}, None)

        committed = reply(b'{"offset": 128}')
        cases = [
            ([OSError(), recovery.TransportError("Waiting"), error(503)], b"chunk", 4),
            # the link dropped in the middle of the body
            ([reply(b"chu", 5)], b"chunk", 2),
            # the first PUT was stored, its reply got lost
            ([http.client.RemoteDisconnected(), error(409), committed], b"", 3),
            ([OSError(), error(409), reply(b'{"offset": 64}')], "HTTP 409", 3),
            ([error(409)], "HTTP 409", 1),
            ([error(403)], "HTTP 403", 1),
            ([error(502)] * 6, "HTTP 502", 6),
            ([OSError("link down")] * 6, "link down", 6),
        ]
        for replies, result, calls in cases:
            with self.subTest(replies=replies), mock.patch.object(
                recovery.time, "sleep"
            ), mock.patch.object(
                transfer.opener, "open", side_effect=replies + [reply(b"chunk")]
            ) as send:
                put = ("PUT", "data/?offset=64", b"x")
                if isinstance(result, bytes):
                    self.assertEqual(transfer.request(*put, committed=128), result)
                else:
                    with self.assertRaisesRegex(
                        (OSError, recovery.RecoveryError), result
                    ):
                        transfer.request(*put, committed=128)
                self.assertEqual(send.call_count, calls)

    def test_insufficient_staging_space_makes_no_download_request(self):
        transfer = mock.Mock()
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryFile(
            dir=folder
        ) as raw:
            with mock.patch.object(
                recovery.os,
                "fstatvfs",
                return_value=SimpleNamespace(f_bavail=0, f_frsize=4096),
            ):
                with self.assertRaisesRegex(
                    recovery.RecoveryError, "Insufficient free staging space"
                ):
                    recovery.stage_restore(
                        transfer, self.image("gzip").manifest, raw, folder
                    )
        transfer.request.assert_not_called()

    def test_internal_socket_is_bound_before_connect(self):
        link = [{"linkinfo": {"info_kind": "wireguard"}, "ifindex": 3, "flags": ["UP"]}]
        connection = recovery.BoundHTTPSConnection("server", interface="wg0")
        peer = ("172.20.0.3", 443)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", peer)]
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        with mock.patch.object(
            recovery.subprocess,
            "run",
            return_value=SimpleNamespace(stdout=json.dumps(link)),
        ), mock.patch.object(
            socket, "if_nametoindex", return_value=3
        ), mock.patch.object(
            socket, "getaddrinfo", return_value=addresses
        ), mock.patch.object(
            socket, "socket", return_value=sock
        ):
            self.assertIs(connection.connect_bound(("server", 443), 1, None), sock)
        sock.assert_has_calls(
            [
                mock.call.settimeout(1),
                mock.call.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wg0\0"
                ),
                mock.call.connect(peer),
            ]
        )


if __name__ == "__main__":
    unittest.main()
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

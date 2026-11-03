# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import lzma
import os
import shutil
import struct
import sys
import tempfile
import time
from unittest.mock import patch

from celery.exceptions import Retry

from django.conf import settings
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from accounts.utils import grant_console_stepup
from knox.models import AuthToken
from logs.models import AuditLog
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import sdio, sdioindex, tasks
from .drivers import clean_drivers
from .models import (
    InstalledDrivers,
    SdioApproval,
    SdioCatalog,
    SdioIndex,
    SdioJob,
)
from .test_winget import FakeResponse

WIN11 = "Windows 11 Pro, 64 bit (build 22631.3447)"
WIN10 = "Windows 10 Pro, 64 bit (build 19045.4291)"
NIC = "PCI\\VEN_8086&DEV_15B8&SUBSYS_86721043&REV_10\\3&11583659&0&FE"
HWID = "PCI\\VEN_8086&DEV_15B8"
SEED = "https://www.glenn.delahoy.com/downloads/sdio/webseed/SDIO_Update/"
PIECE = 16384


def benc(v) -> bytes:
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(benc(x) for x in v) + b"e"
    return b"d" + b"".join(benc(k) + benc(v[k]) for k in sorted(v)) + b"e"


def torrent(files, seed="http://www.glenn.delahoy.com/downloads/sdio/webseed/"):
    stream = b"".join(d for _, d in files)
    pieces = b"".join(
        hashlib.sha1(stream[i : i + PIECE]).digest()
        for i in range(0, len(stream), PIECE)
    )
    info = {
        "name": "SDIO_Update",
        "piece length": PIECE,
        "pieces": pieces,
        "files": [{"length": len(d), "path": p.split("/")} for p, d in files],
    }
    return benc({"creation date": 1792181374, "url-list": seed, "info": info})


def index(entries, x86=False, version=0x205) -> bytes:
    """An index file as the format describes it."""
    text = bytearray(b"\0\0")
    text += "drivers\0".encode("utf-16-le") + "DP_T_1.7z\0".encode("utf-16-le")

    def s(v: str) -> int:
        off = len(text)
        text.extend(v.encode() + b"\0")
        return off

    infs, mfgs, descs, hwids = [], [], [], []
    for e in entries:
        fields, cats = [0] * 11, [0] * 11
        fields[2] = s(e.get("provider", "Intel"))
        if e.get("cat", "2:10.0"):
            fields[3] = s("x.cat")
            cats[3] = s(e.get("cat", "2:10.0"))
        d, m, y = e.get("dmy", (14, 3, 2025))
        infs.append(
            struct.pack(
                "<2I11I11I3i4i2i",
                s(e.get("folder", "intel\\allx64\\nic_1\\")),
                s(e.get("inf", "nic.inf")),
                *fields,
                *cats,
                d,
                m,
                y,
                *e.get("ver", (12, 19, 2, 66)),
                100,
                1,
            )
        )
        names = [s(n) for n in ["standard", *e.get("decors", ["ntamd64"])]]
        arr = len(text)
        text.extend(struct.pack(f"<{len(names)}I", *names) + b"\0")
        mfgs.append(struct.pack("<IIIi", len(infs) - 1, s("Intel"), arr, len(names)))
        descs.append(
            struct.pack(
                "<IiIIII",
                len(mfgs) - 1,
                e.get("sect", 1),
                s(e.get("desc", "Intel Ethernet")),
                s("inst"),
                s("inst"),
                255,
            )
        )
        hwids.append(
            struct.pack("<IiI", len(descs) - 1, e.get("pos", 0), s(e.get("hwid", HWID)))
        )

    def vec(recs) -> bytes:
        b = b"".join(recs)
        return struct.pack("<ii", len(b), len(recs)) + b

    payload = (
        vec(infs)
        + vec(mfgs)
        + vec(descs)
        + vec(hwids)
        + struct.pack("<ii", len(text), len(text))
        + bytes(text)
        + struct.pack("<iii", 1, 0, 0)
    )
    lzma1 = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}
    filters = ([{"id": lzma.FILTER_X86}] if x86 else []) + [lzma1]
    packed = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
    props = lzma._encode_filter_properties(lzma1)
    return (
        b"SDW"
        + struct.pack("<i", version)
        + bytes([int(x86)])
        + props
        + struct.pack("<Q", len(payload))
        + packed
    )


class Mirror:
    """fetch() stand-in serving the torrent and the files in it."""

    def __init__(self, files, missing=(), torrent_status=200):
        self.files = dict(files)
        self.body = torrent(files)
        self.missing = set(missing)
        self.torrent_status = torrent_status
        self.urls = []

    def __call__(self, method, url, hosts, **kw):
        self.urls.append(url)
        headers = kw.get("headers") or {}
        if url == sdio.TORRENT_URL:
            if self.torrent_status == 304 and headers.get("If-None-Match"):
                return FakeResponse(304)
            return FakeResponse(200, self.body, {"ETag": '"e1"'})
        path = url.removeprefix(SEED)
        if path in self.missing or path not in self.files:
            return FakeResponse(404)
        data = self.files[path]
        if rng := headers.get("Range"):
            lo, hi = map(int, rng.removeprefix("bytes=").split("-"))
            return FakeResponse(206, data[lo : hi + 1])
        return FakeResponse(200, data)


class TestTorrent(SimpleTestCase):
    def test_bdecode(self):
        self.assertEqual(
            sdio.bdecode(b"d1:al1:bi-3ee1:c0:e"), {b"a": [b"b", -3], b"c": b""}
        )
        for bad in (b"l1:a", b"i1e1", b"5:abc", b"d1:ae", b"di1ei2ee", b"x", b""):
            with self.subTest(bad), self.assertRaises(sdio.SdioError):
                sdio.bdecode(bad)
        with self.assertRaisesMessage(sdio.SdioError, "too deep"):
            sdio.bdecode(b"l" * 40 + b"e" * 40)

    def test_plan_spans_pieces(self):
        a, b, c = b"a" * 10000, b"b" * 30000, b"c" * 100
        t = sdio.Torrent(torrent([("x/a", a), ("drivers/DP_X_1.7z", b), ("c", c)]))
        self.assertEqual(
            t.seed, "https://www.glenn.delahoy.com/downloads/sdio/webseed/"
        )
        p = t.plan(t.pack("DP_X_1"))
        self.assertEqual(p["url"], SEED + "drivers/DP_X_1.7z")
        self.assertEqual(p["size"], 30000)
        self.assertEqual(
            p["head"], [{"url": SEED + "x/a", "start": 0, "length": 10000}]
        )
        # pieces 0..2: 40000 bytes of a+b end inside piece 2, c fills the rest
        self.assertEqual(p["tail"], [{"url": SEED + "c", "start": 0, "length": 100}])
        self.assertEqual(len(p["hashes"]), 3)
        stream = a + b + c
        self.assertEqual(
            p["hashes"][2], hashlib.sha1(stream[2 * PIECE : 3 * PIECE]).hexdigest()
        )

    def test_rejects(self):
        good = [("indexes/SDIO/DP_A_1.bin", b"x")]
        with self.assertRaisesMessage(sdio.SdioError, "no known web seed"):
            sdio.Torrent(torrent(good, seed="http://evil.example/"))
        with self.assertRaisesMessage(sdio.SdioError, "bad file path"):
            sdio.Torrent(torrent([("indexes/../x", b"x")]))
        data = torrent(good).replace(b"12:piece lengthi16384e", b"12:piece lengthi16e")
        with self.assertRaisesMessage(sdio.SdioError, "not understood"):
            sdio.Torrent(data)


class TestIndex(SimpleTestCase):
    def test_read_both_forms(self):
        entries = [
            {"hwid": HWID, "decors": ["ntamd64", "ntamd64.10.0...19041"], "sect": 2},
            {"hwid": "USB\\VID_1&PID_2", "dmy": (0, 0, -1), "ver": (-1, 0, 0, 0)},
        ]
        for x86 in (False, True):
            with self.subTest(x86=x86):
                rows = list(sdioindex.parse(sdioindex.unpack(index(entries, x86))))
                self.assertEqual(len(rows), 2)
                self.assertEqual(
                    rows[0],
                    {
                        "hwid": HWID,
                        "pos": 0,
                        "folder": "intel/allx64/nic_1/",
                        "inf": "nic.inf",
                        "version": "12.19.2.66",
                        "date": "2025-03-14",
                        "provider": "Intel",
                        "desc": "Intel Ethernet",
                        "decor": "ntamd64.10.0...19041",
                        "alts": ["", "ntamd64"],
                        "cats": {"amd64": "2:10.0", "x86": "2:10.0"},
                    },
                )
                self.assertEqual((rows[1]["date"], rows[1]["version"]), ("", ""))
        wanted = list(sdioindex.parse(sdioindex.unpack(index(entries)), {HWID}))
        self.assertEqual([r["hwid"] for r in wanted], [HWID])

    def test_bad_files(self):
        raw = index([{}])
        for bad, text in (
            (b"XYZ" + raw[3:], "not an SDIO index"),
            (index([{}], version=0x206), "unknown SDIO index version"),
            (raw[:30], "truncated"),
            (raw[:21] + b"\xff" * 40, "does not unpack"),
            # dictionary size from the header is capped
            (raw[:9] + b"\xff\xff\xff\xff" + raw[13:], "not understood"),
        ):
            with self.subTest(text), self.assertRaisesMessage(
                sdioindex.IndexError_, text
            ):
                sdioindex.unpack(bad)
        payload = sdioindex.unpack(raw)
        with self.assertRaises(sdioindex.IndexError_):
            list(sdioindex.parse(payload[:40]))
        # a Python built without liblzma
        with patch.dict(sys.modules, {"lzma": None}), self.assertRaisesMessage(
            sdioindex.IndexError_, "no lzma module"
        ):
            sdioindex.unpack(raw)


def entry(**kw):
    e = {
        "hwid": HWID,
        "pos": 0,
        "folder": "intel/allx64/nic_1/",
        "inf": "nic.inf",
        "version": "12.19.2.66",
        "date": "2025-03-14",
        "provider": "Intel",
        "desc": "Intel Ethernet",
        "decor": "ntamd64",
        "alts": [""],
        "cats": {"amd64": "2:10.0", "x86": "2:10.0"},
        "pack": "DP_Net_1.7z",
        "pack_size": 1000,
    }
    return {**e, **kw}


OS = ("amd64", (10, 0), 22631, False)


class TestMatch(SimpleTestCase):
    def test_device_keys(self):
        self.assertEqual(
            sdio.device_keys(NIC),
            [
                "PCI\\VEN_8086&DEV_15B8&SUBSYS_86721043&REV_10",
                "PCI\\VEN_8086&DEV_15B8&REV_10",
                "PCI\\VEN_8086&DEV_15B8&SUBSYS_86721043",
                HWID,
            ],
        )
        self.assertEqual(sdio.device_keys("ACPI\\INT33A1\\0"), ["ACPI\\INT33A1"])
        for none in ("ACPI\\PNP0A08\\0", "ROOT\\NET\\0000", "nothing", None):
            self.assertEqual(sdio.device_keys(none), [])

    def test_decorations(self):
        for decor, os_, ok in (
            ("ntamd64", OS, True),
            ("", OS, False),
            ("nt", OS, False),
            ("", ("x86", (10, 0), 19045, False), True),
            ("ntx86", OS, False),
            ("ntamd64.10.0...22000", OS, True),
            ("ntamd64.10.0...26100", OS, False),
            ("ntamd64.6.1", OS, True),
            ("ntamd64.10.0.3", OS, False),
            ("ntamd64.10.0.3", ("amd64", (10, 0), 20348, True), True),
            ("ntamd64.10.0.0x1", OS, True),
            ("ntarm64", OS, False),
            ("garbage", OS, False),
        ):
            with self.subTest(decor):
                self.assertEqual(sdio.decor_rank(decor, *os_) is not None, ok)

    def test_applies(self):
        self.assertTrue(sdio.applies(entry(), *OS))
        for bad in (
            {"pos": 1},
            {"folder": "dell/_nb/x/"},
            # the line has a section that fits this build better
            {"alts": ["", "ntamd64.10.0...19041"]},
            {"cats": {"amd64": "2:6.1,2:6.3", "x86": ""}},
            {"cats": {"amd64": "", "x86": "2:10.0"}},
        ):
            with self.subTest(bad):
                self.assertFalse(sdio.applies(entry(**bad), *OS))
        self.assertTrue(
            sdio.applies(entry(decor="ntamd64.10.0...19041", alts=["", "ntamd64"]), *OS)
        )

    def test_newer(self):
        have = {"version": "12.19.2.45", "date": "2025-03-14"}
        self.assertTrue(sdio.newer(entry(), have))
        self.assertFalse(sdio.newer(entry(version="12.19.2.45"), have))
        self.assertTrue(sdio.newer(entry(version="1.0", date="2025-04-01"), have))
        self.assertFalse(sdio.newer(entry(version="99.0", date="2024-01-01"), have))
        self.assertTrue(sdio.newer(entry(), {"version": "12.0"}))
        self.assertFalse(sdio.newer(entry(version=""), {"version": "1.0"}))


def nic(version="12.19.2.45", device_id=NIC, **kw):
    return {
        "device": "Intel(R) Ethernet",
        "class": "Net",
        "manufacturer": "Intel",
        "provider": "Intel",
        "version": version,
        "date": "2025-03-14",
        "inf": "oem12.inf",
        "signed": True,
        "device_id": device_id,
        **kw,
    }


class Base(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        override = override_settings(SDIO_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)
        self.agent = baker.make_recipe(
            "agents.online_agent",
            operating_system=WIN11,
            version=settings.SDIO_MIN_AGENT,
        )

    def store(self, agent=None, drivers=None):
        InstalledDrivers.objects.update_or_create(
            agent=agent or self.agent,
            defaults={
                "received": djangotime.now(),
                "data": clean_drivers({"drivers": drivers or [nic()]}),
            },
        )

    def offer(self, *entries, hwid=HWID, http=("DP_Net_1.7z",)):
        SdioCatalog.objects.update_or_create(
            hwid=hwid, defaults={"checked": djangotime.now(), "entries": list(entries)}
        )
        row = SdioIndex.load()
        row.http_packs = list(http)
        row.save()

    def mirror(self, extra=(), **kw):
        files = [
            ("drivers/DP_Net_1.7z", b"p" * 20000),
            ("indexes/SDIO/DP_Net_1.bin", index([{}])),
            ("indexes/SDIO/DP_Old_1.bin", index([{"hwid": "USB\\VID_1&PID_2"}])),
            ("drivers/DP_Old_1.7z", b"o" * 5000),
            *extra,
        ]
        return Mirror(files, **kw)


@patch.object(sdio, "MIN_INDEXES", 2)
class TestRefresh(Base):
    def test_refresh_and_scan(self):
        m = self.mirror(missing={"drivers/DP_Old_1.7z"})
        with patch.object(sdio, "fetch", m):
            text = sdio.refresh()
        # the indexes share a piece with the pack the mirror lacks
        self.assertEqual(
            text,
            "2 indexes, 2 downloaded, 1 pieces not checkable, 1 packs on the mirror",
        )
        row = SdioIndex.load()
        self.assertEqual(
            (row.error, row.files, row.etag, row.torrent_time, row.http_packs),
            ("", 2, '"e1"', 1792181374, ["DP_Net_1.7z"]),
        )
        # its last piece shares bytes with the pack the mirror lacks
        self.assertEqual(row.full_packs, [])
        self.assertEqual(
            sorted(os.listdir(sdio.index_dir())), ["DP_Net_1.bin", "DP_Old_1.bin"]
        )

        # 304: nothing downloaded again
        m.torrent_status = 304
        m.urls.clear()
        with patch.object(sdio, "fetch", m):
            self.assertTrue(sdio.refresh().startswith("torrent unchanged"))
        self.assertFalse(any(u.endswith(".bin") for u in m.urls))

        other = baker.make_recipe("agents.online_agent", operating_system=WIN11)
        self.store()
        self.store(other, [nic(device_id="PCI\\VEN_10EC&DEV_8168\\4&1")])
        self.assertEqual(sdio.scan(), "5 hardware ids, 1 with pack drivers")
        row = SdioCatalog.objects.get(hwid=HWID)
        self.assertEqual(len(row.entries), 1)
        self.assertEqual(
            (row.entries[0]["pack"], row.entries[0]["pack_size"]),
            ("DP_Net_1.7z", 20000),
        )
        self.assertFalse(SdioCatalog.objects.filter(hwid="USB\\VID_1&PID_2").exists())

    def test_bad_piece_keeps_old_files(self):
        with patch.object(sdio, "fetch", self.mirror()):
            sdio.refresh()
        m = self.mirror(extra=[("indexes/SDIO/DP_New_1.bin", index([{}]))])
        m.files["indexes/SDIO/DP_New_1.bin"] = (
            b"X" + m.files["indexes/SDIO/DP_New_1.bin"][1:]
        )
        with patch.object(sdio, "fetch", m):
            text = sdio.refresh()
        self.assertIn("does not match the torrent", text)
        self.assertIn("does not match the torrent", SdioIndex.load().error)
        self.assertEqual(
            sorted(os.listdir(sdio.index_dir())), ["DP_Net_1.bin", "DP_Old_1.bin"]
        )
        self.assertEqual(sdio.load_torrent().indexes().keys(), {"DP_Net_1", "DP_Old_1"})

    def test_outage_keeps_pack_list(self):
        with patch.object(sdio, "fetch", self.mirror()):
            sdio.refresh()
        self.assertEqual(SdioIndex.load().http_packs, ["DP_Net_1.7z", "DP_Old_1.7z"])
        with patch.object(sdio, "fetch", side_effect=OSError("timed out")):
            self.assertEqual(sdio.refresh(), "timed out, pack list kept")
        row = SdioIndex.load()
        self.assertEqual(
            (row.error, row.http_packs), ("timed out", ["DP_Net_1.7z", "DP_Old_1.7z"])
        )
        # nothing is missing next to DP_Net_1 or DP_Old_1 here
        self.assertEqual(row.full_packs, ["DP_Net_1.7z", "DP_Old_1.7z"])

    def test_too_few_and_unreachable(self):
        with patch.object(sdio, "MIN_INDEXES", 5), patch.object(
            sdio, "fetch", self.mirror()
        ):
            self.assertEqual(
                sdio.refresh(), "index list not understood, pack list kept"
            )
        with patch.object(sdio, "fetch", side_effect=OSError("down")):
            self.assertEqual(sdio.refresh(), "down, pack list kept")
        with self.assertRaisesMessage(sdio.SdioError, "no SDIO index"):
            sdio.scan()


@override_settings(CACHES=LOCMEM_CACHE)
@patch("software.tasks.apply_sdio_task.delay")
class TestApprovals(Base):
    url = "/software/sdio/approvals/"

    def login(self, user):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        grant_console_stepup(user)

    def test_approve_list_revoke(self, delay):
        self.store()
        self.offer(entry())
        r = self.client.post(self.url, {"hwid": HWID, "version": "12.19.2.66"})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.data["stepup"])
        self.login(self.john)
        r = self.client.post(self.url, {"hwid": HWID.lower(), "version": "12.19.2.66"})
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual((r.data["hwid"], r.data["desc"]), (HWID, "Intel Ethernet"))
        delay.assert_called_once_with()
        self.assertTrue(
            AuditLog.objects.filter(message__contains="SDIO driver Intel").exists()
        )
        r = self.client.post(self.url, {"hwid": HWID, "version": "12.19.2.66"})
        self.assertEqual(r.status_code, 409)

        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["approvals"][0]["devices"], 1)
        self.assertEqual(r.data["index"]["http_packs"], 1)

        pk = r.data["approvals"][0]["id"]
        self.client.force_authenticate(user=self.john)
        self.assertEqual(self.client.delete(f"{self.url}{pk}/").status_code, 403)
        self.login(self.john)
        r = self.client.delete(f"{self.url}{pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(SdioApproval.objects.exists())

    def test_refused(self, delay):
        self.login(self.john)
        self.offer(entry(), entry(version="13.0", pack="DP_Old_1.7z"))
        for body, text in (
            ({"hwid": HWID}, "required"),
            ({"hwid": HWID, "version": "1.0"}, "No SDIO pack"),
            ({"hwid": HWID, "version": "13.0"}, "BitTorrent"),
        ):
            with self.subTest(body):
                r = self.client.post(self.url, body)
                self.assertEqual(r.status_code, 400)
                self.assertIn(text, r.data)
        reader = self.create_user_with_roles(["can_list_software"])
        self.login(reader)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        r = self.client.post(self.url, {"hwid": HWID, "version": "12.19.2.66"})
        self.assertEqual(r.status_code, 403)
        scoped = self.create_user_with_roles(["can_install_packages"])
        scoped.role.can_view_sites.set([baker.make("clients.Site")])
        self.login(scoped)
        r = self.client.post(self.url, {"hwid": HWID, "version": "12.19.2.66"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.client.post("/software/sdio/refresh/").status_code, 403)
        delay.assert_not_called()


@patch("agents.models.Agent.nats_cmd")
class TestApply(Base):
    def setUp(self):
        super().setUp()
        self.store()
        self.offer(entry(), entry(version="12.19.2.50"))
        SdioApproval.objects.create(hwid=HWID, version="12.19.2.66", created_by="john")

    def test_sends_one_job(self, nats_cmd):
        nats_cmd.return_value = "ok"
        self.assertEqual(sdio.apply_approvals(), "1 install jobs sent")
        job = SdioJob.objects.get()
        self.assertEqual(job.state, "queued")
        self.assertEqual(
            [(i["hwid"], i["version"], i["pack"], i["folder"]) for i in job.items],
            [(HWID, "12.19.2.66", "DP_Net_1.7z", "intel/allx64/nic_1/")],
        )
        nats_cmd.assert_called_once_with(
            {"func": "sdiodriver", "payload": {"job": job.id}}, timeout=5
        )
        log = AuditLog.objects.get(debug_info__job=job.id)
        self.assertEqual(log.username, "john")
        # a running job blocks a second one
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        # done: never again for this device and version
        job.state = "done"
        job.save()
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")

    def test_failed_waits_a_week(self, nats_cmd):
        nats_cmd.return_value = "ok"
        sdio.apply_approvals()
        job = SdioJob.objects.get()
        job.state = "failed"
        job.results = [{"result": "fail"}]
        job.save()
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        SdioJob.objects.filter(pk=job.pk).update(
            created=djangotime.now() - dt.timedelta(days=8)
        )
        self.assertEqual(sdio.apply_approvals(), "1 install jobs sent")

    def test_not_eligible(self, nats_cmd):
        nats_cmd.return_value = "busy"
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        job = SdioJob.objects.get()
        self.assertEqual(
            (job.state, job.detail), ("failed", "the agent did not take the job: busy")
        )
        # a job the agent never ran is no attempt
        nats_cmd.return_value = "ok"
        self.assertEqual(sdio.apply_approvals(), "1 install jobs sent")
        SdioJob.objects.all().delete()

        self.agent.version = "4.20.10.2026"
        self.agent.save()
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        self.agent.version = settings.SDIO_MIN_AGENT
        self.agent.save()
        policy = self.agent.get_patch_policy()
        policy.drivers = "exclude"
        policy.save()
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        policy.drivers = "inherit"
        policy.save()
        self.offer(entry(), entry(version="12.19.2.50"), http=())
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        self.offer(entry(), entry(version="12.19.2.50"))
        self.agent.last_seen = djangotime.now() - dt.timedelta(hours=1)
        self.agent.save()
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        self.assertFalse(SdioJob.objects.exists())

    def test_stale_job_closed(self, nats_cmd):
        nats_cmd.return_value = "ok"
        sdio.apply_approvals()
        SdioJob.objects.update(updated=djangotime.now() - dt.timedelta(hours=7))
        # no result in 6 hours counts as a failed attempt, so no new job
        self.assertEqual(sdio.apply_approvals(), "0 install jobs sent")
        job = SdioJob.objects.get()
        self.assertEqual(
            (job.state, job.detail, job.results[0]["result"]),
            ("failed", "no result from the agent within 6 hours", "fail"),
        )

    def test_busy_lock_retries_one_agent(self, nats_cmd):
        lock = patch("software.tasks.redis_lock")
        held = lock.start()
        self.addCleanup(lock.stop)
        held.return_value.__enter__.return_value = False
        with self.assertRaises(Retry):
            tasks.apply_sdio_task.run([self.agent.pk])
        self.assertIn("already", tasks.apply_sdio_task.run())
        nats_cmd.assert_not_called()


class TestAgentApi(Base):
    def setUp(self):
        super().setUp()
        with patch.object(sdio, "MIN_INDEXES", 2), patch.object(
            sdio, "fetch", self.mirror()
        ):
            sdio.refresh()
        self.job = SdioJob.objects.create(
            id="a" * 32,
            agent=self.agent,
            state="queued",
            items=[
                {
                    "device_id": NIC,
                    "hwid": HWID,
                    "version": "12.19.2.66",
                    "pack": "DP_Net_1.7z",
                    "folder": "intel/allx64/nic_1/",
                }
            ],
        )
        self.url = f"/api/v4/{self.agent.agent_id}/sdio/{self.job.id}/"
        self.authenticate_agent(self.agent)

    def test_plan_and_result(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200, r.data)
        (pack,) = r.data["packs"]
        self.assertEqual(pack["url"], SEED + "drivers/DP_Net_1.7z")
        self.assertEqual(pack["folders"], ["intel/allx64/nic_1/"])
        self.assertEqual((pack["size"], len(pack["hashes"])), (20000, 2))
        self.assertEqual(
            (pack["head"], pack["head_check"], pack["tail_check"]), ([], True, True)
        )
        self.assertIn("PKG_DIR", r.data["script"])
        self.assertEqual(r.data["deadline"], sdio.DEADLINE)

        r = self.client.patch(self.url, {"state": "downloading", "detail": "x"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.patch(self.url, {"state": "x"}).status_code, 400)
        # download progress: kept when it makes sense, ignored otherwise
        for body, want in (
            ({"done": 500, "total": 20000}, (500, 20000)),
            ({"done": 30000, "total": 20000}, (500, 20000)),
            ({"done": True, "total": 20000}, (500, 20000)),
            ({"done": 20000, "total": 20000}, (20000, 20000)),
        ):
            self.client.patch(self.url, {"state": "downloading", **body}, format="json")
            self.job.refresh_from_db()
            self.assertEqual((self.job.done, self.job.total), want)
        r = self.client.patch(
            self.url,
            {
                "state": "done",
                "results": [
                    {"pack": "DP_Net_1.7z", "result": "ok", "exit": 0, "msg": "fine"},
                    {"result": "nope"},
                ],
                "output": "out",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.job.refresh_from_db()
        self.assertEqual((self.job.state, self.job.output), ("done", "out"))
        self.assertEqual(len(self.job.results), 1)
        # finished jobs are closed for the agent
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_failed_result_and_other_agent(self):
        self.client.patch(
            self.url,
            {"state": "done", "results": [{"pack": "p", "result": "fail"}]},
            format="json",
        )
        self.job.refresh_from_db()
        self.assertEqual(self.job.state, "failed")
        other = baker.make_recipe("agents.online_agent")
        self.authenticate_agent(other)
        self.assertEqual(
            self.client.get(
                f"/api/v4/{other.agent_id}/sdio/{self.job.id}/"
            ).status_code,
            404,
        )

    def test_unchecked_tail(self):
        # the last piece shares bytes with a pack the mirror does not serve
        SdioIndex.objects.update(http_packs=["DP_Net_1.7z"])
        (pack,) = self.client.get(self.url).data["packs"]
        self.assertEqual((pack["head_check"], pack["tail_check"]), (True, False))
        self.assertEqual(
            [t["url"].rsplit("/", 1)[-1] for t in pack["tail"]],
            ["DP_Net_1.bin", "DP_Old_1.bin", "DP_Old_1.7z"],
        )

    def test_pack_gone(self):
        self.job.items[0]["pack"] = "DP_Gone_1.7z"
        self.job.save()
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 400)
        self.job.refresh_from_db()
        self.assertEqual(self.job.state, "failed")
        self.assertIn("no longer listed", self.job.detail)


class TestDriversTab(Base):
    def test_fields(self):
        self.store(drivers=[nic(), nic(device_id="ROOT\\NET\\0000")])
        self.offer(
            entry(), entry(version="13.0", pack="DP_Old_1.7z", date="2026-01-01")
        )
        SdioApproval.objects.create(hwid=HWID, version="12.19.2.66")
        SdioJob.objects.create(
            id="b" * 32,
            agent=self.agent,
            state="installing",
            items=[{"device_id": NIC}],
        )
        r = self.client.get(f"/software/{self.agent.agent_id}/drivers/")
        self.assertEqual(r.status_code, 200)
        row, root = r.data["drivers"]
        # the installable entry wins over a newer one only in the swarm
        self.assertEqual(
            (row["sdio"]["version"], row["sdio"]["approved"], row["sdio"]["pack_http"]),
            ("12.19.2.66", True, True),
        )
        self.assertIsNone(row["sdio_checked"])
        self.assertEqual(row["sdio_job"]["state"], "installing")
        self.assertEqual(
            (root["sdio"], root["sdio_checked"], root["sdio_job"]), (None, None, None)
        )
        self.assertIn("sdio_index", r.data)


@override_settings(CACHES=LOCMEM_CACHE)
class TestProgress(Base):
    @patch.object(sdio, "MIN_INDEXES", 2)
    def test_refresh_phases_and_clear(self):
        phases = []
        real = sdio.set_progress

        def record(phase, done=0, total=0):
            phases.append(phase)
            real(phase, done, total)

        self.store()
        with patch.object(sdio, "fetch", self.mirror()), patch.object(
            sdio, "set_progress", side_effect=record
        ):
            tasks.refresh_sdio_task.run()
        self.assertEqual(
            sorted(set(phases)), ["indexes", "packs", "scan", "torrent", "verify"]
        )
        self.assertIsNone(sdio.get_progress())
        self.assertEqual(
            self.client.get("/software/sdio/progress/").data, {"progress": None}
        )
        sdio.set_progress("indexes", 3, 111)
        self.assertEqual(
            self.client.get("/software/sdio/progress/").data,
            {"progress": {"phase": "indexes", "done": 3, "total": 111}},
        )

    def test_stale_progress_is_gone(self):
        sdio.set_progress("scan", 5, 111)
        self.assertEqual(sdio.get_progress()["phase"], "scan")
        with patch.object(sdio.time, "time", return_value=time.time() + 601):
            self.assertIsNone(sdio.get_progress())

    def test_catalog_check_progress(self):
        url = f"/software/{self.agent.agent_id}/drivers/catalog/check/"
        self.assertEqual(self.client.get(url).data, {"progress": None})
        cache.set(tasks.check_progress_key(self.agent.pk), {"done": 2, "total": 9})
        self.assertEqual(self.client.get(url).data["progress"], {"done": 2, "total": 9})
        reader = self.create_user_with_roles([])
        self.client.force_authenticate(user=reader)
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_offers(self):
        other = baker.make_recipe("agents.online_agent", operating_system=WIN11)
        self.store()
        self.store(other)
        self.offer(
            entry(), entry(version="13.0", pack="DP_Old_1.7z", date="2026-01-01")
        )
        SdioApproval.objects.create(hwid=HWID, version="12.19.2.66")
        r = self.client.get("/software/sdio/offers/")
        self.assertEqual(r.status_code, 200)
        (offer,) = r.data["offers"]
        self.assertEqual(
            (
                offer["version"],
                offer["approved"],
                offer["pack_http"],
                offer["device_count"],
            ),
            ("12.19.2.66", True, True, 2),
        )
        self.assertEqual(
            sorted(d["hostname"] for d in offer["devices"]),
            sorted([self.agent.hostname, other.hostname]),
        )
        # a restricted role sees only its own devices
        scoped = self.create_user_with_roles(["can_list_software"])
        scoped.role.can_view_sites.set([self.agent.site])
        self.client.force_authenticate(user=scoped)
        (offer,) = self.client.get("/software/sdio/offers/").data["offers"]
        self.assertEqual(
            [d["agent_id"] for d in offer["devices"]], [self.agent.agent_id]
        )

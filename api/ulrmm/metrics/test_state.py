# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import copy
import datetime as dt
import importlib
import json
from unittest.mock import patch

from django.apps import apps
from django.core.cache import cache
from django.db import connection
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.management.commands.fake_agents import Command as FakeAgents
from checks.models import Check, CheckHistory, CheckResult
from core.utils import get_core_settings
from ulrmm.constants import AgentPlat, AlertSeverity, CheckStatus, CheckType
from ulrmm.test import ULRMMTestCase

from .models import AgentState, Sample
from .state import (
    MAX_BODY,
    clean_state,
    evaluate_metric_checks,
    ingest,
    parse_key,
    series,
    series_key,
)
from .tasks import prune_metrics_task, sample_metrics_task
from .tests import REPLIES, fake_nats

GB = 1024**3

DOC = {
    "v": 1,
    "ts": 1792130400,
    "dt": 300.5,
    "errors": ["ipmitool: timeout"],
    "perf": {
        "cpu_pct": 12.5,
        "mem_total": 8 * GB,
        "mem_used": 2 * GB,
        "swap_pct": 1.5,
        "load": [0.5, 0.25, 0.125],
    },
    "system": {
        "manager": "systemd",
        "units_total": 200,
        "units_failed": 1,
        "units": [
            {
                "name": "backup.service",
                "active": "failed",
                "sub": "failed",
                "enabled": True,
                "description": "Backup",
            },
            {
                "name": "late.service",
                "active": "activating",
                "sub": "start",
                "enabled": None,
                "description": "",
            },
        ],
        "mounts": [
            {
                "mount": "/",
                "device": "/dev/sda1",
                "fs": "ext4",
                "ro": False,
                "stale": False,
                "size": 100 * GB,
                "used": 40 * GB,
                "used_pct": 40.0,
                "inode_pct": 5.0,
            },
            {
                "mount": "/mnt/nas",
                "device": "nas:/data",
                "fs": "nfs4",
                "ro": True,
                "stale": True,
                "size": 0,
                "used": 0,
                "used_pct": 0.0,
                "inode_pct": None,
            },
        ],
        "time": {
            "synced": True,
            "source": "chrony",
            "server": "ntp.example.org",
            "offset_ms": -0.25,
        },
        "raid": [
            {
                "kind": "md",
                "name": "md0",
                "level": "raid1",
                "state": "clean, degraded",
                "health": "degraded",
                "devices": 2,
                "failed": 1,
                "sync_pct": None,
            }
        ],
        "sensors": [
            {
                "kind": "temp",
                "source": "hwmon",
                "name": "coretemp Core 0",
                "value": 48.0,
                "unit": "C",
                "warn": 80.0,
                "crit": 100.0,
                "status": "ok",
            },
            {
                "kind": "fan",
                "source": "ipmi",
                "name": "FAN1",
                "value": 3600.0,
                "unit": "rpm",
                "warn": None,
                "crit": None,
                "status": "ok",
            },
        ],
    },
    "net": {
        "ifaces": [
            {
                "name": "bond0",
                "kind": "bond",
                "state": "up",
                "speed_mbps": 2000,
                "duplex": "full",
                "mac": "52:54:00:aa:bb:cc",
                "mtu": 1500,
                "addrs": ["10.0.0.2/24", "fe80::1/64"],
                "master": None,
                "members": ["eth0", "eth1"],
                "rx_bytes": 1000,
                "tx_bytes": 2000,
                "rx_packets": 10,
                "tx_packets": 20,
                "rx_errors": 0,
                "tx_errors": 1,
                "rx_drops": 2,
                "tx_drops": 0,
                "rate": {
                    "rx_bps": 1500.0,
                    "tx_bps": 250.0,
                    "rx_pps": 3.0,
                    "tx_pps": 2.0,
                    "err_ps": 0.0,
                    "drop_ps": 0.5,
                },
            },
            {
                "name": "eth0",
                "kind": "ether",
                "state": "up",
                "speed_mbps": None,
                "duplex": None,
                "mac": "52:54:00:aa:bb:cc",
                "mtu": 1500,
                "addrs": [],
                "master": "bond0",
                "members": [],
                "rx_bytes": 500,
                "tx_bytes": 1000,
                "rx_packets": 5,
                "tx_packets": 10,
                "rx_errors": 0,
                "tx_errors": 0,
                "rx_drops": 0,
                "tx_drops": 0,
                "rate": None,
            },
        ]
    },
    "containers": {
        "sources": {"docker": "ok", "pve-lxc": "denied"},
        "items": [
            {
                "kind": "docker",
                "id": "0123456789ab",
                "name": "web",
                "image": "nginx:1.27",
                "state": "running",
                "status": "Up 2 hours",
                "restarts": 0,
                "cpu_pct": 150.0,
                "mem_used": 64 * 1024**2,
                "mem_limit": None,
                "net_rx": 100,
                "net_tx": 200,
                "uptime": 7200,
                "node": None,
            },
            {
                "kind": "docker",
                "id": "ba9876543210",
                "name": "job",
                "image": "busybox",
                "state": "exited",
                "status": "Exited (0)",
                "restarts": None,
                "cpu_pct": None,
                "mem_used": None,
                "mem_limit": None,
                "net_rx": None,
                "net_tx": None,
                "uptime": None,
                "node": None,
            },
        ],
        "cluster": {"name": "lab", "quorate": True, "nodes": 3, "online": 2},
    },
}

SERIES = {
    "cpu.pct": 12.5,
    "mem.pct": 25.0,
    "swap.pct": 1.5,
    "load.1": 0.5,
    "load.5": 0.25,
    "load.15": 0.125,
    "disk.used_pct{mount=/}": 40.0,
    "disk.inode_pct{mount=/}": 5.0,
    "temp.c{sensor=coretemp Core 0}": 48.0,
    "time.offset_ms": -0.25,
    "net.rx_bps{if=bond0}": 1500.0,
    "net.tx_bps{if=bond0}": 250.0,
    "net.err_ps{if=bond0}": 0.0,
    "net.drop_ps{if=bond0}": 0.5,
    "ctr.cpu_pct{kind=docker,name=web}": 150.0,
    "ctr.mem_bytes{kind=docker,name=web}": 64.0 * 1024**2,
    "vm.total{kind=docker}": 2.0,
    "vm.running{kind=docker}": 1.0,
}


def doc(**changes):
    body = copy.deepcopy(DOC)
    body.update(changes)
    return body


class TestIngestOrder(ULRMMTestCase):
    def test_gap_check_runs_under_the_state_row_lock(self):
        agent = baker.make_recipe("agents.online_agent")
        depth = []
        real = Sample.objects.filter

        def gap_filter(*args, **kwargs):
            if "ts__gt" in kwargs:
                depth.append(len(connection.atomic_blocks))
            return real(*args, **kwargs)

        base = len(connection.atomic_blocks)
        with patch.object(Sample.objects, "filter", gap_filter):
            self.assertIsNotNone(ingest(agent, clean_state({})))
            self.assertIsNone(ingest(agent, clean_state({})))
        # a concurrent push waits on the row and then finds this sample
        self.assertEqual(depth, [base + 1, base + 1])
        self.assertEqual(Sample.objects.filter(agent=agent).count(), 1)


class TestCleanState(SimpleTestCase):
    def test_valid_document_is_kept(self):
        self.assertEqual(clean_state(copy.deepcopy(DOC)), DOC)

    def test_not_an_object(self):
        for body in ([], "x", None, 5):
            with self.assertRaises(ValueError):
                clean_state(body)
        self.assertEqual(clean_state({}), {})

    def test_unknown_keys_are_dropped(self):
        body = doc(extra=1)
        body["perf"]["extra"] = 2
        body["system"]["units"][0]["pid"] = 3
        cleaned = clean_state(body)
        self.assertNotIn("extra", cleaned)
        self.assertNotIn("extra", cleaned["perf"])
        self.assertNotIn("pid", cleaned["system"]["units"][0])

    def test_wrong_types_are_dropped_at_their_key(self):
        body = doc(v="1", ts=True, dt=float("nan"))
        body["perf"].update(
            cpu_pct="12", mem_total=True, mem_used=-1, swap_pct=None, load=[1, 2]
        )
        body["system"]["units"] = ["nope", {"name": 5, "active": "failed"}]
        body["system"]["mounts"][0]["size"] = 2**63
        body["system"]["mounts"][0]["used"] = 1.5
        body["system"]["time"]["offset_ms"] = 2e7
        body["net"]["ifaces"][0]["state"] = "sideways"
        body["net"]["ifaces"][0]["rate"]["rx_bps"] = float("inf")
        body["net"]["ifaces"][1]["addrs"] = "10.0.0.3"
        body["containers"]["sources"] = {"docker": "fine", "vmware": "ok", "lxc": "ok"}
        body["containers"]["items"][0]["kind"] = "vmware"
        body["containers"]["cluster"] = "lab"
        cleaned = clean_state(body)

        self.assertEqual(
            set(cleaned) - {"errors", "system", "net", "containers"}, {"perf"}
        )
        self.assertEqual(cleaned["perf"], {})
        self.assertEqual(cleaned["system"]["units"], [{"active": "failed"}])
        mount = cleaned["system"]["mounts"][0]
        self.assertNotIn("size", mount)
        self.assertNotIn("used", mount)
        self.assertNotIn("offset_ms", cleaned["system"]["time"])
        iface = cleaned["net"]["ifaces"][0]
        self.assertNotIn("state", iface)
        self.assertNotIn("rx_bps", iface["rate"])
        self.assertEqual(iface["rate"]["tx_bps"], 250.0)
        self.assertNotIn("addrs", cleaned["net"]["ifaces"][1])
        self.assertEqual(cleaned["containers"]["sources"], {"lxc": "ok"})
        self.assertNotIn("kind", cleaned["containers"]["items"][0])
        self.assertNotIn("cluster", cleaned["containers"])

    def test_null_only_where_allowed(self):
        body = doc(dt=None)
        body["perf"]["cpu_pct"] = None
        body["system"]["units"][0]["name"] = None
        cleaned = clean_state(body)
        self.assertIsNone(cleaned["dt"])
        self.assertNotIn("cpu_pct", cleaned["perf"])
        self.assertNotIn("name", cleaned["system"]["units"][0])
        self.assertIsNone(cleaned["net"]["ifaces"][1]["rate"])
        self.assertIsNone(cleaned["system"]["mounts"][1]["inode_pct"])

        # the agent leaves out empty lists and missing engines
        body = doc()
        del body["containers"], body["system"]["units"], body["errors"]
        del body["net"]["ifaces"][0]["speed_mbps"], body["net"]["ifaces"][0]["duplex"]
        cleaned = clean_state(body)
        self.assertNotIn("containers", cleaned)
        self.assertNotIn("units", cleaned["system"])
        self.assertEqual(cleaned["system"]["units_total"], 200)
        self.assertNotIn("speed_mbps", cleaned["net"]["ifaces"][0])
        self.assertNotIn("vm.total{kind=docker}", series(cleaned))

    def test_ranges_and_clamps(self):
        body = doc()
        body["perf"]["cpu_pct"] = 150
        body["perf"]["swap_pct"] = -3
        body["system"]["sensors"][0]["value"] = 400.0
        body["system"]["sensors"][1]["value"] = 9000
        body["containers"]["items"][0]["cpu_pct"] = 1e9
        body["net"]["ifaces"][0]["rate"]["rx_bps"] = 2e12
        cleaned = clean_state(body)
        self.assertEqual(cleaned["perf"]["cpu_pct"], 100.0)
        self.assertEqual(cleaned["perf"]["swap_pct"], 0.0)
        # a temperature off the scale is a sensor quirk, a fan is not
        self.assertNotIn("value", cleaned["system"]["sensors"][0])
        self.assertEqual(cleaned["system"]["sensors"][1]["value"], 9000.0)
        self.assertEqual(cleaned["containers"]["items"][0]["cpu_pct"], 1e4)
        self.assertNotIn("rx_bps", cleaned["net"]["ifaces"][0]["rate"])

    def test_strings_and_list_caps(self):
        body = doc(errors=["e\x00rr\x1b" + "x" * 200] * 20)
        body["system"]["units"] = [dict(DOC["system"]["units"][0])] * 200
        body["net"]["ifaces"][0]["name"] = "n" * 100
        body["net"]["ifaces"][0]["duplex"] = "both"
        cleaned = clean_state(body)
        self.assertEqual(len(cleaned["errors"]), 16)
        self.assertEqual(cleaned["errors"][0], "err" + "x" * 125)
        self.assertEqual(len(cleaned["system"]["units"]), 128)
        self.assertEqual(cleaned["net"]["ifaces"][0]["name"], "n" * 64)
        self.assertNotIn("duplex", cleaned["net"]["ifaces"][0])


class TestSeries(SimpleTestCase):
    def test_series_of_a_document(self):
        self.assertEqual(series(clean_state(copy.deepcopy(DOC))), SERIES)
        self.assertEqual(series({}), {})

    def test_keys(self):
        self.assertEqual(series_key("cpu.pct", {}), "cpu.pct")
        self.assertEqual(
            series_key("ctr.cpu_pct", {"name": "a{b}=c,d\x01", "kind": "docker"}),
            "ctr.cpu_pct{kind=docker,name=a_b__c_d_}",
        )
        self.assertEqual(
            series_key("temp.c", {"sensor": "s" * 80}), f"temp.c{{sensor={'s' * 64}}}"
        )
        for key in SERIES:
            name, labels = parse_key(key)
            self.assertEqual(series_key(name, labels), key)
        self.assertEqual(
            parse_key("ctr.cpu_pct{kind=docker,name=web}"),
            ("ctr.cpu_pct", {"kind": "docker", "name": "web"}),
        )

    def test_caps(self):
        body = doc()
        mount = DOC["system"]["mounts"][0]
        body["system"]["mounts"] = [dict(mount, mount=f"/m{i}") for i in range(30)]
        iface = DOC["net"]["ifaces"][0]
        body["net"]["ifaces"] = [dict(iface, name=f"if{i}") for i in range(30)]
        body["system"]["sensors"] = [
            dict(DOC["system"]["sensors"][0], name=f"t{i}") for i in range(30)
        ]
        values = series(clean_state(body))
        names = [parse_key(key)[0] for key in values]
        self.assertEqual(names.count("disk.used_pct"), 16)
        self.assertEqual(names.count("net.rx_bps"), 16)
        self.assertEqual(names.count("temp.c"), 16)
        self.assertLessEqual(len(values), 256)

    def mount_series(self, mounts, bound=frozenset()):
        body = doc()
        body["system"]["mounts"] = mounts
        values = series(clean_state(body), bound)
        return [
            parse_key(key)[1]["mount"]
            for key in values
            if parse_key(key)[0] == "disk.used_pct"
        ]

    def test_many_mounts_keep_the_largest(self):
        mount = DOC["system"]["mounts"][0]
        mounts = [dict(mount, mount=f"/small{i}", size=GB) for i in range(20)]
        # large pools arrive last, two of equal size, one without a size
        mounts += [dict(mount, mount=f"/pool{i}", size=(10 + i) * GB) for i in range(3)]
        mounts.append(dict(mount, mount="/tank", size=10 * GB))
        nosize = dict(mount, mount="/nosize")
        del nosize["size"]
        mounts.append(nosize)
        mounts.append(dict(mount, mount="/huge", stale=True, size=1000 * GB))
        kept = self.mount_series(mounts)
        self.assertEqual(len(kept), 16)
        self.assertEqual(
            kept,
            ["/pool2", "/pool1", "/pool0", "/tank"] + [f"/small{i}" for i in range(12)],
        )

    def test_many_mounts_keep_the_ones_a_check_reads(self):
        mount = DOC["system"]["mounts"][0]
        mounts = [dict(mount, mount=f"/small{i}", size=GB) for i in range(20)]
        mounts += [dict(mount, mount=f"/pool{i}", size=(10 + i) * GB) for i in range(3)]
        kept = self.mount_series(mounts, frozenset({"/small19", "/gone"}))
        self.assertEqual(
            kept,
            ["/small19", "/pool2", "/pool1", "/pool0"]
            + [f"/small{i}" for i in range(12)],
        )

    def test_few_mounts_keep_the_received_order(self):
        mount = DOC["system"]["mounts"][0]
        mounts = [dict(mount, mount=f"/m{i}", size=i * GB) for i in range(16)]
        mounts.append(dict(mount, mount="/gone", stale=True, size=1000 * GB))
        self.assertEqual(self.mount_series(mounts), [f"/m{i}" for i in range(16)])


class TestStatePush(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe(
            "agents.online_agent",
            plat=AgentPlat.LINUX,
            disks=[{"device": "/", "percent": 40}],
        )
        self.authenticate_agent(self.agent)
        self.url = f"/api/v3/{self.agent.agent_id}/state/"

    def test_push_stores_state_and_one_sample(self):
        r = self.client.post(self.url, DOC, format="json")
        self.assertEqual((r.status_code, r.data), (200, "ok"))

        state = AgentState.objects.get(agent=self.agent)
        self.assertEqual(state.data, DOC)
        self.assertEqual(state.agent_ts.timestamp(), DOC["ts"])
        self.assertLess(djangotime.now() - state.received, dt.timedelta(minutes=1))
        sample = Sample.objects.get(agent=self.agent)
        self.assertEqual(
            (sample.cpu, sample.mem_total, sample.mem_used, sample.disks),
            (12.5, 8192, 2048, {"/": 40}),
        )
        self.assertEqual(sample.values, SERIES)
        self.assertEqual(sample.ts, state.received)

        # within a minute only the state moves on
        second = doc()
        second["perf"]["cpu_pct"] = 99.0
        self.client.post(self.url, second, format="json")
        self.assertEqual(Sample.objects.filter(agent=self.agent).count(), 1)
        self.assertEqual(
            AgentState.objects.get(agent=self.agent).data["perf"]["cpu_pct"], 99.0
        )

        Sample.objects.update(ts=djangotime.now() - dt.timedelta(minutes=2))
        self.client.post(self.url, second, format="json")
        self.assertEqual(Sample.objects.filter(agent=self.agent).count(), 2)

    def test_bad_bodies(self):
        big = doc(errors=["x" * 128] * 16)
        big["pad"] = "x" * MAX_BODY
        r = self.client.post(self.url, big, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(self.url, [1, 2], format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(self.url, "{nope", content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(AgentState.objects.exists())
        self.assertFalse(Sample.objects.exists())

        # garbage inside an object is dropped, the push still counts
        r = self.client.post(self.url, {"perf": "x", "net": 5}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(AgentState.objects.get(agent=self.agent).data, {})
        self.assertEqual(Sample.objects.get(agent=self.agent).values, {})

    def test_only_the_token_agent(self):
        other = baker.make_recipe("agents.online_agent")
        r = self.client.post(f"/api/v3/{other.agent_id}/state/", DOC, format="json")
        self.assertEqual(r.status_code, 404)
        self.setup_client()
        r = self.client.post(self.url, DOC, format="json")
        self.assertEqual(r.status_code, 401)
        self.assertFalse(AgentState.objects.exists())

    def test_huge_memory_is_not_stored_in_megabytes(self):
        body = doc()
        body["perf"].update(mem_total=2**62, mem_used=2**61)
        self.client.post(self.url, body, format="json")
        sample = Sample.objects.get(agent=self.agent)
        self.assertEqual((sample.mem_total, sample.mem_used), (None, None))
        self.assertEqual(sample.values["mem.pct"], 50.0)


class TestSamplerAndPrune(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    @patch("agents.models.Agent.nats_cmd", autospec=True)
    def test_sampler_skips_fresh_pushers(self, nats_cmd):
        now = djangotime.now()
        fresh, stale, old = (
            baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
            for _ in range(3)
        )
        AgentState.objects.create(agent=fresh, received=now - dt.timedelta(minutes=14))
        AgentState.objects.create(agent=stale, received=now - dt.timedelta(minutes=16))
        nats_cmd.side_effect = fake_nats(
            {a.agent_id: REPLIES["linux"] for a in (fresh, stale, old)}
        )

        self.assertEqual(sample_metrics_task(), "2 of 2 agents sampled")
        self.assertEqual(
            set(Sample.objects.values_list("agent_id", flat=True)), {stale.pk, old.pk}
        )

    def test_prune_uses_core_setting(self):
        self.coresettings.metric_history_days = 7
        self.coresettings.save()
        self.assertEqual(get_core_settings().metric_history_days, 7)
        agent = baker.make_recipe("agents.agent")
        now = djangotime.now()
        old = baker.make(Sample, agent=agent, ts=now - dt.timedelta(days=8))
        new = baker.make(Sample, agent=agent, ts=now - dt.timedelta(days=6))
        self.assertEqual(prune_metrics_task(), "1 samples removed")
        self.assertFalse(Sample.objects.filter(pk=old.pk).exists())
        self.assertTrue(Sample.objects.filter(pk=new.pk).exists())

    def test_state_goes_with_the_agent(self):
        agent = baker.make_recipe("agents.agent")
        AgentState.objects.create(agent=agent, received=djangotime.now())
        agent.delete()
        self.assertFalse(AgentState.objects.exists())

    def test_migration_seeds_from_setting(self):
        migration = importlib.import_module(
            "core.migrations.0003_coresettings_metric_history_days"
        )
        for days, expected in ((90, 90), (1000, 365), (0, 1), ("x", 1)):
            with override_settings(METRICS_RETENTION_DAYS=days):
                migration.seed_from_setting(apps, None)
            self.coresettings.refresh_from_db()
            self.assertEqual(self.coresettings.metric_history_days, expected, days)


def make_values(agent, key, count, step=300, now=None):
    now = now or djangotime.now()
    Sample.objects.bulk_create(
        Sample(
            agent=agent,
            ts=now - dt.timedelta(seconds=i * step),
            values={key: float(i % 10), "cpu.pct": 1.0},
        )
        for i in range(count)
    )


class TestReadAPI(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)

    def series_url(self, **query):
        params = "&".join(f"{k}={v}" for k, v in query.items())
        return f"/metrics/{self.agent.agent_id}/series/?{params}"

    def test_state(self):
        url = f"/metrics/{self.agent.agent_id}/state/"
        r = self.client.get(url)
        self.assertEqual((r.status_code, r.data), (204, None))

        now = djangotime.now()
        AgentState.objects.create(
            agent=self.agent,
            received=now,
            agent_ts=now,
            data=clean_state(copy.deepcopy(DOC)),
        )
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            set(r.data),
            {"received", "agent_ts", "stale", "perf", "system", "net", "containers"},
        )
        self.assertFalse(r.data["stale"])
        self.assertEqual(r.data["received"], now.isoformat())
        self.assertEqual(r.data["containers"], DOC["containers"])

        AgentState.objects.filter(agent=self.agent).update(
            received=now - dt.timedelta(minutes=21), agent_ts=None, data={"perf": {}}
        )
        r = self.client.get(url)
        self.assertTrue(r.data["stale"])
        self.assertIsNone(r.data["agent_ts"])
        self.assertEqual(set(r.data), {"received", "agent_ts", "stale", "perf"})

    def test_catalog(self):
        r = self.client.get(self.series_url())
        self.assertEqual(r.data, {"series": []})
        now = djangotime.now()
        Sample.objects.create(agent=self.agent, ts=now, values=SERIES)
        # an older agent's sampler row without values does not hide the catalog
        Sample.objects.create(agent=self.agent, ts=now + dt.timedelta(seconds=1))
        r = self.client.get(self.series_url())
        self.assertEqual(r.status_code, 200)
        keys = [entry["key"] for entry in r.data["series"]]
        self.assertEqual(keys, sorted(SERIES))
        self.assertIn(
            {
                "key": "ctr.cpu_pct{kind=docker,name=web}",
                "name": "ctr.cpu_pct",
                "labels": {"kind": "docker", "name": "web"},
            },
            r.data["series"],
        )
        self.assertIn(
            {"key": "cpu.pct", "name": "cpu.pct", "labels": {}}, r.data["series"]
        )

    def test_points(self):
        key = "net.rx_bps{if=eth0}"
        make_values(self.agent, key, 30 * 288)
        make_values(self.agent, key, 1, now=djangotime.now() - dt.timedelta(days=31))
        labels = json.dumps({"if": "eth0"})

        for name, step, samples in (
            ("1h", 300, 12),
            ("6h", 300, 72),
            ("24h", 300, 288),
            ("7d", 3600, 7 * 288),
            ("30d", 10800, 30 * 288),
        ):
            r = self.client.get(
                self.series_url(name="net.rx_bps", labels=labels, range=name)
            )
            self.assertEqual(r.status_code, 200, name)
            self.assertEqual(
                (r.data["key"], r.data["range"], r.data["step_seconds"]),
                (key, name, step),
            )
            self.assertLessEqual(len(r.data["points"]), 300, name)
            self.assertGreaterEqual(len(r.data["points"]), samples * 300 // step)
            stamps = [p["ts"] for p in r.data["points"]]
            self.assertEqual(stamps, sorted(stamps))
            if step > 300:
                inner = r.data["points"][1:-1]
                self.assertTrue(all(p["max"] == 9.0 for p in inner), name)

        # cpu.pct is in every row, the default range is 24h
        r = self.client.get(self.series_url(name="cpu.pct"))
        self.assertEqual(r.data["range"], "24h")
        self.assertTrue(
            all(p == {**p, "avg": 1.0, "max": 1.0} for p in r.data["points"])
        )

    def test_bucket_avg_max_and_gaps(self):
        base = djangotime.now().replace(minute=0, second=0, microsecond=0)
        for minutes, value in ((-170, 2.0), (-160, 6.0), (-40, 5.0)):
            Sample.objects.create(
                agent=self.agent,
                ts=base + dt.timedelta(minutes=minutes),
                values={"load.1": value},
            )
        # rows without the series are left out
        Sample.objects.create(agent=self.agent, ts=base, values={"cpu.pct": 3.0})
        r = self.client.get(self.series_url(name="load.1", range="7d"))
        points = r.data["points"]
        self.assertEqual(
            [(p["avg"], p["max"]) for p in points], [(4.0, 6.0), (5.0, 5.0)]
        )
        first = dt.datetime.fromisoformat(points[0]["ts"])
        self.assertEqual(first.timestamp() % 3600, 0)

    def test_bad_queries(self):
        for query in (
            {"name": "nope"},
            {"name": "load.1", "range": "2y"},
            {"name": "net.rx_bps"},
            {"name": "net.rx_bps", "labels": json.dumps({"if": "*"})},
            {"name": "net.rx_bps", "labels": json.dumps({"if": "eth0", "x": "1"})},
            {"name": "net.rx_bps", "labels": json.dumps({"if": 5})},
            {"name": "net.rx_bps", "labels": json.dumps(["eth0"])},
            {"name": "net.rx_bps", "labels": "{nope"},
            {"name": "cpu.pct", "labels": json.dumps({"if": "eth0"})},
        ):
            r = self.client.get(self.series_url(**query))
            self.assertEqual(r.status_code, 400, query)

    def test_scope(self):
        other = baker.make_recipe("agents.online_agent")
        AgentState.objects.create(agent=self.agent, received=djangotime.now())
        urls = (
            f"/metrics/{self.agent.agent_id}/state/",
            f"/metrics/{self.agent.agent_id}/series/",
        )

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        for url in urls:
            self.assertEqual(self.client.get(url).status_code, 403, url)

        user.role.can_list_agents = True
        user.role.can_view_clients.set([self.agent.client])
        user.role.save()
        for url in urls:
            self.assertEqual(self.client.get(url).status_code, 200, url)
            foreign = url.replace(self.agent.agent_id, other.agent_id)
            self.assertEqual(self.client.get(foreign).status_code, 403, foreign)
            missing = url.replace(self.agent.agent_id, "not-an-agent-at-all-12345")
            self.assertEqual(self.client.get(missing).status_code, 403, missing)

        self.client.force_authenticate(user=self.john)
        for url in urls:
            missing = url.replace(self.agent.agent_id, "not-an-agent-at-all-12345")
            self.assertEqual(self.client.get(missing).status_code, 404, missing)
        for url in urls:
            self.check_not_authenticated("get", url)


class TestMetricChecks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)

    def metric_check(self, **fields):
        fields.setdefault("metric", "temp.c")
        return baker.make(
            "checks.Check",
            agent=self.agent,
            check_type=CheckType.METRIC,
            dashboard_alert=True,
            **fields,
        )

    def push(self, values, minutes_ago=0):
        sample = Sample.objects.create(
            agent=self.agent,
            ts=djangotime.now() - dt.timedelta(minutes=minutes_ago),
            values=values,
        )
        evaluate_metric_checks(self.agent, sample)
        return sample

    def result(self, check):
        return CheckResult.objects.get(assigned_check=check, agent=self.agent)

    def test_above_warning_error_and_resolve(self):
        check = self.metric_check(
            metric_labels={"sensor": "cpu"}, metric_warning=70, metric_error=90
        )
        key = "temp.c{sensor=cpu}"

        self.push({key: 50.0})
        result = self.result(check)
        self.assertEqual(result.status, CheckStatus.PASSING)
        self.assertEqual(result.more_info, "Average of 1 samples: 50")

        self.push({key: 75.5})
        result = self.result(check)
        self.assertEqual(
            (result.status, result.alert_severity),
            (CheckStatus.FAILING, AlertSeverity.WARNING),
        )
        alert = check.alert.get(agent=self.agent, resolved=False)
        self.assertEqual(alert.severity, AlertSeverity.WARNING)

        self.push({key: 95.0})
        result = self.result(check)
        self.assertEqual(result.alert_severity, AlertSeverity.ERROR)

        self.push({key: 10.0})
        self.assertEqual(self.result(check).status, CheckStatus.PASSING)
        self.assertFalse(check.alert.filter(resolved=False).exists())

        history = list(
            CheckHistory.objects.filter(check_id=check.pk).values_list("y", "results")
        )
        self.assertEqual(history, [(0, "50"), (1, "75.5"), (1, "95"), (0, "10")])

    def test_below_and_average(self):
        check = self.metric_check(
            metric="disk.used_pct",
            metric_labels={"mount": "/"},
            metric_op="below",
            metric_warning=20,
            metric_error=10,
            metric_samples=3,
        )
        key = "disk.used_pct{mount=/}"
        self.push({key: 30.0}, minutes_ago=15)
        self.push({key: 3.0}, minutes_ago=10)
        self.push({"cpu.pct": 1.0}, minutes_ago=5)
        self.push({key: 15.0})
        result = self.result(check)
        # (30 + 3 + 15) / 3
        self.assertEqual(result.more_info, "Average of 3 samples: 16")
        self.assertEqual(
            (result.status, result.alert_severity),
            (CheckStatus.FAILING, AlertSeverity.WARNING),
        )

    def test_wildcard_takes_the_worst(self):
        above = self.metric_check(metric_labels={"sensor": "*"}, metric_error=80)
        below = self.metric_check(
            metric="disk.used_pct", metric_op="below", metric_error=5
        )
        self.push(
            {
                "temp.c{sensor=a}": 85.0,
                "temp.c{sensor=b}": 40.0,
                "disk.used_pct{mount=/}": 50.0,
                "disk.used_pct{mount=/boot}": 2.0,
            }
        )
        self.assertEqual(self.result(above).more_info, "Average of 1 samples: 85")
        self.assertEqual(self.result(below).more_info, "Average of 1 samples: 2")
        self.assertEqual(self.result(above).status, CheckStatus.FAILING)
        self.assertEqual(self.result(below).status, CheckStatus.FAILING)

    def test_bound_mount_keeps_its_series_on_a_crowded_host(self):
        check = self.metric_check(
            metric="disk.used_pct", metric_labels={"mount": "/data19"}, metric_error=90
        )
        self.metric_check(metric="disk.used_pct", metric_labels={"mount": "*"})
        mount = DOC["system"]["mounts"][0]
        body = doc()
        body["system"]["mounts"] = [
            dict(mount, mount=f"/data{i}", size=(100 - i) * GB) for i in range(20)
        ]
        sample = ingest(self.agent, clean_state(body))
        mounts = [parse_key(k)[1].get("mount") for k in sample.values]
        self.assertIn("/data19", mounts)
        self.assertNotIn("/data15", mounts)
        self.assertEqual(self.result(check).more_info, "Average of 1 samples: 40")

    def test_missing_series_is_an_error(self):
        check = self.metric_check(metric_labels={"sensor": "gone"}, metric_warning=70)
        self.push({"temp.c{sensor=gone}": 20.0}, minutes_ago=5)
        self.push({"temp.c{sensor=other}": 20.0})
        result = self.result(check)
        self.assertEqual(
            (result.status, result.alert_severity, result.more_info),
            (CheckStatus.FAILING, AlertSeverity.ERROR, "Not reported"),
        )
        self.assertTrue(check.alert.filter(resolved=False).exists())

    def test_run_interval_and_fails_before_alert(self):
        check = self.metric_check(
            metric="cpu.pct", metric_warning=50, run_interval=600, fails_b4_alert=2
        )
        self.push({"cpu.pct": 60.0})
        self.assertEqual(self.result(check).fail_count, 1)
        self.assertFalse(check.alert.exists())
        # not due yet
        self.push({"cpu.pct": 60.0})
        self.assertEqual(self.result(check).fail_count, 1)

        CheckResult.objects.filter(assigned_check=check).update(
            last_run=djangotime.now() - dt.timedelta(seconds=580)
        )
        self.push({"cpu.pct": 60.0})
        self.assertEqual(self.result(check).fail_count, 2)
        self.assertTrue(check.alert.filter(resolved=False).exists())

    def test_policy_metric_check_and_template(self):
        policy = baker.make("automation.Policy", active=True)
        template = baker.make(
            "alerts.AlertTemplate", is_active=True, check_always_alert=True
        )
        policy.alert_template = template
        policy.save()
        check = baker.make(
            "checks.Check",
            policy=policy,
            check_type=CheckType.METRIC,
            metric="load.1",
            metric_error=4,
        )
        self.agent.policy = policy
        self.agent.save()
        # policy merges are cached per site and policy id, which repeat per test run
        cache.delete(self.agent._policy_cache_key("checks"))
        self.agent.set_alert_template()
        self.push({"load.1": 8.0})
        result = self.result(check)
        self.assertEqual(result.status, CheckStatus.FAILING)
        self.assertTrue(check.alert.filter(agent=self.agent, resolved=False).exists())

    def test_ingest_without_metric_checks_does_nothing(self):
        baker.make("checks.Check", agent=self.agent, check_type=CheckType.CPU_LOAD)
        self.push({"cpu.pct": 99.0})
        self.assertFalse(CheckResult.objects.exists())

    def test_push_endpoint_evaluates(self):
        check = self.metric_check(metric="cpu.pct", metric_warning=10)
        self.setup_client()
        self.authenticate_agent(self.agent)
        self.client.post(f"/api/v3/{self.agent.agent_id}/state/", DOC, format="json")
        self.assertEqual(self.result(check).status, CheckStatus.FAILING)
        self.assertEqual(self.result(check).more_info, "Average of 1 samples: 12.5")


class TestDemoSeed(ULRMMTestCase):
    def test_fake_agents_state(self):
        self.setup_coresettings()
        agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, total_ram=16
        )
        FakeAgents()._state(agent, with_checks=True)
        state = AgentState.objects.get(agent=agent)
        self.assertEqual(
            set(state.data) >= {"perf", "system", "net", "containers"}, True
        )
        self.assertEqual(clean_state(copy.deepcopy(state.data)), state.data)
        self.assertEqual(Sample.objects.filter(agent=agent).count(), 288)
        self.assertIn(
            "net.rx_bps{if=eth0}", Sample.objects.filter(agent=agent).first().values
        )
        self.assertEqual(
            set(Check.objects.filter(agent=agent).values_list("check_type", flat=True)),
            {CheckType.METRIC, CheckType.SYSTEMD, CheckType.CONTAINER},
        )

        windows = baker.make_recipe("agents.online_agent", total_ram=8)
        FakeAgents()._state(windows, with_checks=True)
        self.assertEqual(
            set(AgentState.objects.get(agent=windows).data),
            {"v", "ts", "dt", "perf", "net"},
        )
        self.assertEqual(
            list(
                Check.objects.filter(agent=windows).values_list("check_type", flat=True)
            ),
            [CheckType.METRIC],
        )

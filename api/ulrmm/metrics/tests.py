# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.perf import perf_command
from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase

from .models import Sample
from .tasks import prune_metrics_task, sample_metrics_task
from .views import downsample

# raw rawcmd replies, same shapes as agents/tests/test_perf.py
REPLIES = {
    "linux": "noise\ncpu 1000 400\ncpu 1100 440\nmem 8000000 3000000\n",
    "darwin": (
        "cpu CPU usage: 7.5% user, 4.5% sys, 88.0% idle\n"
        "memtotal 17179869184\n"
        "vm Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
        "vm Anonymous pages: 500000.\n"
        "vm Pages wired down: 100000.\n"
    ),
    "windows": "cpu 12,5\nmem 16000000 4000000\n",
}


def fake_nats(replies):
    """nats_cmd stand-in answering per agent_id; autospec passes the agent as self."""

    async def nats_cmd(agent, data, timeout=30, wait=True):
        reply = replies[agent.agent_id]
        if isinstance(reply, BaseException):
            raise reply
        return reply

    return nats_cmd


class TestSampler(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    @patch("agents.models.Agent.nats_cmd", autospec=True)
    def test_sample_per_platform(self, nats_cmd):
        agents = {
            plat: baker.make_recipe("agents.online_agent", plat=plat)
            for plat in REPLIES
        }
        agents["linux"].disks = [
            {"device": "/", "fstype": "ext4", "percent": 42},
            {"device": "/boot", "fstype": "vfat", "percent": 10},
            {"device": "/broken"},
            "garbage",
        ]
        agents["linux"].save(update_fields=["disks"])
        offline = baker.make_recipe("agents.offline_agent")
        overdue = baker.make_recipe("agents.overdue_agent")
        never = baker.make_recipe("agents.agent", last_seen=None)
        unknown = baker.make_recipe("agents.online_agent", plat="plan9")
        nats_cmd.side_effect = fake_nats(
            {agents[plat].agent_id: reply for plat, reply in REPLIES.items()}
        )

        self.assertEqual(sample_metrics_task(), "3 of 3 agents sampled")

        called = {call.args[0].agent_id for call in nats_cmd.call_args_list}
        self.assertEqual(called, {agent.agent_id for agent in agents.values()})
        for agent in (offline, overdue, never, unknown):
            self.assertFalse(Sample.objects.filter(agent=agent).exists())

        shell, command = perf_command(AgentPlat.LINUX)
        for call in nats_cmd.call_args_list:
            if call.args[0].plat == AgentPlat.LINUX:
                self.assertEqual(
                    call.args[1],
                    {
                        "func": "rawcmd",
                        "timeout": 10,
                        "payload": {"command": command, "shell": shell},
                        "run_as_user": False,
                    },
                )
                self.assertEqual(call.kwargs, {"timeout": 15})

        expected = {
            # kB from /proc/meminfo, stored in MB
            "linux": (60.0, 4882, 7812, {"/": 42, "/boot": 10}),
            # 600000 pages of 16 KiB used, 16 GiB total
            "darwin": (12.0, 9375, 16384, {}),
            "windows": (12.5, 11718, 15625, {}),
        }
        for plat, (cpu, used, total, disks) in expected.items():
            sample = Sample.objects.get(agent=agents[plat])
            self.assertEqual(
                (sample.cpu, sample.mem_used, sample.mem_total, sample.disks),
                (cpu, used, total, disks),
                plat,
            )
            self.assertLess(djangotime.now() - sample.ts, dt.timedelta(minutes=1))

    @patch("agents.models.Agent.nats_cmd", autospec=True)
    def test_timeouts_and_garbage_are_skipped(self, nats_cmd):
        replies = {
            "timeout": "timeout",
            "natsdown": "natsdown",
            "garbage": "garbage",
            "dict": {},
            "none": None,
            "raises": TimeoutError(),
            "boom": RuntimeError("connection lost"),
            "ok": REPLIES["linux"],
            # cpu only, memory unreadable
            "cpu": "cpu 100 50\ncpu 200 90\n",
        }
        by_id = {}
        for hostname, reply in replies.items():
            agent = baker.make_recipe(
                "agents.online_agent", plat=AgentPlat.LINUX, hostname=hostname
            )
            by_id[agent.agent_id] = reply
        nats_cmd.side_effect = fake_nats(by_id)

        self.assertEqual(sample_metrics_task(), "2 of 9 agents sampled")
        self.assertEqual(nats_cmd.call_count, 9)
        self.assertEqual(
            set(Sample.objects.values_list("agent__hostname", flat=True)), {"ok", "cpu"}
        )
        cpu_only = Sample.objects.get(agent__hostname="cpu")
        self.assertEqual(
            (cpu_only.cpu, cpu_only.mem_used, cpu_only.mem_total), (60.0, None, None)
        )

    @override_settings(METRICS_RETENTION_DAYS=30)
    def test_prune(self):
        agent = baker.make_recipe("agents.agent")
        now = djangotime.now()
        old = baker.make(Sample, agent=agent, ts=now - dt.timedelta(days=31))
        new = baker.make(Sample, agent=agent, ts=now - dt.timedelta(days=29))

        self.assertEqual(prune_metrics_task(), "1 samples removed")
        self.assertFalse(Sample.objects.filter(pk=old.pk).exists())
        self.assertTrue(Sample.objects.filter(pk=new.pk).exists())

        baker.make(Sample, agent=agent, ts=now - dt.timedelta(days=40), _quantity=3)
        with patch("metrics.tasks.BATCH", 2):
            self.assertEqual(prune_metrics_task(), "3 samples removed")
        self.assertEqual(Sample.objects.count(), 1)


def make_samples(agent, count, step=300, now=None):
    now = now or djangotime.now()
    Sample.objects.bulk_create(
        Sample(
            agent=agent,
            ts=now - dt.timedelta(seconds=i * step),
            cpu=float(i % 100),
            mem_used=1000,
            mem_total=4000,
            disks={"/": 50},
        )
        for i in range(count)
    )


class TestMetricsAPI(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_downsample_averages_a_bucket(self):
        base = dt.datetime(2026, 10, 7, 12, 0, tzinfo=dt.timezone.utc)
        rows = [
            (base + dt.timedelta(minutes=1), 10.0, 1000, 4000, {"/": 40}),
            (base + dt.timedelta(minutes=10), 30.0, 3000, 4000, {"/": 60, "D:": 5}),
            (base + dt.timedelta(minutes=65), None, None, None, {}),
        ]
        self.assertEqual(
            downsample(rows, 3600),
            [
                {
                    "ts": "2026-10-07T12:00:00+00:00",
                    "cpu": 20.0,
                    "mem_percent": 50.0,
                    "mem_used": 2000,
                    "mem_total": 4000,
                    "disks": {"/": 50.0, "D:": 5.0},
                },
                {
                    "ts": "2026-10-07T13:00:00+00:00",
                    "cpu": None,
                    "mem_percent": None,
                    "mem_used": None,
                    "mem_total": None,
                    "disks": {},
                },
            ],
        )

    def test_ranges_stay_under_300_points(self):
        agent = baker.make_recipe("agents.online_agent")
        other = baker.make_recipe("agents.online_agent")
        # 30 days every 5 minutes, plus one row too old for any range
        make_samples(agent, 30 * 288)
        make_samples(agent, 1, now=djangotime.now() - dt.timedelta(days=31))
        make_samples(other, 10)

        for name, step, samples in (
            ("1h", 300, 12),
            ("6h", 300, 72),
            ("24h", 300, 288),
            ("7d", 3600, 7 * 288),
            ("30d", 10800, 30 * 288),
        ):
            r = self.client.get(f"/metrics/{agent.agent_id}/?range={name}")
            self.assertEqual(r.status_code, 200, name)
            self.assertEqual(r.data["range"], name)
            self.assertEqual(r.data["step_seconds"], step)
            self.assertLessEqual(len(r.data["points"]), 300, name)
            self.assertGreaterEqual(len(r.data["points"]), samples * 300 // step)
            self.assertEqual(r.data["summary"]["samples"], samples, name)
            self.assertEqual(r.data["summary"]["mem_avg"], 25.0)
            point = r.data["points"][-1]
            self.assertEqual(
                (point["mem_percent"], point["mem_total"], point["disks"]),
                (25.0, 4000, {"/": 50.0}),
            )
            stamps = [p["ts"] for p in r.data["points"]]
            self.assertEqual(stamps, sorted(stamps))

        r = self.client.get(f"/metrics/{agent.agent_id}/?range=30d")
        self.assertEqual(r.data["summary"]["cpu_max"], 99.0)
        # i % 100 over 8640 rows: 86 full cycles plus 0..39
        self.assertEqual(r.data["summary"]["cpu_avg"], 49.4)

        # default range
        r = self.client.get(f"/metrics/{agent.agent_id}/")
        self.assertEqual((r.data["range"], r.data["summary"]["samples"]), ("24h", 288))

    def test_bad_range_and_empty(self):
        agent = baker.make_recipe("agents.online_agent")
        url = f"/metrics/{agent.agent_id}/"

        self.assertEqual(self.client.get(f"{url}?range=2y").status_code, 400)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["points"], [])
        self.assertEqual(
            r.data["summary"],
            {
                "cpu_avg": None,
                "cpu_max": None,
                "mem_avg": None,
                "mem_max": None,
                "samples": 0,
            },
        )

        now = djangotime.now()
        for minutes, cpu, used in ((1, 10.0, 1000), (6, 30.0, 3000)):
            baker.make(
                Sample,
                agent=agent,
                ts=now - dt.timedelta(minutes=minutes),
                cpu=cpu,
                mem_used=used,
                mem_total=4000,
            )
        r = self.client.get(f"{url}?range=1h")
        self.assertEqual(
            r.data["summary"],
            {
                "cpu_avg": 20.0,
                "cpu_max": 30.0,
                "mem_avg": 50.0,
                "mem_max": 75.0,
                "samples": 2,
            },
        )
        self.assertEqual([p["mem_total"] for p in r.data["points"]], [4000, 4000])

    def test_agent_scope(self):
        agent = baker.make_recipe("agents.online_agent")
        other = baker.make_recipe("agents.online_agent")
        make_samples(agent, 3)
        make_samples(other, 3)
        url = f"/metrics/{agent.agent_id}/"

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(url).status_code, 403)

        user.role.can_list_agents = True
        user.role.can_view_clients.set([agent.client])
        user.role.save()
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(
            self.client.get(f"/metrics/{other.agent_id}/").status_code, 403
        )
        # a restricted role cannot tell a missing agent from a foreign one
        self.assertEqual(
            self.client.get("/metrics/not-an-agent-at-all-12345/").status_code, 403
        )

        self.client.force_authenticate(user=self.john)
        self.assertEqual(
            self.client.get("/metrics/not-an-agent-at-all-12345/").status_code, 404
        )
        self.check_not_authenticated("get", url)

    def test_fleet_top_list(self):
        busy = baker.make_recipe("agents.online_agent", hostname="busy")
        idle = baker.make_recipe("agents.online_agent", hostname="idle")
        hidden = baker.make_recipe("agents.online_agent", hostname="hidden")
        now = djangotime.now()
        for agent, cpu, used in (
            (busy, 90.0, 3000),
            (idle, 5.0, 1000),
            (hidden, 99.0, 3900),
        ):
            baker.make(
                Sample, agent=agent, ts=now, cpu=cpu, mem_used=used, mem_total=4000
            )
            baker.make(
                Sample,
                agent=agent,
                ts=now - dt.timedelta(minutes=5),
                cpu=cpu - 2,
                mem_used=used,
                mem_total=4000,
            )
        # outside 24h, memory unknown
        baker.make(Sample, agent=idle, ts=now - dt.timedelta(days=2), cpu=100.0)
        baker.make(Sample, agent=idle, ts=now, cpu=None, mem_used=None, mem_total=None)

        r = self.client.get("/metrics/fleet/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.data["range"], r.data["metric"]), ("24h", "cpu"))
        self.assertEqual(
            [
                (a["hostname"], a["avg"], a["max"], a["samples"])
                for a in r.data["agents"]
            ],
            [("hidden", 98.0, 99.0, 2), ("busy", 89.0, 90.0, 2), ("idle", 4.0, 5.0, 2)],
        )
        top = r.data["agents"][0]
        self.assertEqual(top["agent_id"], hidden.agent_id)
        self.assertEqual(
            (top["client"], top["site"]), (hidden.client.name, hidden.site.name)
        )

        r = self.client.get("/metrics/fleet/?metric=mem&limit=2&range=7d")
        self.assertEqual(
            [(a["hostname"], a["avg"]) for a in r.data["agents"]],
            [("hidden", 97.5), ("busy", 75.0)],
        )

        for query in ("metric=disk", "range=1y", "limit=x"):
            self.assertEqual(
                self.client.get(f"/metrics/fleet/?{query}").status_code, 400, query
            )

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get("/metrics/fleet/").status_code, 403)

        user.role.can_list_agents = True
        user.role.can_view_sites.set([busy.site, idle.site])
        user.role.save()
        r = self.client.get("/metrics/fleet/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([a["hostname"] for a in r.data["agents"]], ["busy", "idle"])
        self.check_not_authenticated("get", "/metrics/fleet/")

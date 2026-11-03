# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import re
import shutil
import subprocess
from unittest.mock import patch

import pytest
from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase

from agents.perf import parse_perf, perf_command

MEMINFO = """MemTotal:       16316500 kB
MemFree:          303284 kB
MemAvailable:    8290372 kB
Buffers:          295848 kB
Cached:          7520676 kB
SwapCached:        12140 kB
Active:          9104244 kB
"""

# kernels before 3.14 have no MemAvailable
MEMINFO_OLD = """MemTotal:        2048000 kB
MemFree:          100000 kB
Buffers:           50000 kB
Cached:           300000 kB
SwapCached:         1000 kB
"""


def test_linux_perf():
    parsed = parse_perf(
        AgentPlat.LINUX,
        "noise from stderr\ncpu 1000 400\ncpu 1100 440\nmem 8000000 3000000\n",
    )
    assert parsed == {
        "cpu_percent": 60.0,
        "mem_total": 8_192_000_000,
        "mem_used": 5_120_000_000,
        "mem_percent": 62.5,
    }
    shell, command = perf_command(AgentPlat.LINUX)
    assert shell == "/bin/sh"
    assert "sleep 1" in command
    assert "MemAvailable" in command
    assert "a=f+b+c" in command
    assert 'printf "cpu %.0f %.0f\\n"' in command
    assert 'printf "mem %.0f %.0f\\n"' in command


@pytest.mark.skipif(not shutil.which("awk"), reason="needs awk")
def test_linux_meminfo_awk():
    _, command = perf_command(AgentPlat.LINUX)
    program = re.search(r"awk '([^']+)' /proc/meminfo", command).group(1)

    def run(meminfo):
        r = subprocess.run(
            ["awk", program],
            input=meminfo,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    assert run(MEMINFO) == "mem 16316500 8290372"
    # MemFree + Buffers + Cached, SwapCached is not part of it
    assert run(MEMINFO_OLD) == "mem 2048000 450000"

    parsed = parse_perf(AgentPlat.LINUX, f"cpu 100 50\ncpu 200 100\n{run(MEMINFO_OLD)}")
    assert parsed["mem_total"] == 2_048_000 * 1024
    assert parsed["mem_used"] == 1_598_000 * 1024


def test_darwin_perf_with_anonymous_pages():
    parsed = parse_perf(
        AgentPlat.DARWIN,
        "warning\n"
        "cpu CPU usage: 7.5% user, 4.5% sys, 88.0% idle\n"
        "memtotal 160000\n"
        "vm Mach Virtual Memory Statistics: (page size of 100 bytes)\n"
        "vm Anonymous pages: 1000.\n"
        "vm Pages purgeable: 100.\n"
        "vm Pages wired down: 200.\n"
        "vm Pages occupied by compressor: 100.\n",
    )
    assert parsed == {
        "cpu_percent": 12.0,
        "mem_total": 160000,
        "mem_used": 120000,
        "mem_percent": 75.0,
    }


def test_darwin_perf_without_anonymous_pages():
    parsed = parse_perf(
        AgentPlat.DARWIN,
        "cpu CPU usage: 10% user, 10% sys, 80% idle\n"
        "memtotal 100000\n"
        "vm Mach Virtual Memory Statistics: (page size of 100 bytes)\n"
        "vm Pages active: 500.\n"
        "vm Pages wired down: 200.\n"
        "vm Pages occupied by compressor: 100.\n",
    )
    assert parsed["cpu_percent"] == 20.0
    assert parsed["mem_used"] == 80000
    assert parsed["mem_percent"] == 80.0


def test_windows_perf_decimal_comma():
    parsed = parse_perf(
        AgentPlat.WINDOWS, "Get-CimInstance warning\ncpu 12,5\nmem 1000 250\n"
    )
    assert parsed == {
        "cpu_percent": 12.5,
        "mem_total": 1_024_000,
        "mem_used": 768_000,
        "mem_percent": 75.0,
    }
    shell, command = perf_command(AgentPlat.WINDOWS)
    assert shell == "powershell"
    assert '"' not in command


def test_perf_garbage_empty_and_clamping():
    empty = {
        "cpu_percent": None,
        "mem_total": None,
        "mem_used": None,
        "mem_percent": None,
    }
    assert parse_perf(AgentPlat.LINUX, "") == empty
    assert parse_perf(AgentPlat.DARWIN, "garbage") == empty
    assert parse_perf(AgentPlat.WINDOWS, b"cpu 5") == empty

    high = parse_perf(AgentPlat.LINUX, "cpu 100 50\ncpu 200 25\nmem 10 -2")
    assert high["cpu_percent"] == 100.0
    assert high["mem_used"] == high["mem_total"]
    assert high["mem_percent"] == 100.0


class TestAgentPerf(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    @patch("agents.models.Agent.nats_cmd")
    def test_offline_does_not_call_agent(self, nats_cmd):
        agent = baker.make_recipe("agents.offline_agent", plat=AgentPlat.LINUX)
        response = self.client.get(f"/agents/{agent.agent_id}/perf/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["error"], "offline")
        self.assertIsNone(response.data["cpu_percent"])
        self.assertIsNotNone(
            dt.datetime.fromisoformat(response.data["collected_at"]).tzinfo
        )
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_online_calls_rawcmd(self, nats_cmd):
        agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, last_seen=djangotime.now()
        )
        nats_cmd.return_value = "cpu 100 50\ncpu 200 90\nmem 1000 250\n"

        response = self.client.get(f"/agents/{agent.agent_id}/perf/")

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data["error"])
        self.assertEqual(response.data["cpu_percent"], 60.0)
        shell, command = perf_command(AgentPlat.LINUX)
        nats_cmd.assert_called_once_with(
            {
                "func": "rawcmd",
                "timeout": 10,
                "payload": {"command": command, "shell": shell},
                "run_as_user": False,
            },
            timeout=20,
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_agent_failures_are_http_200(self, nats_cmd):
        agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        url = f"/agents/{agent.agent_id}/perf/"
        for reply, error in (
            ("timeout", "unreachable"),
            ({}, "unreachable"),
            ("bad", "unparseable"),
        ):
            nats_cmd.return_value = reply
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data["error"], error)

        nats_cmd.side_effect = TimeoutError
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["error"], "unreachable")

    @patch("agents.models.Agent.nats_cmd")
    def test_unknown_plat_does_not_call_agent(self, nats_cmd):
        agent = baker.make_recipe("agents.online_agent", plat="plan9")

        response = self.client.get(f"/agents/{agent.agent_id}/perf/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["error"], "unsupported")
        self.assertIsNone(response.data["cpu_percent"])
        self.assertIsNone(perf_command("plan9"))
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_permissions_unknown_and_unauthenticated(self, nats_cmd):
        agent = baker.make_recipe("agents.online_agent")
        other = baker.make_recipe("agents.online_agent")
        url = f"/agents/{agent.agent_id}/perf/"
        nats_cmd.return_value = "cpu 100 50\ncpu 200 90\nmem 1000 250\n"

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(url).status_code, 403)

        user.role.can_list_agents = True
        user.role.can_view_clients.set([agent.client])
        user.role.save()
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(
            self.client.get(f"/agents/{other.agent_id}/perf/").status_code, 403
        )

        self.client.force_authenticate(user=self.john)
        self.assertEqual(self.client.get("/agents/not-an-agent/perf/").status_code, 404)
        self.check_not_authenticated("get", url)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""CPU and memory via one rawcmd on the agent.

Each platform has a shell command that prints tagged lines, and a parser
for those lines. Unknown lines (stderr, warnings) are ignored.
"""

import math
import re
from typing import Callable, Optional

from ulrmm.constants import AgentPlat

# /proc/stat: total = user..steal (fields 2-9), idle = idle + iowait
_STAT_AWK = (
    "awk '/^cpu /{t=0; for (i=2; i<=9; i++) t+=$i; "
    'printf "cpu %.0f %.0f\\n", t, $5+$6; exit}\' /proc/stat'
)

# kernels before 3.14 have no MemAvailable, estimate it from the free parts
_MEMINFO_AWK = (
    "awk '/^MemTotal:/{t=$2} /^MemFree:/{f=$2} /^Buffers:/{b=$2} "
    "/^Cached:/{c=$2} /^MemAvailable:/{a=$2; seen=1} "
    'END{if (!seen) a=f+b+c; printf "mem %.0f %.0f\\n", t, a}\' /proc/meminfo'
)

_LINUX_CMD = f"{_STAT_AWK}; sleep 1; {_STAT_AWK}; {_MEMINFO_AWK}"

_DARWIN_CMD = (
    "top -l 2 -n 0 -s 1 | awk '/^CPU usage:/{l=$0} END{print \"cpu \" l}'; "
    'echo "memtotal $(sysctl -n hw.memsize)"; '
    "vm_stat | sed 's/^/vm /'"
)

# v_cache_count is gone on newer releases; sysctl then warns and goes on
_FREEBSD_CMD = (
    "sysctl kern.cp_time; sleep 1; sysctl kern.cp_time; "
    "sysctl hw.physmem vm.stats.vm.v_page_size vm.stats.vm.v_free_count "
    "vm.stats.vm.v_inactive_count vm.stats.vm.v_cache_count"
)

# no double quotes: the agent hands this to powershell as one argument
_WINDOWS_CMD = (
    "$c = (Get-CimInstance Win32_Processor | "
    "Measure-Object -Property LoadPercentage -Average).Average; "
    "$o = Get-CimInstance Win32_OperatingSystem; "
    "Write-Output ('cpu ' + $c); "
    "Write-Output ('mem ' + $o.TotalVisibleMemorySize + ' ' + $o.FreePhysicalMemory)"
)

_COMMANDS = {
    AgentPlat.LINUX: ("/bin/sh", _LINUX_CMD),
    AgentPlat.DARWIN: ("/bin/sh", _DARWIN_CMD),
    AgentPlat.FREEBSD: ("/bin/sh", _FREEBSD_CMD),
    AgentPlat.WINDOWS: ("powershell", _WINDOWS_CMD),
}

_IDLE_RE = re.compile(r"([0-9]+(?:[.,][0-9]+)?)%\s*idle")
_PAGE_SIZE_RE = re.compile(r"page size of ([0-9]+) bytes")
_VM_LINE_RE = re.compile(r"^vm (.+?):\s+([0-9]+)\.?$")

Reading = dict[str, Optional[float]]


def perf_command(plat: str) -> Optional[tuple[str, str]]:
    """(shell, command) for the platform, None when there is none."""
    return _COMMANDS.get(plat)


def _number(text: str) -> Optional[float]:
    try:
        value = float(text.replace(",", "."))
    except (AttributeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _lines(output: str) -> list[list[str]]:
    return [line.split() for line in output.splitlines() if line.strip()]


def _linux(output: str) -> tuple[Optional[float], Optional[float], Optional[float]]:
    samples = []
    total = avail = None
    for fields in _lines(output):
        if len(fields) != 3:
            continue
        if fields[0] == "cpu":
            t, i = _number(fields[1]), _number(fields[2])
            if t is not None and i is not None:
                samples.append((t, i))
        elif fields[0] == "mem":
            t, a = _number(fields[1]), _number(fields[2])
            if t is not None and a is not None:
                total, avail = t * 1024, a * 1024

    cpu = None
    if len(samples) >= 2:
        (t0, i0), (t1, i1) = samples[-2], samples[-1]
        if t1 - t0 > 0:
            cpu = ((t1 - t0) - (i1 - i0)) * 100 / (t1 - t0)

    used = total - avail if total is not None else None
    return cpu, total, used


def _darwin(output: str) -> tuple[Optional[float], Optional[float], Optional[float]]:
    cpu = total = page_size = None
    pages: dict[str, float] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("cpu "):
            m = _IDLE_RE.search(line)
            idle = _number(m.group(1)) if m else None
            if idle is not None:
                cpu = 100 - idle
        elif line.startswith("memtotal "):
            total = _number(line.split(None, 1)[1])
        elif line.startswith("vm "):
            m = _PAGE_SIZE_RE.search(line)
            if m:
                page_size = float(m.group(1))
                continue
            m = _VM_LINE_RE.match(line)
            if m:
                pages[m.group(1)] = float(m.group(2))

    used = None
    if total is not None and page_size is not None and pages:
        wired = pages.get("Pages wired down", 0)
        compressed = pages.get("Pages occupied by compressor", 0)
        if "Anonymous pages" in pages:
            app = pages["Anonymous pages"] - pages.get("Pages purgeable", 0)
        else:
            app = pages.get("Pages active", 0)
        used = (app + wired + compressed) * page_size
    else:
        total = None
    return cpu, total, used


def _freebsd(output: str) -> tuple[Optional[float], Optional[float], Optional[float]]:
    samples = []
    values: dict[str, float] = {}
    for fields in _lines(output):
        name = fields[0]
        if name == "kern.cp_time:" and len(fields) == 6:
            # user nice sys intr idle
            ticks = [_number(f) for f in fields[1:]]
            if None not in ticks:
                samples.append((sum(ticks), ticks[4]))
        elif name.endswith(":") and len(fields) == 2:
            value = _number(fields[1])
            if value is not None:
                values[name[:-1]] = value

    cpu = None
    if len(samples) >= 2:
        (t0, i0), (t1, i1) = samples[-2], samples[-1]
        if t1 - t0 > 0:
            cpu = ((t1 - t0) - (i1 - i0)) * 100 / (t1 - t0)

    total = values.get("hw.physmem")
    page = values.get("vm.stats.vm.v_page_size")
    free = values.get("vm.stats.vm.v_free_count")
    inactive = values.get("vm.stats.vm.v_inactive_count")
    used = None
    if total is not None and None not in (page, free, inactive):
        cache = values.get("vm.stats.vm.v_cache_count", 0)
        used = total - (free + inactive + cache) * page
    return cpu, total, used


def _windows(output: str) -> tuple[Optional[float], Optional[float], Optional[float]]:
    cpu = total = used = None
    for fields in _lines(output):
        if fields[0] == "cpu" and len(fields) == 2:
            value = _number(fields[1])
            if value is not None:
                cpu = value
        elif fields[0] == "mem" and len(fields) == 3:
            t, f = _number(fields[1]), _number(fields[2])
            if t is not None and f is not None:
                total, used = t * 1024, (t - f) * 1024
    return cpu, total, used


_PARSERS: dict[str, Callable] = {
    AgentPlat.LINUX: _linux,
    AgentPlat.DARWIN: _darwin,
    AgentPlat.FREEBSD: _freebsd,
    AgentPlat.WINDOWS: _windows,
}


def parse_perf(plat: str, output) -> Reading:
    reading: Reading = {
        "cpu_percent": None,
        "mem_total": None,
        "mem_used": None,
        "mem_percent": None,
    }
    parser = _PARSERS.get(plat)
    if parser is None or not isinstance(output, str):
        return reading

    cpu, total, used = parser(output)

    if cpu is not None:
        reading["cpu_percent"] = round(min(max(cpu, 0.0), 100.0), 1)

    if total is not None and used is not None and total > 0:
        total_i = int(total)
        used_i = int(min(max(used, 0), total_i))
        reading["mem_total"] = total_i
        reading["mem_used"] = used_i
        reading["mem_percent"] = round(used_i * 100 / total_i, 1)

    return reading

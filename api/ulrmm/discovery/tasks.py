# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from celery.exceptions import SoftTimeLimitExceeded
from django.core.cache import cache
from django.db.models import F
from django.db.models.fields.json import KeyTransform
from django.utils import timezone as djangotime

from agents.models import Agent
from agents.utils import MAC_RE
from netmon.models import NetworkDevice, probe_scope
from netmon.probe import ProbeError, address_error, clean, ping, snmp_poll, tcp_open
from remote.utils import decrypt_secret
from ulrmm.celery import app

from .models import HKDF_INFO, DeviceState, DiscoveredDevice, Scan, ScanStatus

SCAN_LOCK = "discovery-scan-lock-key"
# wall clock of one scan, the task limits sit above it
SCAN_LIMIT = 600
PING_CONCURRENCY = 64
TCP_CONCURRENCY = 256
DNS_TIMEOUT = 2
DNS_THREADS = 16
SNMP_PORT = 161
ARP = "/proc/net/arp"
RETENTION_DAYS = 90
# a scan still queued or running after this was lost with its worker
STALE_AFTER = dt.timedelta(minutes=30)


def targets(networks, allowed, own) -> list[str]:
    """Addresses the server may probe.

    Read again here: the allowed networks can change while the scan sits queued.
    """
    hosts = {str(ip) for n in networks for ip in IPv4Network(n).hosts()}
    return sorted(
        (h for h in hosts if not address_error(h, allowed, own)), key=IPv4Address
    )


def arp_table() -> dict[str, str]:
    """ip -> mac for complete ARP entries on a segment this server is on.

    An unreadable table comes back empty, and the scan still finishes.
    """
    try:
        with open(ARP) as f:
            rows = [line.split() for line in f.readlines()[1:]]
        return {
            r[0]: r[3].lower()
            for r in rows
            if len(r) >= 4
            and int(r[2], 16) & 2
            and MAC_RE.fullmatch(r[3])
            and r[3] != "00:00:00:00:00:00"
        }
    except Exception:
        return {}


async def bounded(coros, until: float) -> list:
    """Results in order, None for whatever still runs at until (monotonic)."""
    tasks = [asyncio.ensure_future(c) for c in coros]
    if not tasks:
        return []
    done, pending = await asyncio.wait(tasks, timeout=max(0, until - time.monotonic()))
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    return [t.result() if t in done and not t.exception() else None for t in tasks]


async def sweep(hosts: list, ports: list, community: str, until: float):
    """({ip: {"mac", "hostname", "open_ports", "snmp"}}, error text).

    Ping sweep first. A host that drops ping still counts if it is in the
    ARP table and a probed port is open. A stale ARP entry has no open port.
    """
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(DNS_THREADS)
    host_sem = asyncio.Semaphore(PING_CONCURRENCY)
    tcp_sem = asyncio.Semaphore(TCP_CONCURRENCY)
    ping_errors = []

    async def replied(ip):
        async with host_sem:
            try:
                return (await ping(ip))[0]
            except (ProbeError, TimeoutError) as e:
                ping_errors.append(clean(e, 200) or "ping timed out")
                return False

    async def port_open(ip, port):
        async with tcp_sem:
            return await tcp_open(ip, port)

    async def reverse_name(ip):
        try:
            name = await asyncio.wait_for(
                loop.run_in_executor(pool, socket.gethostbyaddr, ip), DNS_TIMEOUT
            )
        except Exception:
            return ""
        return clean(name[0], 255)

    async def snmp_names(ip):
        if not community:
            return {}
        try:
            r = await snmp_poll(ip, SNMP_PORT, "v2c", {"community": community})
        except Exception:
            return {}
        return {"sysName": r["sys_name"], "sysDescr": r["sys_descr"]}

    async def detail(ip, pinged, mac):
        async with host_sem:
            states = await asyncio.gather(*(port_open(ip, p) for p in ports))
            open_ports = [p for p, is_open in zip(ports, states) if is_open]
            if not (pinged or open_ports):
                return {}
            hostname, snmp = await asyncio.gather(reverse_name(ip), snmp_names(ip))
        return {
            "mac": mac,
            "hostname": hostname,
            "open_ports": open_ports,
            "snmp": snmp,
        }

    try:
        pings = await bounded((replied(ip) for ip in hosts), until)
        if hosts and len(ping_errors) == len(hosts):
            raise ProbeError(ping_errors[0])
        arp = arp_table()
        candidates = [
            (ip, bool(ok))
            for ip, ok in zip(hosts, pings)
            if ok or (ok is False and ip in arp)
        ]
        details = await bounded(
            (detail(ip, ok, arp.get(ip, "")) for ip, ok in candidates), until
        )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    found = {ip: d for (ip, _), d in zip(candidates, details) if d}
    errors = []
    unfinished = pings.count(None) + details.count(None)
    if unfinished:
        errors.append(
            f"Stopped after {SCAN_LIMIT // 60} minutes, {unfinished} addresses"
            " were not finished."
        )
    if ping_errors:
        errors.append(f"Ping failed for {len(ping_errors)} addresses: {ping_errors[0]}")
    return found, " ".join(errors)


def agent_matches() -> dict[str, int]:
    """IPv4 address -> agent pk, from Agent.local_ips.

    If several agents report one address, the one seen last is kept.
    """
    ips = {}
    agents = (
        Agent.objects.only("plat")
        .annotate(
            posix_ips=KeyTransform("local_ips", "wmi_detail"),
            win_config=KeyTransform("network_config", "wmi_detail"),
        )
        .order_by(F("last_seen").asc(nulls_first=True))
    )
    for agent in agents:
        # the two keys local_ips reads
        agent.wmi_detail = {
            "local_ips": agent.posix_ips or [],
            "network_config": agent.win_config or [],
        }
        for part in agent.local_ips.split(","):
            with suppress(ValueError):
                ips[str(IPv4Interface(part.strip()).ip)] = agent.pk
    return ips


def netmon_matches() -> dict[str, int]:
    """host -> NetworkDevice pk, the oldest device for a shared address."""
    return dict(
        NetworkDevice.objects.order_by("-pk").values_list("host", "pk").iterator()
    )


def matched_state(ip: str, agents: dict, netmon: dict) -> str:
    if ip in agents:
        return DeviceState.AGENT
    if ip in netmon:
        return DeviceState.NETMON
    return DeviceState.NEW


def save_devices(scan: Scan, found: dict, seen: dt.datetime) -> None:
    # read after the sweep, an ignore clicked meanwhile stays
    agents, netmon = agent_matches(), netmon_matches()
    old = {d.ip: d for d in DiscoveredDevice.objects.filter(ip__in=list(found))}
    rows = []
    for ip, info in found.items():
        prev = old.get(ip) or DiscoveredDevice()
        if prev.state == DeviceState.IGNORED:
            state = DeviceState.IGNORED
        else:
            state = matched_state(ip, agents, netmon)
        rows.append(
            DiscoveredDevice(
                ip=ip,
                mac=info["mac"] or prev.mac,
                hostname=info["hostname"] or prev.hostname,
                open_ports=info["open_ports"],
                snmp=info["snmp"] if scan.snmp else prev.snmp,
                last_seen=seen,
                last_scan=scan,
                state=state,
                agent_id=agents.get(ip),
                netmon_device_id=netmon.get(ip),
            )
        )
    DiscoveredDevice.objects.bulk_create(
        rows,
        batch_size=500,
        update_conflicts=True,
        unique_fields=["ip"],
        update_fields=[
            "mac",
            "hostname",
            "open_ports",
            "snmp",
            "last_seen",
            "last_scan",
            "state",
            "agent",
            "netmon_device",
        ],
    )


def expire_stale() -> None:
    """Mark scans whose worker died as failed, and delete the community."""
    now = djangotime.now()
    Scan.objects.filter(
        status__in=(ScanStatus.QUEUED, ScanStatus.RUNNING),
        started_at__lt=now - STALE_AFTER,
    ).update(
        status=ScanStatus.FAILED,
        finished_at=now,
        error="Did not finish.",
        snmp_community="",
    )


def finish(pk: int, status: str, error: str = "", **fields) -> None:
    # the community is only needed while the scan runs
    Scan.objects.filter(pk=pk).update(
        status=status,
        error=error,
        finished_at=djangotime.now(),
        snmp_community="",
        **fields,
    )


@app.task(soft_time_limit=SCAN_LIMIT + 60, time_limit=SCAN_LIMIT + 90)
def scan_network_task(pk: int) -> str:
    scan = Scan.objects.filter(pk=pk, status=ScanStatus.QUEUED).first()
    if not scan:
        return "not queued"
    if not cache.add(SCAN_LOCK, pk, SCAN_LIMIT + 120):
        finish(pk, ScanStatus.FAILED, "Another scan was running.")
        return "already running"

    try:
        allowed, own = probe_scope()
        hosts = targets(scan.networks, allowed, own)
        Scan.objects.filter(pk=pk).update(
            status=ScanStatus.RUNNING, hosts_total=len(hosts)
        )
        community = ""
        if scan.snmp_community:
            community = decrypt_secret(scan.snmp_community, HKDF_INFO)
        until = time.monotonic() + SCAN_LIMIT
        found, error = asyncio.run(sweep(hosts, scan.ports, community, until))
        save_devices(scan, found, djangotime.now())
        finish(pk, ScanStatus.DONE, error, hosts_total=len(hosts), hosts_up=len(found))
    except SoftTimeLimitExceeded:
        finish(pk, ScanStatus.FAILED, "Stopped at the time limit.")
    except Exception as e:
        finish(pk, ScanStatus.FAILED, clean(e, 300) or type(e).__name__)
    finally:
        cache.delete(SCAN_LOCK)
    return "ok"


@app.task
def prune_discovery_task() -> str:
    expire_stale()
    cutoff = djangotime.now() - dt.timedelta(days=RETENTION_DAYS)
    DiscoveredDevice.objects.filter(last_seen__lt=cutoff).delete()
    Scan.objects.filter(started_at__lt=cutoff).delete()
    return "ok"

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import socket
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import AuditLog
from netmon.models import NetworkDevice
from netmon.probe import ProbeError
from remote.utils import decrypt_secret
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .models import HKDF_INFO, DeviceState, DiscoveredDevice, Scan, ScanStatus
from .serializers import DEFAULT_PORTS
from .tasks import SCAN_LOCK, prune_discovery_task, scan_network_task, sweep


def _addr(address, netmask):
    return SimpleNamespace(family=socket.AF_INET, address=address, netmask=netmask)


# loopback plus one LAN, the server is .3
NICS = {
    "lo": [_addr("127.0.0.1", "255.0.0.0")],
    "enp1s0": [_addr("192.168.178.3", "255.255.255.0")],
}

ARP_TABLE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.178.1    0x1         0x2         AA:BB:CC:DD:EE:01     *        enp1s0
192.168.178.11   0x1         0x2         aa:bb:cc:dd:ee:0b     *        enp1s0
192.168.178.12   0x1         0x2         aa:bb:cc:dd:ee:0c     *        enp1s0
192.168.178.13   0x1         0x0         00:00:00:00:00:00     *        enp1s0
"""

PINGS = {"192.168.178.1", "192.168.178.5", "192.168.178.7", "192.168.178.9"}
OPEN = {("192.168.178.1", 22), ("192.168.178.1", 443), ("192.168.178.11", 445)}


async def fake_ping(host):
    return (True, 0.3) if host in PINGS else (False, None)


async def fake_tcp(host, port):
    return (host, port) in OPEN


def fake_rdns(ip):
    if ip == "192.168.178.1":
        return ("fw.lan", [], [ip])
    raise socket.herror(1, "Unknown host")


@patch("psutil.net_if_addrs", return_value=NICS)
class TestScanRequests(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    @patch("discovery.views.scan_network_task.delay")
    def test_networks_are_validated(self, delay, _):
        for networks in (
            ["10.0.0.0/24"],  # private, not attached, not allowed
            ["8.8.8.0/24"],
            ["127.0.0.0/24"],
            ["192.168.0.0/16"],  # contains the LAN, but larger
            ["192.168.178.0/33"],
            ["router.lan"],
            ["fe80::/64"],
            ["192.168.178.001/32"],
            [],
            ["192.168.178.0/24", "10.1.0.0/20"],
        ):
            with self.subTest(networks=networks):
                r = self.client.post(
                    "/discovery/scans/", {"networks": networks}, format="json"
                )
                self.assertEqual(r.status_code, 400)
                self.assertIn("networks", r.data)

        # within the allowed set, but over 4096 addresses
        with override_settings(NETMON_ALLOWED_NETWORKS=["10.0.0.0/16"]):
            r = self.client.post(
                "/discovery/scans/", {"networks": ["10.0.0.0/19"]}, format="json"
            )
            self.assertEqual(r.status_code, 400)
            self.assertIn("4096", str(r.data["networks"]))

        for ports in (list(range(1, 18)), [0], [65536], ["ssh"]):
            with self.subTest(ports=ports):
                r = self.client.post(
                    "/discovery/scans/",
                    {"networks": ["192.168.178.0/24"], "ports": ports},
                    format="json",
                )
                self.assertEqual(r.status_code, 400)
                self.assertIn("ports", r.data)

        self.assertFalse(Scan.objects.exists())
        delay.assert_not_called()

    @patch("discovery.views.scan_network_task.delay")
    def test_start(self, delay, _):
        r = self.client.post(
            "/discovery/scans/",
            {
                "networks": ["192.168.178.5/24", "192.168.178.16/28"],
                "ports": [443, 22, 443],
                "snmp_community": "s3cret",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        scan = Scan.objects.get()
        delay.assert_called_once_with(scan.pk)
        # normalized and merged
        self.assertEqual(r.data["networks"], ["192.168.178.0/24"])
        self.assertEqual(r.data["ports"], [22, 443])
        self.assertEqual(r.data["status"], ScanStatus.QUEUED)
        self.assertEqual(r.data["started_by"], "john")
        self.assertTrue(r.data["snmp"])
        # community is stored encrypted and left out of the response
        self.assertNotIn("snmp_community", r.data)
        self.assertNotIn("s3cret", str(r.data))
        self.assertNotIn("s3cret", scan.snmp_community)
        self.assertEqual(decrypt_secret(scan.snmp_community, HKDF_INFO), "s3cret")
        self.assertNotIn("s3cret", str(self.client.get("/discovery/scans/").data))

        log = AuditLog.objects.get(action=AuditActionType.CHECK_RUN)
        self.assertEqual(log.object_type, AuditObjType.DISCOVERY)
        self.assertIn("192.168.178.0/24", log.message)
        self.assertNotIn("s3cret", str(log.after_value))

        # one at a time
        r = self.client.post(
            "/discovery/scans/", {"networks": ["192.168.178.0/24"]}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(delay.call_count, 1)

        # a scan whose worker died gets cleared instead of staying queued
        Scan.objects.filter(pk=scan.pk).update(
            started_at=djangotime.now() - dt.timedelta(hours=1)
        )
        r = self.client.post(
            "/discovery/scans/", {"networks": ["192.168.178.0/24"]}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["ports"], DEFAULT_PORTS)
        self.assertFalse(r.data["snmp"])
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertEqual(scan.snmp_community, "")

        r = self.client.get(f"/discovery/scans/{scan.pk}/")
        self.assertEqual(r.data["status"], ScanStatus.FAILED)
        self.assertEqual(self.client.get("/discovery/scans/999/").status_code, 404)

    def test_lost_scans_expire(self, _):
        lost = Scan.objects.create(
            networks=["192.168.178.0/24"],
            status=ScanStatus.RUNNING,
            snmp=True,
            snmp_community=_encrypted("s3cret"),
        )
        fresh = Scan.objects.create(networks=["192.168.178.0/24"])
        Scan.objects.filter(pk=lost.pk).update(
            started_at=djangotime.now() - dt.timedelta(hours=1)
        )
        # whoever looks first, the daily prune at the latest
        r = self.client.get(f"/discovery/scans/{lost.pk}/")
        self.assertEqual(r.data["status"], ScanStatus.FAILED)
        lost.refresh_from_db()
        self.assertEqual((lost.snmp_community, lost.error), ("", "Did not finish."))
        self.assertEqual(Scan.objects.get(pk=fresh.pk).status, ScanStatus.QUEUED)

        Scan.objects.filter(pk=lost.pk).update(
            status=ScanStatus.RUNNING, snmp_community=_encrypted("s3cret")
        )
        prune_discovery_task()
        lost.refresh_from_db()
        self.assertEqual((lost.status, lost.snmp_community), (ScanStatus.FAILED, ""))

    def test_networks(self, _):
        with override_settings(NETMON_ALLOWED_NETWORKS=["10.20.0.0/16"]):
            r = self.client.get("/discovery/networks/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data["networks"],
            [
                {"network": "10.20.0.0/16", "attached": False, "addresses": 65536},
                {"network": "192.168.178.0/24", "attached": True, "addresses": 256},
            ],
        )
        self.assertEqual(r.data["max_addresses"], 4096)
        self.assertEqual(r.data["max_ports"], 16)
        self.assertEqual(r.data["default_ports"], DEFAULT_PORTS)


@patch("psutil.net_if_addrs", return_value=NICS)
@patch("socket.gethostbyaddr", side_effect=fake_rdns)
@patch("discovery.tasks.tcp_open", side_effect=fake_tcp)
@patch("discovery.tasks.ping", side_effect=fake_ping)
class TestScanTask(ULRMMTestCase):
    def setUp(self):
        self.site = baker.make("clients.Site")
        self.arp = tempfile.NamedTemporaryFile("w", suffix=".arp")
        self.arp.write(ARP_TABLE)
        self.arp.flush()
        self.addCleanup(self.arp.close)

    def scan(self, **kwargs):
        return Scan.objects.create(
            networks=["192.168.178.0/28"], ports=[22, 443, 445], **kwargs
        )

    def run_scan(self, scan):
        with patch("discovery.tasks.ARP", self.arp.name):
            self.assertEqual(scan_network_task(scan.pk), "ok")
        scan.refresh_from_db()
        return scan

    @patch("discovery.tasks.snmp_poll", new_callable=AsyncMock)
    def test_scan(self, snmp, ping, tcp, rdns, _):
        linux = baker.make_recipe(
            "agents.agent",
            plat="linux",
            wmi_detail={"local_ips": ["192.168.178.5/24", "fe80::1/64"]},
        )
        win = baker.make_recipe(
            "agents.agent",
            plat="windows",
            wmi_detail={
                "network_config": [[{"IPAddress": ["192.168.178.7", "fe80::2"]}]]
            },
        )
        baker.make_recipe("agents.agent", plat="windows", wmi_detail={})
        nd = baker.make("netmon.NetworkDevice", site=self.site, host="192.168.178.9")
        old = djangotime.now() - dt.timedelta(days=3)
        ignored = baker.make(
            "discovery.DiscoveredDevice",
            ip="192.168.178.1",
            hostname="old-name",
            state=DeviceState.IGNORED,
            note="the firewall",
            last_seen=old,
        )
        DiscoveredDevice.objects.filter(pk=ignored.pk).update(first_seen=old)
        baker.make("discovery.DiscoveredDevice", ip="192.168.178.2", last_seen=old)

        scan = self.run_scan(self.scan())
        self.assertEqual(scan.status, ScanStatus.DONE, scan.error)
        self.assertEqual(scan.error, "")
        # .1 to .14 without the server's own .3
        self.assertEqual(scan.hosts_total, 13)
        self.assertEqual(scan.hosts_up, 5)
        self.assertIsNotNone(scan.finished_at)
        pinged = {c.args[0] for c in ping.call_args_list}
        self.assertEqual(len(pinged), 13)
        self.assertNotIn("192.168.178.3", pinged)
        self.assertNotIn("192.168.178.0", pinged)
        # ports are probed on hosts that answered. SNMP needs a community
        self.assertEqual(
            {c.args[0] for c in tcp.call_args_list},
            PINGS | {"192.168.178.11", "192.168.178.12"},
        )
        snmp.assert_not_called()

        devices = {d.ip: d for d in DiscoveredDevice.objects.all()}
        self.assertEqual(
            set(devices),
            PINGS | {"192.168.178.2", "192.168.178.11"},
        )
        fw = devices["192.168.178.1"]
        self.assertEqual(fw.state, DeviceState.IGNORED)
        self.assertEqual(fw.note, "the firewall")
        self.assertEqual(fw.open_ports, [22, 443])
        self.assertEqual(fw.hostname, "fw.lan")
        self.assertEqual(fw.mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(fw.last_scan, scan)
        self.assertGreater(fw.last_seen, old)
        self.assertEqual(fw.first_seen, old)

        self.assertEqual(devices["192.168.178.5"].state, DeviceState.AGENT)
        self.assertEqual(devices["192.168.178.7"].state, DeviceState.AGENT)
        self.assertEqual(devices["192.168.178.9"].state, DeviceState.NETMON)
        matches = {ip: (d.agent_id, d.netmon_device_id) for ip, d in devices.items()}
        self.assertEqual(
            matches,
            {
                "192.168.178.1": (None, None),
                "192.168.178.2": (None, None),
                "192.168.178.5": (linux.pk, None),
                "192.168.178.7": (win.pk, None),
                "192.168.178.9": (None, nd.pk),
                "192.168.178.11": (None, None),
            },
        )
        quiet = devices["192.168.178.9"]
        self.assertEqual((quiet.open_ports, quiet.hostname, quiet.mac), ([], "", ""))
        # drops ping, found through ARP and an open port
        arp_only = devices["192.168.178.11"]
        self.assertEqual(arp_only.state, DeviceState.NEW)
        self.assertEqual(arp_only.open_ports, [445])
        self.assertEqual(arp_only.mac, "aa:bb:cc:dd:ee:0b")
        self.assertEqual(devices["192.168.178.2"].last_seen, old)

        # a rescan keeps a name and MAC it cannot see this time, and follows
        # the matches: the agent moved to .9, the other one is gone, the
        # ignored .1 got a netmon device
        rdns.side_effect = socket.herror(1, "Unknown host")
        linux.wmi_detail = {"local_ips": ["192.168.178.9/24"]}
        linux.save(update_fields=["wmi_detail"])
        win.delete()
        nd1 = baker.make("netmon.NetworkDevice", site=self.site, host="192.168.178.1")
        with patch("discovery.tasks.ARP", "/nonexistent/arp"):
            self.assertEqual(scan_network_task(self.scan().pk), "ok")
        fw.refresh_from_db()
        self.assertEqual((fw.hostname, fw.mac), ("fw.lan", "aa:bb:cc:dd:ee:01"))
        rows = DiscoveredDevice.objects.filter(ip__in=PINGS)
        self.assertEqual(
            {d.ip: (d.state, d.agent_id, d.netmon_device_id) for d in rows},
            {
                "192.168.178.1": (DeviceState.IGNORED, None, nd1.pk),
                "192.168.178.5": (DeviceState.NEW, None, None),
                "192.168.178.7": (DeviceState.NEW, None, None),
                "192.168.178.9": (DeviceState.AGENT, linux.pk, nd.pk),
            },
        )
        # without the ARP table .11 is not seen this time
        self.assertEqual(
            DiscoveredDevice.objects.get(ip="192.168.178.11").last_scan, scan
        )

    @patch("discovery.tasks.snmp_poll", new_callable=AsyncMock)
    def test_snmp(self, snmp, *_):
        snmp.return_value = {"sys_name": "sw1", "sys_uptime": 5, "sys_descr": "Switch"}
        scan = self.scan(snmp=True, snmp_community=_encrypted("s3cret"))
        scan = self.run_scan(scan)
        self.assertEqual(scan.status, ScanStatus.DONE)
        self.assertEqual(scan.snmp_community, "")
        self.assertEqual(
            snmp.await_args.args[1:], (161, "v2c", {"community": "s3cret"})
        )
        self.assertEqual(
            DiscoveredDevice.objects.get(ip="192.168.178.5").snmp,
            {"sysName": "sw1", "sysDescr": "Switch"},
        )

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_one_scan_at_a_time(self, ping, *_):
        cache.add(SCAN_LOCK, 1, 60)
        try:
            scan = self.scan(snmp=True, snmp_community=_encrypted("s3cret"))
            with patch("discovery.tasks.ARP", self.arp.name):
                self.assertEqual(scan_network_task(scan.pk), "already running")
        finally:
            cache.delete(SCAN_LOCK)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertEqual(scan.snmp_community, "")
        ping.assert_not_called()

        # the lock is released after a run
        scan = self.run_scan(self.scan())
        self.assertEqual(scan.status, ScanStatus.DONE)
        self.assertIsNone(cache.get(SCAN_LOCK))
        # a finished scan is left alone
        self.assertEqual(scan_network_task(scan.pk), "not queued")

    def test_ping_failing_fails_the_scan(self, ping, *_):
        ping.side_effect = ProbeError("/usr/bin/ping exited with 2")
        scan = self.run_scan(self.scan())
        self.assertEqual(scan.status, ScanStatus.FAILED)
        self.assertIn("exited with 2", scan.error)
        self.assertFalse(DiscoveredDevice.objects.exists())

    def test_allowed_networks_checked_again(self, ping, *_):
        scan = self.run_scan(Scan.objects.create(networks=["10.0.0.0/30"], ports=[22]))
        self.assertEqual(scan.status, ScanStatus.DONE)
        self.assertEqual(scan.hosts_total, 0)
        ping.assert_not_called()

    def test_wall_clock_cap(self, *_):
        found, error = asyncio.run(
            sweep(["192.168.178.1"], [22], "", time.monotonic() - 1)
        )
        self.assertEqual(found, {})
        self.assertIn("1 addresses were not finished", error)

    def test_prune(self, *_):
        now = djangotime.now()
        old_scan = self.scan()
        Scan.objects.filter(pk=old_scan.pk).update(
            started_at=now - dt.timedelta(days=91)
        )
        new_scan = self.scan()
        gone = baker.make(
            "discovery.DiscoveredDevice",
            ip="192.168.178.20",
            last_seen=now - dt.timedelta(days=91),
        )
        kept = baker.make(
            "discovery.DiscoveredDevice",
            ip="192.168.178.21",
            last_seen=now - dt.timedelta(days=10),
            state=DeviceState.IGNORED,
        )
        self.assertEqual(prune_discovery_task(), "ok")
        self.assertFalse(DiscoveredDevice.objects.filter(pk=gone.pk).exists())
        self.assertTrue(DiscoveredDevice.objects.filter(pk=kept.pk).exists())
        self.assertEqual(list(Scan.objects.values_list("pk", flat=True)), [new_scan.pk])


def _encrypted(value):
    from remote.utils import encrypt_secret

    return encrypt_secret(value, HKDF_INFO)


@patch("psutil.net_if_addrs", return_value=NICS)
class TestDeviceViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.other_site = baker.make("clients.Site")
        now = djangotime.now()
        self.fw = baker.make(
            "discovery.DiscoveredDevice",
            ip="192.168.178.1",
            open_ports=[22, 443],
            last_seen=now,
        )
        self.pc = baker.make(
            "discovery.DiscoveredDevice", ip="192.168.178.20", last_seen=now
        )
        self.remote = baker.make(
            "discovery.DiscoveredDevice",
            ip="10.20.0.5",
            last_seen=now,
            state=DeviceState.AGENT,
        )

    def test_list(self, _):
        agent = baker.make_recipe("agents.agent", display_name="Front desk")
        nd = baker.make("netmon.NetworkDevice", site=self.site, host="192.168.178.1")
        DiscoveredDevice.objects.filter(pk=self.fw.pk).update(
            agent=agent, netmon_device=nd
        )
        r = self.client.get("/discovery/devices/")
        self.assertEqual(
            [d["ip"] for d in r.data], ["10.20.0.5", "192.168.178.1", "192.168.178.20"]
        )
        fw, pc = r.data[1], r.data[2]
        self.assertEqual(
            (fw["agent_id"], fw["agent_hostname"], fw["netmon_id"]),
            (agent.agent_id, "Front desk", nd.pk),
        )
        self.assertEqual(
            (pc["agent_id"], pc["agent_hostname"], pc["netmon_id"]), (None,) * 3
        )
        self.assertNotIn("agent", fw)
        self.assertNotIn("netmon_device", fw)
        r = self.client.get("/discovery/devices/?state=new&network=192.168.178.0/24")
        self.assertEqual([d["ip"] for d in r.data], ["192.168.178.1", "192.168.178.20"])
        r = self.client.get("/discovery/devices/?network=10.20.0.0/16")
        self.assertEqual([d["ip"] for d in r.data], ["10.20.0.5"])
        self.assertEqual(
            self.client.get("/discovery/devices/?state=bogus").status_code, 400
        )
        self.assertEqual(
            self.client.get("/discovery/devices/?network=lan").status_code, 400
        )

    def test_matched_agent_only_within_scope(self, _):
        mine = baker.make_recipe("agents.agent", site=self.site, display_name="Mine")
        theirs = baker.make_recipe(
            "agents.agent", site=self.other_site, display_name="Theirs"
        )
        DiscoveredDevice.objects.filter(pk=self.fw.pk).update(
            agent=mine, state=DeviceState.AGENT
        )
        DiscoveredDevice.objects.filter(pk=self.pc.pk).update(
            agent=theirs, state=DeviceState.AGENT
        )
        user = self.create_user_with_roles(["can_run_network_discovery"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)

        r = self.client.get("/discovery/devices/")
        rows = {d["ip"]: d for d in r.data}
        fw, pc = rows["192.168.178.1"], rows["192.168.178.20"]
        self.assertEqual(
            (fw["agent_id"], fw["agent_hostname"]), (mine.agent_id, "Mine")
        )
        self.assertEqual(
            (pc["state"], pc["agent_id"], pc["agent_hostname"]),
            (DeviceState.AGENT, None, None),
        )
        self.assertNotIn(theirs.agent_id, str(r.data))
        self.assertNotIn("Theirs", str(r.data))
        r = self.client.post(f"/discovery/devices/{self.pc.pk}/ignore/")
        self.assertEqual((r.data["state"], r.data["agent_id"]), ("ignored", None))

    def test_ignore_toggles(self, _):
        agent = baker.make_recipe(
            "agents.agent",
            plat="linux",
            wmi_detail={"local_ips": ["192.168.178.20/24"]},
        )
        url = f"/discovery/devices/{self.pc.pk}/ignore/"
        r = self.client.post(url, {"note": "printer\x00 in the hall"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["state"], DeviceState.IGNORED)
        self.assertEqual(r.data["note"], "printer in the hall")
        # back to what it matches, the note stays
        r = self.client.post(url)
        self.assertEqual(r.data["state"], DeviceState.AGENT)
        self.assertEqual(
            (r.data["agent_id"], r.data["agent_hostname"]),
            (agent.agent_id, "DESKTOP-TEST123"),
        )
        self.assertEqual(r.data["note"], "printer in the hall")
        logs = AuditLog.objects.filter(
            action=AuditActionType.MODIFY, object_type=AuditObjType.DISCOVERY
        ).order_by("pk")
        self.assertEqual(
            [log.message for log in logs],
            [
                "john ignored discovered device 192.168.178.20",
                "john stopped ignoring discovered device 192.168.178.20",
            ],
        )

    def test_add_to_netmon(self, _):
        url = f"/discovery/devices/{self.fw.pk}/netmon/"
        r = self.client.post(url, {"site": self.site.pk, "name": "fw"}, format="json")
        self.assertEqual(r.status_code, 200)
        device = NetworkDevice.objects.get(pk=r.data["id"])
        self.assertEqual(
            (device.site, device.name, device.host, device.ping, device.tcp_ports),
            (self.site, "fw", "192.168.178.1", True, [22, 443]),
        )
        self.fw.refresh_from_db()
        self.assertEqual(self.fw.state, DeviceState.NETMON)
        self.assertEqual(self.fw.netmon_device, device)
        log = AuditLog.objects.get(
            action=AuditActionType.ADD, object_type=AuditObjType.NETWORK_DEVICE
        )
        self.assertIn("192.168.178.1", log.message)

        # host stays the discovered address. netmon checks the other fields
        r = self.client.post(
            f"/discovery/devices/{self.pc.pk}/netmon/",
            {"site": self.site.pk, "name": "pc", "host": "192.168.178.50"},
            format="json",
        )
        self.assertEqual(NetworkDevice.objects.get(name="pc").host, "192.168.178.20")
        r = self.client.post(
            f"/discovery/devices/{self.remote.pk}/netmon/",
            {"site": self.site.pk, "name": "far"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("host", r.data)
        r = self.client.post(url, {"name": "no site"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(url, ["x"], format="json")
        self.assertEqual(r.status_code, 400)

    @patch("discovery.views.scan_network_task.delay")
    def test_permissions(self, delay, _):
        endpoints = (
            ("get", "/discovery/scans/", {}),
            ("post", "/discovery/scans/", {"networks": ["192.168.178.0/24"]}),
            ("get", "/discovery/scans/1/", {}),
            ("get", "/discovery/devices/", {}),
            ("post", f"/discovery/devices/{self.pc.pk}/ignore/", {}),
            (
                "post",
                f"/discovery/devices/{self.fw.pk}/netmon/",
                {"site": self.site.pk, "name": "fw"},
            ),
            ("get", "/discovery/networks/", {}),
        )
        for method, url, _ in endpoints:
            with self.subTest(method=method, url=url):
                self.check_not_authenticated(method, url)

        user = self.create_user_with_roles(
            ["can_list_network_devices", "can_manage_network_devices"]
        )
        self.client.force_authenticate(user=user)
        for method, url, data in endpoints:
            with self.subTest(method=method, url=url):
                self.check_not_authorized(method, url, data)
        delay.assert_not_called()
        self.pc.refresh_from_db()
        self.assertEqual(self.pc.state, DeviceState.NEW)

        # the discovery flag does not cover adding network devices
        user = self.create_user_with_roles(["can_run_network_discovery"])
        self.client.force_authenticate(user=user)
        for method, url, data in endpoints[:-2] + endpoints[-1:]:
            with self.subTest(method=method, url=url):
                self.check_authorized(method, url, data)
        self.check_not_authorized(*endpoints[-2][:2], endpoints[-2][2])
        self.assertFalse(NetworkDevice.objects.exists())

        # and only into a site the user may see
        user.role.can_manage_network_devices = True
        user.role.save()
        user.role.can_view_sites.set([self.other_site])
        self.check_not_authorized(*endpoints[-2][:2], endpoints[-2][2])
        self.assertFalse(NetworkDevice.objects.exists())
        user.role.can_view_sites.set([self.site])
        r = self.client.post(*endpoints[-2][1:], format="json")
        self.assertEqual(r.status_code, 200)

        Scan.objects.all().delete()
        for method, url, data in endpoints:
            with self.subTest(method=method, url=url, superuser=True):
                self.check_authorized_superuser(method, url, data)

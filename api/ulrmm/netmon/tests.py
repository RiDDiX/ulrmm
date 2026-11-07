# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import json
import socket
import ssl
import struct
import tempfile
from ipaddress import IPv4Address, IPv4Network
from types import SimpleNamespace
from unittest.mock import AsyncMock, PropertyMock, patch

from cryptography.fernet import InvalidToken
from django.test import override_settings
from model_bakery import baker

from alerts.models import Alert
from logs.models import AuditLog
from remote.utils import decrypt_secret
from ulrmm.constants import AlertSeverity, AlertTemplateActionType, AlertType
from ulrmm.constants import AuditActionType, AuditObjType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from . import probe
from .models import HKDF_INFO, NetworkDevice, probe_scope
from .tasks import poll_network_devices, record

base_url = "/netmon/devices"

LAN = IPv4Network("192.168.178.0/24")
OWN = {IPv4Address("192.168.178.3"), IPv4Address("127.0.0.1")}


def _addr(address, netmask):
    return SimpleNamespace(family=socket.AF_INET, address=address, netmask=netmask)


# the server as on prod: loopback plus one LAN
NICS = {
    "lo": [_addr("127.0.0.1", "255.0.0.0")],
    "enp1s0": [_addr("192.168.178.3", "255.255.255.0")],
}


def up_result(**kwargs):
    result = {"ping": True, "rtt_ms": 0.3, "ports": {}, "snmp": None, "error": ""}
    result.update(kwargs)
    result["status"] = kwargs.get("status", "up")
    return result


HTTPS = {
    "type": "http",
    "scheme": "https",
    "port": 443,
    "path": "/",
    "method": "GET",
    "server_name": "",
    "status": "200-399",
    "allow_self_signed": False,
    "warn_days": 21,
    "error_days": 7,
}
DNS = {"type": "dns", "query": "rd.riddix.de", "record": "A", "expect": []}


class TestAddressScope(ULRMMTestCase):
    def test_address_error(self):
        nets = {LAN}
        for host in (
            "127.0.0.1",
            "127.1.2.3",
            "192.168.178.3",  # the server itself
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "240.0.0.1",
            "192.168.178.0",  # network
            "192.168.178.255",  # broadcast
            "8.8.8.8",
            "10.0.0.1",  # private, but not attached
            "router.lan",
            "fe80::1",
            "192.168.178.01",
            "",
        ):
            with self.subTest(host=host):
                self.assertTrue(probe.address_error(host, nets, OWN))

        self.assertEqual(probe.address_error("192.168.178.1", nets, OWN), "")
        self.assertEqual(probe.address_error("192.168.178.254", nets, OWN), "")

    @patch("psutil.net_if_addrs", return_value=NICS)
    def test_probe_scope(self, _):
        nets, own = probe_scope()
        # loopback is attached but never allowed
        self.assertEqual(nets, {LAN})
        self.assertEqual(own, OWN)

        with override_settings(NETMON_ALLOWED_NETWORKS=["10.20.0.0/16"]):
            nets, _ = probe_scope()
            self.assertEqual(nets, {LAN, IPv4Network("10.20.0.0/16")})
            self.assertEqual(probe.address_error("10.20.3.4", nets, own), "")
            # widening never opens the server's own addresses
            self.assertTrue(
                probe.address_error(
                    "127.0.0.1", nets | {IPv4Network("127.0.0.0/8")}, own
                )
            )


class TestProbe(ULRMMTestCase):
    def _ping(self, rc, out=b""):
        proc = SimpleNamespace(returncode=rc)
        proc.communicate = AsyncMock(return_value=(out, b""))
        return patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc))

    def test_ping(self):
        out = b"rtt min/avg/max/mdev = 0.152/0.310/0.401/0.050 ms\n"
        with self._ping(0, out) as exec_:
            self.assertEqual(asyncio.run(probe.ping("192.168.178.1")), (True, 0.31))
        # fixed binary, fixed argv, no shell, the address as its own argument
        args = exec_.call_args.args
        self.assertEqual(args[0], "/usr/bin/ping")
        self.assertEqual(args[1:], probe.PING_ARGS + ("192.168.178.1",))
        self.assertNotIn("shell", exec_.call_args.kwargs)

        with self._ping(1):
            self.assertEqual(asyncio.run(probe.ping("192.168.178.1")), (False, None))
        # 2 is ping failing, not the device being down
        with self._ping(2), self.assertRaises(probe.ProbeError):
            asyncio.run(probe.ping("192.168.178.1"))
        with patch(
            "asyncio.create_subprocess_exec", side_effect=PermissionError(1, "denied")
        ):
            with self.assertRaises(probe.ProbeError):
                asyncio.run(probe.ping("192.168.178.1"))

    def test_status(self):
        cases = [
            # ping, ports, snmp, error -> status
            (True, {}, None, "", "up"),
            (False, {"443": True}, None, "", "down"),
            (True, {"443": True, "53": False}, None, "", "degraded"),
            (True, {}, {"error": "timeout"}, "", "degraded"),
            (None, {"443": False}, {"error": "timeout"}, "", "down"),
            (None, {"443": False}, {"sys_name": "fw"}, "", "degraded"),
            (None, {"443": True}, None, "", "up"),
            (None, {}, None, "ping exited with 2", "error"),
        ]
        for ping, ports, snmp, error, want in cases:
            with self.subTest(ping=ping, ports=ports, snmp=snmp):
                target = {"ping": ping is not None, "snmp": bool(snmp)}
                result = {"ping": ping, "ports": ports, "snmp": snmp, "error": error}
                self.assertEqual(probe.status_of(target, result), want)

    @patch("netmon.probe.tcp_open", new_callable=AsyncMock)
    @patch("netmon.probe.ping", new_callable=AsyncMock)
    def test_probe(self, ping, tcp_open):
        ping.return_value = (True, 0.5)
        tcp_open.side_effect = lambda host, port: port == 443
        target = {
            "host": "192.168.178.1",
            "ping": True,
            "tcp_ports": [53, 443],
            "snmp": None,
        }
        r = asyncio.run(probe.probe(target))
        self.assertEqual(r["ports"], {"53": False, "443": True})
        self.assertEqual(r["status"], "degraded")

        ping.side_effect = probe.ProbeError("/usr/bin/ping exited with 2")
        r = asyncio.run(probe.probe(target))
        self.assertEqual(r["status"], "error")
        self.assertIn("exited with 2", r["error"])

    def test_tcp_open(self):
        async def run():
            server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            is_open = await probe.tcp_open("127.0.0.1", port)
            server.close()
            await server.wait_closed()
            return is_open, await probe.tcp_open("127.0.0.1", port)

        self.assertEqual(asyncio.run(run()), (True, False))

    def test_probe_all_deadline(self):
        async def slow(target):
            await asyncio.sleep(0 if target == "fast" else 5)
            return {"status": "up"}

        with patch("netmon.probe.probe", side_effect=slow):
            self.assertEqual(
                asyncio.run(probe.probe_all(["fast", "slow"], deadline=0.2)),
                [{"status": "up"}, None],
            )

    def test_if_counts(self):
        binds = [
            ("1.3.6.1.2.1.2.2.1.7.1", 1),
            ("1.3.6.1.2.1.2.2.1.8.1", 1),
            ("1.3.6.1.2.1.2.2.1.7.2", 1),
            ("1.3.6.1.2.1.2.2.1.8.2", 2),
            # admin down does not count
            ("1.3.6.1.2.1.2.2.1.7.3", 2),
            ("1.3.6.1.2.1.2.2.1.8.3", 2),
            # past the table
            ("1.3.6.1.2.1.2.2.1.9.1", 5),
        ]
        self.assertEqual(probe.if_counts(binds), (1, 1))


class TestSnmp(ULRMMTestCase):
    """pysnmp against a responder in this process. This also catches a
    cryptography upgrade that drops the CFB mode AES-128 needs."""

    PORT = 16163

    async def _poll(self, **kwargs):
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.entity import config, engine
        from pysnmp.entity.rfc3413 import cmdrsp, context

        eng = engine.SnmpEngine()
        config.add_transport(
            eng,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode(("127.0.0.1", self.PORT)),
        )
        config.add_v1_system(eng, "area", "c0mmunity")
        config.add_vacm_user(eng, 2, "area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1))
        config.add_v3_user(
            eng,
            "monitor",
            config.USM_AUTH_HMAC192_SHA256,
            "auth-key-123",
            config.USM_PRIV_CFB128_AES,
            "priv-key-123",
        )
        config.add_vacm_user(eng, 3, "monitor", "authPriv", (1, 3, 6, 1, 2, 1))
        ctx = context.SnmpContext(eng)
        cmdrsp.GetCommandResponder(eng, ctx)
        cmdrsp.BulkCommandResponder(eng, ctx)
        try:
            return await probe.snmp_poll("127.0.0.1", self.PORT, **kwargs)
        finally:
            eng.close_dispatcher()

    @patch("netmon.probe.SNMP_RETRIES", 0)
    @patch("netmon.probe.SNMP_TIMEOUT", 0.5)
    def test_round_trip(self):
        r = asyncio.run(self._poll(version="v2c", secret={"community": "c0mmunity"}))
        self.assertIn("PySNMP", r["sys_descr"])
        self.assertIsInstance(r["sys_uptime"], int)
        # the GETBULK went through, the responder has no interface table
        self.assertEqual((r["if_up"], r["if_down"]), (0, 0))

        v3 = {"auth_key": "auth-key-123", "priv_key": "priv-key-123"}
        r = asyncio.run(self._poll(version="v3", user="monitor", secret=v3))
        self.assertIn("PySNMP", r["sys_descr"])

        # the responder has no Printer-MIB
        r = asyncio.run(
            self._poll(version="v2c", secret={"community": "c0mmunity"}, printer=True)
        )
        self.assertEqual(r["printer"], {"supplies": [], "pages": None})

        with self.assertRaises(probe.ProbeError):
            asyncio.run(self._poll(version="v2c", secret={"community": "wrong"}))
        bad = {"auth_key": "wrong-auth-key", "priv_key": "priv-key-123"}
        with self.assertRaises(probe.ProbeError) as e:
            asyncio.run(self._poll(version="v3", user="monitor", secret=bad))
        self.assertNotIn("wrong-auth-key", str(e.exception))


@patch("psutil.net_if_addrs", return_value=NICS)
class TestNetworkDeviceViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.other_site = baker.make("clients.Site")

    def device(self, site=None, **kwargs):
        return baker.make(
            "netmon.NetworkDevice",
            site=site or self.site,
            host="192.168.178.1",
            **kwargs,
        )

    def test_add_rejects_addresses(self, _):
        data = {"site": self.site.pk, "name": "fw", "ping": True}
        for host in (
            "127.0.0.1",
            "192.168.178.3",
            "169.254.0.1",
            "192.168.178.255",
            "1.1.1.1",
            "fw.lan",
        ):
            with self.subTest(host=host):
                r = self.client.post(
                    f"{base_url}/", {**data, "host": host}, format="json"
                )
                self.assertEqual(r.status_code, 400)
        self.assertFalse(NetworkDevice.objects.exists())

        r = self.client.post(
            f"{base_url}/",
            {**data, "host": "192.168.178.1", "tcp_ports": [443, 53]},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(NetworkDevice.objects.get().tcp_ports, [53, 443])

    def test_limits(self, _):
        data = {"site": self.site.pk, "name": "fw", "host": "192.168.178.1"}
        for extra in (
            {"interval": 30},
            {"tcp_ports": list(range(1, 10))},
            {"tcp_ports": [0]},
            {"tcp_ports": [443, 443]},
            {"ping": False},  # nothing left to check
            {"snmp_version": "v1"},
            {
                "snmp_version": "v3",
                "snmp_v3_user": "m",
                "snmp_auth_key": "a" * 8,
                "snmp_priv_key": "p" * 8,
                "snmp_v3_auth_proto": "md5",
            },
            {
                "snmp_version": "v3",
                "snmp_v3_user": "m",
                "snmp_auth_key": "short",
                "snmp_priv_key": "p" * 8,
            },
            {"snmp_version": "v2c"},  # no community
        ):
            with self.subTest(extra=extra):
                r = self.client.post(f"{base_url}/", {**data, **extra}, format="json")
                self.assertEqual(r.status_code, 400)

    def test_secret_is_write_only(self, _):
        data = {
            "site": self.site.pk,
            "name": "fw",
            "host": "192.168.178.1",
            "snmp_version": "v2c",
            "snmp_community": "s3cret-community",
        }
        r = self.client.post(f"{base_url}/", data, format="json")
        self.assertEqual(r.status_code, 200)
        device = NetworkDevice.objects.get()
        self.assertNotIn("s3cret", device.snmp_secret)
        self.assertEqual(device.secret(), {"community": "s3cret-community"})
        # its own key, the RustDesk one does not open it
        with self.assertRaises(InvalidToken):
            decrypt_secret(device.snmp_secret)
        self.assertEqual(
            json.loads(decrypt_secret(device.snmp_secret, HKDF_INFO)),
            {"community": "s3cret-community"},
        )

        for r in (
            self.client.get(f"{base_url}/"),
            self.client.get(f"{base_url}/{device.pk}/"),
        ):
            body = json.dumps(r.data)
            self.assertNotIn("s3cret", body)
            self.assertNotIn('snmp_secret"', body)
            self.assertNotIn(device.snmp_secret, body)
        self.assertTrue(r.data["snmp_secret_set"])

        # an edit without the secret keeps it, token and all
        token = device.snmp_secret
        r = self.client.put(
            f"{base_url}/{device.pk}/",
            {
                "name": "fw1",
                "host": "192.168.178.1",
                "snmp_port": 161,
                "snmp_community": "",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        device.refresh_from_db()
        self.assertEqual(device.snmp_secret, token)

        # it is never sent to another address or port without entering it again
        for change in ({"host": "192.168.178.50"}, {"snmp_port": 1161}):
            with self.subTest(change=change):
                r = self.client.put(f"{base_url}/{device.pk}/", change, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertIn("snmp_community", r.data)
        device.refresh_from_db()
        self.assertEqual((device.host, device.snmp_port), ("192.168.178.1", 161))
        self.assertEqual(device.snmp_secret, token)
        r = self.client.put(
            f"{base_url}/{device.pk}/",
            {"host": "192.168.178.50", "snmp_community": "new-community"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        device.refresh_from_db()
        self.assertEqual(device.secret(), {"community": "new-community"})

        # a new one replaces it, switching to v3 drops the community
        r = self.client.put(
            f"{base_url}/{device.pk}/",
            {
                "snmp_version": "v3",
                "snmp_v3_user": "monitor",
                "snmp_auth_key": "auth-key-1",
                "snmp_priv_key": "priv-key-1",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        device.refresh_from_db()
        self.assertEqual(
            device.secret(), {"auth_key": "auth-key-1", "priv_key": "priv-key-1"}
        )
        # the v3 keys belong to their user as well
        r = self.client.put(
            f"{base_url}/{device.pk}/", {"snmp_v3_user": "other"}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("snmp_auth_key", r.data)

        r = self.client.put(
            f"{base_url}/{device.pk}/", {"snmp_version": "off"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        device.refresh_from_db()
        self.assertEqual(device.snmp_secret, "")

        # the audit log records the changes, never a secret
        logs = AuditLog.objects.filter(object_type=AuditObjType.NETWORK_DEVICE)
        self.assertGreaterEqual(logs.count(), 4)
        dump = json.dumps(list(logs.values("before_value", "after_value", "message")))
        for secret in (
            "s3cret-community",
            "new-community",
            "auth-key-1",
            "priv-key-1",
            token,
        ):
            self.assertNotIn(secret, dump)
        self.assertIn("hmac:", dump)
        for volatile in ("last_result", "fail_count"):
            self.assertNotIn(volatile, dump)

    def test_secret_clear_and_unreadable(self, _):
        data = {
            "site": self.site.pk,
            "name": "fw",
            "host": "192.168.178.1",
            "snmp_version": "v2c",
            "snmp_community": "public1",
        }
        self.client.post(f"{base_url}/", data, format="json")
        device = NetworkDevice.objects.get()
        r = self.client.put(
            f"{base_url}/{device.pk}/", {"snmp_secret_clear": True}, format="json"
        )
        self.assertEqual(r.status_code, 400)  # v2c without a community

        # a token from before a SECRET_KEY change has to be entered again
        NetworkDevice.objects.filter(pk=device.pk).update(snmp_secret="gAAAAinvalid")
        device.refresh_from_db()
        with self.assertRaises(ValueError) as e:
            device.probe_target({LAN}, OWN)
        self.assertIn("entered again", str(e.exception))

    def test_move_to_site_needs_both_sites(self, _):
        device = self.device()
        user = self.create_user_with_roles(
            ["can_list_network_devices", "can_manage_network_devices"]
        )
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)

        r = self.client.put(
            f"{base_url}/{device.pk}/", {"site": self.other_site.pk}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        r = self.client.post(
            f"{base_url}/",
            {"site": self.other_site.pk, "name": "x", "host": "192.168.178.2"},
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        device.refresh_from_db()
        self.assertEqual(device.site, self.site)
        self.assertFalse(NetworkDevice.objects.filter(name="x").exists())

    @patch("netmon.views.probe", new_callable=AsyncMock)
    def test_permissions(self, probe_, _):
        mine = self.device()
        theirs = self.device(site=self.other_site)
        probe_.return_value = up_result()

        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("get", f"{base_url}/")
        self.check_not_authorized("get", f"{base_url}/{mine.pk}/")
        self.check_not_authorized("post", f"{base_url}/{mine.pk}/test/")

        user.role.can_list_network_devices = True
        user.role.save()
        r = self.check_authorized("get", f"{base_url}/")
        self.assertEqual(len(r.data), 2)
        # listing is not managing
        self.check_not_authorized("put", f"{base_url}/{mine.pk}/", {"name": "x"})
        self.check_not_authorized("delete", f"{base_url}/{mine.pk}/")
        self.check_not_authorized("post", f"{base_url}/{mine.pk}/test/")

        user.role.can_manage_network_devices = True
        user.role.save()
        user.role.can_view_sites.set([self.site])
        r = self.client.get(f"{base_url}/")
        self.assertEqual([d["id"] for d in r.data], [mine.pk])
        for method, url in (
            ("get", f"{base_url}/{theirs.pk}/"),
            ("put", f"{base_url}/{theirs.pk}/"),
            ("delete", f"{base_url}/{theirs.pk}/"),
            ("post", f"{base_url}/{theirs.pk}/test/"),
        ):
            with self.subTest(method=method, url=url):
                self.check_not_authorized(method, url, {"name": "x"})
        self.check_authorized("get", f"{base_url}/{mine.pk}/")

        user.role.can_view_sites.clear()
        user.role.can_view_clients.set([self.other_site.client])
        r = self.client.get(f"{base_url}/")
        self.assertEqual([d["id"] for d in r.data], [theirs.pk])
        self.assertTrue(NetworkDevice.objects.filter(pk=theirs.pk).exists())

        self.check_authorized_superuser("get", f"{base_url}/")

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("netmon.views.probe", new_callable=AsyncMock)
    def test_test_now(self, probe_, _):
        device = self.device(tcp_ports=[443])
        probe_.return_value = up_result(ports={"443": True})
        r = self.client.post(f"{base_url}/{device.pk}/test/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["status"], "up")
        target = probe_.call_args.args[0]
        self.assertEqual(target["host"], "192.168.178.1")
        self.assertEqual(target["tcp_ports"], [443])
        log = AuditLog.objects.get(object_type=AuditObjType.NETWORK_DEVICE)
        self.assertEqual(log.action, AuditActionType.CHECK_RUN)
        # the test shows a result, it does not change state or alerts
        device.refresh_from_db()
        self.assertEqual(device.status, "pending")

        # one test per device at a time
        from django.core.cache import cache

        cache.add(f"netmon_test_{device.pk}", 1, 30)
        r = self.client.post(f"{base_url}/{device.pk}/test/")
        self.assertEqual(r.status_code, 400)
        cache.delete(f"netmon_test_{device.pk}")

        # the address is checked again before probing
        NetworkDevice.objects.filter(pk=device.pk).update(host="127.0.0.1")
        r = self.client.post(f"{base_url}/{device.pk}/test/")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(probe_.await_count, 1)

        # throttled per user
        NetworkDevice.objects.filter(pk=device.pk).update(host="192.168.178.1")
        codes = {
            self.client.post(f"{base_url}/{device.pk}/test/").status_code
            for _ in range(12)
        }
        self.assertIn(429, codes)


@patch("psutil.net_if_addrs", return_value=NICS)
class TestPollerAndAlerts(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.site = baker.make("clients.Site", name="HQ", client__name="Acme")
        self.device = baker.make(
            "netmon.NetworkDevice",
            site=self.site,
            name="fw",
            host="192.168.178.1",
            dashboard_alert=True,
            email_alert=True,
        )

    @patch("netmon.tasks.probe_all", new_callable=AsyncMock)
    def test_poll_only_due_devices(self, probe_all, _):
        blocked = baker.make("netmon.NetworkDevice", site=self.site, host="127.0.0.1")
        baker.make(
            "netmon.NetworkDevice", site=self.site, host="192.168.178.2", enabled=False
        )
        probe_all.return_value = [up_result()]
        poll_network_devices()

        self.assertEqual(
            [t["host"] for t in probe_all.call_args.args[0]], ["192.168.178.1"]
        )
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, "up")
        # an address that is no longer allowed is not probed
        blocked.refresh_from_db()
        self.assertEqual(blocked.status, "error")

        # checked a moment ago, not due again
        probe_all.reset_mock()
        poll_network_devices()
        probe_all.assert_not_called()

        # a device the deadline cut off stays due
        NetworkDevice.objects.update(last_checked=None)
        probe_all.return_value = [None]
        poll_network_devices()
        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_checked)

    @patch(
        "core.models.CoreSettings.email_is_configured",
        new=PropertyMock(return_value=True),
    )
    @patch("netmon.tasks.network_resolved_email_task.delay")
    @patch("netmon.tasks.network_alert_email_task.delay")
    def test_alert_after_fails_and_resolve(self, email, resolved_email, _):
        from django.utils import timezone as djangotime

        now = djangotime.now()
        down = up_result(ping=False, status="down")
        record(self.device, down, now)
        self.assertFalse(Alert.objects.exists())  # fails_b4_alert is 2

        record(self.device, down, now)
        alert = Alert.objects.get()
        self.assertEqual(alert.alert_type, AlertType.NETWORK)
        self.assertEqual(alert.severity, AlertSeverity.ERROR)
        self.assertFalse(alert.hidden)
        self.assertIsNone(alert.agent)
        email.assert_called_once()

        # probe errors are the server's problem, they neither alert nor resolve
        record(self.device, {"status": "error", "error": "x", "ports": {}}, now)
        self.assertEqual(self.device.fail_count, 2)
        self.assertFalse(Alert.objects.get().resolved)

        degraded = up_result(ports={"443": False}, status="degraded")
        record(self.device, degraded, now)
        alert.refresh_from_db()
        # an open alert keeps its peak severity
        self.assertEqual(alert.severity, AlertSeverity.ERROR)

        # the failure mail went out, so the recovery is news
        Alert.objects.filter(pk=alert.pk).update(email_sent=now)
        record(self.device, up_result(), now)
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)
        resolved_email.assert_called_once()
        self.assertEqual(self.device.fail_count, 0)

    def test_maintenance_mode(self, _):
        from django.utils import timezone as djangotime

        self.device.maintenance_mode = True
        down = up_result(ping=False, status="down")
        for _ in range(3):
            record(self.device, down, djangotime.now())
        self.assertFalse(Alert.objects.exists())

    @patch("agents.models.Agent.run_script")
    @patch("netmon.tasks.network_alert_email_task.delay")
    def test_script_action_is_skipped(self, _, run_script, __):
        from django.utils import timezone as djangotime

        script = baker.make("scripts.Script")
        template = baker.make(
            "alerts.AlertTemplate",
            is_active=True,
            action=script,
            action_type=AlertTemplateActionType.SCRIPT,
            check_script_actions=True,
        )
        self.site.alert_template = template
        self.site.save()
        self.device.refresh_from_db()
        self.assertEqual(self.device.get_alert_template(), template)

        down = up_result(ping=False, status="down")
        record(self.device, down, djangotime.now())
        record(self.device, down, djangotime.now())
        self.assertTrue(Alert.objects.exists())
        run_script.assert_not_called()

        # an excluded site gets no template
        template.excluded_sites.add(self.site)
        self.assertIsNone(self.device.get_alert_template())

    @patch("core.models.CoreSettings.send_mail")
    def test_email(self, send_mail, _):
        self.device.last_result = up_result(
            ping=False, ports={"443": False}, status="down"
        )
        self.device.save()
        alert = baker.make(
            "alerts.Alert",
            network_device=self.device,
            alert_type=AlertType.NETWORK,
            severity=AlertSeverity.ERROR,
        )
        from .tasks import network_alert_email_task, network_resolved_email_task

        network_alert_email_task(pk=alert.pk)
        subject, body = send_mail.call_args.args
        self.assertEqual(subject, "Acme, HQ, fw (192.168.178.1) is down")
        self.assertIn("no ping reply", body)
        self.assertIn("closed: 443", body)
        # sent once unless the interval allows another
        network_alert_email_task(pk=alert.pk)
        self.assertEqual(send_mail.call_count, 1)
        network_resolved_email_task(pk=alert.pk)
        self.assertIn("is back up", send_mail.call_args.args[0])


class TestNetworkAlertPermissions(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()

    def test_device_alerts_stay_in_their_site(self):
        agent = baker.make_recipe("agents.agent")
        other_site = baker.make("clients.Site")
        mine = baker.make(
            "netmon.NetworkDevice", site=agent.site, host="192.168.178.1", name="fw"
        )
        theirs = baker.make(
            "netmon.NetworkDevice", site=other_site, host="192.168.178.2"
        )
        mine_alert = baker.make(
            "alerts.Alert", network_device=mine, alert_type=AlertType.NETWORK
        )
        their_alert = baker.make(
            "alerts.Alert", network_device=theirs, alert_type=AlertType.NETWORK
        )
        baker.make("alerts.Alert", agent=agent, alert_type=AlertType.AVAILABILITY)
        baker.make("alerts.Alert", alert_type=AlertType.CUSTOM)

        user = self.create_user_with_roles(["can_list_alerts", "can_manage_alerts"])
        self.client.force_authenticate(user=user)
        self.assertEqual(len(self.client.patch("/alerts/").data), 4)

        # custom alerts stay visible, the other site's device alert does not
        for scope in ("sites", "clients"):
            with self.subTest(scope=scope):
                user.role.can_view_sites.clear()
                user.role.can_view_clients.clear()
                if scope == "sites":
                    user.role.can_view_sites.set([agent.site])
                else:
                    user.role.can_view_clients.set([agent.client])
                r = self.client.patch("/alerts/")
                ids = {a["id"] for a in r.data}
                self.assertIn(mine_alert.pk, ids)
                self.assertNotIn(their_alert.pk, ids)
                self.assertEqual(len(ids), 3)

                self.check_not_authorized("get", f"/alerts/{their_alert.pk}/")
                self.check_not_authorized(
                    "put", f"/alerts/{their_alert.pk}/", {"type": "resolve"}
                )
                self.check_not_authorized("delete", f"/alerts/{their_alert.pk}/")
                r = self.check_authorized("get", f"/alerts/{mine_alert.pk}/")
                self.assertEqual(r.data["hostname"], "fw")
                self.assertEqual(r.data["site"], agent.site.name)
                self.assertEqual(r.data["client"], agent.client.name)
                self.assertFalse(r.data.get("agent_id"))

        # bulk resolve only reaches the visible ones
        self.client.post(
            "/alerts/bulk/",
            {"bulk_action": "resolve", "alerts": [their_alert.pk]},
            format="json",
        )
        their_alert.refresh_from_db()
        self.assertFalse(their_alert.resolved)

        # the client filter finds device alerts too
        r = self.client.patch(
            "/alerts/", {"clientFilter": [agent.client.pk]}, format="json"
        )
        self.assertIn(mine_alert.pk, {a["id"] for a in r.data})

        # the device cannot be swapped through the alert API
        self.client.put(
            f"/alerts/{mine_alert.pk}/", {"network_device": theirs.pk}, format="json"
        )
        mine_alert.refresh_from_db()
        self.assertEqual(mine_alert.network_device, mine)

    def test_alert_cannot_be_rebound_to_a_foreign_agent(self):
        site = baker.make("clients.Site")
        victim = baker.make_recipe("agents.agent")
        victim_check = baker.make("checks.Check", agent=victim)
        device = baker.make("netmon.NetworkDevice", site=site, host="192.168.178.1")
        device_alert = baker.make(
            "alerts.Alert", network_device=device, alert_type=AlertType.NETWORK
        )
        user = self.create_user_with_roles(["can_list_alerts", "can_manage_alerts"])
        user.role.can_view_sites.set([site])
        self.client.force_authenticate(user=user)

        r = self.client.put(
            f"/alerts/{device_alert.pk}/",
            {
                "agent": victim.pk,
                "assigned_check": victim_check.pk,
                "message": "call 0800",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        device_alert.refresh_from_db()
        self.assertIsNone(device_alert.agent)
        self.assertIsNone(device_alert.assigned_check)
        r = self.client.get(f"/alerts/{device_alert.pk}/")
        self.assertFalse(r.data.get("agent_id"))
        self.assertNotEqual(r.data["hostname"], victim.hostname)

        # an alert that somehow carries both needs access to both
        Alert.objects.filter(pk=device_alert.pk).update(agent=victim)
        self.check_not_authorized("get", f"/alerts/{device_alert.pk}/")

        # new alerts only for agents in scope
        self.check_not_authorized(
            "post", "/alerts/", {"agent": victim.pk, "severity": "warning"}
        )
        self.assertEqual(Alert.objects.filter(agent=victim).count(), 1)
        own = baker.make_recipe("agents.agent", site=site)
        self.check_authorized(
            "post", "/alerts/", {"agent": own.pk, "severity": "warning"}
        )
        self.assertTrue(Alert.objects.filter(agent=own).exists())


def make_cert(name, days, ca=None, san=True):
    """(certificate, key), self-signed or issued by ca, expiring in days
    (and an hour)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca[0].subject if ca else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(now + dt.timedelta(days=days, hours=1))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[1].public_key()),
            False,
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), True
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), False
        )
    return builder.sign(ca[1] if ca else key, hashes.SHA256()), key


def pem(cert, key=None) -> bytes:
    from cryptography.hazmat.primitives import serialization

    out = cert.public_bytes(serialization.Encoding.PEM)
    if key:
        out += key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return out


def server_context(cert, key, sni):
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(pem(cert, key))
        f.flush()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f.name)
    ctx.sni_callback = lambda sslobj, name, _: sni.append(name)
    return ctx


class TestHttpMonitor(ULRMMTestCase):
    """http_check against a server in this process on 127.0.0.1."""

    OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    def run_check(self, monitor, reply=OK, cert=None, handler=None):
        """(result, requests seen, SNI names seen)."""
        seen, sni = [], []

        async def answer(reader, writer):
            try:
                seen.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(reply)
                await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            writer.close()

        async def run():
            ctx = server_context(*cert, sni) if cert else None
            server = await asyncio.start_server(
                handler or answer, "127.0.0.1", 0, ssl=ctx
            )
            port = server.sockets[0].getsockname()[1]
            try:
                return await probe.run_monitor(
                    "127.0.0.1", {**HTTPS, "port": port, **monitor}
                )
            finally:
                server.close()
                await server.wait_closed()

        return asyncio.run(run()), seen, sni

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ca = make_cert("Test CA", 3650)
        cls.leaf = make_cert("nas.test", 90, ca=cls.ca)
        cls.self_signed = make_cert("nas.test", 90)

    def trust_test_ca(self):
        real = ssl.create_default_context
        cadata = pem(self.ca[0]).decode()
        return patch("ssl.create_default_context", lambda: real(cadata=cadata))

    def test_server_name_never_moves_the_connection(self):
        # a name that resolves elsewhere only goes into SNI and Host, nothing
        # is resolved and the request reaches the device address
        with patch("socket.getaddrinfo", side_effect=OSError("resolved")) as gai:
            r, seen, sni = self.run_check(
                {"server_name": "example.com", "allow_self_signed": True},
                cert=make_cert("example.com", 90),
            )
        gai.assert_not_called()
        self.assertEqual(r["status"], "ok", r)
        self.assertEqual(sni, ["example.com"])
        self.assertEqual(len(seen), 1)
        self.assertIn(b"\r\nHost: example.com:", seen[0])
        self.assertEqual(r["cert"]["issuer"], "example.com")
        self.assertEqual(r["cert"]["days_left"], 90)
        self.assertFalse(r["cert"]["verified"])

        # no credentials, cookies or body, the fixed request only
        r, seen, _ = self.run_check(
            {"scheme": "http", "method": "HEAD", "path": "/status?x=1"}
        )
        self.assertEqual(r["code"], 200)
        self.assertIsNone(r["cert"])
        port = r["label"].rsplit(" ", 1)[1].split("/")[0]
        self.assertEqual(
            seen[0],
            f"HEAD /status?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "User-Agent: ULRMM-netmon\r\nConnection: close\r\n\r\n".encode(),
        )

    def test_invalid_monitor_does_not_connect(self):
        with patch("asyncio.open_connection") as open_connection:
            for bad in (
                {"server_name": "nas.test\r\nX-Evil: 1"},
                {"server_name": "nas.test:8443"},
                {"path": "/a b"},
                {"path": "http://evil/"},
                {"method": "POST"},
            ):
                with self.subTest(bad=bad):
                    r = asyncio.run(probe.run_monitor("127.0.0.1", {**HTTPS, **bad}))
                    self.assertEqual(r["status"], "error")
            # a name as the device address is never resolved either
            r = asyncio.run(probe.run_monitor("nas.test", HTTPS))
            self.assertEqual(r["status"], "error")
        open_connection.assert_not_called()

    def test_certificate_is_verified(self):
        with self.trust_test_ca():
            r, _, _ = self.run_check({"server_name": "nas.test"}, cert=self.leaf)
            self.assertEqual(r["status"], "ok", r)
            self.assertTrue(r["cert"]["verified"])
            self.assertEqual(r["cert"]["issuer"], "Test CA")
            self.assertEqual(r["cert"]["names"], ["nas.test"])

            # a mismatch is an error, the certificate is still shown
            r, _, _ = self.run_check({"server_name": "other.test"}, cert=self.leaf)
            self.assertEqual(r["status"], "error")
            self.assertIn("Hostname mismatch", r["message"])
            self.assertFalse(r["cert"]["verified"])
            self.assertEqual(r["cert"]["days_left"], 90)

            # without a server name only the chain is checked
            r, _, _ = self.run_check({}, cert=self.leaf)
            self.assertEqual(r["status"], "ok", r)

        # not in the system store
        r, _, _ = self.run_check({"server_name": "nas.test"}, cert=self.leaf)
        self.assertEqual(r["status"], "error")
        self.assertIn("certificate:", r["message"])
        r, _, _ = self.run_check({}, cert=self.self_signed)
        self.assertIn("self-signed", r["message"])
        # unless self-signed is allowed, then only the dates count
        r, _, _ = self.run_check({"allow_self_signed": True}, cert=self.self_signed)
        self.assertEqual(r["status"], "ok")
        # and the name, when there is one
        monitor = {"allow_self_signed": True, "server_name": "nas.test"}
        r, _, _ = self.run_check(monitor, cert=self.self_signed)
        self.assertEqual(r["status"], "ok", r)
        monitor["server_name"] = "other.test"
        r, _, _ = self.run_check(monitor, cert=self.self_signed)
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["message"], "certificate is not for other.test")
        self.assertEqual(r["cert"]["names"], ["nas.test"])

    def test_name_matches(self):
        for name, patterns, ok in (
            ("nas.test", ["NAS.test."], True),
            ("a.nas.test", ["x.test", "*.nas.test"], True),
            ("nas.test", ["*.nas.test"], False),
            ("a.b.nas.test", ["*.nas.test"], False),
            ("a.nas.test", ["a*.nas.test"], False),
            ("nas.test", [], False),
        ):
            with self.subTest(name=name, patterns=patterns):
                self.assertEqual(probe.name_matches(name, patterns), ok)

        # the common name counts only without DNS names
        from cryptography.hazmat.primitives.serialization import Encoding

        der = make_cert("nas.test", 90, san=False)[0].public_bytes(Encoding.DER)
        self.assertTrue(probe.cert_info(der, "nas.test")["name_ok"])
        self.assertFalse(probe.cert_info(der, "other.test")["name_ok"])
        self.assertNotIn("name_ok", probe.cert_info(der))

    def test_expiry_thresholds(self):
        for days, monitor, status in (
            (30, {}, "ok"),
            (15, {}, "warning"),
            (5, {}, "error"),
            (-2, {}, "error"),
            (15, {"warn_days": 10, "error_days": 3}, "ok"),
            (5, {"warn_days": 10, "error_days": 3}, "warning"),
        ):
            with self.subTest(days=days, monitor=monitor):
                cert = make_cert("nas.test", days)
                r, _, _ = self.run_check(
                    {"allow_self_signed": True, **monitor}, cert=cert
                )
                self.assertEqual(r["status"], status, r)
                self.assertEqual(r["cert"]["days_left"], days)
        self.assertEqual(r["message"], "certificate expires in 5 days")

        # verified and expired
        expired = make_cert("nas.test", -2, ca=self.ca)
        with self.trust_test_ca():
            r, _, _ = self.run_check({"server_name": "nas.test"}, cert=expired)
        self.assertEqual(r["status"], "error")
        self.assertIn("expired", r["message"])

    def test_redirect_is_reported_not_followed(self):
        reply = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:8/x\r\n\r\n"
        r, seen, _ = self.run_check({"scheme": "http"}, reply)
        self.assertEqual((r["status"], r["code"]), ("ok", 302))
        self.assertEqual(len(seen), 1)
        r, seen, _ = self.run_check({"scheme": "http", "status": "200"}, reply)
        self.assertEqual((r["status"], r["message"]), ("error", "HTTP 302"))
        self.assertEqual(len(seen), 1)
        r, _, _ = self.run_check({"scheme": "http", "status": "401"}, self.OK)
        self.assertEqual(r["message"], "HTTP 200")

    def test_response_limits(self):
        # the body is never read, a huge one changes nothing
        big = b"HTTP/1.1 200 OK\r\nContent-Length: 8000000\r\n\r\n" + b"x" * 8000000
        r, _, _ = self.run_check({"scheme": "http"}, big)
        self.assertEqual(r["status"], "ok")

        for reply, message in (
            (b"HTTP/1.1 200 OK\r\nX: " + b"a" * 100000, "response head over"),
            (b"SSH-2.0-OpenSSH_9.6\r\n\r\n", "not an HTTP/1 response"),
            (b"HTTP/1.1 200 OK\r\n", "connection closed before a response"),
        ):
            with self.subTest(message=message):
                r, _, _ = self.run_check({"scheme": "http"}, reply)
                self.assertEqual(r["status"], "error")
                self.assertIn(message, r["message"])

    @patch("netmon.probe.MONITOR_TIMEOUT", 0.3)
    def test_timeout(self):
        async def silent(reader, writer):
            await reader.read()
            writer.close()

        r, _, _ = self.run_check({"scheme": "http"}, handler=silent)
        self.assertEqual(
            r, {"status": "error", "message": "timed out", "label": r["label"]}
        )


QUESTION = probe.dns_question("rd.riddix.de", 1)


def dns_reply(qid, question=QUESTION, flags=0x8180, records=b"", count=0):
    return struct.pack("!6H", qid, flags, 1, count, 0, 0) + question + records


def a_record(address, name=b"\xc0\x0c", rtype=1):
    return name + struct.pack("!HHIH", rtype, 1, 60, 4) + socket.inet_aton(address)


class TestDnsMonitor(ULRMMTestCase):
    def test_parse(self):
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 4) + b"\x02rd\x00"
        records = cname + a_record("192.168.178.9") + a_record("192.168.178.10")
        reply = dns_reply(7, records=records, count=3)
        self.assertEqual(
            probe.dns_answers(reply, 7, QUESTION, 1),
            (0, ["192.168.178.9", "192.168.178.10"]),
        )
        # the echo may differ in case only
        upper = dns_reply(7, QUESTION.upper(), records=a_record("10.0.0.1"), count=1)
        self.assertEqual(probe.dns_answers(upper, 7, QUESTION, 1), (0, ["10.0.0.1"]))
        self.assertEqual(
            probe.dns_answers(dns_reply(7, flags=0x8183), 7, QUESTION, 1), (3, [])
        )

        # not an answer to this query
        other = probe.dns_question("evil.example", 1)
        for spoof in (
            dns_reply(8, records=a_record("6.6.6.6"), count=1),  # wrong ID
            dns_reply(7, other, records=a_record("6.6.6.6"), count=1),
            dns_reply(7, probe.dns_question("rd.riddix.de", 28)),
            dns_reply(7, flags=0x0100),  # a query, not a response
            dns_reply(7, flags=0x8980),  # opcode 1
            b"\x00\x07\x81",
            b"",
        ):
            with self.subTest(spoof=spoof):
                self.assertIsNone(probe.dns_answers(spoof, 7, QUESTION, 1))

    def test_malformed_does_not_crash(self):
        offset = 12 + len(QUESTION)
        for records, count in (
            # pointer to itself: skipped, never followed
            (a_record("10.0.0.2", name=bytes([0xC0, offset])), 1),
            # pointer loop across two names
            (a_record("10.0.0.2", name=b"\xc0\x0c") * 2, 2),
        ):
            reply = dns_reply(7, records=records, count=count)
            self.assertEqual(probe.dns_answers(reply, 7, QUESTION, 1)[0], 0)

        for records, count in (
            (a_record("10.0.0.2")[:-2], 1),  # record past the end
            (b"\x3f" + b"a" * 10, 1),  # label past the end
            (b"\x40abc", 1),  # reserved label type
            (a_record("10.0.0.2"), 65535),  # more answers than data
        ):
            with self.subTest(records=records, count=count):
                reply = dns_reply(7, records=records, count=count)
                with self.assertRaises((ValueError, IndexError, struct.error)):
                    probe.dns_answers(reply, 7, QUESTION, 1)

    def run_check(self, monitor, replies):
        """(result, queries seen). replies(qid, question) -> datagrams."""
        queries = []

        class Responder(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                queries.append(data)
                qid = struct.unpack_from("!H", data)[0]
                for reply in replies(qid, data[12:]):
                    self.transport.sendto(reply, addr)

        async def run():
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                Responder, local_addr=("127.0.0.1", 0)
            )
            port = transport.get_extra_info("sockname")[1]
            try:
                with patch("netmon.probe.DNS_PORT", port):
                    return await probe.run_monitor("127.0.0.1", {**DNS, **monitor})
            finally:
                transport.close()

        return asyncio.run(run()), queries

    def test_spoofed_replies_are_ignored(self):
        def replies(qid, question):
            evil = a_record("6.6.6.6")
            return (
                dns_reply(qid ^ 1, question, records=evil, count=1),
                dns_reply(
                    qid, probe.dns_question("x.example", 1), records=evil, count=1
                ),
                dns_reply(qid, question, flags=0x0100, records=evil, count=1),
                dns_reply(qid, question, records=a_record("192.168.178.9"), count=1),
            )

        r, queries = self.run_check({"expect": ["192.168.178.9"]}, replies)
        self.assertEqual(r["status"], "ok", r)
        self.assertEqual(r["answers"], ["192.168.178.9"])
        # one query, recursion desired, the name as entered
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0][2:12], b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        self.assertEqual(queries[0][12:], QUESTION)

    def test_failing_answers(self):
        def answer(*addresses, flags=0x8180):
            records = b"".join(a_record(a) for a in addresses)
            return lambda qid, q: [dns_reply(qid, q, flags, records, len(addresses))]

        for monitor, replies, message in (
            ({}, answer(flags=0x8183), "DNS NXDOMAIN"),
            ({}, answer(flags=0x8182), "DNS SERVFAIL"),
            ({}, answer(), "no A record"),
            (
                {"expect": ["192.168.178.9"]},
                answer("192.168.178.9", "6.6.6.6"),
                "answered 192.168.178.9, 6.6.6.6, expected 192.168.178.9",
            ),
            (
                {},
                lambda qid, q: [dns_reply(qid, q, records=b"\x3f", count=1)],
                "malformed DNS response",
            ),
        ):
            with self.subTest(message=message):
                r, _ = self.run_check(monitor, replies)
                self.assertEqual((r["status"], r["message"]), ("error", message))

        with patch("netmon.probe.MONITOR_TIMEOUT", 0.3):
            r, _ = self.run_check({}, lambda qid, q: [])
        self.assertEqual(r["message"], "timed out")


class TestMonitorStatus(ULRMMTestCase):
    def test_hostnames(self):
        for name in ("nas", "nas.lan", "api.riddix.de", "a-1.b2.example"):
            self.assertTrue(probe.is_hostname(name), name)
        for name in (
            "https://nas.lan",
            "nas.lan:443",
            "user@nas.lan",
            "nas.lan/",
            "nas lan",
            "nas.lan\r\nx",
            "nas.lan\x00",
            "192.168.178.1",
            "nas.lan.",
            ".nas.lan",
            "-nas.lan",
            "nas-.lan",
            "NAS.lan",  # stored lower case
            "exämple.de",
            "a" * 64 + ".lan",
            ("a" * 60 + ".") * 5,
            "",
        ):
            with self.subTest(name=name):
                self.assertFalse(probe.is_hostname(name))

    def test_status(self):
        ok = {"status": "ok"}
        warning = {"status": "warning"}
        error = {"status": "error"}
        cases = [
            # ping, monitors -> status
            (True, [ok, ok], "up"),
            (True, [ok, warning], "degraded"),
            (True, [error], "degraded"),
            (False, [ok, ok], "down"),
            (None, [error, error], "down"),
            (None, [warning], "degraded"),
            (None, [error, ok], "degraded"),
            (None, [ok], "up"),
        ]
        for ping, monitors, want in cases:
            with self.subTest(ping=ping, monitors=monitors):
                target = {"ping": ping is not None, "snmp": None}
                result = {"ping": ping, "ports": {}, "monitors": monitors, "error": ""}
                self.assertEqual(probe.status_of(target, result), want)

    @patch("netmon.probe.dns_check", new_callable=AsyncMock)
    @patch("netmon.probe.http_check", new_callable=AsyncMock)
    def test_probe(self, http_check, dns_check):
        http_check.return_value = {"status": "warning", "message": "soon"}
        dns_check.side_effect = OSError("[Errno 111] Connection refused")
        target = {
            "host": "192.168.178.1",
            "ping": False,
            "tcp_ports": [],
            "snmp": None,
            "monitors": [HTTPS, DNS],
        }
        r = asyncio.run(probe.probe(target))
        self.assertEqual(
            r["monitors"],
            [
                {"status": "warning", "message": "soon", "label": "HTTPS 443/"},
                {
                    "status": "error",
                    "message": "[Errno 111] Connection refused",
                    "label": "DNS A rd.riddix.de",
                },
            ],
        )
        self.assertEqual(r["status"], "degraded")
        self.assertEqual(http_check.call_args.args, ("192.168.178.1", HTTPS))

    def test_own_address(self):
        own_https = {
            "ping": False,
            "tcp_ports": [],
            "snmp": None,
            "monitors": [{**HTTPS, "server_name": "api.riddix.de"}],
        }
        self.assertTrue(probe.own_ok(own_https))
        self.assertEqual(
            probe.address_error("192.168.178.3", {LAN}, OWN, own_allowed=True), ""
        )
        # never loopback, never outside the networks
        self.assertTrue(probe.address_error("127.0.0.1", {LAN}, OWN, own_allowed=True))
        self.assertTrue(
            probe.address_error("192.168.178.3", set(), OWN, own_allowed=True)
        )
        for change in (
            {"ping": True},
            {"tcp_ports": [443]},
            {"snmp": {"version": "v2c"}},
            {"monitors": []},
            {"monitors": [{**HTTPS, "port": 8443}]},
            {"monitors": [{**HTTPS, "scheme": "http"}]},
            {"monitors": [{**HTTPS, "path": "/admin"}]},
            {"monitors": [HTTPS, DNS]},
        ):
            with self.subTest(change=change):
                self.assertFalse(probe.own_ok({**own_https, **change}))


@patch("psutil.net_if_addrs", return_value=NICS)
class TestMonitorViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.data = {"site": self.site.pk, "name": "fw", "host": "192.168.178.1"}

    def post(self, **kwargs):
        return self.client.post(f"{base_url}/", {**self.data, **kwargs}, format="json")

    def test_saved_normalized(self, _):
        r = self.post(
            monitors=[
                {
                    "type": "http",
                    "server_name": "NAS.Example.Lan",
                    "status": "200-299, 401",
                    "url": "http://evil.example/",
                    "query": "dropped.example",
                },
                {"type": "http", "scheme": "http", "method": "HEAD"},
                {
                    "type": "dns",
                    "query": "RD.riddix.de",
                    "expect": ["192.168.178.10", "192.168.178.9"],
                    "port": 5353,
                },
            ]
        )
        self.assertEqual(r.status_code, 200, r.data)
        device = NetworkDevice.objects.get()
        self.assertEqual(
            device.monitors,
            [
                {
                    **HTTPS,
                    "server_name": "nas.example.lan",
                    "status": "200-299,401",
                },
                {**HTTPS, "scheme": "http", "port": 80, "method": "HEAD"},
                {**DNS, "expect": ["192.168.178.9", "192.168.178.10"]},
            ],
        )
        r = self.client.get(f"{base_url}/{device.pk}/")
        self.assertEqual(r.data["monitors"], device.monitors)
        # monitors alone are enough to check a device
        self.assertEqual(self.post(ping=False, monitors=[DNS]).status_code, 200)

    def test_rejected(self, _):
        http = {"type": "http"}
        for monitor in (
            {**http, "server_name": "https://nas.lan"},
            {**http, "server_name": "nas.lan:443"},
            {**http, "server_name": "admin:pw@nas.lan"},
            {**http, "server_name": "nas.lan/x"},
            {**http, "server_name": "nas.lan\r\nHost: evil"},
            {**http, "server_name": "192.168.178.50"},
            {**http, "path": "x"},
            {**http, "path": "/a b"},
            {**http, "path": "/a\tb"},
            {**http, "path": "/ä"},
            {**http, "path": "/" + "a" * 256},
            {**http, "method": "POST"},
            {**http, "scheme": "ftp"},
            {**http, "port": 0},
            {**http, "port": 65536},
            {**http, "status": "600"},
            {**http, "status": "399-200"},
            {**http, "status": "2xx"},
            {**http, "status": "200,"},
            {**http, "warn_days": 5, "error_days": 7},
            {"type": "icmp"},
            {"type": "dns"},
            {"type": "dns", "query": "rd.riddix.de:53"},
            {"type": "dns", "query": "rd.riddix.de", "record": "MX"},
            {"type": "dns", "query": "rd.riddix.de", "expect": ["::1"]},
            {"type": "dns", "query": "rd.riddix.de", "expect": ["rd.riddix.de"]},
        ):
            with self.subTest(monitor=monitor):
                r = self.post(monitors=[monitor])
                self.assertEqual(r.status_code, 400)
                self.assertIn("monitors", r.data)
        r = self.post(monitors=[DNS] * 9)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(NetworkDevice.objects.exists())
        # one line the web toast can show
        r = self.post(monitors=[DNS, {"type": "http", "server_name": "nas:443"}])
        self.assertTrue(
            r.data["monitors"][0].startswith("Monitor 2, server name: A host name")
        )

    def test_own_address_only_for_its_certificate(self, _):
        own = {
            **self.data,
            "host": "192.168.178.3",
            "ping": False,
            "monitors": [{"type": "http", "server_name": "api.riddix.de"}],
        }
        for change in (
            {"ping": True},
            {"tcp_ports": [443]},
            {"snmp_version": "v2c", "snmp_community": "public1"},
            {"monitors": [{"type": "http", "port": 8443}]},
            {"monitors": [{"type": "http", "scheme": "http", "port": 443}]},
            {"monitors": [{"type": "http", "path": "/admin"}]},
            {"monitors": [{"type": "http"}, DNS]},
            {"host": "127.0.0.1"},
        ):
            with self.subTest(change=change):
                r = self.client.post(f"{base_url}/", {**own, **change}, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertIn("host", r.data)
        self.assertFalse(NetworkDevice.objects.exists())

        r = self.client.post(f"{base_url}/", own, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        device = NetworkDevice.objects.get()
        target = device.probe_target({LAN}, OWN)
        self.assertEqual(target["host"], "192.168.178.3")

        # an edit cannot widen it, host or not in the request
        for change in (
            {"ping": True},
            {"monitors": [{"type": "http", "port": 22}]},
            {"monitors": [DNS]},
        ):
            with self.subTest(edit=change):
                r = self.client.put(f"{base_url}/{device.pk}/", change, format="json")
                self.assertEqual(r.status_code, 400)
        # and the probe checks again
        NetworkDevice.objects.filter(pk=device.pk).update(
            monitors=[{**HTTPS, "port": 8443}]
        )
        device.refresh_from_db()
        with self.assertRaises(ValueError):
            device.probe_target({LAN}, OWN)

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("netmon.views.probe", new_callable=AsyncMock)
    def test_test_now_covers_monitors(self, probe_, _):
        device = baker.make(
            "netmon.NetworkDevice",
            site=self.site,
            host="192.168.178.1",
            monitors=[HTTPS, DNS],
        )
        probe_.return_value = up_result()
        r = self.client.post(f"{base_url}/{device.pk}/test/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(probe_.call_args.args[0]["monitors"], [HTTPS, DNS])


@patch("psutil.net_if_addrs", return_value=NICS)
class TestMonitorAlerts(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.site = baker.make("clients.Site", name="HQ", client__name="Acme")
        self.device = baker.make(
            "netmon.NetworkDevice",
            site=self.site,
            name="nas",
            host="192.168.178.8",
            dashboard_alert=True,
            monitors=[HTTPS],
            fails_b4_alert=1,
        )

    def result(self, status, message):
        monitor = {"status": status, "message": message, "label": "HTTPS 443/"}
        return up_result(monitors=[monitor], status="degraded")

    @patch("core.models.CoreSettings.send_mail")
    def test_severity_and_text(self, send_mail, _):
        from django.utils import timezone as djangotime

        from .tasks import network_alert_email_task

        record(
            self.device,
            self.result("warning", "certificate expires in 12 days"),
            djangotime.now(),
        )
        alert = Alert.objects.get()
        self.assertEqual(alert.severity, AlertSeverity.WARNING)

        record(
            self.device,
            self.result("error", "certificate expires in 3 days"),
            djangotime.now(),
        )
        alert.refresh_from_db()
        self.assertEqual(alert.severity, AlertSeverity.ERROR)

        network_alert_email_task(pk=alert.pk)
        subject, body = send_mail.call_args.args
        self.assertEqual(subject, "Acme, HQ, nas (192.168.178.8) is degraded")
        self.assertIn("HTTPS 443/: certificate expires in 3 days", body)

        ok = up_result(monitors=[{"status": "ok", "message": "", "label": "x"}])
        record(self.device, ok, djangotime.now())
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)

    @patch(
        "core.models.CoreSettings.email_is_configured",
        new=PropertyMock(return_value=True),
    )
    @patch("core.models.CoreSettings.send_mail")
    def test_error_mails_after_a_warning_mail(self, send_mail, _):
        from django.utils import timezone as djangotime

        from .tasks import network_alert_email_task

        self.device.email_alert = True
        self.device.save()
        warning = self.result("warning", "certificate expires in 12 days")
        error = self.result("error", "certificate expires in 3 days")
        with patch.object(
            network_alert_email_task, "delay", side_effect=network_alert_email_task
        ):
            record(self.device, warning, djangotime.now())
            self.assertEqual(send_mail.call_count, 1)
            record(self.device, error, djangotime.now())
            self.assertEqual(send_mail.call_count, 2)
            self.assertIn("expires in 3 days", send_mail.call_args.args[1])
            # once, not on every poll
            record(self.device, error, djangotime.now())
            self.assertEqual(send_mail.call_count, 2)


PRT = "1.3.6.1.2.1.43.11.1.1."


def supplies_binds():
    return [
        (PRT + "6.1.1", "Black Toner"),
        (PRT + "8.1.1", 100),
        (PRT + "9.1.1", 8),
        (PRT + "6.1.2", "Cyan Toner"),
        (PRT + "8.1.2", 2000),
        (PRT + "9.1.2", 1500),
        # "some left", no percent
        (PRT + "6.1.3", "Waste Toner"),
        (PRT + "8.1.3", -2),
        (PRT + "9.1.3", -3),
        # past the table
        (PRT + "7.1.1", 3),
        (PRT + "10.1.1", 1),
    ]


class TestPrinterMonitor(ULRMMTestCase):
    def test_supplies_and_threshold(self):
        supplies = probe.printer_supplies(supplies_binds())
        self.assertEqual(
            [(s["name"], s["level"], s["max"], s["percent"]) for s in supplies],
            [
                ("Black Toner", 8, 100, 8),
                ("Cyan Toner", 1500, 2000, 75),
                ("Waste Toner", -3, -2, None),
            ],
        )
        printer = {"supplies": supplies, "pages": 1234}
        r = probe.printer_check({"type": "printer", "threshold": 15}, printer)
        self.assertEqual(r["status"], "warning")
        self.assertEqual(r["message"], "low: Black Toner 8%")
        self.assertEqual([s["low"] for s in supplies], [True, False, False])
        r = probe.printer_check({"type": "printer", "threshold": 5}, printer)
        self.assertEqual((r["status"], r["message"]), ("ok", ""))
        r = probe.printer_check({"type": "printer", "threshold": 15}, None)
        self.assertEqual(r["status"], "error")

    @patch("netmon.probe.ping", new_callable=AsyncMock, return_value=(True, 1.0))
    @patch("netmon.probe.snmp_poll", new_callable=AsyncMock)
    def test_probe(self, snmp_poll, _):
        snmp_poll.return_value = {
            "sys_name": "printer",
            "printer": {"supplies": probe.printer_supplies(supplies_binds())},
        }
        target = {
            "host": "192.168.178.9",
            "ping": True,
            "tcp_ports": [],
            "snmp": {"port": 161, "version": "v2c", "secret": {"community": "c"}},
            "monitors": [{"type": "printer", "threshold": 15}],
        }
        result = asyncio.run(probe.probe(target))
        self.assertIs(snmp_poll.call_args.kwargs["printer"], True)
        self.assertNotIn("printer", result["snmp"])
        self.assertEqual(result["printer"]["supplies"][0]["percent"], 8)
        self.assertEqual(result["monitors"][0]["label"], "Printer supplies")
        self.assertEqual(result["status"], "degraded")

        # no printer monitor: no Printer-MIB requests
        snmp_poll.return_value = {"sys_name": "switch"}
        result = asyncio.run(probe.probe({**target, "monitors": []}))
        self.assertIs(snmp_poll.call_args.kwargs["printer"], False)
        self.assertNotIn("printer", result)
        self.assertEqual(result["status"], "up")


@patch("psutil.net_if_addrs", return_value=NICS)
class TestPrinterMonitorDevice(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site", name="HQ", client__name="Acme")

    def test_needs_snmp(self, _):
        data = {
            "site": self.site.pk,
            "name": "printer",
            "host": "192.168.178.9",
            "monitors": [{"type": "printer"}],
        }
        r = self.client.post(f"{base_url}/", data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("SNMP", str(r.data))
        data.update(snmp_version="v2c", snmp_community="public1")
        data["monitors"] = [{"type": "printer", "threshold": 10, "path": "/x"}]
        r = self.client.post(f"{base_url}/", data, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        device = NetworkDevice.objects.get(name="printer")
        self.assertEqual(device.monitors, [{"type": "printer", "threshold": 10}])
        data["monitors"] = [{"type": "printer", "threshold": 100}]
        r = self.client.post(f"{base_url}/", data, format="json")
        self.assertEqual(r.status_code, 400)

    @patch("notify.tasks.send_notifications_task.delay")
    def test_low_supply_notifies_once(self, delay, _):
        from django.utils import timezone as djangotime

        from notify.models import Notification

        channel = baker.make(
            "notify.Channel", name="n", kind="ntfy", config={"topic": "rmm"}
        )
        baker.make("notify.Route", name="r", sources=["netmon"]).channels.set([channel])
        device = baker.make(
            "netmon.NetworkDevice",
            site=self.site,
            name="printer",
            host="192.168.178.9",
            dashboard_alert=True,
            fails_b4_alert=1,
        )

        def result(level):
            binds = supplies_binds()
            binds[2] = (PRT + "9.1.1", level)
            printer = {"supplies": probe.printer_supplies(binds)}
            check = probe.printer_check({"type": "printer", "threshold": 15}, printer)
            return up_result(printer=printer, monitors=[check], status="degraded")

        # one path: the device's alert carries the low supplies
        record(device, result(8), djangotime.now())
        record(device, result(7), djangotime.now())
        row = Notification.objects.get()
        self.assertEqual((row.source, row.severity), ("netmon", "warning"))
        self.assertEqual(row.alert, Alert.objects.get(network_device=device))
        self.assertIn("Acme, HQ, printer", row.body)
        self.assertIn("Black Toner 8%", row.body)

        # in maintenance nothing goes out
        record(device, up_result(), djangotime.now())
        device.maintenance_mode = True
        record(device, result(5), djangotime.now())
        self.assertEqual(Notification.objects.exclude(alert=row.alert).count(), 0)

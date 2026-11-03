# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from discovery.models import DiscoveredDevice
from logs.models import AuditLog, DebugLog
from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .models import (
    OPNSENSE_INFO,
    UNIFI_INFO,
    NetworkClient,
    OpnsenseFirewall,
    UniFiController,
)
from .tasks import SYNC_LOCK, sync, sync_integrations_task

UNIFI = "https://unifi.lan"
OPN = "https://fw.lan:8443"
API = "/proxy/network/api/s/default"
NOW = int(djangotime.now().timestamp())

UNIFI_DATA = {
    f"{API}/rest/networkconf": [
        {"_id": "lan", "name": "LAN", "ip_subnet": "192.168.1.1/24"},
        {
            "_id": "iot",
            "name": "IoT",
            "vlan_enabled": True,
            "vlan": "20",
            "ip_subnet": "10.0.20.1/24",
        },
        {"_id": "wan", "name": "WAN", "purpose": "wan"},
    ],
    f"{API}/stat/device": [
        {"mac": "aa:aa:aa:00:00:01", "name": "Core switch"},
        {"mac": "aa:aa:aa:00:00:02", "model": "U6-Lite"},
    ],
    f"{API}/stat/sta": [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.20",
            "hostname": "desktop",
            "network_id": "lan",
            "is_wired": True,
            "sw_mac": "AA:AA:AA:00:00:01",
            "sw_port": 7,
            "last_seen": NOW,
        },
        {
            "mac": "00:11:22:33:44:66",
            "ip": "10.0.20.5",
            "name": "camera",
            "network_id": "iot",
            "is_wired": False,
            "ap_mac": "aa:aa:aa:00:00:02",
            "essid": "iot-wifi",
            "last_seen": NOW,
        },
        {"mac": "not a mac"},
    ],
}
OPN_DATA = {
    "/api/interfaces/vlan_settings/searchItem": {
        "rows": [{"vlanif": "vlan0.30", "tag": "30", "descr": "Guests"}]
    },
    "/api/diagnostics/interface/getArp": [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.20",
            "intf": "igb1",
            "intf_description": "LAN",
            "hostname": "",
        },
        {
            "mac": "00-11-22-33-44-77",
            "ip": "10.0.30.9",
            "intf": "vlan0.30",
            "hostname": "arp-name",
        },
        {"mac": "00:11:22:33:44:88", "ip": "10.0.30.10", "expired": True},
    ],
    "/api/dhcpv4/leases/searchLease": {
        "rows": [{"hwaddr": "00:11:22:33:44:77", "hostname": "guest-phone"}]
    },
    "/api/diagnostics/interface/getInterfaceConfig": {
        "vlan0.30": {"ipv4": [{"ipaddr": "10.0.30.1", "subnetbits": 24}]}
    },
}


class Answer:
    def __init__(self, data, status=200, redirect=False):
        self.data, self.status_code, self.is_redirect = data, status, redirect

    def json(self):
        if self.data is None:
            raise ValueError("no json")
        return self.data


def fake(answers: dict):
    """Session.request stand-in. answers: url -> Answer or data."""
    calls = []

    def request(session, method, url, **kwargs):
        calls.append((session, method, url, kwargs))
        answer = answers.get(url, Answer(None, 404))
        return answer if isinstance(answer, Answer) else Answer(answer)

    return request, calls


def network_answers():
    answers = {UNIFI + "/api/auth/login": {}}
    answers.update({UNIFI + k: {"data": v} for k, v in UNIFI_DATA.items()})
    answers.update({OPN + k: v for k, v in OPN_DATA.items()})
    return answers


def turn_on():
    UniFiController.objects.create(
        pk=1,
        url=UNIFI,
        username="ro",
        password=encrypt_secret("unifi-pass", UNIFI_INFO),
        enabled=True,
        verify_tls=False,
    )
    OpnsenseFirewall.objects.create(
        pk=1,
        url=OPN,
        api_key=encrypt_secret("key", OPNSENSE_INFO),
        api_secret=encrypt_secret("secret", OPNSENSE_INFO),
        enabled=True,
    )


class TestSettings(ULRMMTestCase):
    url = "/integrations/settings/"

    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_secrets_are_write_only(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            set(r.data),
            {"unifi", "opnsense"},
        )
        self.assertFalse(r.data["unifi"]["password_set"])
        self.assertEqual(r.data["unifi"]["site"], "default")

        data = {
            "unifi": {
                "url": UNIFI,
                "username": "ro",
                "password": "unifi-pass",
                "enabled": True,
            },
            "opnsense": {"url": OPN, "api_key": "key", "api_secret": "s3cret"},
        }
        r = self.client.put(self.url, data, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertTrue(r.data["unifi"]["password_set"])
        self.assertFalse(r.data["unifi"]["api_key_set"])
        self.assertTrue(r.data["opnsense"]["api_secret_set"])
        self.assertNotIn("unifi-pass", json.dumps(r.data))
        unifi, opn = UniFiController.get(), OpnsenseFirewall.get()
        self.assertEqual(decrypt_secret(unifi.password, UNIFI_INFO), "unifi-pass")
        self.assertEqual(decrypt_secret(opn.api_secret, OPNSENSE_INFO), "s3cret")

        # blank keeps, null deletes
        r = self.client.put(
            self.url,
            {"unifi": {"password": "", "api_key": "k"}, "opnsense": {"api_key": None}},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertTrue(r.data["unifi"]["password_set"])
        self.assertTrue(r.data["unifi"]["api_key_set"])
        self.assertFalse(r.data["opnsense"]["api_key_set"])

        # a new address needs the stored secrets again, or their removal
        r = self.client.put(
            self.url, {"unifi": {"url": "https://evil.example"}}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.data["unifi"]), {"password", "api_key"})
        r = self.client.put(
            self.url,
            {"unifi": {"url": UNIFI + "/", "password": ""}, "opnsense": {"url": OPN}},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        r = self.client.put(
            self.url,
            {"opnsense": {"url": "https://fw2.example", "api_secret": "new"}},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(OpnsenseFirewall.get().url, "https://fw2.example")

        logs = json.dumps(list(AuditLog.objects.values("before_value", "after_value")))
        self.assertIn("hmac:", logs)
        for secret in ("unifi-pass", "s3cret", unifi.password):
            self.assertNotIn(secret, logs)

    def test_validation(self):
        for bad in (
            {"unifi": {"url": "http://unifi.lan"}},
            {"unifi": {"url": "https://unifi.lan/path"}},
            {"unifi": {"site": "a b"}},
            {"unifi": {"enabled": True}},
            {"unifi": {"url": UNIFI, "username": "x", "enabled": True}},
            {"opnsense": {"url": OPN, "api_key": "k", "enabled": True}},
            {"opnsense": "x"},
        ):
            r = self.client.put(self.url, bad, format="json")
            self.assertEqual(r.status_code, 400, bad)
        # nothing was saved by the failed requests
        self.assertFalse(UniFiController.get().url)

    def test_permissions(self):
        user = self.create_user_with_roles(
            ["can_edit_core_settings", "can_list_agents"]
        )
        self.client.force_authenticate(user=user)
        self.check_not_authorized("get", self.url)
        self.check_not_authorized("put", self.url, {})
        self.check_not_authorized("post", "/integrations/sync/")
        user = self.create_user_with_roles(["can_manage_integrations"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.check_not_authorized("get", "/integrations/clients/")
        self.check_not_authorized("get", "/integrations/vlans/")
        self.check_not_authenticated("get", self.url)


class TestSync(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site", name="HQ", client__name="Acme")
        self.agent = baker.make_recipe(
            "agents.agent",
            site=self.site,
            hostname="desktop",
            wmi_detail={
                "nics": [
                    {"mac": "00:11:22:33:44:55", "ips": ["192.168.1.20/24"]},
                    {"mac": "00:11:22:33:44:99", "ips": []},
                ]
            },
        )
        self.other = baker.make_recipe(
            "agents.agent",
            site=baker.make("clients.Site"),
            wmi_detail={"nics": [{"mac": "00-11-22-33-44-77", "ips": []}]},
        )

    def run_sync(self, answers=None):
        request, calls = fake(answers or network_answers())
        with patch.object(
            requests.Session, "request", autospec=True, side_effect=request
        ):
            return sync(), calls

    def test_nothing_on(self):
        results, calls = self.run_sync()
        self.assertEqual(results, {})
        self.assertEqual(calls, [])
        r = self.client.post("/integrations/sync/")
        self.assertEqual(r.status_code, 400)

    def test_sync_links_agents_and_discovery(self):
        turn_on()
        DiscoveredDevice.objects.create(
            ip="192.168.1.20", mac="00:11:22:33:44:55", last_seen=djangotime.now()
        )
        DiscoveredDevice.objects.create(
            ip="10.0.30.9", hostname="", last_seen=djangotime.now()
        )
        DiscoveredDevice.objects.create(
            ip="10.0.99.1", hostname="kept", vlan_id=5, last_seen=djangotime.now()
        )
        results, calls = self.run_sync()
        self.assertEqual(
            results,
            {
                "opnsense": {"ok": True, "clients": 2, "vlans": 1},
                "unifi": {"ok": True, "clients": 2, "vlans": 2},
            },
        )
        for session, method, url, kwargs in calls:
            self.assertTrue(url.startswith("https://"))
            self.assertIs(kwargs["allow_redirects"], False)
            self.assertEqual(kwargs["timeout"], 20)
            if url.startswith(OPN):
                self.assertEqual(session.auth, ("key", "secret"))
                self.assertTrue(session.verify)
            else:
                self.assertFalse(session.verify)
        login = [c for c in calls if c[2].endswith("/api/auth/login")]
        self.assertEqual(
            login[0][3]["json"], {"username": "ro", "password": "unifi-pass"}
        )

        wired = NetworkClient.objects.get(mac="00:11:22:33:44:55")
        self.assertEqual(wired.source, "opnsense,unifi")
        self.assertEqual(
            (wired.vlan_id, wired.vlan_name, wired.switch, wired.port),
            (1, "LAN", "Core switch", "7"),
        )
        wifi = NetworkClient.objects.get(mac="00:11:22:33:44:66")
        self.assertEqual(
            (wifi.vlan_id, wifi.ap, wifi.ssid, wifi.hostname),
            (20, "U6-Lite", "iot-wifi", "camera"),
        )
        guest = NetworkClient.objects.get(mac="00:11:22:33:44:77")
        self.assertEqual(
            (guest.vlan_id, guest.vlan_name, guest.hostname, guest.source),
            (30, "Guests", "guest-phone", "opnsense"),
        )
        self.assertFalse(NetworkClient.objects.filter(mac="00:11:22:33:44:88").exists())

        self.agent.refresh_from_db()
        info = self.agent.network_info
        self.assertEqual(info["switch"], "Core switch")
        self.assertEqual(info["port"], "7")
        self.assertEqual(info["vlan_id"], 1)
        self.assertEqual(info["mac"], "00:11:22:33:44:55")
        self.other.refresh_from_db()
        self.assertEqual(self.other.network_info["vlan_name"], "Guests")

        found = {d.ip: d for d in DiscoveredDevice.objects.all()}
        self.assertEqual(found["192.168.1.20"].switch, "Core switch")
        self.assertEqual(found["10.0.30.9"].vlan_id, 30)
        self.assertEqual(found["10.0.30.9"].hostname, "guest-phone")
        # no longer known: the network fields are cleared, the name stays
        self.assertIsNone(found["10.0.99.1"].vlan_id)
        self.assertEqual(found["10.0.99.1"].hostname, "kept")
        r = self.client.get("/discovery/devices/")
        row = next(d for d in r.data if d["ip"] == "10.0.30.9")
        self.assertEqual((row["vlan_id"], row["vlan_name"]), (30, "Guests"))

        r = self.client.get("/integrations/vlans/")
        self.assertEqual(
            [(v["vlan_id"], v["name"], v["subnet"], v["source"]) for v in r.data],
            [
                (1, "LAN", "192.168.1.0/24", "unifi"),
                (20, "IoT", "10.0.20.0/24", "unifi"),
                (30, "Guests", "10.0.30.0/24", "opnsense"),
            ],
        )

        r = self.client.get("/integrations/clients/")
        self.assertEqual(len(r.data), 3)
        wired = next(c for c in r.data if c["mac"] == "00:11:22:33:44:55")
        self.assertEqual(wired["agent"]["agent_id"], self.agent.agent_id)
        self.assertEqual(
            [c["mac"] for c in self.client.get("/integrations/clients/?vlan=30").data],
            ["00:11:22:33:44:77"],
        )
        r = self.client.get("/integrations/clients/?search=camera")
        self.assertEqual([c["mac"] for c in r.data], ["00:11:22:33:44:66"])
        r = self.client.get("/integrations/clients/?search=10.0.30")
        self.assertEqual([c["mac"] for c in r.data], ["00:11:22:33:44:77"])
        self.assertEqual(
            self.client.get("/integrations/clients/?vlan=x").status_code, 400
        )

        # a role limited to a site gets the clients of its devices only
        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_sites.set([self.site])
        self.client.force_authenticate(user=user)
        r = self.client.get("/integrations/clients/")
        self.assertEqual([c["mac"] for c in r.data], ["00:11:22:33:44:55"])

        # the nic is gone from the network: the agent's info goes too
        NetworkClient.objects.all().delete()
        answers = network_answers()
        answers[UNIFI + f"{API}/stat/sta"] = {"data": []}
        answers[OPN + "/api/diagnostics/interface/getArp"] = []
        self.run_sync(answers)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.network_info, {})

    def test_api_key_and_optional_opnsense_calls(self):
        turn_on()
        UniFiController.objects.update(api_key=encrypt_secret("the-key", UNIFI_INFO))
        answers = network_answers()
        del answers[UNIFI + "/api/auth/login"]
        del answers[OPN + "/api/dhcpv4/leases/searchLease"]
        del answers[OPN + "/api/diagnostics/interface/getInterfaceConfig"]
        results, calls = self.run_sync(answers)
        self.assertTrue(results["unifi"]["ok"] and results["opnsense"]["ok"])
        unifi = [c for c in calls if c[2].startswith(UNIFI)]
        self.assertEqual(unifi[0][0].headers["X-API-KEY"], "the-key")
        self.assertEqual(
            NetworkClient.objects.get(mac="00:11:22:33:44:77").hostname, "arp-name"
        )
        self.assertEqual(OpnsenseFirewall.get().vlans[0]["subnet"], "")

    def test_errors_are_stored_not_raised(self):
        turn_on()
        answers = network_answers()
        answers[UNIFI + "/api/auth/login"] = Answer({}, 401)
        answers[OPN + "/api/interfaces/vlan_settings/searchItem"] = Answer(
            None, 302, redirect=True
        )
        results, _ = self.run_sync(answers)
        self.assertFalse(results["unifi"]["ok"])
        self.assertIn("refused", results["unifi"]["error"])
        self.assertIn("redirect", results["opnsense"]["error"])
        unifi = UniFiController.get()
        self.assertIn("refused", unifi.last_error)
        self.assertIsNone(unifi.last_sync)
        self.assertEqual(DebugLog.objects.count(), 2)
        self.assertFalse(NetworkClient.objects.exists())

        # unreachable, unreadable secret, html instead of json
        answers = network_answers()
        answers[OPN + "/api/diagnostics/interface/getArp"] = Answer(None)
        UniFiController.objects.update(password="gAAAA-bad")
        results, _ = self.run_sync(answers)
        self.assertIn("can no longer be read", results["unifi"]["error"])
        self.assertIn("did not answer with JSON", results["opnsense"]["error"])

        def down(*args, **kwargs):
            raise requests.ConnectionError("connection refused")

        with patch.object(requests.Session, "request", side_effect=down):
            r = self.client.post("/integrations/sync/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("connection refused", r.data["results"]["opnsense"]["error"])
        self.assertIn("connection refused", r.data["opnsense"]["last_error"])

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("integrations.tasks.sync", return_value={})
    def test_task_lock(self, sync_mock):
        self.assertEqual(sync_integrations_task(), {})
        cache.add(SYNC_LOCK, "x", 60)
        try:
            self.assertIn("still running", sync_integrations_task())
            r = self.client.post("/integrations/sync/")
            self.assertEqual(r.status_code, 400)
        finally:
            cache.delete(SYNC_LOCK)
        sync_mock.assert_called_once()

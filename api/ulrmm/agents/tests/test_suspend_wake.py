# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import ipaddress
import socket
from unittest.mock import AsyncMock, patch

from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import Agent
from agents.utils import magic_packet, reported_nics, send_magic_packet, wake_agents
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType
from ulrmm.exceptions import NatsDown
from ulrmm.test import ULRMMTestCase

base_url = "/agents"


def nics(mac, *ips):
    return {"nics": [{"name": "eth0", "mac": mac, "ips": list(ips)}]}


class TestSuspendWake(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")

    def agent(self, online=True, **kwargs):
        ago = 0 if online else 10
        kwargs.setdefault("site", self.site)
        kwargs.setdefault(
            "last_seen", djangotime.now() - djangotime.timedelta(minutes=ago)
        )
        return baker.make_recipe("agents.agent", **kwargs)

    def bulk(self, mode, agents):
        data = {
            "mode": mode,
            "target": "agents",
            "agents": [a.agent_id for a in agents],
            "monType": "all",
            "osType": "all",
        }
        return self.client.post(f"{base_url}/actions/bulk/", data, format="json")

    def test_magic_packet(self):
        p = magic_packet("00:11:22:AA:bb:cc")
        self.assertEqual(p, b"\xff" * 6 + bytes.fromhex("001122aabbcc") * 16)
        self.assertEqual(len(p), 102)
        for bad in ("", "00:11:22:33:44", "zz:11:22:33:44:55", "00:11:22:33:44:55\n"):
            with self.assertRaises(ValueError):
                magic_packet(bad)

    @patch("agents.utils.socket.socket")
    def test_send_magic_packet_broadcasts(self, sock):
        s = sock.return_value.__enter__.return_value
        send_magic_packet(["00:11:22:33:44:55"], "192.168.178.255")

        s.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto.assert_called_once_with(
            magic_packet("00:11:22:33:44:55"), ("192.168.178.255", 9)
        )

    def test_reported_nics_drops_malformed(self):
        data = [
            {"mac": "00:11:22:33:44:55", "ips": ["192.168.178.20/24", "fe80::1/64"]},
            {"mac": "bad", "ips": ["10.0.0.1/8"]},
            {"mac": "00:11:22:33:44:66", "ips": "10.0.0.1/8"},
            {"mac": "00:11:22:33:44:77", "ips": ["169.254.1.2/16", "10.0.0.1/32"]},
            {"mac": "00:11:22:33:44:88", "ips": [None, {}, "0.0.0.0/0"]},
            "junk",
        ]
        self.assertEqual(
            reported_nics(data),
            [("00:11:22:33:44:55", ipaddress.IPv4Network("192.168.178.0/24"))],
        )
        self.assertEqual(reported_nics(None), [])

    @patch("agents.utils.send_magic_packet")
    @patch("agents.utils.abulk_nats_command", new_callable=AsyncMock)
    @patch("agents.utils.server_networks")
    def test_wake_agents_picks_relays(self, own, abulk, send):
        own.return_value = set()
        lan = "192.168.178.{}/24"
        other_site = baker.make("clients.Site")

        target = self.agent(
            online=False,
            public_ip="1.2.3.4",
            wmi_detail=nics("00:11:22:33:44:01", lan.format(20)),
        )
        # same public ip, or same site, and the same network
        good = [
            self.agent(
                site=other_site,
                public_ip="1.2.3.4",
                hostname=f"r{i}",
                wmi_detail=nics(f"02:00:00:00:00:0{i}", lan.format(30 + i)),
            )
            for i in range(2)
        ]
        good.append(
            self.agent(
                hostname="r2",
                plat=AgentPlat.LINUX,
                wmi_detail=nics("02:00:00:00:00:02", lan.format(32)),
            )
        )
        # mac, only if we still need a relay
        self.agent(
            hostname="mac",
            plat=AgentPlat.DARWIN,
            wmi_detail=nics("02:00:00:00:00:03", lan.format(33)),
        )
        # never: another network, another customer on the same subnet, offline,
        # an agent without NICs (an older one)
        self.agent(
            public_ip="1.2.3.4", wmi_detail=nics("02:00:00:00:00:04", "10.0.0.5/24")
        )
        self.agent(
            site=other_site,
            public_ip="5.6.7.8",
            wmi_detail=nics("02:00:00:00:00:05", lan.format(50)),
        )
        self.agent(online=False, wmi_detail=nics("02:00:00:00:00:06", lan.format(60)))
        self.agent(wmi_detail={"local_ips": [lan.format(70)]})

        sent = wake_agents(Agent.objects.filter(pk=target.pk), self.john)

        self.assertCountEqual(sent[target.pk], ["r0", "r1", "r2"])
        items = abulk.call_args.kwargs["items"]
        self.assertCountEqual([i[0] for i in items], [a.agent_id for a in good])
        for _, data in items:
            self.assertEqual(data, {"func": "wakeonlan", "macs": ["00:11:22:33:44:01"]})
        send.assert_not_called()

        # server sends on its own nets. relays stay in the user's scope.
        # a target that is also online goes last.
        own.return_value = {ipaddress.IPv4Network("192.168.178.0/24")}
        user = self.create_user_with_roles([])
        user.role.can_view_sites.set([self.site])

        both = Agent.objects.filter(pk__in=[target.pk, good[2].pk])
        sent = wake_agents(both, user)

        send.assert_any_call(["00:11:22:33:44:01"], "192.168.178.255")
        self.assertEqual(sent[target.pk], ["server (192.168.178.0/24)", "mac", "r2"])
        self.assertEqual(sent[good[2].pk], ["server (192.168.178.0/24)", "mac"])

        # no NICs reported, nothing to send
        old = self.agent(online=False)
        self.assertEqual(wake_agents(Agent.objects.filter(pk=old.pk), self.john), {})

    @patch("agents.utils.send_magic_packet")
    @patch("agents.utils.abulk_nats_command", new_callable=AsyncMock)
    @patch("agents.utils.server_networks")
    def test_wake_sends_every_reported_mac(self, own, abulk, send):
        own.return_value = {ipaddress.IPv4Network("192.168.178.0/24")}
        # fiber can't WoL; wifi had no lease
        target = self.agent(
            online=False,
            wmi_detail={
                "nics": [
                    {
                        "name": "fiber",
                        "mac": "00:11:22:33:44:01",
                        "ips": ["192.168.178.40/24"],
                    },
                    {
                        "name": "wifi",
                        "mac": "58:10:31:EC:6D:55",
                        "ips": ["169.254.78.237/16"],
                    },
                    {"name": "bad", "mac": "nope", "ips": []},
                ]
            },
        )
        relay = self.agent(
            hostname="r0", wmi_detail=nics("02:00:00:00:00:01", "192.168.178.30/24")
        )

        wake_agents(Agent.objects.filter(pk=target.pk), self.john)

        macs = ["00:11:22:33:44:01", "58:10:31:ec:6d:55"]
        send.assert_called_once_with(macs, "192.168.178.255")
        self.assertEqual(
            abulk.call_args.kwargs["items"],
            [(relay.agent_id, {"func": "wakeonlan", "macs": macs})],
        )

    @patch("agents.utils.send_magic_packet")
    @patch("agents.utils.abulk_nats_command", new_callable=AsyncMock)
    @patch("agents.utils.server_networks", return_value=set())
    def test_wake_agents_needs_a_real_public_ip(self, own, abulk, send):
        lan = "192.168.178.{}/24"
        target = self.agent(
            online=False,
            public_ip="error",
            wmi_detail=nics("00:11:22:33:44:01", lan.format(20)),
        )
        # another customer whose lookup failed the same way
        self.agent(
            site=baker.make("clients.Site"),
            public_ip="error",
            wmi_detail=nics("02:00:00:00:00:01", lan.format(30)),
        )

        sent = wake_agents(Agent.objects.filter(pk=target.pk), self.john)

        self.assertEqual(sent, {target.pk: []})
        abulk.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_suspend_needs_nics(self, nats_cmd):
        nats_cmd.return_value = "ok"
        old = self.agent(wmi_detail={"local_ips": []})
        r = self.client.post(f"{base_url}/{old.agent_id}/suspend/")
        self.assertEqual(r.status_code, 400)
        nats_cmd.assert_not_called()

        agent = self.agent(wmi_detail=nics("00:11:22:33:44:01", "192.168.178.20/24"))
        url = f"{base_url}/{agent.agent_id}/suspend/"
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        nats_cmd.assert_called_with({"func": "suspend"}, timeout=10)

        nats_cmd.return_value = "timeout"
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)

        self.check_not_authenticated("post", url)

    @patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
    @patch("agents.views.wake_on_lan", new_callable=AsyncMock)
    @patch("agents.views.wake_agents")
    def test_wol_native_and_mesh(self, wake, mesh, _):
        agent = self.agent(online=False, mesh_node_id="abcd")
        url = f"{base_url}/{agent.agent_id}/wol/"

        wake.return_value = {agent.pk: ["server (192.168.178.0/24)"]}
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            f"Wake-on-LAN sent to {agent.hostname} via server (192.168.178.0/24), MeshCentral",
        )
        mesh.assert_called_once_with(uri="ws://mesh", mesh_node_ids=["abcd"])

        # mesh error is still 200 if something else sent
        mesh.side_effect = OSError("refused")
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)

        wake.return_value = {}
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "refused")

    @patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
    @patch("agents.views.wake_on_lan", new_callable=AsyncMock)
    @patch("agents.utils.send_magic_packet")
    @patch("agents.utils.abulk_nats_command", new_callable=AsyncMock)
    @patch("agents.utils.server_networks")
    def test_wol_nats_down(self, own, abulk, send, mesh, _):
        abulk.side_effect = NatsDown
        own.return_value = {ipaddress.IPv4Network("192.168.178.0/24")}
        target = self.agent(
            online=False,
            mesh_node_id="abcd",
            wmi_detail=nics("00:11:22:33:44:01", "192.168.178.20/24"),
        )
        self.agent(
            hostname="r0", wmi_detail=nics("02:00:00:00:00:00", "192.168.178.30/24")
        )

        r = self.client.post(f"{base_url}/{target.agent_id}/wol/")

        # nats never reached the relay, so it is not in the result
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            f"Wake-on-LAN sent to {target.hostname} via server (192.168.178.0/24), MeshCentral",
        )
        abulk.assert_called_once()
        send.assert_called_once_with(["00:11:22:33:44:01"], "192.168.178.255")
        mesh.assert_called_once_with(uri="ws://mesh", mesh_node_ids=["abcd"])

    @patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
    @patch("agents.views.wake_on_lan", new_callable=AsyncMock)
    @patch("agents.views.wake_agents")
    def test_bulk_wake_skips_nothing(self, wake, mesh, _):
        agents = [
            self.agent(mesh_node_id="aa01"),
            self.agent(online=False, mesh_node_id="aa02"),
            self.agent(online=False, last_seen=None),
            # "graphical version" is not a node id. keep going.
            self.agent(online=False, mesh_node_id="graphical version"),
        ]
        wake.return_value = {agents[1].pk: ["r0"], agents[2].pk: []}

        user = self.create_user_with_roles(["can_run_bulk"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.bulk("wake", agents).status_code, 403)
        user.role.can_send_wol = True
        user.role.save()

        r = self.bulk("wake", agents)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            "Wake-on-LAN sent for 4 agents: 1 from the server or a neighbor agent, "
            "2 through MeshCentral",
        )
        self.assertCountEqual(wake.call_args.args[0], agents)
        self.assertCountEqual(mesh.call_args.kwargs["mesh_node_ids"], ["aa01", "aa02"])
        audit = AuditLog.objects.get(action=AuditActionType.BULK_ACTION)
        self.assertTrue(audit.message.endswith("sent to 4 agents"), audit.message)

    @patch("agents.views.abulk_nats_command", new_callable=AsyncMock)
    def test_bulk_suspend_online_only(self, abulk):
        new = self.agent(wmi_detail=nics("00:11:22:33:44:01", "10.0.0.2/24"))
        self.agent(online=False, wmi_detail=nics("00:11:22:33:44:02", "10.0.0.3/24"))
        old = self.agent(wmi_detail={"local_ips": []})
        agents = Agent.objects.all()

        user = self.create_user_with_roles(["can_run_bulk"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.bulk("suspend", agents).status_code, 403)
        user.role.can_reboot_agents = True
        user.role.save()

        r = self.bulk("suspend", agents)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            "1 agents will now go to sleep, 1 offline agents were skipped, "
            "1 agents need the agent update first",
        )
        abulk.assert_called_once_with(items=[(new.agent_id, {"func": "suspend"})])
        self.assertNotIn(old.agent_id, str(abulk.call_args))

        # all old agents: not the empty-selection error
        r = self.bulk("suspend", [old, self.agent(wmi_detail=None)])
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data,
            "No agent meeting the selected criteria can go to sleep, "
            "2 agents need the agent update first",
        )
        abulk.assert_called_once()

    @patch("agents.views.get_mesh_ws_url", return_value="ws://mesh")
    @patch("agents.views.wake_on_lan", new_callable=AsyncMock)
    @patch("agents.views.wake_agents", return_value={})
    @patch("agents.models.Agent.nats_cmd", return_value="ok")
    def test_single_power_actions_are_audited(self, nats_cmd, *_):
        agent = self.agent(
            mesh_node_id="abcd",
            wmi_detail=nics("00:11:22:33:44:01", "192.168.178.20/24"),
        )
        for action, path in (
            ("suspend", "suspend"),
            ("shutdown", "shutdown"),
            ("reboot", "reboot"),
            ("wake", "wol"),
        ):
            r = self.client.post(f"{base_url}/{agent.agent_id}/{path}/")
            self.assertEqual(r.status_code, 200, action)
            audit = AuditLog.objects.latest("id")
            self.assertEqual(audit.agent_id, agent.agent_id)
            self.assertEqual(audit.username, "john")
            self.assertEqual(audit.after_value, {"mode": action})
            self.assertEqual(
                audit.message, f"john executed {action} on {agent.hostname}"
            )
            self.assertIn("ip", audit.debug_info)
        self.assertEqual(AuditLog.objects.count(), 4)

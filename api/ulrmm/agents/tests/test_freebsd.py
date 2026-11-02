# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""FreeBSD agents and the TrueNAS SCALE layout, server side."""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from django.conf import settings
from django.test import override_settings
from model_bakery import baker

from agents.consumers import InvalidTerminalShellError, TerminalStreamConsumer
from agents.models import _shell_for
from agents.perf import parse_perf, perf_command
from agents.utils import render_linux_install
from agents.views import _shell_error
from apiv3.views import MESH_IDENTS
from automation.models import _check_key
from checks.health import evaluate
from checks.models import Check
from core.serializers import CoreSettingsSerializer
from metrics.state import clean_state
from ulrmm.agent_ident import agent_artifact, agent_ident, nix_rc_name
from ulrmm.constants import AgentPlat, CheckType, MeshAgentIdent
from ulrmm.test import ULRMMTestCase
from winupdate.posix import managed_reason

TRUENAS = {"appliance": {"name": "TrueNAS", "version": "25.04.2.6"}}

# sh -c output of perf_command("freebsd") on the FreeBSD 14.4 VM
VM_PERF = """kern.cp_time: 20360 0 15336 386 460109
kern.cp_time: 20360 0 15344 387 460632
hw.physmem: 2104963072
vm.stats.vm.v_page_size: 4096
vm.stats.vm.v_free_count: 343569
vm.stats.vm.v_inactive_count: 23307
vm.stats.vm.v_cache_count: 0
"""


def test_rc_name():
    assert nix_rc_name(agent_ident()) == "ulrmm_agent"
    assert nix_rc_name({"identNixSvc": "my-rmm-agent.service"}) == "my_rmm_agent"


def test_shells():
    assert _shell_for(AgentPlat.FREEBSD, "", "") == "sh"
    assert _shell_for(AgentPlat.FREEBSD, "BASH", "") == "bash"
    assert _shell_for(AgentPlat.FREEBSD, "powershell", "") == "sh"
    assert _shell_for(AgentPlat.FREEBSD, "custom", "/usr/local/bin/zsh") == (
        "/usr/local/bin/zsh"
    )
    assert _shell_for(AgentPlat.FREEBSD, "custom", "zsh") == "sh"
    # Linux and macOS keep bash only
    assert _shell_for(AgentPlat.LINUX, "sh", "") == "bash"
    assert _shell_for(AgentPlat.DARWIN, "sh", "") == "bash"

    consumer = TerminalStreamConsumer()
    assert consumer._resolve_explicit_shell("sh", AgentPlat.FREEBSD) == "sh"
    assert consumer._resolve_explicit_shell("bash", AgentPlat.FREEBSD) == "bash"
    assert consumer._resolve_explicit_shell("/bin/csh", AgentPlat.FREEBSD) == (
        "/bin/csh"
    )
    for shell, plat in (("cmd", AgentPlat.FREEBSD), ("sh", AgentPlat.LINUX)):
        with pytest.raises(InvalidTerminalShellError):
            consumer._resolve_explicit_shell(shell, plat)
    assert consumer._resolve_default_shell("cmd", AgentPlat.FREEBSD) == "sh"


def test_perf_on_vm_output():
    shell, command = perf_command(AgentPlat.FREEBSD)
    assert shell == "/bin/sh"
    assert command.count("sysctl kern.cp_time") == 2
    assert "sleep 1" in command
    # busy ticks 9 of 532, (2104963072 - 366876 pages * 4096) used
    assert parse_perf(AgentPlat.FREEBSD, VM_PERF) == {
        "cpu_percent": 1.7,
        "mem_total": 2104963072,
        "mem_used": 602238976,
        "mem_percent": 28.6,
    }
    # newer releases drop v_cache_count, sysctl warns and prints the rest
    newer = VM_PERF.replace(
        "vm.stats.vm.v_cache_count: 0",
        "sysctl: unknown oid 'vm.stats.vm.v_cache_count'",
    )
    assert parse_perf(AgentPlat.FREEBSD, newer)["mem_used"] == 602238976
    no_mem = parse_perf(AgentPlat.FREEBSD, VM_PERF.split("hw.physmem")[0])
    assert no_mem["cpu_percent"] == 1.7
    assert no_mem["mem_total"] is None


def test_security_is_report_only():
    health = {"v": 1, "av": [], "firewall": {"enabled": False}}
    status, severity, text = evaluate("security", AgentPlat.FREEBSD, health, 3, 7)
    assert (status, severity) == ("passing", None)
    assert text.startswith("OK: FreeBSD, not alerted: antivirus none, firewall off")
    status, _, text = evaluate("security", AgentPlat.LINUX, health, 3, 7)
    assert status == "passing"
    assert text.startswith("OK: Linux, not alerted")


def test_mesh_idents():
    assert MESH_IDENTS[("amd64", "freebsd")] == MeshAgentIdent.FREEBSD64
    assert MeshAgentIdent.FREEBSD64.value == 30
    assert ("arm64", "freebsd") not in MESH_IDENTS


def test_state_accepts_freebsd_values():
    state = clean_state(
        {
            "v": 1,
            "system": {
                "manager": "rc.d",
                "raid": [{"kind": "gmirror", "name": "gm0", "health": "ok"}],
                "sensors": [
                    {"kind": "temp", "source": "sysctl", "name": "cpu0", "value": 41.0}
                ],
            },
        }
    )
    system = state["system"]
    assert system["manager"] == "rc.d"
    assert system["raid"][0]["kind"] == "gmirror"
    assert system["sensors"][0]["source"] == "sysctl"


class TestFreeBSDServer(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.bsd = baker.make_recipe(
            "agents.online_agent",
            plat=AgentPlat.FREEBSD,
            goarch="amd64",
            agent_ident="ulrmm-agent",
        )
        self.linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        self.win = baker.make_recipe("agents.online_agent")

    def test_posix_and_default_shell(self):
        self.assertTrue(self.bsd.is_posix)
        self.assertEqual(self.bsd.effective_default_shell, "sh")
        self.assertEqual(self.bsd.resolved_default_shell, "sh")
        self.coresettings.default_shell_freebsd = "bash"
        self.coresettings.save()
        self.assertEqual(self.bsd.effective_default_shell, "bash")
        self.bsd.default_shell = "sh"
        self.assertEqual(self.bsd.effective_default_shell, "sh")

        attrs = {"default_shell": "SH"}
        self.assertIsNone(_shell_error(self.bsd, attrs))
        self.assertEqual(attrs["default_shell"], "sh")
        self.assertIn(
            "Linux",
            _shell_error(self.linux, {"default_shell": "sh"})["default_shell"][0],
        )
        self.assertIn(
            "default_shell_custom",
            _shell_error(self.bsd, {"default_shell": "custom"}),
        )

    def test_core_settings_custom_shell_needs_a_path(self):
        serializer = CoreSettingsSerializer(
            instance=self.coresettings,
            data={"default_shell_freebsd": "custom"},
            partial=True,
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("default_shell_freebsd_custom", serializer.errors)

    @patch("agents.models.send_command_with_mesh", new_callable=AsyncMock)
    def test_recover_restarts_the_rc_service(self, mesh):
        self.assertEqual(self.bsd.recover("agent", "wss://mesh"), ("ok", False))
        cmd, _, _, shell, _ = mesh.call_args.args
        self.assertEqual((cmd, shell), ("service ulrmm_agent onerestart", 3))

    def _install(self, **body):
        data = {
            "installMethod": "freebsd",
            "client": self.site.client_id,
            "site": self.site.pk,
            "expires": 24,
            "agenttype": "server",
            "plat": "freebsd",
            "goarch": "amd64",
            "api": "https://api.example.test",
            "rdp": 0,
            "ping": 0,
            "power": 0,
            **body,
        }
        return self.client.post("/agents/installer/", data, format="json")

    def test_install_script(self):
        self.site = baker.make("clients.Site")
        dist = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, dist, ignore_errors=True)
        name = agent_artifact(settings.LATEST_AGENT_VER, "freebsd", "amd64")
        (dist / name).write_bytes(b"\x7fELF freebsd build")

        with override_settings(AGENTS_DIST_DIR=str(dist), SELF_BUILT_AGENTS_URL=""):
            r = self._install()
        self.assertEqual(r.status_code, 200)
        self.assertIn("freebsd_agent_install.sh", r["Content-Disposition"])
        text = b"".join(r.streaming_content).decode()
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertRegex(text, rf"agentDL='https://[^']+/agentdist/{name}'")
        self.assertRegex(text, r"agentSha256='[0-9a-f]{64}'")
        self.assertIn("agentBin='/usr/local/bin/ulrmm-agent'", text)
        self.assertIn("healName='ulrmm-agent-selfheal'", text)
        self.assertNotRegex(text, r"[A-Za-z]+Change'|identNix")
        if shutil.which("sh"):
            check = subprocess.run(
                ["sh", "-n"], input=text, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(check.returncode, 0, check.stderr)

        for body, message in (
            ({"goarch": "386"}, "amd64 and arm64"),
            ({"goarch": "arm"}, "amd64 and arm64"),
            ({"installMethod": "bash"}, "FreeBSD method"),
            ({"installMethod": "manual"}, "FreeBSD method"),
            ({"plat": "linux"}, "FreeBSD method"),
        ):
            r = self._install(**body)
            self.assertEqual(r.status_code, 400, body)
            self.assertIn(message, r.data)

    def test_mac_one_liner_checks_the_download(self):
        self.site = baker.make("clients.Site")
        body = {"installMethod": "mac", "plat": "darwin", "goarch": "arm64"}
        r = self._install(**body)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("shasum", r.data["cmd"])

        dist = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, dist, ignore_errors=True)
        name = agent_artifact(settings.LATEST_AGENT_VER, "darwin", "arm64")
        (dist / name).write_bytes(b"mach-o")
        with override_settings(AGENTS_DIST_DIR=str(dist), SELF_BUILT_AGENTS_URL=""):
            r = self._install(**body)
        cmd = r.data["cmd"]
        self.assertRegex(
            cmd,
            rf"^curl -fL --proto '=https' --proto-redir '=https' -o {name} '[^']+' && "
            rf"echo '[0-9a-f]{{64}}  {name}' \| shasum -a 256 -c && chmod \+x {name} && ",
        )
        # the token goes through a root-only file, printf is a shell builtin
        self.assertRegex(
            cmd,
            r"&& f=\$\(sudo mktemp\) && printf '%s' '[0-9a-f]{64}' \| "
            rf'sudo tee "\$f" >/dev/null && sudo \./{name} -m install .* -auth-file "\$f"$',
        )
        self.assertNotIn("--auth", cmd)

    @patch("agents.views.sync_mesh_perms_task")
    @patch("agents.views.reload_nats")
    @patch("agents.views._ask", return_value="pong")
    @patch("agents.views.verify_fresh_totp", return_value=True)
    @patch("agents.models.Agent.nats_cmd")
    def test_delete_sends_the_freebsd_script(self, nats_cmd, *_):
        r = self.client.delete(
            f"/agents/{self.bsd.agent_id}/", {"totp_code": "1"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        data = nats_cmd.call_args.args[0]
        self.assertEqual(data["func"], "uninstall")
        self.assertIn("agent installer for FreeBSD", data["code"])
        self.assertIn("agentSvcName='ulrmm-agent.service'", data["code"])

    @patch("apiv3.views.download_mesh_agent")
    @patch("apiv3.views._mesh_device_id", return_value=("grp", None))
    def test_meshexe(self, _, download):
        from django.http import HttpResponse

        download.return_value = HttpResponse(b"mesh")
        from knox.models import AuthToken

        from accounts.models import User
        from clients.models import InstallerToken

        installer = User.objects.filter(is_installer_user=True).first()
        auth_token, token = AuthToken.objects.create(user=installer)
        InstallerToken.objects.create(
            auth_token=auth_token, site=baker.make("clients.Site")
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        r = self.client.post(
            "/api/v3/meshexe/", {"goarch": "arm64", "plat": "freebsd"}, format="json"
        )
        self.assertEqual((r.status_code, r.data), (400, "Arch not supported"))
        self.client.post(
            "/api/v3/meshexe/", {"goarch": "amd64", "plat": "freebsd"}, format="json"
        )
        self.assertIn("meshinstall=30", download.call_args.args[0])

    @patch("agents.models.Agent.nats_cmd")
    def test_nix_logs_and_own_service(self, nats_cmd):
        nats_cmd.return_value = {"lines": []}
        r = self.client.get(f"/nix/{self.bsd.agent_id}/logs/")
        self.assertEqual(r.status_code, 200)
        payload = nats_cmd.call_args.kwargs["data"]["payload"]
        self.assertEqual(
            (payload["source"], payload["path"]), ("file", "/var/log/messages")
        )
        r = self.client.get(f"/nix/{self.bsd.agent_id}/logs/?path=/var/log/auth.log")
        payload = nats_cmd.call_args.kwargs["data"]["payload"]
        self.assertEqual(payload["path"], "/var/log/auth.log")
        # Linux keeps the journal
        self.client.get(f"/nix/{self.linux.agent_id}/logs/")
        self.assertEqual(
            nats_cmd.call_args.kwargs["data"]["payload"]["source"], "journal"
        )

        nats_cmd.return_value = "timeout"
        r = self.client.post(
            f"/nix/{self.bsd.agent_id}/services/ulrmm_agent/",
            {"action": "restart"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("restarting its own service", r.data)

    def test_service_checks(self):
        def add(agent, name):
            return self.client.post(
                "/checks/",
                {"agent": agent.agent_id, "check_type": "systemd", "svc_name": name},
                format="json",
            )

        self.assertEqual(add(self.bsd, "sshd").status_code, 200)
        self.assertEqual(add(self.linux, "sshd").status_code, 200)
        names = dict(
            Check.objects.filter(check_type=CheckType.SYSTEMD).values_list(
                "agent__plat", "svc_name"
            )
        )
        self.assertEqual(names, {"freebsd": "sshd", "linux": "sshd.service"})
        r = add(self.win, "sshd")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data, "Service checks are only supported on Linux and FreeBSD agents"
        )

        policy_check = Check(check_type=CheckType.SYSTEMD, svc_name="sshd.service")
        self.assertEqual(
            _check_key(policy_check, self.bsd), ("systemd", "sshd.service")
        )
        self.assertIsNone(_check_key(policy_check, self.win))

    def test_features_without_freebsd_support(self):
        from appupdates.tasks import PLATS as APP_PLATS
        from encryption.utils import COLLECTORS
        from laps.tasks import library_script
        from packages.models import PLATS as PACKAGE_PLATS
        from remote.utils import unsupported_reason

        self.assertEqual(
            unsupported_reason(self.bsd, probe=False),
            "There is no RustDesk client for freebsd/amd64.",
        )
        self.assertIsNone(library_script(AgentPlat.FREEBSD))
        self.assertNotIn(AgentPlat.FREEBSD, COLLECTORS)
        self.assertNotIn(AgentPlat.FREEBSD, APP_PLATS)
        # FreeBSD packages are .pkg files like macOS ones, none are offered
        self.assertNotIn(AgentPlat.FREEBSD, PACKAGE_PLATS.values())

    def test_task_cmd_defaults_to_sh(self):
        from autotasks.serializers import TaskGOGetSerializer

        task = baker.make(
            "autotasks.AutomatedTask",
            agent=self.bsd,
            actions=[{"type": "cmd", "command": "uptime", "timeout": 30}],
        )
        data = TaskGOGetSerializer(task, context={"agent": self.bsd}).data
        self.assertEqual(data["task_actions"][0]["shell"], "/bin/sh")
        data = TaskGOGetSerializer(task, context={"agent": self.linux}).data
        self.assertEqual(data["task_actions"][0]["shell"], "/bin/bash")


class TestTrueNAS(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.nas = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, wmi_detail=TRUENAS
        )
        self.linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)

    def test_appliance(self):
        self.assertEqual(self.nas.appliance, "TrueNAS")
        self.assertEqual(self.linux.appliance, "")
        self.assertEqual(
            managed_reason(self.nas), "package updates are managed by TrueNAS"
        )
        self.assertEqual(managed_reason(self.linux), "")
        # a Windows agent never reports one; a stray field changes nothing
        win = baker.make_recipe("agents.online_agent", wmi_detail=TRUENAS)
        self.assertEqual(managed_reason(win), "")
        for odd in ({"appliance": "TrueNAS"}, {"appliance": {"name": 5}}, []):
            self.linux.wmi_detail = odd
            self.assertEqual(self.linux.appliance, "")

    @patch("software.views.posix_uninstall_task.delay")
    @patch("winupdate.views.posix_install_updates_task.delay")
    @patch("winupdate.views.posix_refresh_task.delay")
    def test_package_actions_refused(self, refresh, install, uninstall):
        reason = "package updates are managed by TrueNAS"
        for url, data in (
            (f"/winupdate/{self.nas.agent_id}/scan/", {}),
            (f"/winupdate/{self.nas.agent_id}/install/", {}),
            (
                f"/software/{self.nas.agent_id}/uninstall/",
                {"name": "curl", "source": "dpkg"},
            ),
        ):
            r = self.client.post(url, data, format="json")
            self.assertEqual((r.status_code, r.data), (400, reason), url)
        refresh.assert_not_called()
        install.assert_not_called()
        uninstall.assert_not_called()

        r = self.client.post(f"/winupdate/{self.linux.agent_id}/scan/", format="json")
        self.assertEqual(r.status_code, 200)
        refresh.assert_called_once_with(self.linux.pk, "scan")

    def test_bulk_skips_truenas(self):
        from winupdate.tasks import _bulk_agents

        pks = [a.pk for a in _bulk_agents([self.nas.pk, self.linux.pk])]
        self.assertEqual(pks, [self.linux.pk])


def _linux_script() -> str:
    with patch("core.utils.get_branding") as branding:
        branding.return_value.product_name = 'Acme "Ops" RMM'
        return _render()


def _render() -> str:
    return render_linux_install(
        download_url="https://api.example.test/agentdist/a",
        sha256="",
        mesh_url="https://mesh.example.test/meshagents?id=1",
        client="1",
        site="1",
        agent_type="server",
        token="t",
        api="https://api.example.test",
    )


def _function(text: str, name: str) -> str:
    return re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M).group(0)


def test_linux_installer_truenas_layout():
    text = _linux_script()
    assert "agentHome='/root/ulrmm-agent'" in text
    assert 'agentConf="${agentHome}/ulrmm-agent.conf"' in text
    assert "meshDir='/root/ulrmm-mesh'" in text
    assert 'healCmd="${agentHome}/selfheal/ulrmm-agent -m selfheal"' in text
    assert _function(text, "is_truenas") == (
        "is_truenas() {\n  [ -e /data/manifest.json ] && [ -e /usr/bin/midclt ]\n}\n"
    )
    # byte for byte the unit the agent restores (trueNASMeshUnit)
    unit = re.search(r'cat >"\$meshSvcFile" <<UNIT\n(.*?)^UNIT$', text, re.S | re.M)
    assert unit.group(1) == (
        "[Unit]\nDescription=Mesh Agent\n\n[Service]\nWorkingDirectory=${meshDir}\n"
        "ExecStart=${meshBin}\nStandardOutput=null\nRestart=always\nRestartSec=3\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


@pytest.mark.skipif(
    not shutil.which("bash") or not shutil.which("python3"),
    reason="needs bash and python3",
)
def test_linux_installer_postinit(tmp_path):
    text = _linux_script()
    log = tmp_path / "midclt.log"
    # a stand-in for midclt: query answers from a file, every call is logged
    runner = (
        "".join(
            _function(text, name)
            for name in ("postinit_ids", "register_postinit", "remove_postinit")
        )
        + f"""midclt() {{ printf '%s\\n' "$*" >>{log}; [ "$2" = initshutdownscript.query ] && cat {tmp_path}/rows; return 0; }}
healCmd=/root/ulrmm-agent/selfheal/ulrmm-agent' -m selfheal'
"""
        + re.search(r"^agentBrand=.*$", text, re.M).group(0)
        + '\n"$@"\n'
    )

    def run(*args, rc=0):
        r = subprocess.run(
            ["bash", "-c", runner, "bash", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == rc, r.stderr
        calls = log.read_text().splitlines() if log.exists() else []
        log.unlink(missing_ok=True)
        return calls

    (tmp_path / "rows").write_text("[]")
    query, create = run("register_postinit")
    # like the agent, only a POSTINIT entry counts
    assert json.loads(query.split(" ", 2)[2]) == [
        ["command", "=", "/root/ulrmm-agent/selfheal/ulrmm-agent -m selfheal"],
        ["when", "=", "POSTINIT"],
    ]
    assert create.startswith("call initshutdownscript.create ")
    assert json.loads(create.split(" ", 2)[2]) == {
        "type": "COMMAND",
        "command": "/root/ulrmm-agent/selfheal/ulrmm-agent -m selfheal",
        "when": "POSTINIT",
        "enabled": True,
        "timeout": 120,
        "comment": 'Acme "Ops" RMM Agent',
    }

    (tmp_path / "rows").write_text('[{"id": 7}, {"id": 9}]')
    assert len(run("register_postinit")) == 1
    removed = run("remove_postinit")
    # every entry with the command goes, whatever its "when"
    assert json.loads(removed[0].split(" ", 2)[2]) == [
        ["command", "=", "/root/ulrmm-agent/selfheal/ulrmm-agent -m selfheal"]
    ]
    assert removed[1:] == [
        "call initshutdownscript.delete 7",
        "call initshutdownscript.delete 9",
    ]
    # a failed query never registers a second entry
    (tmp_path / "rows").write_text("not json")
    assert len(run("register_postinit", rc=1)) == 1


def test_brand_agent_name_matches_the_build():
    from importlib.util import module_from_spec, spec_from_file_location

    from ulrmm.agent_ident import brand_agent_name

    path = settings.BASE_DIR.parent.parent / "riddix" / "agents" / "write_brand.py"
    spec = spec_from_file_location("write_brand", path)
    write_brand = module_from_spec(spec)
    spec.loader.exec_module(write_brand)
    for product in ("UniversalLocal RMM", "", "  Acme\tRMM  ", 'Acme "Ops"', None):
        with patch("core.utils.get_branding") as branding:
            branding.return_value.product_name = product
            assert brand_agent_name() == (
                write_brand.brand_values(product, "")["BrandAgentName"]
            ), product
    with patch("core.utils.get_branding") as branding:
        branding.return_value.product_name = "UniversalLocal RMM"
        assert "agentBrand='UniversalLocal RMM Agent'" in _render()


def _freebsd_function(name: str) -> str:
    return _function(Path(settings.FREEBSD_AGENT_SCRIPT).read_text(), name)


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("od"), reason="needs sh and od"
)
def test_freebsd_installer_download_checks(tmp_path):
    def elf(abi: int, machine: int) -> bytes:
        head = bytearray(64)
        head[:4] = b"\x7fELF"
        head[7], head[18] = abi, machine
        return bytes(head)

    cases = {
        "amd64": elf(9, 62),
        "arm64": elf(9, 183),
        "linux": elf(0, 62),
        "riscv": elf(9, 243),
        "html": b"<!DOCTYPE html><title>x</title>",
    }
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
    # the download is a copy; sha256(1) is FreeBSD only, so no sha here
    runner = (
        'die() { echo "ERROR: $*"; exit 1; }\n'
        + 'limited() { "$@"; }\n'
        # fetch -A -q -T 30 -o <dest> <url>: no redirects
        + 'fetch() { [ "$1" = -A ] || exit 7; cp "${7#https://}" "$6"; }\n'
        + "command() { return 1; }\n"
        + _freebsd_function("fetch_binary")
        + 'machine=62\nfetch_binary agent "${3:-https://}$1" "$2" ""\necho PASS\n'
    )

    def run(name, scheme="https://"):
        r = subprocess.run(
            [
                "sh",
                "-c",
                runner,
                "sh",
                str(tmp_path / name),
                str(tmp_path / "out"),
                scheme,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.stdout.strip()

    assert run("amd64") == "PASS"
    assert "is built for arm64, this system is" in run("arm64")
    assert "is built for ELF machine 243" in run("riscv")
    assert "is not a FreeBSD program (ELF OS ABI 0)" in run("linux")
    assert "is not a program, it starts with: <!DOCTYPE html>" in run("html")
    assert "download is not an https url: http://" in run("amd64", "http://")
    assert not (tmp_path / "out").exists()


def test_freebsd_installer_keeps_the_log_on_reinstall():
    text = Path(settings.FREEBSD_AGENT_SCRIPT).read_text()
    assert "agentLog" not in _freebsd_function("remove_agent")
    assert '"/var/run/${rcName}.pid"' in _freebsd_function("remove_agent")
    uninstall = re.search(r"^uninstall \| .*?;;$", text, re.S | re.M).group(0)
    assert 'rm -f "$agentLog" "${agentLog}.1" "${agentLog}.2"' in uninstall

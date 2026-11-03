# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import InvalidToken
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from agents.utils import get_agents_dist_url
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType, AuditObjType, GoArch
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.throttles import VaultRevealThrottle
from ulrmm.utils import get_db_value

from .models import RustDeskPeer, RustDeskSettings
from .views import RevealRustDeskPassword
from .utils import (
    CLIENT_NAMES,
    DEPLOY_SCRIPTS,
    DEPLOY_TIMEOUT,
    INSTALLERS,
    VIEWER_DOWNLOADS,
    DeployError,
    PasswordNotSent,
    config_string,
    connect_uri,
    decrypt_secret,
    encrypt_secret,
    new_password,
    parse_deploy_output,
    pinned_client,
    render_deploy,
    update_available,
    version_key,
)

# pinned by migration 0002
CLIENT_VERSION = "1.4.9"

KEY = "5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM="
# src/custom_server.rs, test_filename_license_string: this string decodes to
# host "1.1.1.1" and the key above
CLIENT_FIXTURE = (
    "0nI900VsFHZVBVdIlncwpHS4V0bOZ0dtVldrpVO4JHdCp0YV5WdzUGZzdnYRVjI6ISeltmIs"
    "ISMuEjLx4SMiojI0N3boJye"
)


def template_failures() -> set[str]:
    """Fixed RUSTDESK_FAIL strings the templates can emit."""
    reasons = set()
    for plat, path in DEPLOY_SCRIPTS.items():
        text = path.read_text()
        if plat == AgentPlat.WINDOWS:
            prefix = re.search(r"\$prefix = '(.+)'", text)[1]
            setup, rest = text.split("$prefix = ''")
            throws = r"throw \(?'([^']*)'"
            reasons |= {prefix + r for r in re.findall(throws, setup)}
            # any exception up to there, e.g. from Invoke-WebRequest
            reasons.add(prefix + "Unable to connect to the remote server")
            reasons |= set(re.findall(throws, rest))
        else:
            reasons |= set(re.findall(r'\bfail "([^"$]*)', text))
    return reasons


def ran(stdout, stderr="", retcode=0):
    """What nats_cmd returns for runscriptfull (RunScriptResp)."""
    return {
        "stdout": stdout,
        "stderr": stderr,
        "retcode": retcode,
        "execution_time": 1.0,
        "id": 0,
    }


class KeyFileMixin:
    def use_key_file(self, key: str = KEY, version: str = "1.1.16") -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "id_ed25519.pub"
        if key:
            path.write_text(key + "\n")
            (Path(tmp.name) / "version").write_text(version + "\n")
        override = override_settings(RUSTDESK_KEY_FILE=str(path))
        override.enable()
        self.addCleanup(override.disable)


class TestSecrets(ULRMMTestCase):
    def test_round_trip_and_ciphertext(self):
        password = new_password()
        self.assertRegex(password, r"^[A-Za-z0-9]{24}$")
        self.assertNotEqual(password, new_password())

        token = encrypt_secret(password)
        self.assertNotIn(password, token)
        self.assertEqual(decrypt_secret(token), password)

        agent = baker.make_recipe("agents.agent")
        RustDeskPeer.objects.create(agent=agent, password=token)
        stored = RustDeskPeer.objects.values_list("password", flat=True).get()
        self.assertNotIn(password, stored)
        self.assertEqual(decrypt_secret(stored), password)

        with override_settings(SECRET_KEY="another-secret-key"):
            with self.assertRaises(InvalidToken):
                decrypt_secret(token)

    def test_peer_is_a_credential_model(self):
        agent = baker.make_recipe("agents.agent")
        RustDeskPeer.objects.create(agent=agent, password=encrypt_secret("x"))
        self.assertIsNone(
            get_db_value(string="agent.rustdesk_peer.password", instance=agent)
        )


class TestConfigString(ULRMMTestCase):
    def test_client_fixture(self):
        self.assertEqual(config_string("1.1.1.1", "", KEY), CLIENT_FIXTURE)

    def test_decodes_like_the_client(self):
        s = config_string("rd.example.com:21116", "relay.example.com", KEY)
        # what get_custom_server_from_config_string does: reverse, base64url
        # without padding, JSON
        self.assertNotIn("=", s)
        self.assertNotIn("--", s)
        raw = s[::-1]
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        self.assertEqual(
            data,
            {"host": "rd.example.com:21116", "relay": "relay.example.com", "key": KEY},
        )


class TestConnectUri(ULRMMTestCase):
    def test_key_and_password_survive_query_decoding(self):
        uri = connect_uri("123456789", "192.168.178.3", KEY, "aB3dE5gH7jK9mN1pQ3sT5vW7")
        self.assertTrue(
            uri.startswith("rustdesk://connection/new/123456789@192.168.178.3?")
        )
        # client decodes the query; a raw "+" becomes a space
        self.assertNotIn("+", uri)
        parts = urlsplit(uri)
        self.assertEqual(parts.path, "/new/123456789@192.168.178.3")
        query = parse_qs(parts.query, strict_parsing=True)
        self.assertEqual(query["key"], [KEY])
        self.assertEqual(query["password"], ["aB3dE5gH7jK9mN1pQ3sT5vW7"])

    def test_host_with_port(self):
        uri = connect_uri("123456789", "rd.example.com:21116", KEY, "x" * 24)
        self.assertIn("/new/123456789@rd.example.com:21116?key=", uri)


class TestRustDeskSettings(KeyFileMixin, ULRMMTestCase):
    url = "/core/rustdesk/"

    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_get_does_not_write(self):
        self.use_key_file(key="")
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {
                "enabled": False,
                "id_server": "",
                "relay_server": "",
                "public_key": "",
                "key_present": False,
                "config_string": "",
                "server_version": "",
                "auto_update_server": False,
                "auto_update_clients": False,
            },
        )
        self.assertFalse(RustDeskSettings.objects.exists())
        self.check_not_authenticated("get", self.url)

    def test_get_with_key(self):
        self.use_key_file()
        RustDeskSettings.objects.create(pk=1, enabled=True, id_server="1.1.1.1")
        r = self.client.get(self.url)
        self.assertEqual(r.data["public_key"], KEY)
        self.assertTrue(r.data["key_present"])
        self.assertEqual(r.data["config_string"], CLIENT_FIXTURE)
        self.assertEqual(r.data["server_version"], "1.1.16")

    def test_put_validation_and_audit(self):
        self.use_key_file()
        for data in (
            {"enabled": True, "id_server": ""},
            {"id_server": "rd.example.com'; id"},
            {"id_server": "rd.example.com:70000"},
            {"relay_server": "a b"},
        ):
            r = self.client.put(self.url, data, format="json")
            self.assertEqual(r.status_code, 400, data)
        self.assertFalse(RustDeskSettings.objects.exists())
        self.assertFalse(AuditLog.objects.exists())

        data = {"enabled": True, "id_server": "192.168.178.3", "relay_server": ""}
        r = self.client.put(self.url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["id_server"], "192.168.178.3")
        self.assertTrue(r.data["enabled"])
        self.assertEqual(
            r.data["config_string"], config_string("192.168.178.3", "", KEY)
        )
        self.assertEqual(set(r.data), set(self.client.get(self.url).data))
        self.assertEqual(RustDeskSettings.objects.get().pk, 1)

        audit = AuditLog.objects.get()
        self.assertEqual(audit.object_type, AuditObjType.CORE)
        self.assertEqual(audit.action, AuditActionType.MODIFY)
        self.assertIn("RustDesk", audit.message)
        self.assertEqual(audit.after_value["id_server"], "192.168.178.3")

        # nothing changed, nothing logged
        self.client.put(self.url, data, format="json")
        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(RustDeskSettings.objects.count(), 1)

    def test_permissions(self):
        self.use_key_file()
        user = self.create_user_with_roles([])
        self.client.force_authenticate(user=user)
        self.check_not_authorized("get", self.url)
        self.check_not_authorized("put", self.url, {"enabled": False})

        user.role.can_view_core_settings = True
        user.role.save()
        self.check_authorized("get", self.url)
        self.check_not_authorized("put", self.url, {"enabled": False})

        user.role.can_edit_core_settings = True
        user.role.save()
        self.check_authorized("put", self.url, {"enabled": False})


@override_settings(SELF_BUILT_AGENTS_URL="https://rmm.example.com/agentdist")
class TestAgentRustDesk(KeyFileMixin, ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.use_key_file()
        RustDeskSettings.objects.create(pk=1, enabled=True, id_server="rd.example.com")
        self.agent = self.make_agent(AgentPlat.WINDOWS, GoArch.AMD64)

    def make_agent(self, plat, goarch, **kwargs):
        return baker.make_recipe(
            "agents.agent",
            plat=plat,
            goarch=goarch,
            last_seen=djangotime.now(),
            **kwargs,
        )

    def url(self, agent, action=""):
        return f"/agents/{agent.agent_id}/rustdesk/{action}"

    def deploy(self, agent, nats_cmd, reply):
        nats_cmd.reset_mock(side_effect=True)
        nats_cmd.return_value = reply
        return self.client.post(self.url(agent, "deploy/"), format="json")

    def assert_no_secret(self, password):
        for row in AuditLog.objects.values():
            self.assertNotIn(password, json.dumps(row, default=str))

    def test_status(self):
        r = self.client.get(self.url(self.agent))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {
                "available": True,
                "supported": True,
                "installed": False,
                "rustdesk_id": "",
                "password_set": False,
                "client_version": "",
                "latest_version": CLIENT_VERSION,
                "update_available": False,
                "deployed_at": None,
                "last_error": "",
                "downloads": [
                    {
                        "label": label,
                        "file": name,
                        "url": f"{get_agents_dist_url()}/rustdesk/{name}",
                    }
                    for label, name in (
                        (label, name.format(v=CLIENT_VERSION))
                        for label, name in VIEWER_DOWNLOADS
                    )
                ],
            },
        )
        self.assertFalse(AuditLog.objects.exists())
        files = pinned_client()[1]
        self.assertEqual(len(files), 5)
        self.assertTrue(set(files) >= {d["file"] for d in r.data["downloads"]})

        x86 = self.make_agent(AgentPlat.WINDOWS, GoArch.i386)
        self.assertFalse(self.client.get(self.url(x86)).data["supported"])
        RustDeskSettings.objects.filter(pk=1).update(enabled=False)
        r = self.client.get(self.url(self.agent))
        self.assertFalse(r.data["available"])
        self.assertEqual(r.data["downloads"], [])

    @patch("agents.models.Agent.nats_cmd")
    def test_status_never_probes_the_display(self, nats_cmd):
        linux = self.make_agent(AgentPlat.LINUX, GoArch.AMD64)
        self.assertTrue(self.client.get(self.url(linux)).data["supported"])
        nats_cmd.assert_not_called()

        with patch("agents.utils.cache.get", return_value="absent"):
            self.assertFalse(self.client.get(self.url(linux)).data["supported"])
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_windows(self, nats_cmd):
        r = self.deploy(self.agent, nats_cmd, ran("RUSTDESK_OK 123456789 1.4.9\r\n"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data, {"rustdesk_id": "123456789", "client_version": "1.4.9"}
        )

        peer = RustDeskPeer.objects.get(agent=self.agent)
        password = decrypt_secret(peer.password)
        self.assertRegex(password, r"^[A-Za-z0-9]{24}$")
        self.assertEqual(peer.rustdesk_id, "123456789")
        self.assertEqual(peer.client_version, "1.4.9")
        self.assertIsNotNone(peer.deployed_at)
        self.assertEqual(peer.last_error, "")

        nats_cmd.assert_called_once()
        data = nats_cmd.call_args.args[0]
        self.assertEqual(nats_cmd.call_args.kwargs, {"timeout": DEPLOY_TIMEOUT + 10})
        self.assertEqual(
            set(data), {"func", "timeout", "payload", "run_as_user", "env_vars"}
        )
        self.assertEqual(data["func"], "runscriptfull")
        self.assertEqual(data["timeout"], DEPLOY_TIMEOUT)
        self.assertIs(data["run_as_user"], False)
        self.assertEqual(data["env_vars"], [f"RD_PASSWORD={password}"])
        self.assertEqual(data["payload"]["shell"], "powershell")
        code = data["payload"]["code"]
        self.assertIn(
            "& $exe --password $env:RD_PASSWORD 2>$null | ForEach-Object", code
        )
        self.assertIn(
            "https://rmm.example.com/agentdist/rustdesk/rustdesk-1.4.9-x86_64.msi",
            code,
        )
        self.assertIn(pinned_client()[1]["rustdesk-1.4.9-x86_64.msi"], code)
        self.assertIn(config_string("rd.example.com", "", KEY), code)
        self.assertIsNone(re.search(r"\brd[A-Z]\w*", code))

        status = self.client.get(self.url(self.agent)).data
        self.assertTrue(status["installed"])
        self.assertTrue(status["password_set"])
        self.assertEqual(status["rustdesk_id"], "123456789")

        audit = AuditLog.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(audit.action, AuditActionType.EXEC_COMMAND)
        self.assertIn("deployed RustDesk 1.4.9", audit.message)
        self.assert_no_secret(password)

    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_posix_payloads(self, nats_cmd):
        linux = self.make_agent(AgentPlat.LINUX, GoArch.AMD64)
        # first call is the display probe
        nats_cmd.side_effect = ["present", ran("RUSTDESK_OK 987654321 1.4.9\n")]
        r = self.client.post(self.url(linux, "deploy/"))
        self.assertEqual(r.status_code, 200)
        data = nats_cmd.call_args.args[0]
        self.assertEqual(data["func"], "runscriptfull")
        # the agent runs the file itself, by its shebang
        self.assertEqual(data["payload"]["shell"], "shell")
        code = data["payload"]["code"]
        self.assertTrue(code.startswith("#!/usr/bin/env bash\n"))
        self.assertIn('"$rd" --password "$RD_PASSWORD" |', code)
        for name in ("rustdesk-1.4.9-x86_64.deb", "rustdesk-1.4.9-0.x86_64.rpm"):
            self.assertIn(f"/agentdist/rustdesk/{name}'", code)
            self.assertIn(pinned_client()[1][name], code)
        self.assertIsNone(re.search(r"\brd[A-Z]\w*", code))

        mac = self.make_agent(AgentPlat.DARWIN, GoArch.ARM64)
        self.deploy(mac, nats_cmd, ran("RUSTDESK_OK 111222333 1.4.9\n"))
        data = nats_cmd.call_args.args[0]
        self.assertEqual(data["payload"]["shell"], "shell")
        code = data["payload"]["code"]
        # root script, never a bash found through PATH
        self.assertTrue(code.startswith("#!/bin/bash\n"))
        self.assertIn("rustdesk-1.4.9-aarch64.dmg", code)
        self.assertIn(pinned_client()[1]["rustdesk-1.4.9-aarch64.dmg"], code)
        self.assertNotIn("x86_64", code)
        self.assertIsNone(re.search(r"\brd[A-Z]\w*", code))

    def test_mac_app_ends_up_root_owned_and_signed(self):
        # a root LaunchDaemon runs the bundle's service binary. A bundle the
        # user owned is only used as a fresh root-owned copy that passes the
        # signature check, and that happens before anything else runs it.
        text = DEPLOY_SCRIPTS[AgentPlat.DARWIN].read_text()
        self.assertIn("new=$dir/RustDesk.app\n", text)
        steps = [
            'ditto --noacl "$dir/mnt/RustDesk.app" "$new"',
            'find "$app" \\( ! -user root -o ! -type l -perm +022 \\)',
            'ditto --noacl "$app" "$new"',
            'chown -Rh root:wheel "$new" && chmod -R go-w "$new"',
            'signed "$new" || fail',
            "RustDesk.app is not com.carriez.rustdesk $want",
            '            stop\n            mv "$app" "$old"',
            'mv "$new" "$app" || fail',
            "            start\n        else\n",
            'rm -rf "$app" && mv "$new" "$app"',
            'signed "$app" || fail',
            'chmod 644 "$daemon" && launchctl load',
            '--password "$RD_PASSWORD"',
        ]
        at = [text.index(step) for step in steps]
        self.assertEqual(at, sorted(at))
        self.assertIn('codesign --verify --deep --strict "$1" &&', text)
        self.assertIn('codesign -dv "$1" 2>&1 |', text)
        self.assertIn("grep -qx 'TeamIdentifier=HZF9JMC8YN'", text)
        self.assertNotIn(":staff", text)

    def test_password_only_in_env_vars(self):
        password = new_password()
        config = config_string("rd.example.com", "", KEY)
        for plat, goarch in INSTALLERS:
            agent = self.make_agent(plat, goarch)
            data = render_deploy(
                agent, password=password, host="rd.example.com", config=config
            )
            self.assertEqual(data.pop("env_vars"), [f"RD_PASSWORD={password}"])
            self.assertNotIn(password, json.dumps(data), (plat, goarch))
            self.assertIn("RD_PASSWORD", data["payload"]["code"])
            self.assertIsNone(re.search(r"\brd[A-Z]\w*", data["payload"]["code"]))

    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_failures(self, nats_cmd):
        r = self.deploy(
            self.agent, nats_cmd, ran("RUSTDESK_FAIL checksum mismatch: x\n")
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            r.data,
            f"RustDesk deploy on {self.agent.hostname} failed: checksum mismatch: x",
        )
        peer = RustDeskPeer.objects.get(agent=self.agent)
        self.assertEqual(peer.last_error, r.data)
        self.assertEqual(peer.rustdesk_id, "")
        self.assertIsNone(peer.deployed_at)
        # the endpoint never got it, so nothing is stored
        self.assertEqual(peer.password, "")
        self.assertIn(r.data, AuditLog.objects.get().message)
        password = nats_cmd.call_args.args[0]["env_vars"][0].split("=", 1)[1]
        self.assert_no_secret(password)

        # an echoed password must not show up in the error
        def echo(stdout, stderr=""):
            def reply(data, timeout):
                password = data["env_vars"][0].split("=", 1)[1]
                return ran(stdout + password, stderr + password, 1)

            return reply

        for reply, shown in (
            (echo("RUSTDESK_FAIL oops "), "oops ********"),
            (echo("", "boom "), "(exit code 1): boom ********, see"),
        ):
            nats_cmd.side_effect = reply
            r = self.client.post(self.url(self.agent, "deploy/"))
            peer = RustDeskPeer.objects.get(agent=self.agent)
            password = decrypt_secret(peer.password)
            self.assertEqual(r.status_code, 400)
            self.assertNotIn(password, r.data)
            self.assertIn(shown, r.data)
            self.assertNotIn(password, peer.last_error)
            self.assert_no_secret(password)

    @patch("agents.models.Agent.nats_cmd")
    def test_failure_before_the_password_keeps_the_old_one(self, nats_cmd):
        reasons = template_failures()
        # only in update mode, which never sends a password
        update_only = {
            "the RustDesk ID changed to ",
            "the update left RustDesk at ",
            "the RustDesk key or password changed during the update, use "
            "Install or reconfigure",
        }
        self.assertLess(update_only, reasons)
        reasons -= update_only
        # after the password step: the endpoint has the new password
        later = {
            "the server settings did not stick",
            "rustdesk --get-id printed nothing",
            "RustDesk --get-id printed nothing",
            "RustDesk on this Mac cannot reach rdHost (No route to host). Allow "
            "RustDesk under System Settings > Privacy & Security > Local Network, "
            "then deploy again",
        }
        self.assertLess(later, reasons)
        self.assertGreater(len(reasons - later), 10)

        old = encrypt_secret("old")
        peer = RustDeskPeer.objects.create(agent=self.agent, password=old)
        replies = [(ran(f"RUSTDESK_FAIL {r}x"), r not in later) for r in reasons]
        replies += [
            ("natsdown", True),
            ("timeout", False),
            (ran("", "\nScript timed out after 240 seconds", 98), False),
            (ran("RUSTDESK_FAIL something else"), False),
        ]
        for reply, restored in replies:
            r = self.deploy(self.agent, nats_cmd, reply)
            self.assertEqual(r.status_code, 400, reply)
            peer.refresh_from_db()
            if restored:
                self.assertEqual(peer.password, old, reply)
            else:
                self.assertNotEqual(peer.password, old, reply)
                self.assertRegex(decrypt_secret(peer.password), r"^[A-Za-z0-9]{24}$")
                peer.password = old
                peer.save(update_fields=["password"])

    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_strict_parse(self, nats_cmd):
        for reply in (
            "timeout",
            "natsdown",
            "",
            None,
            {"error": "x"},
            # rawcmd's answer
            "RUSTDESK_OK 123456789 1.4.9",
            ran(""),
            ran(None),
            ran("", "RUSTDESK_OK 123456789 1.4.9"),
            ran("RUSTDESK_OK 123456789 1.4.9\nRUSTDESK_OK 123456789 1.4.9"),
            ran("some output\nRUSTDESK_OK 123456789 1.4.9"),
            ran("RUSTDESK_OK 123456789 1.4.9 trailing"),
            ran("x RUSTDESK_OK 123456789 1.4.9"),
            ran("RUSTDESK_OK 12345 1.4.9"),
            ran("RUSTDESK_OK 123456789"),
            ran("RUSTDESK_OK 1234;id 1.4.9"),
            ran("RUSTDESK_OK 123456789 v1.4.9"),
            ran("RUSTDESK_FAIL"),
        ):
            r = self.deploy(self.agent, nats_cmd, reply)
            self.assertEqual(r.status_code, 400, reply)
            self.assertIsInstance(r.data, str)
        peer = RustDeskPeer.objects.get(agent=self.agent)
        self.assertEqual(peer.rustdesk_id, "")
        self.assertIsNone(peer.deployed_at)

        with self.assertRaises(DeployError):
            parse_deploy_output(ran("RUSTDESK_OK 123456789 1.4.9 \nx"), "pw")
        self.assertEqual(
            parse_deploy_output(ran("\n RUSTDESK_OK abc_123456 1.4.9-1 \r\n"), "pw"),
            ("abc_123456", "1.4.9-1"),
        )
        with self.assertRaisesMessage(
            DeployError, "(exit code 98): Script timed out after 240 seconds, see"
        ):
            parse_deploy_output(
                ran("", "\nScript timed out after 240 seconds", 98), "pw"
            )
        with self.assertRaises(PasswordNotSent):
            parse_deploy_output(ran("RUSTDESK_FAIL setup: x"), "pw")

    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_refusals(self, nats_cmd):
        offline = baker.make_recipe(
            "agents.agent", plat=AgentPlat.WINDOWS, goarch=GoArch.AMD64
        )
        r = self.client.post(self.url(offline, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("offline", r.data)

        x86 = self.make_agent(AgentPlat.WINDOWS, GoArch.i386)
        r = self.client.post(self.url(x86, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("windows/386", r.data)
        nats_cmd.assert_not_called()

        headless = self.make_agent(AgentPlat.LINUX, GoArch.AMD64)
        nats_cmd.return_value = "absent\n"
        r = self.client.post(self.url(headless, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("no graphical session", r.data)
        # the display probe, and nothing else
        nats_cmd.assert_called_once()
        self.assertEqual(nats_cmd.call_args.args[0]["timeout"], 5)

        with patch("remote.views.cache.add", return_value=False):
            r = self.client.post(self.url(self.agent, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("already being deployed", r.data)

        RustDeskSettings.objects.filter(pk=1).update(enabled=False)
        r = self.client.post(self.url(self.agent, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("Global Settings", r.data)

        RustDeskSettings.objects.filter(pk=1).update(enabled=True)
        self.use_key_file(key="")
        r = self.client.post(self.url(self.agent, "deploy/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("key is missing", r.data)

        nats_cmd.assert_called_once()
        self.assertFalse(RustDeskPeer.objects.exists())
        self.assertFalse(AuditLog.objects.exists())

    def make_peer(self, agent=None, version="1.0.0"):
        return RustDeskPeer.objects.create(
            agent=agent or self.agent,
            rustdesk_id="123456789",
            client_version=version,
            password=encrypt_secret("old"),
        )

    def update(self, agent, nats_cmd, reply):
        nats_cmd.reset_mock(side_effect=True)
        nats_cmd.return_value = reply
        return self.client.post(self.url(agent, "update/"), format="json")

    def test_update_payloads(self):
        config = config_string("rd.example.com", "", KEY)
        for plat, goarch in INSTALLERS:
            agent = self.make_agent(plat, goarch)
            data = render_deploy(
                agent,
                host="rd.example.com",
                config=config,
                mode="update",
                expect_id="123456789",
            )
            # no password at all, not even an empty one
            self.assertEqual(set(data), {"func", "timeout", "payload", "run_as_user"})
            code = data["payload"]["code"]
            self.assertIsNone(re.search(r"\brd[A-Z]\w*", code))
            for value in ("update", "123456789", CLIENT_VERSION):
                self.assertIn(f"'{value}'", code)

            data = render_deploy(
                agent, host="rd.example.com", config=config, password=new_password()
            )
            self.assertIn("'deploy'", data["payload"]["code"])
            self.assertIn("env_vars", data)

        for kwargs in (
            {"mode": "update", "expect_id": "123456789", "password": new_password()},
            {"mode": "update", "expect_id": ""},
            {"mode": "update", "expect_id": "12345"},
            {"mode": "update", "expect_id": "1234567';x"},
            {"mode": "deploy", "expect_id": "123456789", "password": new_password()},
            {"mode": "deploy"},
            {"mode": "Update", "expect_id": "123456789"},
        ):
            with self.assertRaises(DeployError, msg=str(kwargs)):
                render_deploy(
                    self.agent, host="rd.example.com", config=config, **kwargs
                )
        files = pinned_client()[1]
        with patch("remote.utils.pinned_client", return_value=("1.4.9'; x", files)):
            with self.assertRaisesRegex(DeployError, "Refusing"):
                render_deploy(
                    self.agent,
                    host="rd.example.com",
                    config=config,
                    mode="update",
                    expect_id="123456789",
                )

    def test_update_order_in_templates(self):
        # busy check and first fingerprint before anything is installed, the
        # ID, version and fingerprint checks before the success line
        post = [
            "rdExpectId",
            "instead of rdVersion",
            "the RustDesk key or password changed during the update",
        ]
        # a session at the sign-in screen has no --cm process, only its TCP
        # connection, so the busy check looks at both
        steps = {
            AgentPlat.WINDOWS: [
                "$before = Get-Fingerprint",
                "RustDesk was not installed from the MSI",
                "Get-NetTCPConnection -ErrorAction Stop",
                "-notin 21114..21116",
                "busy: a RustDesk session is open",
                "msiexec.exe",
                *post,
                "Write-Output ('RUSTDESK_OK",
            ],
            AgentPlat.LINUX: [
                "before=$(fingerprint)",
                "busy: a RustDesk session is open",
                'conns=$(ss -Htnp state established) || fail "busy: ',
                "$4 !~ /:2111[456]$/",
                "busy: a RustDesk session is open",
                "apt-get install",
                *post,
                'echo "RUSTDESK_OK',
            ],
            AgentPlat.DARWIN: [
                "before=$(fingerprint)",
                "busy: a RustDesk session is open",
                "lsof -w -nP -a -p",
                'fail "busy: cannot list',
                "grep -Evq ':2111[456]$'",
                "busy: a RustDesk session is open",
                "hdiutil attach",
                *post,
                'echo "RUSTDESK_OK',
            ],
        }
        flags = "--cm|--connect|--play|--file-transfer|--view-camera|--port-forward"
        for plat, path in DEPLOY_SCRIPTS.items():
            text = path.read_text()
            pos = 0
            for step in steps[plat]:
                pos = text.find(step, pos)
                self.assertGreaterEqual(pos, 0, f"{plat}: {step}")
            self.assertIn(flags + "|--terminal|--whiteboard|--rdp|rustdesk:)", text)

    def test_only_update_mode_upgrades(self):
        # Install or reconfigure rotates the password, which must not hinge
        # on an upgrade (open session, exe install, signature, ...)
        upgrade = {
            AgentPlat.WINDOWS: "if (-not $installed -or ($update -and $have -lt "
            "[version]'rdVersion')) {",
            AgentPlat.LINUX: 'if [ ! -x "$rd" ] || { [ -n "$have" ] && older "$have" '
            "'rdVersion'; }; then",
            AgentPlat.DARWIN: 'if [ -z "$have" ] || { [ "$mode" = update ] && '
            "older \"$have\" 'rdVersion'; }; then",
        }
        # have is only read in update mode there
        read = {
            AgentPlat.WINDOWS: ("if ($update) {", "[version]::TryParse("),
            AgentPlat.LINUX: (
                'if [ "$mode" = update ]; then',
                'have=$("$rd" --version',
            ),
        }
        for plat, path in DEPLOY_SCRIPTS.items():
            text = path.read_text()
            self.assertEqual(text.count(upgrade[plat]), 1, plat)
            if plat in read:
                gate, have = read[plat]
                self.assertEqual(text.count(have), 1, plat)
                self.assertLess(text.index(gate), text.index(have), plat)

    @patch("agents.models.Agent.nats_cmd")
    def test_update(self, nats_cmd):
        peer = self.make_peer()
        status = self.client.get(self.url(self.agent)).data
        self.assertTrue(status["update_available"])
        self.assertEqual(status["latest_version"], CLIENT_VERSION)

        ok = ran(f"RUSTDESK_OK 123456789 {CLIENT_VERSION}\r\n")
        r = self.update(self.agent, nats_cmd, ok)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data, {"rustdesk_id": "123456789", "client_version": CLIENT_VERSION}
        )
        nats_cmd.assert_called_once()
        data = nats_cmd.call_args.args[0]
        self.assertEqual(nats_cmd.call_args.kwargs, {"timeout": DEPLOY_TIMEOUT + 10})
        self.assertEqual(data["func"], "runscriptfull")
        self.assertEqual(data["timeout"], DEPLOY_TIMEOUT)
        self.assertNotIn("env_vars", data)
        code = data["payload"]["code"]
        self.assertIn("$update = 'update' -eq 'update'", code)
        self.assertIn("-cne '123456789'", code)
        self.assertIn(config_string("rd.example.com", "", KEY), code)

        stored = peer.password
        peer.refresh_from_db()
        self.assertEqual(peer.password, stored)
        self.assertEqual(peer.client_version, CLIENT_VERSION)
        self.assertEqual(peer.rustdesk_id, "123456789")
        self.assertIsNone(peer.deployed_at)
        self.assertEqual(peer.last_error, "")
        self.assertFalse(self.client.get(self.url(self.agent)).data["update_available"])

        audit = AuditLog.objects.get()
        self.assertEqual(audit.action, AuditActionType.EXEC_COMMAND)
        self.assertEqual(audit.agent_id, self.agent.agent_id)
        self.assertEqual(
            audit.message,
            f"john updated RustDesk 1.0.0 -> {CLIENT_VERSION} on "
            f"{self.agent.hostname}, ID 123456789",
        )

        # a client that is already current only gets the checks
        self.assertEqual(self.update(self.agent, nats_cmd, ok).status_code, 200)

        mac = self.make_agent(AgentPlat.DARWIN, GoArch.ARM64)
        self.make_peer(mac)
        self.update(mac, nats_cmd, ok)
        code = nats_cmd.call_args.args[0]["payload"]["code"]
        self.assertIn("mode='update'", code)
        self.assertIn("[ \"$id\" = '123456789' ]", code)
        self.assertNotIn("env_vars", nats_cmd.call_args.args[0])

    @patch("agents.models.Agent.nats_cmd")
    def test_update_failures_keep_the_password(self, nats_cmd):
        peer = self.make_peer()
        stored = peer.password
        replies = [ran(f"RUSTDESK_FAIL {reason}x") for reason in template_failures()]
        replies += [
            "natsdown",
            "timeout",
            ran("", "boom", 1),
            ran("RUSTDESK_OK 987654321 " + CLIENT_VERSION),
            ran("RUSTDESK_OK 123456789 1.0.1"),
            ran(f"RUSTDESK_OK 123456789 {CLIENT_VERSION}.1"),
        ]
        for n, reply in enumerate(replies, 1):
            r = self.update(self.agent, nats_cmd, reply)
            self.assertEqual(r.status_code, 400, reply)
            prefix = f"RustDesk update on {self.agent.hostname} failed: "
            self.assertTrue(r.data.startswith(prefix), r.data)
            peer.refresh_from_db()
            self.assertEqual(peer.password, stored, reply)
            self.assertEqual(peer.rustdesk_id, "123456789")
            self.assertEqual(peer.client_version, "1.0.0")
            self.assertEqual(peer.last_error, r.data)
            self.assertEqual(AuditLog.objects.count(), n)
            self.assertIn(
                f"{r.data} (1.0.0 -> {CLIENT_VERSION})", AuditLog.objects.last().message
            )
        self.assertEqual(decrypt_secret(stored), "old")

        r = self.update(self.agent, nats_cmd, ran("RUSTDESK_OK 987654321 1.4.9"))
        self.assertIn("reported ID 987654321", r.data)
        busy = "setup: busy: a RustDesk session is open on this device"
        r = self.update(self.agent, nats_cmd, ran(f"RUSTDESK_FAIL {busy}"))
        self.assertTrue(r.data.endswith(busy))

    @patch("agents.models.Agent.nats_cmd")
    def test_update_refusals(self, nats_cmd):
        url = self.url(self.agent, "update/")
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not installed", r.data)
        # a deploy that failed before the endpoint reported an ID
        peer = RustDeskPeer.objects.create(agent=self.agent, password="token")
        r = self.client.post(url)
        self.assertIn("not installed", r.data)

        offline = baker.make_recipe(
            "agents.agent", plat=AgentPlat.WINDOWS, goarch=GoArch.AMD64
        )
        self.make_peer(offline)
        r = self.client.post(self.url(offline, "update/"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("offline", r.data)

        RustDeskSettings.objects.filter(pk=1).update(enabled=False)
        r = self.client.post(url)
        self.assertIn("Global Settings", r.data)

        nats_cmd.assert_not_called()
        self.assertFalse(AuditLog.objects.exists())
        peer.refresh_from_db()
        self.assertEqual(peer.password, "token")

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("agents.models.Agent.nats_cmd")
    def test_deploy_and_update_share_the_lock(self, nats_cmd):
        cache.clear()
        self.addCleanup(cache.clear)
        self.make_peer()
        lock = f"rustdesk_deploy_{self.agent.agent_id}"
        cache.add(lock, 1)
        for action in ("deploy/", "update/"):
            r = self.client.post(self.url(self.agent, action))
            self.assertEqual(r.status_code, 400)
            self.assertIn("already being deployed or updated", r.data)
        nats_cmd.assert_not_called()
        cache.delete(lock)

        def reply(data, timeout):
            # held while the endpoint works
            self.assertEqual(cache.get(lock), 1)
            return ran(f"RUSTDESK_OK 123456789 {CLIENT_VERSION}")

        nats_cmd.side_effect = reply
        r = self.client.post(self.url(self.agent, "update/"))
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(cache.get(lock))

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_reveal_needs_stepup_and_a_dashboard_token(self):
        cache.clear()
        self.addCleanup(cache.clear)
        RustDeskPeer.objects.create(agent=self.agent, password=encrypt_secret("x"))
        url = self.url(self.agent, "password/")
        # authenticate() is not a dashboard token, so the step-up does not apply
        grant_console_stepup(self.john)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        cache.clear()
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.assertFalse(AuditLog.objects.exists())
        self.assertEqual(RevealRustDeskPassword.throttle_classes, [VaultRevealThrottle])

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_reveal(self):
        cache.clear()
        self.addCleanup(cache.clear)
        token, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=token)
        grant_console_stepup(self.john)
        url = self.url(self.agent, "password/")
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(AuditLog.objects.exists())

        password = new_password()
        RustDeskPeer.objects.create(agent=self.agent, password=encrypt_secret(password))
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        # uri stays empty until rustdesk_id is set
        self.assertEqual(r.data, {"password": password, "uri": ""})
        RustDeskPeer.objects.filter(agent=self.agent).update(rustdesk_id="123456789")
        r = self.client.post(url)
        self.assertEqual(
            r.data["uri"], connect_uri("123456789", "rd.example.com", KEY, password)
        )
        self.assertEqual(AuditLog.objects.count(), 2)

        audit = AuditLog.objects.first()
        self.assertEqual(audit.action, AuditActionType.VIEW)
        self.assertEqual(audit.agent_id, self.agent.agent_id)
        self.assertEqual(
            audit.message,
            f"john revealed the RustDesk password of {self.agent.hostname}",
        )
        self.assert_no_secret(password)

        with override_settings(SECRET_KEY="another-secret-key"):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(AuditLog.objects.count(), 2)

    @patch("remote.views.stepup_denied", return_value=None)
    @patch(
        "agents.models.Agent.nats_cmd", return_value=ran("RUSTDESK_OK 123456789 1.4.9")
    )
    def test_permissions_and_scope(self, nats_cmd, _):
        RustDeskPeer.objects.create(agent=self.agent, password=encrypt_secret("x"))
        other = self.make_agent(AgentPlat.WINDOWS, GoArch.AMD64)
        RustDeskPeer.objects.create(agent=other, password=encrypt_secret("x"))

        actions = (
            ("get", ""),
            ("post", "deploy/"),
            ("post", "update/"),
            ("post", "password/"),
        )
        for method, action in actions:
            url = self.url(self.agent, action)
            self.check_authorized_superuser(method, url)

            user = self.create_user_with_roles([])
            self.client.force_authenticate(user=user)
            self.check_not_authorized(method, url)

            user.role.can_view_core_settings = True
            user.role.can_edit_core_settings = True
            user.role.save()
            self.check_not_authorized(method, url)

            user.role.can_use_mesh = True
            user.role.save()
            self.check_authorized(method, url)
            self.check_authorized(method, self.url(other, action))

            user.role.can_view_sites.set([self.agent.site])
            self.check_authorized(method, url)
            self.check_not_authorized(method, self.url(other, action))

            user.role.can_view_sites.clear()
            user.role.can_view_clients.set([other.client])
            self.check_not_authorized(method, url)
            self.check_authorized(method, self.url(other, action))

        self.client.logout()
        for method, action in actions:
            self.check_not_authenticated(method, self.url(self.agent, action))


class TestPins(ULRMMTestCase):
    def test_mirror_script_pins_the_same_files(self):
        script = (
            settings.BASE_DIR.parent.parent
            / "riddix/rustdesk/install-rustdesk-server.sh"
        ).read_text()
        # no manifest: the script mirrors the seeded release
        version, files = pinned_client()
        pinned = dict(re.findall(r"(rustdesk-[0-9][^\s\"]*) ([0-9a-f]{64})", script))
        self.assertEqual(pinned, files)
        self.assertEqual(re.search(r"^CLIENT_VER=(\S+)$", script, re.M)[1], version)
        self.assertEqual(
            sorted(files), sorted(n.format(v=version) for n in CLIENT_NAMES)
        )

    def test_versions(self):
        self.assertLess(version_key("1.4.9"), version_key("1.4.10"))
        self.assertEqual(version_key("1.4.9-1"), (1, 4, 9))
        for junk in ("", "v1.4.9", "abc"):
            self.assertIsNone(version_key(junk))

        peer = RustDeskPeer(rustdesk_id="123456789")
        for version, expected in (
            ("1.0.0", True),
            (CLIENT_VERSION, False),
            (CLIENT_VERSION + ".1", False),
            ("", False),
            ("garbage", False),
        ):
            peer.client_version = version
            self.assertIs(update_available(peer), expected, version)
        peer.rustdesk_id = ""
        peer.client_version = "1.0.0"
        self.assertIs(update_available(peer), False)

    def test_templates(self):
        for path in DEPLOY_SCRIPTS.values():
            text = path.read_text()
            self.assertNotIn("rdPassword", text)
            self.assertIn("RD_PASSWORD", text)
            # windows powershell reads a script file without a BOM as ANSI
            self.assertTrue(text.isascii(), path)

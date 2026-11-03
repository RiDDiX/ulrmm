# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.models import APIKey
from accounts.utils import grant_console_stepup
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .models import EncryptionState, KeyStatus, RecoveryKey
from .tasks import collect_recovery_keys_task
from .utils import (
    COLLECT_TIMEOUT,
    MAX_MARKERS,
    ROTATE_TIMEOUT,
    SCRIPTS,
    RotateError,
    parse_collect,
    parse_rotate,
    seal,
    unseal,
)

base_url = "/encryption"


def password(*groups: int) -> str:
    return "-".join(f"{11 * g:06d}" for g in groups)


PW1 = password(1234, 5678, 9012, 3456, 7890, 1111, 2222, 65535)
PW2 = password(1, 2, 3, 4, 5, 6, 7, 8)
PW_OLD = password(9, 9, 9, 9, 9, 9, 9, 9)
ID1 = "{11111111-2222-3333-4444-555555555555}"
ID2 = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
ID_OLD = "{99999999-9999-9999-9999-999999999999}"
FV_KEY = "AB12-CD34-EF56-GH78-JK90-LM12"


def reply(stdout: str, retcode: int = 0, stderr: str = "") -> dict:
    return {"stdout": stdout, "stderr": stderr, "retcode": retcode, "id": 0}


WIN_LINES = (
    "some text the shell printed\n"
    f"ULRMM-BL C:|{ID1}|{PW1}|On|100\n"
    f"  ULRMM-BL D:|{ID2}|{PW2}|Off|57\n"
    "ULRMM-BL \\\\?\\Volume{0a1b2c3d-0000-1111-2222-333344445555}\\|||Off|0\n"
)
WIN_OK = reply(WIN_LINES + "ULRMM-END\n")
WIN_VOLUME = "\\\\?\\Volume{0a1b2c3d-0000-1111-2222-333344445555}\\"


class TestParse(ULRMMTestCase):
    def test_windows_lines(self):
        rep = parse_collect(AgentPlat.WINDOWS, WIN_OK)
        self.assertTrue(rep.complete)
        self.assertEqual(rep.error, "")
        self.assertEqual(rep.keys, {("C:", ID1): PW1, ("D:", ID2): PW2})
        self.assertEqual(
            list(rep.volumes.values()),
            [
                {
                    "volume": "C:",
                    "kind": "bitlocker",
                    "protection": "on",
                    "percent": 100,
                },
                {
                    "volume": "D:",
                    "kind": "bitlocker",
                    "protection": "off",
                    "percent": 57,
                },
                {
                    "volume": WIN_VOLUME,
                    "kind": "bitlocker",
                    "protection": "off",
                    "percent": 0,
                },
            ],
        )

    def test_malformed_markers_make_it_incomplete(self):
        bad = (
            f"ULRMM-BL C:|{ID1}|{PW1}|On|100 trailing",
            # 000012 is no multiple of 11
            f"ULRMM-BL C:|{ID1}|{PW1[:-6]}000012|On|100",
            f"ULRMM-BL C:|{ID1}||On|100",
            f"ULRMM-BL C:||{PW1}|On|100",
            f"ULRMM-BL C:|{ID1}|{PW1}|Maybe|100",
            "ULRMM-BL C|D:|||On|100",
            "ULRMM-SOMETHING else",
        )
        for line in bad:
            with self.subTest(line=line):
                rep = parse_collect(
                    AgentPlat.WINDOWS, reply(f"ULRMM-BL E:|||Off|0\n{line}\nULRMM-END")
                )
                self.assertFalse(rep.complete)
                self.assertEqual(rep.keys, {})
                self.assertIn("incomplete", rep.error)
                self.assertNotIn(PW1, rep.error)

    def test_partial_output(self):
        cases = (
            reply(WIN_LINES),
            reply(WIN_LINES + "ULRMM-END", retcode=1),
            reply(WIN_LINES + f"ULRMM-END\nULRMM-BL F:|{ID_OLD}|{PW_OLD}|On|100"),
            reply(WIN_LINES[: WIN_LINES.index("ULRMM-BL D:") + 30]),
        )
        for out in cases:
            with self.subTest(out=out):
                rep = parse_collect(AgentPlat.WINDOWS, out)
                self.assertFalse(rep.complete)
                self.assertIn(("C:", ID1), rep.keys)
                self.assertIn("The script output was incomplete", rep.error)

    def test_fail_line_and_no_reply(self):
        rep = parse_collect(
            AgentPlat.WINDOWS,
            reply(
                "ULRMM-FAIL BitLocker is not available on this edition "
                "(no BitLocker PowerShell module)\n",
                retcode=3,
            ),
        )
        self.assertFalse(rep.complete)
        self.assertIn("BitLocker is not available", rep.error)

        for out, error in (
            ("timeout", f"within {COLLECT_TIMEOUT + 10} seconds"),
            ("natsdown", "NATS is not reachable"),
            ("msgpack: decode error", "unreadable reply"),
            (None, "unreadable reply"),
        ):
            rep = parse_collect(AgentPlat.WINDOWS, out)
            self.assertFalse(rep.complete)
            self.assertIn(error, rep.error)
            self.assertEqual((rep.keys, rep.volumes), ({}, {}))

    def test_endpoint_text_never_carries_a_key(self):
        rep = parse_collect(
            AgentPlat.WINDOWS, reply("", retcode=1, stderr=f"oops {PW1} and {FV_KEY}")
        )
        self.assertNotIn(PW1, rep.error)
        self.assertNotIn(FV_KEY, rep.error)
        rep = parse_collect(AgentPlat.WINDOWS, reply(f"ULRMM-FAIL bad {PW1}"))
        self.assertEqual(rep.error, "bad ***")

    def test_flooded_output_stores_nothing(self):
        lines = "".join(
            f"ULRMM-BL V{n}:|{ID1}|{PW1}|On|100\n" for n in range(MAX_MARKERS + 1)
        )
        rep = parse_collect(AgentPlat.WINDOWS, reply(lines + "ULRMM-END\n"))
        self.assertFalse(rep.complete)
        self.assertEqual((rep.keys, rep.volumes), ({}, {}))
        self.assertIn(f"more than {MAX_MARKERS}", rep.error)

    def test_filevault_and_luks(self):
        for line, percent, personal in (
            ("on|45.2|true", 45, True),
            ("on||false", 100, False),
            ("off||unknown", 0, None),
            ("unknown||unknown", None, None),
        ):
            rep = parse_collect(AgentPlat.DARWIN, reply(f"ULRMM-FVS {line}\nULRMM-END"))
            self.assertTrue(rep.complete, line)
            self.assertEqual(rep.volumes["/"]["percent"], percent)
            self.assertEqual(rep.volumes["/"]["personal_key"], personal)
        self.assertFalse(
            parse_collect(
                AgentPlat.DARWIN, reply("ULRMM-FVS on|x|true\nULRMM-END")
            ).complete
        )

        rep = parse_collect(
            AgentPlat.LINUX,
            reply("ULRMM-LUKS /dev/sda2|/\nULRMM-LUKS /dev/sdb1|\nULRMM-END"),
        )
        self.assertTrue(rep.complete)
        self.assertEqual(
            [(v["volume"], v["mount"], v["protection"]) for v in rep.volumes.values()],
            [("/dev/sda2", "/", "on"), ("/dev/sdb1", "", "on")],
        )
        rep = parse_collect(AgentPlat.LINUX, reply("ULRMM-END"))
        self.assertTrue(rep.complete)
        self.assertEqual(rep.volumes, {})

    def test_parse_rotate(self):
        self.assertEqual(parse_rotate(reply(f"text\nULRMM-FV {FV_KEY}\n")), FV_KEY)
        for out, replaced in (
            (reply("ULRMM-FAIL fdesetup changerecovery failed (exit 12)", 1), False),
            ("natsdown", False),
            (reply("ULRMM-LOST fdesetup reported success but no key", 1), True),
            ("timeout", True),
            (reply(f"ULRMM-FV {FV_KEY}", retcode=1), True),
            (reply(f"ULRMM-FV {FV_KEY}\nULRMM-FV {FV_KEY}"), True),
            (reply("ULRMM-FV ab12-cd34-ef56-gh78-jk90-lm12"), True),
            (reply(""), True),
        ):
            with self.subTest(out=out):
                with self.assertRaises(RotateError) as e:
                    parse_rotate(out)
                self.assertIs(e.exception.replaced, replaced)
                self.assertNotIn(FV_KEY, str(e.exception))


class EncryptionTestCase(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.authenticate()
        self.setup_coresettings()

    def login_with_stepup(self, user):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        grant_console_stepup(user)

    def key(self, agent, volume="C:", protector_id=ID1, value=PW1, **kwargs):
        kwargs.setdefault("kind", "bitlocker")
        return RecoveryKey.objects.create(
            agent=agent,
            volume=volume,
            protector_id=protector_id,
            key=seal(value),
            **kwargs,
        )


@override_settings(CACHES=LOCMEM_CACHE)
class TestCollect(EncryptionTestCase):
    @patch("agents.models.Agent.nats_cmd")
    def test_windows_keys_are_stored_encrypted_and_missing_ones_go_stale(self, nats):
        agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        other = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        self.key(agent, protector_id=ID_OLD, value=PW_OLD)
        foreign = self.key(other)
        nats.return_value = WIN_OK

        r = self.client.post(f"{base_url}/{agent.agent_id}/collect/")
        self.assertEqual(r.status_code, 200, r.data)
        data = nats.call_args.args[0]
        self.assertEqual(data["func"], "runscriptfull")
        self.assertEqual(data["payload"]["shell"], "powershell")
        self.assertEqual(
            data["payload"]["code"], (SCRIPTS / "collect_windows.ps1").read_text()
        )
        self.assertNotIn("env_vars", data)
        self.assertEqual(nats.call_args.kwargs["timeout"], COLLECT_TIMEOUT + 10)

        rows = {k.protector_id: k for k in RecoveryKey.objects.filter(agent=agent)}
        self.assertEqual(set(rows), {ID1, ID2, ID_OLD})
        self.assertEqual(rows[ID_OLD].status, KeyStatus.STALE)
        self.assertEqual(rows[ID1].status, KeyStatus.ACTIVE)
        self.assertNotIn(PW1, rows[ID1].key)
        self.assertEqual(unseal(rows[ID1].key), PW1)
        self.assertEqual(unseal(rows[ID2].key), PW2)
        foreign.refresh_from_db()
        self.assertEqual(foreign.status, KeyStatus.ACTIVE)

        body = json.dumps(r.data, default=str)
        for secret in (PW1, PW2, PW_OLD):
            self.assertNotIn(secret, body)
        self.assertEqual(
            [(v["volume"], v["has_key"]) for v in r.data["volumes"]],
            [("C:", True), ("D:", True), (WIN_VOLUME, False)],
        )
        self.assertEqual(
            [(k["protector_id"], k["status"]) for k in r.data["keys"]],
            [(ID1, "active"), (ID_OLD, "stale"), (ID2, "active")],
        )
        self.assertNotIn("key", r.data["keys"][0])
        audit = AuditLog.objects.get(agent_id=agent.agent_id)
        self.assertEqual(audit.action, AuditActionType.EXEC_SCRIPT)
        self.assertNotIn(PW1, audit.message)

        # same keys again: updated, not duplicated, and a key that comes back is active
        RecoveryKey.objects.filter(protector_id=ID1).update(status=KeyStatus.STALE)
        self.assertEqual(
            self.client.post(f"{base_url}/{agent.agent_id}/collect/").status_code, 200
        )
        self.assertEqual(RecoveryKey.objects.filter(agent=agent).count(), 3)
        self.assertEqual(
            RecoveryKey.objects.get(agent=agent, protector_id=ID1).status,
            KeyStatus.ACTIVE,
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_partial_output_keeps_keys_and_marks_nothing_stale(self, nats):
        agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        old = self.key(agent, protector_id=ID_OLD, value=PW_OLD)
        nats.return_value = reply(f"ULRMM-BL C:|{ID1}|{PW1}|On|100\n")

        r = self.client.post(f"{base_url}/{agent.agent_id}/collect/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("incomplete", r.data)
        self.assertEqual(unseal(RecoveryKey.objects.get(protector_id=ID1).key), PW1)
        old.refresh_from_db()
        self.assertEqual(old.status, KeyStatus.ACTIVE)
        state = EncryptionState.objects.get(agent=agent)
        self.assertIsNone(state.collected_at)
        self.assertEqual(state.volumes, [])
        self.assertIn("incomplete", state.error)

    @patch("agents.models.Agent.nats_cmd")
    def test_no_bitlocker_module(self, nats):
        agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        nats.return_value = reply(
            "ULRMM-FAIL BitLocker is not available on this edition "
            "(no BitLocker PowerShell module)\n",
            retcode=3,
        )
        r = self.client.post(f"{base_url}/{agent.agent_id}/collect/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("BitLocker is not available", r.data)
        r = self.client.get(f"{base_url}/{agent.agent_id}/")
        self.assertEqual(r.data["volumes"], [])
        self.assertIn("BitLocker is not available", r.data["error"])

    @patch("agents.models.Agent.nats_cmd")
    def test_mac_and_linux_status(self, nats):
        mac = baker.make_recipe("agents.online_agent", plat=AgentPlat.DARWIN)
        nats.return_value = reply("ULRMM-FVS on|45.2|true\nULRMM-END\n")
        r = self.client.post(f"{base_url}/{mac.agent_id}/collect/")
        self.assertEqual(r.status_code, 200, r.data)
        data = nats.call_args.args[0]
        self.assertEqual(data["payload"]["shell"], "shell")
        self.assertEqual(
            data["payload"]["code"], (SCRIPTS / "status_mac.sh").read_text()
        )
        (volume,) = r.data["volumes"]
        self.assertEqual(
            {k: volume[k] for k in ("volume", "kind", "protection", "percent")},
            {"volume": "/", "kind": "filevault", "protection": "on", "percent": 45},
        )
        self.assertIs(volume["personal_key"], True)
        self.assertIs(volume["has_key"], False)
        self.assertIsNotNone(volume["collected_at"])

        linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        nats.return_value = reply("ULRMM-LUKS /dev/nvme0n1p3|/\nULRMM-END\n")
        r = self.client.post(f"{base_url}/{linux.agent_id}/collect/")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(
            nats.call_args.args[0]["payload"]["code"],
            (SCRIPTS / "status_linux.sh").read_text(),
        )
        self.assertEqual(
            [(v["volume"], v["mount"], v["kind"]) for v in r.data["volumes"]],
            [("/dev/nvme0n1p3", "/", "luks")],
        )
        self.assertEqual(r.data["keys"], [])

    @patch("agents.models.Agent.nats_cmd")
    def test_offline(self, nats):
        agent = baker.make_recipe("agents.offline_agent", plat=AgentPlat.WINDOWS)
        r = self.client.post(f"{base_url}/{agent.agent_id}/collect/")
        self.assertEqual(r.status_code, 400)
        nats.assert_not_called()


@override_settings(CACHES=LOCMEM_CACHE)
class TestReveal(EncryptionTestCase):
    def setUp(self):
        super().setUp()
        self.agent = baker.make_recipe("agents.agent", plat=AgentPlat.WINDOWS)
        self.row = self.key(self.agent)
        self.url = f"{base_url}/keys/{self.row.pk}/reveal/"

    def test_permission_matrix(self):
        nobody = self.create_user_with_roles([])
        outside = self.create_user_with_roles(["can_view_recovery_keys"])
        outside.role.can_view_clients.set([baker.make("clients.Client")])
        inside = self.create_user_with_roles(["can_view_recovery_keys"])
        inside.role.can_view_clients.set([self.agent.client])

        for user, status in ((nobody, 403), (outside, 403)):
            self.login_with_stepup(user)
            self.assertEqual(self.client.post(self.url).status_code, status)
            self.assertEqual(
                self.client.get(f"{base_url}/{self.agent.agent_id}/").status_code, 403
            )
            self.assertEqual(
                self.client.get(f"{base_url}/summary/").status_code,
                403 if user is nobody else 200,
            )

        # scope ok, no step-up
        token, _ = AuthToken.objects.create(user=inside)
        self.client.force_authenticate(user=inside, token=token)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.assertEqual(
            self.client.get(f"{base_url}/{self.agent.agent_id}/").status_code, 200
        )

        # step-up, but an api key instead of a dashboard token
        grant_console_stepup(inside)
        APIKey.objects.create(name="key", key="insidekey", user=inside)
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_X_API_KEY="insidekey")
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.client.credentials()

        self.assertFalse(AuditLog.objects.filter(action=AuditActionType.VIEW).exists())
        self.login_with_stepup(inside)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"key": PW1})
        self.assertEqual(r["Cache-Control"], "no-store")
        audit = AuditLog.objects.get(action=AuditActionType.VIEW)
        self.assertEqual(audit.username, inside.username)
        self.assertIn(
            f"BitLocker recovery key of {self.agent.hostname} (C:", audit.message
        )
        self.assertNotIn(PW1, audit.message + json.dumps(audit.debug_info or {}))

        self.assertEqual(
            self.client.post(
                f"{base_url}/keys/{self.row.pk + 100}/reveal/"
            ).status_code,
            404,
        )

    def test_reveal_throttled_per_user(self):
        self.login_with_stepup(self.john)
        codes = [self.client.post(self.url).status_code for _ in range(31)]
        self.assertEqual(codes, [200] * 30 + [429])

    def test_stale_keys_reveal_and_broken_tokens_do_not(self):
        self.login_with_stepup(self.john)
        self.row.status = KeyStatus.STALE
        self.row.save()
        self.assertEqual(self.client.post(self.url).data, {"key": PW1})
        self.row.key = "not a token"
        self.row.save()
        self.assertEqual(self.client.post(self.url).status_code, 400)


@override_settings(CACHES=LOCMEM_CACHE)
class TestRotate(EncryptionTestCase):
    def setUp(self):
        super().setUp()
        self.mac = baker.make_recipe("agents.online_agent", plat=AgentPlat.DARWIN)
        self.url = f"{base_url}/{self.mac.agent_id}/rotate/"
        self.creds = {"username": "alice", "password": 'p&ss <w> "x" end'}

    @patch("agents.models.Agent.nats_cmd")
    def test_credentials_only_in_env_vars(self, nats):
        self.login_with_stepup(self.john)
        nats.return_value = reply(f"ULRMM-FV {FV_KEY}\n")
        r = self.client.post(self.url, self.creds, format="json")
        self.assertEqual(r.status_code, 200, r.data)

        data = nats.call_args.args[0]
        self.assertEqual(nats.call_args.kwargs["timeout"], ROTATE_TIMEOUT + 10)
        self.assertEqual(
            data["env_vars"], ["FV_USER=alice", 'FV_PASSWORD=p&ss <w> "x" end']
        )
        self.assertEqual(
            data["payload"]["code"], (SCRIPTS / "rotate_mac.sh").read_text()
        )
        self.assertEqual(data["payload"]["shell"], "shell")
        self.assertIs(data["run_as_user"], False)
        rest = json.dumps({k: v for k, v in data.items() if k != "env_vars"})
        self.assertNotIn(self.creds["password"], rest)
        self.assertNotIn("alice", rest)

        row = RecoveryKey.objects.get(agent=self.mac)
        self.assertEqual(
            (row.kind, row.volume, row.status), ("filevault", "/", "active")
        )
        self.assertEqual(unseal(row.key), FV_KEY)
        body = json.dumps(r.data, default=str)
        self.assertNotIn(FV_KEY, body)
        self.assertNotIn(self.creds["password"], body)
        audit = AuditLog.objects.get(agent_id=self.mac.agent_id)
        self.assertIn("rotated the FileVault recovery key", audit.message)
        self.assertNotIn(FV_KEY, audit.message)
        self.assertNotIn(self.creds["password"], audit.message)

    @patch("agents.models.Agent.nats_cmd")
    def test_needs_stepup_flag_and_valid_input(self, nats):
        self.client.force_authenticate(user=self.john)
        r = self.client.post(self.url, self.creds, format="json")
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)

        user = self.create_user_with_roles([])
        self.login_with_stepup(user)
        self.assertEqual(
            self.client.post(self.url, self.creds, format="json").status_code, 403
        )

        self.login_with_stepup(self.john)
        windows = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        for url, body in (
            (f"{base_url}/{windows.agent_id}/rotate/", self.creds),
            (self.url, {"username": "alice"}),
            (self.url, {"username": "alice", "password": "a\nb"}),
            (self.url, {"username": "", "password": "x"}),
            (self.url, {"username": "alice", "password": ["x"]}),
            (self.url, {"username": "alice", "password": "x" * 1025}),
        ):
            with self.subTest(body=body):
                self.assertEqual(
                    self.client.post(url, body, format="json").status_code, 400
                )
        offline = baker.make_recipe("agents.offline_agent", plat=AgentPlat.DARWIN)
        r = self.client.post(
            f"{base_url}/{offline.agent_id}/rotate/", self.creds, format="json"
        )
        self.assertEqual(r.status_code, 400)
        nats.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_failure_keeps_the_old_key_unless_it_may_be_replaced(self, nats):
        self.login_with_stepup(self.john)
        old = self.key(
            self.mac, kind="filevault", volume="/", protector_id="", value=FV_KEY
        )

        nats.return_value = reply(
            "ULRMM-FAIL fdesetup changerecovery failed (exit 12)", 1
        )
        r = self.client.post(self.url, self.creds, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("exit 12", r.data)
        old.refresh_from_db()
        self.assertEqual(old.status, KeyStatus.ACTIVE)

        for out in ("timeout", reply("ULRMM-LOST no key in the output", 1)):
            old.status = KeyStatus.ACTIVE
            old.save()
            nats.return_value = out
            r = self.client.post(self.url, self.creds, format="json")
            self.assertEqual(r.status_code, 400)
            self.assertIn("marked stale", r.data)
            old.refresh_from_db()
            self.assertEqual(old.status, KeyStatus.STALE)
        for audit in AuditLog.objects.filter(agent_id=self.mac.agent_id):
            self.assertNotIn(self.creds["password"], audit.message)


class TestSummary(EncryptionTestCase):
    def test_summary(self):
        win = baker.make_recipe("agents.agent", plat=AgentPlat.WINDOWS)
        linux = baker.make_recipe("agents.agent", plat=AgentPlat.LINUX)
        mac = baker.make_recipe("agents.agent", plat=AgentPlat.DARWIN)
        baker.make_recipe("agents.agent", plat=AgentPlat.WINDOWS)
        now = djangotime.now()
        EncryptionState.objects.create(
            agent=win,
            collected_at=now,
            volumes=[
                {
                    "volume": "C:",
                    "kind": "bitlocker",
                    "protection": "on",
                    "percent": 100,
                },
                {
                    "volume": "D:",
                    "kind": "bitlocker",
                    "protection": "off",
                    "percent": 0,
                },
            ],
        )
        EncryptionState.objects.create(agent=linux, collected_at=now, volumes=[])
        EncryptionState.objects.create(agent=mac, error="NATS is not reachable")
        self.key(win)
        self.key(win, volume="D:", protector_id=ID2)
        self.key(win, protector_id=ID_OLD, status=KeyStatus.STALE)

        r = self.client.get(f"{base_url}/summary/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data,
            {
                "agents": 4,
                "encrypted": 1,
                "not_encrypted": 1,
                "unknown": 2,
                "keys_escrowed": 2,
            },
        )

        user = self.create_user_with_roles(["can_view_recovery_keys"])
        user.role.can_view_clients.set([linux.client])
        self.client.force_authenticate(user=user)
        r = self.client.get(f"{base_url}/summary/")
        self.assertEqual(
            r.data,
            {
                "agents": 1,
                "encrypted": 0,
                "not_encrypted": 1,
                "unknown": 0,
                "keys_escrowed": 0,
            },
        )


class TestTask(EncryptionTestCase):
    @patch("agents.models.Agent.nats_cmd")
    def test_online_windows_agents_only(self, nats):
        online = baker.make_recipe("agents.online_agent", plat=AgentPlat.WINDOWS)
        baker.make_recipe("agents.offline_agent", plat=AgentPlat.WINDOWS)
        baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        baker.make_recipe("agents.online_agent", plat=AgentPlat.DARWIN)
        nats.return_value = WIN_OK

        collect_recovery_keys_task()
        nats.assert_called_once()
        self.assertEqual(
            nats.call_args.args[0]["payload"]["code"],
            (SCRIPTS / "collect_windows.ps1").read_text(),
        )
        self.assertEqual(
            set(RecoveryKey.objects.values_list("agent_id", "protector_id")),
            {(online.pk, ID1), (online.pk, ID2)},
        )
        state = EncryptionState.objects.get()
        self.assertEqual(state.agent_id, online.pk)
        self.assertIsNotNone(state.collected_at)

    @patch("agents.models.Agent.nats_cmd")
    def test_a_failing_agent_does_not_stop_the_run(self, nats):
        a, b = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.WINDOWS, _quantity=2
        )
        nats.side_effect = [RuntimeError("nats broke"), WIN_OK]
        with self.assertLogs("ulrmm", "ERROR"):
            collect_recovery_keys_task()
        self.assertEqual(nats.call_count, 2)
        self.assertEqual(RecoveryKey.objects.count(), 2)
        self.assertIn(EncryptionState.objects.get().agent_id, (a.pk, b.pk))

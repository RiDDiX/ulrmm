# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt
import json
import shutil
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import Agent
from logs.models import DebugLog
from ulrmm.constants import AgentPlat
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from ..models import PLATS, InstallState, PackageInstall, SoftwarePackage
from ..tasks import finish, install_batch_task
from ..utils import (
    SCRIPTS,
    TOKEN_RE,
    batch_key,
    download_key,
    expire_stale,
    parse_result,
)
from .test_api import make_package

TOKEN = "k" * 43


def ran(stdout="", stderr="", retcode=0):
    """nats_cmd reply shape for runscriptfull."""
    return {
        "stdout": stdout,
        "stderr": stderr,
        "retcode": retcode,
        "execution_time": 1.0,
        "id": 0,
    }


def marker(result="ok", **kwargs):
    data = {"result": result, "exit": 0, "sig": "Valid", "signer": "CN=Vendor"}
    data["msg"] = ""
    data.update(kwargs)
    return "ULRMM-PKG " + json.dumps(data, separators=(",", ":"))


class TestParseResult(SimpleTestCase):
    def parse(self, stdout="", stderr="", retcode=0):
        return parse_result(ran(stdout, stderr, retcode), 1800, TOKEN)

    def test_results(self):
        for line, state, code in (
            (marker(), InstallState.SUCCEEDED, 0),
            (marker("reboot", exit=3010), InstallState.REBOOT_REQUIRED, 3010),
            (marker("fail", exit=1603, msg="1603"), InstallState.FAILED, 1603),
            (marker("refused", exit=None, sig="NotSigned"), InstallState.REFUSED, None),
        ):
            with self.subTest(line=line):
                got, fields = self.parse(f"downloading\r\n{line}\r\n", "warning: x")
                self.assertEqual(got, state)
                self.assertEqual(fields["exit_code"], code)
                self.assertIn(line, fields["output"])
                self.assertTrue(fields["output"].endswith("warning: x"))

        state, fields = self.parse(marker("refused", sig="NotTrusted", msg="untrusted"))
        self.assertEqual(
            fields,
            {
                "exit_code": 0,
                "signature": "NotTrusted",
                "signer": "CN=Vendor",
                "detail": "untrusted",
                "output": marker("refused", sig="NotTrusted", msg="untrusted"),
            },
        )

    def test_the_last_marker_counts(self):
        state, _ = self.parse(f"{marker('fail')}\n{marker()}\ntrailing noise\n")
        self.assertEqual(state, InstallState.SUCCEEDED)
        # only at the start of a line
        state, _ = self.parse(f"{marker('fail')}\necho {marker()}\n")
        self.assertEqual(state, InstallState.FAILED)

    def test_garbage(self):
        for stdout in (
            "",
            "done",
            "ULRMM-PKG {not json",
            "ULRMM-PKG [1]",
            "ULRMM-PKG " + "[" * 100000,
            marker("maybe"),
            marker(result=None),
        ):
            with self.subTest(stdout=stdout[:40]):
                state, fields = self.parse(stdout, "boom\nthe last line\n", 1)
                self.assertEqual(state, InstallState.FAILED)
                self.assertEqual(
                    fields["detail"],
                    "the install script reported no result (exit code 1): the last line",
                )

    def test_agent_errors(self):
        for out, detail in (
            ("timeout", "the agent gave no answer within 1830 seconds"),
            ("natsdown", "NATS is not reachable from this server"),
            ("nats: no responders", "the agent sent an unreadable reply"),
            (None, "the agent sent an unreadable reply"),
        ):
            with self.subTest(out=out):
                self.assertEqual(
                    parse_result(out, 1800), (InstallState.FAILED, {"detail": detail})
                )

    def test_fields_are_checked(self):
        for code, expected in (
            (True, None),
            ("1", None),
            (1.5, None),
            (2**31, None),
            (-(2**31), -(2**31)),
            (-1073741819, -1073741819),
        ):
            with self.subTest(code=code):
                _, fields = self.parse(marker("fail", exit=code))
                self.assertEqual(fields["exit_code"], expected)

        _, fields = self.parse(marker(sig=123, signer=["x"], msg="m" * 900))
        self.assertEqual((fields["signature"], fields["signer"]), ("", ""))
        self.assertEqual(len(fields["detail"]), 500)
        _, fields = self.parse(marker(sig="S" * 40, signer="C" * 300))
        self.assertEqual((len(fields["signature"]), len(fields["signer"])), (32, 255))

        _, fields = self.parse("x" * 20000 + "\n" + marker(), "e" * 100)
        self.assertEqual(len(fields["output"]), 8000)
        self.assertTrue(fields["output"].endswith("e" * 100))

    def test_the_token_never_comes_back(self):
        url = f"https://api.example.com/packages/download/{TOKEN}/"
        state, fields = self.parse(
            f"GET {url}\n" + marker("fail", msg=f"404 from {url}", signer=TOKEN),
            f"error {TOKEN}",
        )
        self.assertEqual(state, InstallState.FAILED)
        self.assertNotIn(TOKEN, json.dumps(fields))
        self.assertIn("/packages/download/***", fields["output"])

        state, fields = self.parse("oops", f"curl: {url} failed")
        self.assertNotIn(TOKEN, json.dumps(fields))
        # without the token itself the path pattern still goes
        _, fields = parse_result(ran("", f"curl: {url} failed", 1), 1800)
        self.assertNotIn(TOKEN, json.dumps(fields))


class TestScripts(SimpleTestCase):
    def test_one_static_script_per_platform(self):
        # every platform a package kind installs on, FreeBSD has none
        self.assertEqual(set(SCRIPTS), set(PLATS.values()))
        self.assertNotIn(AgentPlat.FREEBSD, SCRIPTS)
        for plat, path in SCRIPTS.items():
            with self.subTest(plat=plat):
                text = path.read_text()
                self.assertIn("ULRMM-PKG", text)
                self.assertIn("PKG_URL", text)


@override_settings(
    CACHES=LOCMEM_CACHE,
    ALLOWED_HOSTS=["api.example.com"],
    ULRMM_PROTO="https",
    ULRMM_BACKEND_PORT=None,
)
@patch("agents.models.Agent.nats_cmd")
class TestInstallTask(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        scripts = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scripts, ignore_errors=True)
        for plat, text in (
            (AgentPlat.WINDOWS, "# windows"),
            (AgentPlat.LINUX, "#!/bin/sh\n# linux"),
            (AgentPlat.DARWIN, "#!/bin/bash\n# mac"),
        ):
            (scripts / plat).write_text(text)
        self.enterContext(
            patch.dict(SCRIPTS, {plat: scripts / plat for plat in AgentPlat.values})
        )
        self.agent = baker.make_recipe("agents.online_agent")
        self.package = make_package(
            name="Tool", default_args="/S /D=C:\\x", allow_unsigned=True, timeout=900
        )
        self.lock = f"pkg_install_{self.agent.agent_id}"

    def queue(self, **kwargs):
        kwargs.setdefault("package", self.package)
        kwargs.setdefault("agent", self.agent)
        kwargs.setdefault("run_as", "system")
        kwargs.setdefault("batch", uuid.uuid4())
        return baker.make(
            "packages.PackageInstall",
            package_name=kwargs["package"].name if kwargs["package"] else "gone",
            state=InstallState.QUEUED,
            **kwargs,
        )

    def run_task(self, install):
        install_batch_task(str(install.batch))
        install.refresh_from_db()
        return install

    def assert_released(self, token=""):
        self.assertIsNone(cache.get(self.lock))
        if token:
            self.assertIsNone(cache.get(download_key(token)))

    def test_install(self, nats_cmd):
        install = self.queue()
        seen = {}

        def reply(data, timeout):
            env = dict(v.split("=", 1) for v in data["env_vars"])
            token = env["PKG_URL"].rstrip("/").rsplit("/", 1)[1]
            seen.update(data=data, env=env, token=token)
            # the download works only now
            seen["cached"] = cache.get(download_key(token))
            seen["lock"] = cache.get(self.lock)
            return ran(f"GET {env['PKG_URL']}\n" + marker(msg=f"from {env['PKG_URL']}"))

        nats_cmd.side_effect = reply
        install = self.run_task(install)

        data, env, token = seen["data"], seen["env"], seen["token"]
        self.assertEqual(nats_cmd.call_args.kwargs, {"timeout": 930})
        self.assertEqual(data["func"], "runscriptfull")
        self.assertEqual(data["timeout"], 900)
        self.assertEqual(data["payload"], {"code": "# windows", "shell": "powershell"})
        self.assertIs(data["run_as_user"], False)
        self.assertRegex(token, TOKEN_RE)
        self.assertEqual(
            env,
            {
                "PKG_URL": f"https://api.example.com/packages/download/{token}/",
                "PKG_SHA256": self.package.sha256,
                "PKG_NAME": self.package.filename,
                "PKG_KIND": "exe",
                "PKG_ALLOW_UNSIGNED": "1",
                "PKG_MODE": "system",
                "PKG_ARGS": "/S /D=C:\\x",
                "PKG_TIMEOUT": "855",
            },
        )
        self.assertEqual(seen["cached"], install.pk)
        self.assertEqual(seen["lock"], install.pk)

        self.assertEqual(install.state, InstallState.SUCCEEDED)
        self.assertEqual((install.exit_code, install.signature), (0, "Valid"))
        self.assertIsNotNone(install.started)
        self.assertIsNotNone(install.finished)
        self.assert_released(token)

        # the token is nowhere once the install is over
        self.assertNotIn(
            token, json.dumps(list(PackageInstall.objects.values()), default=str)
        )
        log = DebugLog.objects.get(agent=self.agent)
        self.assertIn("Tool", log.message)
        self.assertIn("succeeded", log.message)
        self.assertNotIn(token, log.message)

    def test_posix_and_user_payloads(self, nats_cmd):
        nats_cmd.return_value = ran(marker())
        linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        deb = make_package(kind="deb", plat=AgentPlat.LINUX)
        self.run_task(self.queue(agent=linux, package=deb))
        data = nats_cmd.call_args.args[0]
        env = dict(v.split("=", 1) for v in data["env_vars"])
        self.assertEqual(data["payload"]["shell"], "shell")
        self.assertEqual(data["payload"]["code"], "#!/bin/sh\n# linux")
        self.assertNotIn("PKG_ARGS", env)
        self.assertNotIn("PKG_TIMEOUT", env)
        self.assertEqual((env["PKG_KIND"], env["PKG_ALLOW_UNSIGNED"]), ("deb", "0"))

        self.run_task(self.queue(run_as="user"))
        data = nats_cmd.call_args.args[0]
        self.assertIs(data["run_as_user"], True)
        self.assertIn("PKG_MODE=user", data["env_vars"])

    def test_failures_release_everything(self, nats_cmd):
        for reply, state, detail in (
            (ran(marker("refused", sig="NotSigned")), InstallState.REFUSED, ""),
            ("timeout", InstallState.FAILED, "within 930 seconds"),
            (RuntimeError("boom"), InstallState.FAILED, "server error: boom"),
            (ran("garbage", "", 98), InstallState.FAILED, "(exit code 98)"),
        ):
            with self.subTest(reply=reply):
                nats_cmd.reset_mock(side_effect=True)
                nats_cmd.side_effect = [reply]
                install = self.run_task(self.queue())
                self.assertEqual(install.state, state)
                self.assertIn(detail, install.detail)
                self.assertIsNotNone(install.finished)
                token = nats_cmd.call_args.args[0]["env_vars"][0].rsplit("/", 2)[1]
                self.assert_released(token)
                self.assertNotIn(token, install.detail + install.output)

        # the script file is missing
        nats_cmd.reset_mock(side_effect=True)
        with patch.dict(SCRIPTS, {AgentPlat.WINDOWS: Path("/nonexistent/x.ps1")}):
            install = self.run_task(self.queue())
        self.assertEqual(install.state, InstallState.FAILED)
        self.assertIn("server error", install.detail)
        nats_cmd.assert_not_called()
        self.assert_released()

    @patch("packages.tasks.LOCK_TRIES", 3)
    @patch("packages.tasks.LOCK_WAIT", 0)
    def test_busy_agent_gives_up(self, nats_cmd):
        cache.add(self.lock, "other", 60)
        install = self.run_task(self.queue())
        self.assertEqual(install.state, InstallState.FAILED)
        self.assertEqual(install.detail, "another package install is still running")
        # not ours to release
        self.assertEqual(cache.get(self.lock), "other")
        nats_cmd.assert_not_called()

    @patch("packages.tasks.CONCURRENCY", 2)
    @patch("packages.tasks.LOCK_WAIT", 0.01)
    @patch("packages.tasks.HEARTBEAT", 0.01)
    def test_batch(self, nats_cmd):
        batch = uuid.uuid4()
        agents = [self.agent] + [
            baker.make_recipe("agents.online_agent") for _ in range(3)
        ]
        # two more for the first agent, they wait for its lock
        installs = [self.queue(agent=a, batch=batch) for a in agents + agents[:1] * 2]
        owner = {i.pk: i.agent.agent_id for i in installs}
        busy, peak, beats = [], [0], []

        async def reply(data, timeout):
            env = dict(v.split("=", 1) for v in data["env_vars"])
            token = env["PKG_URL"].rstrip("/").rsplit("/", 1)[1]
            agent_id = owner[cache.get(download_key(token))]
            # never two on one agent, never more than CONCURRENCY at all
            self.assertNotIn(agent_id, busy)
            busy.append(agent_id)
            peak[0] = max(peak[0], len(busy))
            cache.delete(batch_key(batch))
            await asyncio.sleep(0.1)
            beats.append(cache.get(batch_key(batch)))
            busy.remove(agent_id)
            return ran(marker())

        nats_cmd.side_effect = reply
        install_batch_task(str(batch))

        self.assertEqual(peak[0], 2)
        # the task keeps its batch alive while it runs, and ends it
        self.assertEqual(beats, [1] * 6)
        self.assertIsNone(cache.get(batch_key(batch)))
        for install in installs:
            install.refresh_from_db()
            self.assertEqual(install.state, InstallState.SUCCEEDED)
        for agent in agents:
            self.assertIsNone(cache.get(f"pkg_install_{agent.agent_id}"))
        self.assertEqual(nats_cmd.await_count, 6)

    @patch("packages.tasks.HEARTBEAT", 0.01)
    def test_heartbeat_outlives_a_cache_error(self, nats_cmd):
        install = self.queue()
        real, calls, alive = cache.aset, [], []

        async def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionError("redis restarted")
            return await real(*args, **kwargs)

        async def reply(data, timeout):
            await asyncio.sleep(0.1)
            alive.append(cache.get(batch_key(install.batch)))
            return ran(marker())

        nats_cmd.side_effect = reply
        with patch.object(cache, "aset", flaky):
            install = self.run_task(install)
        self.assertGreater(len(calls), 2)
        self.assertEqual(alive, [1])
        self.assertEqual(install.state, InstallState.SUCCEEDED)

    def test_nothing_to_run(self, nats_cmd):
        Agent.objects.filter(pk=self.agent.pk).update(
            last_seen=djangotime.now() - dt.timedelta(hours=1)
        )
        install = self.run_task(self.queue())
        self.assertEqual(
            (install.state, install.detail), (InstallState.SKIPPED, "offline")
        )
        self.assert_released()

        install = self.run_task(self.queue(package=None))
        self.assertEqual(
            (install.state, install.detail),
            (InstallState.FAILED, "the package was deleted"),
        )

        for state in (InstallState.RUNNING, InstallState.SUCCEEDED):
            install = self.queue()
            PackageInstall.objects.filter(pk=install.pk).update(state=state)
            self.assertEqual(self.run_task(install).state, state)
        nats_cmd.assert_not_called()
        self.assertFalse(cache.get(self.lock))

    def test_finish_after_the_package_is_gone(self, nats_cmd):
        install = PackageInstall.objects.select_related("package", "agent").get(
            pk=self.queue().pk
        )
        SoftwarePackage.objects.get(pk=self.package.pk).delete()
        finish(install, InstallState.SUCCEEDED, detail="done")
        # a full save would write the old package_id back
        connection.check_constraints()
        install.refresh_from_db()
        self.assertIsNone(install.package)
        self.assertEqual(install.state, InstallState.SUCCEEDED)


@override_settings(CACHES=LOCMEM_CACHE)
class TestExpireStale(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.agent = baker.make_recipe("agents.online_agent")

    def row(self, state, minutes_ago, alive=False):
        install = baker.make(
            "packages.PackageInstall",
            package_name="x",
            agent=self.agent,
            batch=uuid.uuid4(),
            run_as="system",
            state=state,
        )
        PackageInstall.objects.filter(pk=install.pk).update(
            created=djangotime.now() - dt.timedelta(minutes=minutes_ago)
        )
        if alive:
            cache.set(batch_key(install.batch), 1, 60)
        return install

    def test_only_rows_without_a_batch_task(self):
        lost = [
            self.row(InstallState.QUEUED, 10),
            self.row(InstallState.RUNNING, 60 * 24),
        ]
        kept = {
            # its task is alive, however long it waits or runs
            self.row(InstallState.QUEUED, 60 * 24, alive=True): InstallState.QUEUED,
            self.row(InstallState.RUNNING, 60 * 24, alive=True): InstallState.RUNNING,
            # just created, the grace covers it
            self.row(InstallState.QUEUED, 1): InstallState.QUEUED,
            self.row(InstallState.SUCCEEDED, 60): InstallState.SUCCEEDED,
        }
        expire_stale()
        for install in lost:
            install.refresh_from_db()
            self.assertEqual(install.state, InstallState.FAILED)
            self.assertEqual(install.detail, "no result, the server lost this install")
            self.assertIsNotNone(install.finished)
        for install, state in kept.items():
            install.refresh_from_db()
            self.assertEqual(install.state, state)

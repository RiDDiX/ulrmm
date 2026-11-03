# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import time
import uuid
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.constants import AgentPlat
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .. import jobs
from ..models import InstallState, PackageInstall
from ..services import start_installs
from ..tasks import install_batch_task
from ..utils import (
    JOB_IDLE,
    SCRIPTS,
    agent_lock,
    download_key,
    expire_stale,
    job_key,
)
from .test_tasks import marker

NEW = jobs.PKGJOB_MIN_AGENT


def package(kind="archive", plat=AgentPlat.WINDOWS, filename="tools.7z", **kw):
    body = uuid.uuid4().bytes
    kw.setdefault("command", "setup/setup.exe" if kind == "archive" else "")
    return baker.make(
        "packages.SoftwarePackage",
        name=f"pkg {body.hex()[:8]}",
        kind=kind,
        plat=plat,
        filename=filename,
        sha256=hashlib.sha256(body).hexdigest(),
        size=kw.pop("size", 1000),
        **kw,
    )


def queued(pkg, agent, run_as="system"):
    return PackageInstall.objects.create(
        package=pkg,
        package_name=pkg.name,
        agent=agent,
        batch=uuid.uuid4(),
        run_as=run_as,
        requested_by="john",
    )


@override_settings(CACHES=LOCMEM_CACHE)
@patch("agents.models.Agent.nats_cmd")
class TestRouting(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", version=NEW)

    def run_one(self, pkg, agent=None, run_as="system"):
        install = queued(pkg, agent or self.agent, run_as)
        install_batch_task(str(install.batch))
        install.refresh_from_db()
        return install

    def test_archive_is_a_job(self, nats_cmd):
        nats_cmd.return_value = "ok"
        install = self.run_one(package())
        nats_cmd.assert_called_once_with(
            {"func": "pkgjob", "payload": {"job": str(install.pk)}}, timeout=10
        )
        self.assertEqual(install.state, InstallState.RUNNING)
        self.assertEqual((install.done_bytes, install.total_bytes), (0, 1000))
        # the agent reports later: lock and job stay
        self.assertEqual(cache.get(agent_lock(self.agent.agent_id)), install.pk)
        self.assertIsNotNone(cache.get(job_key(install.pk)))

    def test_size_and_agent_decide(self, nats_cmd):
        big = jobs.JOB_SIZE + 1
        old = baker.make_recipe("agents.online_agent", version="2.21.10.2026")
        for kwargs, agent, run_as, func in (
            ({"size": big}, None, "system", "pkgjob"),
            ({"size": jobs.JOB_SIZE}, None, "system", "runscriptfull"),
            ({"size": big}, old, "system", "runscriptfull"),
            ({"size": big}, None, "user", "runscriptfull"),
        ):
            with self.subTest(kwargs=kwargs, agent=agent, run_as=run_as):
                cache.clear()
                nats_cmd.reset_mock()
                nats_cmd.return_value = "ok" if func == "pkgjob" else "timeout"
                pkg = package("exe", filename="setup.exe", **kwargs)
                self.run_one(pkg, agent, run_as)
                self.assertEqual(nats_cmd.call_args.args[0]["func"], func)

    def test_agent_does_not_take_it(self, nats_cmd):
        for answer, detail in (
            ("timeout", "the agent did not take the job: no answer"),
            ("busy", "the agent did not take the job: busy"),
        ):
            with self.subTest(answer=answer):
                nats_cmd.return_value = answer
                install = self.run_one(package())
                self.assertEqual(install.state, InstallState.FAILED)
                self.assertEqual(install.detail, detail)
                self.assertIsNone(cache.get(agent_lock(self.agent.agent_id)))
                self.assertIsNone(cache.get(job_key(install.pk)))

    def test_start_installs(self, nats_cmd):
        old = baker.make_recipe("agents.online_agent", version="2.21.10.2026")
        user = baker.make("accounts.User", username="john")
        with patch("packages.services.install_batch_task.delay"):
            result = start_installs(user, package(), [old], "system")
            row = PackageInstall.objects.get(batch=result["batch"])
            self.assertEqual(row.state, InstallState.SKIPPED)
            self.assertEqual(row.detail, f"archives need agent {NEW} or newer")
            result = start_installs(
                user, package(), [self.agent], "system", requested_by="baseline"
            )
            row = PackageInstall.objects.get(batch=result["batch"])
            self.assertEqual((row.state, row.requested_by), ("queued", "baseline"))
        with self.assertRaisesMessage(ValueError, "Archives install as system."):
            start_installs(user, package(), [self.agent], "user")


@override_settings(CACHES=LOCMEM_CACHE)
@patch("agents.models.Agent.nats_cmd")
class TestJobApi(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.online_agent", version=NEW)
        self.user = self.authenticate_agent(self.agent)

    def running(self, pkg):
        install = queued(pkg, self.agent)
        cache.add(agent_lock(self.agent.agent_id), install.pk, 60)
        jobs.start(install)
        return install

    def url(self, install, agent=None):
        return f"/api/v4/{(agent or self.agent).agent_id}/pkgjob/{install.pk}/"

    def test_plan_command(self, nats_cmd):
        install = self.running(package(default_args="/quiet"))
        first = self.client.get(self.url(install))
        self.assertEqual(first.status_code, 200, first.data)
        plan = first.data
        self.assertEqual(plan["extract"], "7z")
        self.assertEqual(
            plan["run"],
            {
                "type": "command",
                "exe": "setup/setup.exe",
                "args": "/quiet",
                "argv": [],
                "timeout": 1800,
            },
        )
        self.assertEqual(
            (plan["success_codes"], plan["reboot_codes"]), ([0], [3010, 1641])
        )
        self.assertEqual((plan["size"], plan["filename"]), (1000, "tools.7z"))
        # a fresh link per fetch, each one serves the file while the job runs
        second = self.client.get(self.url(install)).data
        self.assertNotEqual(plan["url"], second["url"])
        for link in (plan["url"], second["url"]):
            token = link.rstrip("/").rsplit("/", 1)[1]
            self.assertEqual(cache.get(download_key(token)), install.pk)
            r = self.client.get(f"/packages/download/{token}/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(
                r["X-Accel-Redirect"], f"/private/packages/{install.package.sha256}"
            )

    def test_plan_posix_and_script(self, nats_cmd):
        pkg = package(
            plat=AgentPlat.LINUX,
            filename="tools.tar.gz",
            command="sh",
            default_args='install.sh --prefix "/opt/my app"',
        )
        self.agent.plat = AgentPlat.LINUX
        self.agent.save(update_fields=["plat"])
        plan = self.client.get(self.url(self.running(pkg))).data
        self.assertEqual(plan["extract"], "tar.gz")
        self.assertEqual(plan["run"]["argv"], ["install.sh", "--prefix", "/opt/my app"])

        PackageInstall.objects.update(state=InstallState.SUCCEEDED)
        cache.clear()
        exe = package("exe", filename="setup.exe", size=jobs.JOB_SIZE + 1)
        plan = self.client.get(self.url(self.running(exe))).data
        run = plan["run"]
        self.assertEqual((run["type"], run["shell"]), ("script", "powershell"))
        self.assertEqual(run["body"], SCRIPTS[AgentPlat.WINDOWS].read_text())
        self.assertEqual(run["env"]["PKG_SHA256"], exe.sha256)
        self.assertEqual(run["env"]["PKG_MODE"], "system")
        self.assertNotIn("PKG_URL", run["env"])
        self.assertEqual(plan["extract"], "none")

    def test_only_its_running_job(self, nats_cmd):
        install = self.running(package())
        other = baker.make_recipe("agents.online_agent", version=NEW)
        self.assertEqual(self.client.get(self.url(install, other)).status_code, 404)
        self.authenticate_agent(other)
        self.assertEqual(self.client.get(self.url(install)).status_code, 404)
        self.assertEqual(self.client.get(self.url(install, other)).status_code, 404)

        self.client.force_authenticate(user=self.user)
        script_run = queued(package("exe", filename="setup.exe"), self.agent)
        script_run.state = InstallState.RUNNING
        script_run.save()
        self.assertEqual(self.client.get(self.url(script_run)).status_code, 404)
        install.state = InstallState.FAILED
        install.save()
        self.assertEqual(self.client.get(self.url(install)).status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get(self.url(install)).status_code, 401)

    def test_progress(self, nats_cmd):
        install = self.running(package())
        cache.delete(job_key(install.pk))
        body = {"state": "downloading", "done": 400, "total": 1000}
        r = self.client.patch(self.url(install), body, format="json")
        self.assertEqual((r.status_code, r.data), (200, "ok"))
        install.refresh_from_db()
        self.assertEqual((install.detail, install.done_bytes), ("downloading", 400))
        self.assertIsNotNone(cache.get(job_key(install.pk)))

        for bad in ({"done": 2000, "total": 1000}, {"done": True, "total": 5}):
            body = {"state": "extracting", **bad}
            self.client.patch(self.url(install), body, format="json")
            install.refresh_from_db()
            self.assertEqual((install.detail, install.done_bytes), ("extracting", 400))
        r = self.client.patch(self.url(install), {"state": "nope"}, format="json")
        self.assertEqual((r.status_code, r.data), (400, "unknown state"))

    def test_command_results(self, nats_cmd):
        for body, state, detail in (
            ({"state": "done", "exit_code": 0}, InstallState.SUCCEEDED, ""),
            ({"state": "done", "exit_code": 3010}, InstallState.REBOOT_REQUIRED, ""),
            (
                {"state": "done", "exit_code": 5},
                InstallState.FAILED,
                "setup/setup.exe exited with 5",
            ),
            (
                {"state": "failed", "exit_code": None, "detail": "sha256 mismatch"},
                InstallState.FAILED,
                "sha256 mismatch",
            ),
            ({"state": "done", "exit_code": "0"}, InstallState.FAILED, "the agent"),
        ):
            with self.subTest(body=body):
                cache.clear()
                install = self.running(package())
                body = {"output": "log line", **body}
                r = self.client.patch(self.url(install), body, format="json")
                self.assertEqual(r.status_code, 200)
                install.refresh_from_db()
                self.assertEqual(install.state, state)
                self.assertTrue(install.detail.startswith(detail), install.detail)
                self.assertEqual(install.output, "log line")
                self.assertIsNotNone(install.finished)
                self.assertIsNone(cache.get(agent_lock(self.agent.agent_id)))
                # once only
                r = self.client.patch(self.url(install), body, format="json")
                self.assertEqual(r.status_code, 404)

    def test_script_results(self, nats_cmd):
        exe = dict(kind="exe", filename="setup.exe", size=jobs.JOB_SIZE + 1)
        install = self.running(package(**exe))
        out = "installing\n" + marker("reboot", exit=3010)
        body = {"state": "done", "exit_code": 0, "output": out}
        self.client.patch(self.url(install), body, format="json")
        install.refresh_from_db()
        self.assertEqual((install.state, install.exit_code), ("reboot_required", 3010))

        cache.clear()
        install = self.running(package(**exe))
        body = {"state": "failed", "exit_code": None, "detail": "disk full"}
        self.client.patch(self.url(install), body, format="json")
        install.refresh_from_db()
        self.assertEqual((install.state, install.detail), ("failed", "disk full"))

    def test_quiet_jobs_expire(self, nats_cmd):
        quiet, alive = self.running(package()), self.running(package())
        cache.delete(job_key(quiet.pk))
        PackageInstall.objects.update(created=djangotime.now() - dt.timedelta(hours=1))
        cache.set(agent_lock(self.agent.agent_id), quiet.pk, 60)
        expire_stale()
        quiet.refresh_from_db()
        alive.refresh_from_db()
        self.assertEqual(quiet.state, InstallState.FAILED)
        self.assertIn("sent nothing about this job", quiet.detail)
        # the batch key is long gone: a job is judged by its own key only
        self.assertEqual(alive.state, InstallState.RUNNING)
        self.assertIsNone(cache.get(agent_lock(self.agent.agent_id)))

    def expire_at(self, seconds: int) -> None:
        """expire_stale as the cache sees it that many seconds from now."""
        with patch("django.core.cache.backends.locmem.time") as clock:
            clock.time.return_value = time.time() + seconds
            expire_stale()

    def test_unpacking_and_installing_get_the_package_timeout(self, nats_cmd):
        lock = agent_lock(self.agent.agent_id)
        downloading = self.running(package(timeout=3600))
        cache.delete(lock)
        installing = self.running(package(timeout=3600))
        PackageInstall.objects.update(created=djangotime.now() - dt.timedelta(hours=1))
        for install, steps in (
            (downloading, ("downloading",)),
            (installing, ("downloading", "extracting", "installing")),
        ):
            for step in steps:
                body = {"state": step, "done": 1000, "total": 1000}
                r = self.client.patch(self.url(install), body, format="json")
                self.assertEqual(r.status_code, 200)

        self.expire_at(JOB_IDLE + 1)
        downloading.refresh_from_db()
        self.assertEqual(downloading.state, InstallState.FAILED)
        self.assertIn("sent nothing about this job", downloading.detail)
        # the agent says nothing until the installer ends
        self.expire_at(3600)
        installing.refresh_from_db()
        self.assertEqual(installing.state, InstallState.RUNNING)
        self.assertEqual(cache.get(lock), installing.pk)

        self.expire_at(3600 + JOB_IDLE + 61)
        installing.refresh_from_db()
        self.assertEqual(installing.state, InstallState.FAILED)
        self.assertIsNone(cache.get(lock))

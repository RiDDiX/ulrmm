# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import fnmatch
import hashlib
import json
import uuid
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework import serializers

from agents.models import Agent
from deploy.models import Enrollment
from deploy.signals import agent_enrolled
from logs.models import AuditLog, PendingAction
from packages.models import InstallState, PackageInstall
from ulrmm.constants import AgentPlat, PAStatus
from ulrmm.test import ULRMMTestCase

from . import baselines, detect
from .models import (
    Baseline,
    BaselineItem,
    BaselineState,
    BaselineStatus,
    InstalledSoftware,
    WingetCatalog,
)

W, L = AgentPlat.WINDOWS, AgentPlat.LINUX
NEW = "9.30.12.2099"
SEVEN_ZIP = {"name": "7-Zip 24.08 (x64)", "version": "24.08"}


def det(found, version=""):
    line = "ULRMM-DET " + json.dumps({"found": found, "version": version})
    return {"stdout": f"noise\n{line}\n", "stderr": "", "retcode": 0}


def pkg_marker(result="ok", code=0):
    line = json.dumps({"result": result, "exit": code, "msg": "done"})
    return {"stdout": f"ULRMM-PKG {line}\n", "stderr": "", "retcode": 0}


class TestDetect(SimpleTestCase):
    def test_clean(self):
        for value, plat, want in (
            (None, W, None),
            ({}, W, None),
            ({"type": "none", "x": 1}, L, {"type": "none"}),
            (
                {"type": "inventory", "name": "^7-Zip", "version_min": "24"},
                W,
                {"type": "inventory", "name": "^7-Zip", "version_min": "24"},
            ),
            (
                {
                    "type": "file",
                    "path": "%ProgramFiles%\\X\\x.exe",
                    "version_min": "2",
                },
                W,
                {
                    "type": "file",
                    "path": "%ProgramFiles%\\X\\x.exe",
                    "version_min": "2",
                },
            ),
            ({"type": "file", "path": "/usr/bin/htop"}, L, None),
            (
                {"type": "registry", "key": "HKLM:\\SOFTWARE\\X", "value": "Ver"},
                W,
                None,
            ),
        ):
            with self.subTest(value=value):
                got = detect.clean(value, plat)
                self.assertEqual(got, want if want or not value else value)

        for value, plat, error in (
            ({"type": "x"}, W, "type must be"),
            ("inventory", W, "type must be"),
            ({"type": "inventory", "name": "("}, W, "not a valid regular"),
            ({"type": "inventory", "name": ""}, W, "regular expression"),
            ({"type": "file", "path": "x.exe"}, W, "full path"),
            ({"type": "file", "path": "C:\\x.exe"}, L, "full path"),
            ({"type": "file", "path": "/x", "version_min": "1"}, L, "Windows only"),
            ({"type": "registry", "key": "HKLM\\X"}, L, "Windows only"),
            ({"type": "registry", "key": "HKCU\\X"}, W, "below HKLM"),
            ({"type": "none", "version_min": "1"}, W, "no version"),
            ({"type": "inventory", "name": "x", "version_min": "new"}, W, "number"),
        ):
            with self.subTest(value=value), self.assertRaisesMessage(
                serializers.ValidationError, error
            ):
                detect.clean(value, plat)

    def test_inventory(self):
        software = [
            SEVEN_ZIP,
            {"name": "Google Chrome", "version": "130.0.1"},
            {"name": "Mozilla Firefox (x64 en-US)", "version": "131.0"},
            "junk",
            {"name": None},
        ]
        for rule, want in (
            (detect.name_rule("7-Zip"), (True, "24.08")),
            (detect.name_rule("googlechrome"), (True, "130.0.1")),
            (detect.name_rule("Mozilla Firefox (en-US)"), (True, "131.0")),
            (
                {"type": "inventory", "name": "^7-zip", "version_min": "25"},
                (False, "24.08"),
            ),
            (
                {"type": "inventory", "name": "^7-zip", "version_min": "24.8"},
                (True, "24.08"),
            ),
            (detect.name_rule("LibreOffice"), (False, "")),
        ):
            with self.subTest(rule=rule):
                self.assertEqual(detect.in_inventory(rule, software), want)
        self.assertEqual(detect.version_key("1:2.30-1ubuntu1"), (2, 30, 1, 1))
        self.assertTrue(detect.new_enough("10.0", "9.9"))
        self.assertFalse(detect.new_enough("", "1"))
        self.assertTrue(detect.new_enough("", None))

    def test_parse(self):
        self.assertEqual(detect.parse(det(True, "1.2")), (True, "1.2"))
        self.assertEqual(detect.parse(det(False)), (False, ""))
        for out in (
            "timeout",
            {"stdout": "ULRMM-DET {"},
            {"stdout": 'ULRMM-DET {"found": "yes"}'},
            {"stdout": "nothing"},
        ):
            self.assertIsNone(detect.parse(out))


@patch("agents.models.Agent.nats_cmd")
class TestEngine(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", version=NEW)
        self.policy = baker.make("automation.Policy", active=True)
        Agent.objects.filter(pk=self.agent.pk).update(policy=self.policy)
        self.agent.refresh_from_db()
        self.baseline = Baseline.objects.create(name="Office", plat=W)
        self.baseline.policies.add(self.policy)
        WingetCatalog.objects.create(pk=1, packages=[["7zip.7zip", "7-Zip", "24.08"]])
        self.inventory = []
        self.scripts = []

    def item(self, baseline=None, **kw):
        kw.setdefault("source", "winget")
        kw.setdefault("ref", "7zip.7zip")
        kw.setdefault("name", "7-Zip")
        return BaselineItem.objects.create(baseline=baseline or self.baseline, **kw)

    def agent_replies(self, nats_cmd, ack="ok", script=None):
        def reply(data, *args, **kwargs):
            if data["func"] == "softwarelist":
                return list(self.inventory)
            if data["func"] in ("installwithwinget", "installwithchoco"):
                return ack
            self.scripts.append(data)
            return script(data) if script else "timeout"

        nats_cmd.side_effect = reply

    def state(self, item=None):
        return BaselineState.objects.get(agent=self.agent, item=item or self.item_)

    def step(self):
        agent = Agent.objects.select_related("site__client").get(pk=self.agent.pk)
        return baselines.step(agent)

    def test_winget_install_and_check(self, nats_cmd):
        self.agent_replies(nats_cmd)
        self.item_ = self.item()
        self.assertEqual(self.step(), "started")
        state = self.state()
        self.assertEqual((state.status, state.attempts), ("installing", 1))
        action = state.action
        self.assertEqual(action.details["id"], "7zip.7zip")
        audit = AuditLog.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(audit.username, "baseline")

        # still running
        self.assertEqual(self.step(), "installing")
        action.status = PAStatus.COMPLETED
        action.details["installed"] = True
        action.save()
        self.inventory = [SEVEN_ZIP]
        self.step()
        state = self.state()
        self.assertEqual(state.status, BaselineStatus.INSTALLED)
        self.assertEqual(state.detected_version, "24.08")
        self.assertIsNotNone(state.verified_at)
        self.assertIsNone(state.action)

    def test_installed_already_and_not_found_after(self, nats_cmd):
        self.agent_replies(nats_cmd)
        self.inventory = [SEVEN_ZIP]
        self.item_ = self.item()
        self.assertEqual(self.step(), "checked")
        self.assertEqual(self.state().status, BaselineStatus.INSTALLED)
        self.assertFalse(PendingAction.objects.exists())

        # the installer says ok, the inventory disagrees
        other = self.item(source="choco", ref="libreoffice", name="LibreOffice")
        self.step()
        action = self.state(other).action
        action.status = PAStatus.COMPLETED
        action.details.update(installed=True, output="done")
        action.save()
        self.step()
        state = self.state(other)
        self.assertEqual(state.status, BaselineStatus.FAILED)
        self.assertIn("does not find it", state.detail)

    def test_failures(self, nats_cmd):
        self.agent_replies(nats_cmd, ack="nope")
        self.item_ = self.item()
        self.step()
        state = self.state()
        self.assertEqual((state.status, state.attempts), ("failed", 1))
        self.assertEqual(state.detail, "Unable to contact the agent")
        self.assertFalse(PendingAction.objects.exists())

        now = djangotime.now()
        for attempts, ago, want in (
            (1, 29, False),
            (1, 31, True),
            (2, 59, False),
            (2, 61, True),
            (3, 600, False),
        ):
            state.attempts = attempts
            state.updated = now - dt.timedelta(minutes=ago)
            self.assertEqual(baselines.due(state, now), want, (attempts, ago))

    def test_deadline_and_cancel(self, nats_cmd):
        self.agent_replies(nats_cmd)
        self.item_ = self.item(timeout=1800)
        self.step()
        BaselineState.objects.update(
            started_at=djangotime.now() - dt.timedelta(minutes=41)
        )
        self.step()
        state = self.state()
        self.assertEqual(state.status, BaselineStatus.FAILED)
        self.assertEqual(state.detail, "no result from the agent within 40 minutes")

        BaselineState.objects.update(status="pending", attempts=0)
        self.step()
        self.state().action.delete()
        self.step()
        self.assertEqual(self.state().detail, "the install was cancelled")

    def test_unsupported_and_recheck(self, nats_cmd):
        self.agent_replies(nats_cmd)
        Agent.objects.filter(pk=self.agent.pk).update(version="1.3.0")
        self.item_ = self.item()
        self.step()
        state = self.state()
        self.assertEqual(state.status, BaselineStatus.UNSUPPORTED)
        self.assertIn("winget needs agent", state.detail)
        now = djangotime.now()
        self.assertFalse(baselines.due(state, now))
        self.assertTrue(baselines.due(state, now + dt.timedelta(days=1, minutes=1)))

        # installed but gone a day later: installed again
        Agent.objects.filter(pk=self.agent.pk).update(version=NEW)
        BaselineState.objects.update(
            status="installed", updated=now - dt.timedelta(days=2)
        )
        self.assertEqual(self.step(), "started")
        self.assertEqual(self.state().status, BaselineStatus.INSTALLING)

    def test_one_install_at_a_time(self, nats_cmd):
        self.agent_replies(nats_cmd)
        self.item_ = self.item()
        second = self.item(source="choco", ref="vlc", name="VLC", order=1)
        self.step()
        self.assertEqual(self.state().status, BaselineStatus.INSTALLING)
        self.assertEqual(self.state(second).status, BaselineStatus.PENDING)
        self.assertEqual(PendingAction.objects.count(), 1)

    @patch("packages.services.install_batch_task.delay")
    def test_hosted_package(self, delay, nats_cmd):
        body = uuid.uuid4().bytes
        pkg = baker.make(
            "packages.SoftwarePackage",
            name="Tool",
            kind="exe",
            plat=W,
            filename="tool.exe",
            sha256=hashlib.sha256(body).hexdigest(),
            size=10,
            detection={"type": "registry", "key": "HKLM:\\SOFTWARE\\Tool"},
        )
        self.agent_replies(nats_cmd, script=lambda data: det(True, "5.0"))
        self.item_ = self.item(source="package", ref=str(pkg.pk), name="Tool")
        # the registry check runs first: found means installed already
        self.step()
        self.assertEqual(self.state().status, BaselineStatus.INSTALLED)
        env = self.scripts[0]["env_vars"]
        self.assertIn("DET_KEY=Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Tool", env)

        self.agent_replies(nats_cmd, script=lambda data: det(False))
        BaselineState.objects.update(status="pending")
        self.step()
        state = self.state()
        install = state.install
        self.assertEqual((install.requested_by, install.state), ("baseline", "queued"))
        delay.assert_called_once()
        self.assertEqual(self.step(), "installing")

        PackageInstall.objects.update(state=InstallState.SUCCEEDED)
        self.agent_replies(nats_cmd, script=lambda data: det(True, "5.1"))
        self.step()
        state = self.state()
        self.assertEqual((state.status, state.detected_version), ("installed", "5.1"))

        # no rule: the installer's word, marked as not checked
        pkg.detection = None
        pkg.save()
        BaselineState.objects.update(status="pending")
        self.step()
        PackageInstall.objects.update(state=InstallState.SUCCEEDED)
        self.step()
        state = self.state()
        self.assertEqual(state.status, BaselineStatus.INSTALLED)
        self.assertTrue(state.detail.startswith("unverified"), state.detail)

    @patch("software.tasks.baseline_linux_pkg_task.delay")
    @patch("winupdate.tasks.posix_refresh_task")
    def test_linux_package(self, refresh, delay, nats_cmd):
        Agent.objects.filter(pk=self.agent.pk).update(plat=L)
        self.baseline.plat = L
        self.baseline.save()
        self.item_ = self.item(source="linux_pkg", ref="htop", name="htop")

        def refreshed(agent_pk, mode):
            InstalledSoftware.objects.update_or_create(
                agent_id=agent_pk, defaults={"software": list(self.inventory)}
            )
            return "ok"

        refresh.side_effect = refreshed
        self.agent_replies(nats_cmd, script=lambda data: pkg_marker())
        self.step()
        state = self.state()
        self.assertEqual(state.status, BaselineStatus.INSTALLING)
        delay.assert_called_once_with(state.pk)

        self.inventory = [{"name": "htop", "version": "3.3.0", "source": "dpkg"}]
        self.assertEqual(baselines.install_linux_pkg(state.pk), "installed")
        self.assertEqual(self.scripts[-1]["env_vars"], ["PKG_NAME=htop"])
        self.assertEqual(self.state().detected_version, "3.3.0")

    def test_sync_and_enrollment(self, nats_cmd):
        self.item_ = self.item()
        linux = Baseline.objects.create(name="Servers", plat=L)
        linux.policies.add(self.policy)
        self.item(baseline=linux, source="linux_pkg", ref="htop")
        deployment = baker.make("clients.Deployment", site=self.agent.site)
        enrolled = Baseline.objects.create(name="Shop", plat=W)
        enrolled.deployments.add(deployment)
        shop = self.item(baseline=enrolled, source="choco", ref="vlc")
        Enrollment.objects.create(agent=self.agent, deployment=deployment)

        agent_enrolled.send(sender=Agent, agent=self.agent, deployment=deployment)
        got = set(BaselineState.objects.values_list("item_id", "status"))
        self.assertEqual(got, {(self.item_.pk, "pending"), (shop.pk, "pending")})

        # gone from the policy: the state goes too
        self.baseline.policies.clear()
        baselines.sync(self.agent)
        self.assertEqual(
            list(BaselineState.objects.values_list("item_id", flat=True)), [shop.pk]
        )

    @patch("software.tasks.baseline_agent_task.delay")
    def test_tick(self, delay, nats_cmd):
        Baseline.objects.update(enabled=False)
        self.assertEqual(baselines.tick(), "no baselines")
        Baseline.objects.update(enabled=True)
        self.item_ = self.item()
        offline = baker.make_recipe("agents.offline_agent", policy=self.policy)
        self.assertEqual(baselines.tick(), "1 agents with baseline work")
        delay.assert_called_once_with(self.agent.pk)
        self.assertFalse(BaselineState.objects.filter(agent=offline).exists())

    def test_cache_key_follows_policy_keys(self, nats_cmd):
        key = baselines._cache_key(self.agent)
        self.assertEqual(key, self.agent._policy_cache_key("baselines"))
        patterns = ("site_workstation_*", "site_server_*", "agent_*")
        self.assertTrue(any(fnmatch.fnmatch(key, p) for p in patterns))
        self.assertTrue(fnmatch.fnmatch(key, "*_baselines"))
        with patch("software.baselines.cache") as cache:
            baselines.forget_cache()
        cache.delete_many_pattern.assert_called_once_with("*_baselines")


@patch("software.baseline_views.forget_cache")
class TestBaselineApi(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.setup_base_instance()
        WingetCatalog.objects.create(pk=1, packages=[["7zip.7zip", "7-Zip", "24.08"]])
        self.policy = baker.make("automation.Policy", active=True)

    def create(self, **body):
        body = {"name": "Office", "plat": W, **body}
        return self.client.post("/software/baselines/", body, format="json")

    def test_crud(self, forget):
        items = [
            {"source": "winget", "ref": "7zip.7zip"},
            {"source": "choco", "ref": "googlechrome", "name": "Google Chrome"},
        ]
        r = self.create(items=items, policies=[self.policy.pk])
        self.assertEqual(r.status_code, 201, r.data)
        pk = r.data["id"]
        first, second = r.data["items"]
        self.assertEqual((first["name"], first["order"]), ("7-Zip", 0))
        self.assertEqual((second["name"], second["order"]), ("Google Chrome", 1))
        self.assertEqual(r.data["policies"], [self.policy.pk])
        forget.assert_called()
        audit = AuditLog.objects.filter(object_type="baseline").order_by("pk")
        self.assertEqual(len(audit[1].after_value["items"]), 2)

        agent = baker.make_recipe("agents.online_agent")
        state = BaselineState.objects.create(
            agent=agent, item_id=first["id"], status="installed"
        )
        body = {"items": [{**first, "required": False}]}
        r = self.client.put(f"/software/baselines/{pk}/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual([i["id"] for i in r.data["items"]], [first["id"]])
        state.refresh_from_db()
        self.assertEqual(state.status, "installed")
        # a new rule checks the item again
        body = {
            "items": [
                {
                    "id": first["id"],
                    "source": "winget",
                    "ref": "7zip.7zip",
                    "detection": {"type": "none"},
                }
            ]
        }
        self.client.put(f"/software/baselines/{pk}/", body, format="json")
        state.refresh_from_db()
        self.assertEqual(state.status, "pending")

        r = self.client.get("/software/baselines/")
        self.assertEqual([b["name"] for b in r.data], ["Office"])
        r = self.client.delete(f"/software/baselines/{pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Baseline.objects.exists())

    def test_validation(self, forget):
        body = uuid.uuid4().bytes
        mac = baker.make(
            "packages.SoftwarePackage",
            name="Mac tool",
            kind="pkg",
            plat=AgentPlat.DARWIN,
            filename="t.pkg",
            sha256=hashlib.sha256(body).hexdigest(),
            size=1,
        )
        for item, error in (
            ({"source": "linux_pkg", "ref": "htop"}, "do not install on windows"),
            ({"source": "winget", "ref": "-x"}, "winget package id"),
            ({"source": "choco", "ref": "a b"}, "chocolatey"),
            ({"source": "package", "ref": "999999"}, "No hosted package"),
            ({"source": "package", "ref": str(mac.pk)}, "macOS package"),
            (
                {"source": "winget", "ref": "7zip.7zip", "detection": {"type": "x"}},
                "type",
            ),
            ({"source": "winget", "ref": "7zip.7zip", "id": 999}, "Not an item"),
            ({"source": "winget", "ref": "7zip.7zip", "timeout": 5}, "timeout"),
        ):
            with self.subTest(item=item):
                r = self.create(items=[item])
                self.assertEqual(r.status_code, 400)
                self.assertIn(error, json.dumps(r.data))
        self.assertEqual(self.create(plat="freebsd").status_code, 400)
        pk = self.create().data["id"]
        r = self.client.put(f"/software/baselines/{pk}/", {"plat": L}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("fixed", str(r.data))

    def test_permissions(self, forget):
        for flags, get, post in (
            ([], 403, 403),
            (["can_manage_packages"], 200, 403),
            (["can_install_packages"], 200, 201),
        ):
            with self.subTest(flags=flags):
                Baseline.objects.all().delete()
                self.client.force_authenticate(user=self.create_user_with_roles(flags))
                self.assertEqual(
                    self.client.get("/software/baselines/").status_code, get
                )
                self.assertEqual(self.create().status_code, post)

    def scoped(self, *flags):
        role = baker.make("accounts.Role", **dict.fromkeys(flags, True))
        role.can_view_sites.add(self.site1)
        user = baker.make("accounts.User", role=role, is_active=True)
        self.client.force_authenticate(user=user)
        return user

    def test_scope(self, forget):
        mine = baker.make_recipe("agents.online_agent", site=self.site1)
        theirs = baker.make_recipe("agents.online_agent", site=self.site3)
        # own reaches only the role's agent, shared only the other one
        own, shared = baker.make("automation.Policy", active=True, _quantity=2)
        Agent.objects.filter(pk=mine.pk).update(policy=own)
        Agent.objects.filter(pk=theirs.pk).update(policy=shared)
        dep_mine = baker.make("clients.Deployment", site=self.site1)
        dep_theirs = baker.make("clients.Deployment", site=self.site3)

        self.scoped("can_install_packages")
        self.assertEqual(self.create(policies=[shared.pk]).status_code, 403)
        self.assertEqual(self.create(deployments=[dep_theirs.pk]).status_code, 403)
        r = self.create(policies=[own.pk], deployments=[dep_mine.pk])
        self.assertEqual(r.status_code, 201, r.data)

        other = Baseline.objects.create(name="Theirs", plat=W)
        other.deployments.add(dep_theirs)
        url = f"/software/baselines/{other.pk}/"
        self.assertEqual(
            self.client.put(url, {"enabled": False}, format="json").status_code, 403
        )
        self.assertEqual(self.client.delete(url).status_code, 403)

    def test_status_and_agent_views(self, forget):
        baseline = Baseline.objects.create(name="Office", plat=W)
        baseline.policies.add(self.policy)
        item = BaselineItem.objects.create(baseline=baseline, source="choco", ref="vlc")
        done = baker.make_recipe(
            "agents.online_agent", site=self.site1, hostname="a-done"
        )
        waiting = baker.make_recipe(
            "agents.online_agent", site=self.site1, hostname="b-wait"
        )
        hidden = baker.make_recipe(
            "agents.online_agent", site=self.site3, hostname="c-hid"
        )
        Agent.objects.filter(pk__in=[done.pk, waiting.pk, hidden.pk]).update(
            policy=self.policy
        )
        BaselineState.objects.create(agent=done, item=item, status="installed")
        BaselineState.objects.create(agent=hidden, item=item, status="failed")

        r = self.client.get(f"/software/baselines/{baseline.pk}/status/")
        self.assertEqual(r.status_code, 200)
        got = [(row["hostname"], row["status"]) for row in r.data]
        self.assertEqual(
            sorted(got),
            [("a-done", "installed"), ("b-wait", "pending"), ("c-hid", "failed")],
        )
        self.scoped("can_install_packages")
        r = self.client.get(f"/software/baselines/{baseline.pk}/status/")
        got = [(row["hostname"], row["status"]) for row in r.data]
        self.assertEqual(sorted(got), [("a-done", "installed"), ("b-wait", "pending")])

        self.client.force_authenticate(user=self.john)
        r = self.client.get(f"/software/{hidden.agent_id}/baseline/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["status"], "failed")
        self.assertEqual(r.data["items"][0]["baseline_name"], "Office")

        with patch("software.tasks.baseline_agent_task.delay") as delay:
            r = self.client.post(f"/software/{hidden.agent_id}/baseline/retry/")
            self.assertEqual(r.status_code, 200)
            delay.assert_called_once_with(hidden.pk)
        state = BaselineState.objects.get(agent=hidden)
        self.assertEqual((state.status, state.attempts), ("pending", 0))
        self.assertTrue(AuditLog.objects.filter(agent_id=hidden.agent_id).exists())

        self.scoped("can_list_software", "can_install_packages")
        for method, url in (
            ("get", f"/software/{hidden.agent_id}/baseline/"),
            ("post", f"/software/{hidden.agent_id}/baseline/retry/"),
        ):
            self.assertEqual(getattr(self.client, method)(url).status_code, 403)
        self.scoped("can_list_software")
        r = self.client.post(f"/software/{done.agent_id}/baseline/retry/")
        self.assertEqual(r.status_code, 403)

    def test_deployment_baselines(self, forget):
        baseline = Baseline.objects.create(name="Office", plat=W)
        dep = baker.make("clients.Deployment", site=self.site1)
        far = baker.make("clients.Deployment", site=self.site3)
        url = f"/software/deployments/{dep.pk}/baselines/"

        r = self.client.put(url, {"baselines": [baseline.pk]}, format="json")
        self.assertEqual((r.status_code, r.data), (200, {"baselines": [baseline.pk]}))
        self.assertEqual(self.client.get(url).data, {"baselines": [baseline.pk]})
        audit = AuditLog.objects.get(action="modify", object_type="site")
        self.assertEqual(audit.after_value, {"baselines": [baseline.pk]})
        for bad in ({"baselines": [999]}, {"baselines": "1"}, {"baselines": [True]}):
            r = self.client.put(url, bad, format="json")
            self.assertEqual(r.status_code, 400)

        self.scoped("can_manage_deployments", "can_list_deployments")
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(
            self.client.put(url, {"baselines": []}, format="json").status_code, 403
        )
        self.scoped(
            "can_manage_deployments", "can_list_deployments", "can_install_packages"
        )
        self.assertEqual(
            self.client.put(url, {"baselines": []}, format="json").status_code, 200
        )
        far_url = f"/software/deployments/{far.pk}/baselines/"
        self.assertEqual(self.client.get(far_url).status_code, 403)
        self.assertEqual(
            self.client.put(far_url, {"baselines": []}, format="json").status_code, 403
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# from itertools import cycle
import datetime as dt
from contextlib import contextmanager
from unittest.mock import AsyncMock, patch
from zoneinfo import ZoneInfo

from celery.exceptions import Retry
from django.conf import settings
from django.core.cache import cache as django_cache
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.models import AgentHistory
from logs.models import DebugLog
from software.models import InstalledSoftware
from ulrmm.constants import AgentHistoryType, AgentPlat, DebugLogLevel
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .installing import get_installing, mark_installing
from .models import DRIVERS_CATEGORY, WinUpdate
from .posix import build_script_payload, parse_packages_output
from .tasks import (
    auto_approve_updates_task,
    bulk_check_for_updates_task,
    bulk_install_updates_task,
    check_agent_update_schedule_task,
    posix_install_updates_task,
    posix_refresh_all_task,
    posix_refresh_task,
    posix_uninstall_task,
)

FIXTURES = settings.BASE_DIR / "ulrmm" / "test_data" / "posix"


def script_reply(stdout: str, retcode: int = 0) -> dict:
    return {
        "stdout": stdout,
        "stderr": "",
        "retcode": retcode,
        "execution_time": 1.0,
        "id": 0,
    }


def fixture_reply(name: str) -> dict:
    return script_reply((FIXTURES / name).read_text())


@contextmanager
def lock_held(*args):
    yield False


PCRE = "apt:libpcre2-8-0:amd64:10.42-1+deb12u1"
PCRE_U = "U\tapt\tlibpcre2-8-0\tamd64\t10.42-1\t10.42-1+deb12u1\tImportant\toldstable-security\n"


class TestAgentWinUpdatesAPI(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.policy = baker.make("winupdate.WinUpdatePolicy", agent=self.agent)
        self.authenticate_agent(self.agent)
        self.url = "/api/v3/winupdates/"

    @patch("agents.models.Agent.nats_cmd")
    def test_reboot_after_install(self, nats_cmd):
        for policy, needs_reboot, reboots in (
            ("never", True, False),
            ("inherit", True, False),
            ("required", False, False),
            ("required", True, True),
            ("always", False, True),
        ):
            nats_cmd.reset_mock()
            self.policy.reboot_after_install = policy
            self.policy.save()

            r = self.client.put(self.url, {"needs_reboot": needs_reboot}, format="json")
            self.assertEqual(r.status_code, 200)
            self.agent.refresh_from_db()
            self.assertEqual(self.agent.needs_reboot, needs_reboot)
            if reboots:
                nats_cmd.assert_called_once_with({"func": "rebootnow"}, wait=False)
            else:
                nats_cmd.assert_not_called()

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_update_result(self):
        django_cache.clear()
        update = baker.make("winupdate.WinUpdate", agent=self.agent, guid="abc")
        mark_installing(self.agent.pk, [update.guid])

        r = self.client.patch(
            self.url, {"guid": "abc", "success": False}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(get_installing(self.agent.pk), set())
        update.refresh_from_db()
        self.assertEqual(update.result, "failed")
        self.assertFalse(update.installed)

        r = self.client.patch(self.url, {"guid": "abc", "success": True}, format="json")
        self.assertEqual(r.status_code, 200)
        update.refresh_from_db()
        self.assertEqual(update.result, "success")
        self.assertTrue(update.installed)
        self.assertTrue(update.downloaded)
        self.assertIsNotNone(update.date_installed)

        r = self.client.patch(
            self.url, {"guid": "nope", "success": True}, format="json"
        )
        self.assertEqual((r.status_code, r.data), (400, "Unknown update guid"))

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_install_end_clears_remaining_markers(self):
        django_cache.clear()
        mark_installing(self.agent.pk, ["unreported"])

        r = self.client.put(self.url, {"needs_reboot": False}, format="json")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(get_installing(self.agent.pk), set())

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("apiv3.views.abulk_nats_command", new_callable=AsyncMock)
    def test_checkin_only_clears_old_markers(self, nats_cmd):
        django_cache.clear()
        with patch("winupdate.installing.time") as installing_time:
            installing_time.time.return_value = 1
            mark_installing(self.agent.pk, ["old"])
            installing_time.time.return_value = 100
            mark_installing(self.agent.pk, ["fresh"])
            installing_time.time.return_value = 120
            r = self.client.post("/api/v3/checkin/", format="json")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(get_installing(self.agent.pk), {"fresh"})

    def wua_update(self, guid):
        return {
            "guid": guid,
            "kb_article_ids": ["5000001"],
            "title": f"update {guid}",
            "installed": False,
            "downloaded": False,
            "description": "",
            "severity": "Critical",
            "categories": [],
            "category_ids": [],
            "more_info_urls": [],
            "support_url": "",
            "revision_number": 1,
        }

    def test_scan_keeps_ignored_updates(self):
        self.policy.critical = "approve"
        self.policy.save()
        ignored = baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            guid="ignored",
            severity="Critical",
            action="ignore",
            installed=False,
        )
        baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            guid="stale",
            severity="Critical",
            action="nothing",
            installed=False,
        )

        r = self.client.post(
            self.url, {"wua_updates": [self.wua_update("offered")]}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        # the row windows stopped offering is gone, the ignored one stays
        self.assertCountEqual(
            self.agent.winupdates.values_list("guid", flat=True),
            ["ignored", "offered"],
        )
        ignored.refresh_from_db()
        self.assertEqual(ignored.action, "ignore")

        # and the kept row is never approved or installed
        self.agent.approve_updates()
        self.assertEqual(self.agent.get_approved_update_guids(), ["offered"])

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_installed_scan_clears_installing(self):
        django_cache.clear()
        update = baker.make("winupdate.WinUpdate", agent=self.agent, guid="installed")
        mark_installing(self.agent.pk, [update.guid])
        payload = self.wua_update(update.guid)
        payload["installed"] = True

        r = self.client.post(self.url, {"wua_updates": [payload]}, format="json")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(get_installing(self.agent.pk), set())

    def test_scan_without_updates_keeps_decisions(self):
        approved = baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            guid="approved",
            severity="Critical",
            action="approve",
            installed=False,
        )

        # a scan that reports nothing is a broken scan, not an empty machine
        r = self.client.post(self.url, {"wua_updates": []}, format="json")
        self.assertEqual(r.status_code, 400)

        approved.refresh_from_db()
        self.assertEqual(approved.action, "approve")
        self.assertEqual(
            DebugLog.objects.filter(
                agent=self.agent,
                log_level=DebugLogLevel.WARN,
                message__contains="returned no updates",
            ).count(),
            1,
        )


class TestPosixPackageTasks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = self.make_agent(AgentPlat.LINUX)

    def make_agent(self, plat=AgentPlat.WINDOWS):
        return baker.make_recipe("agents.agent", plat=plat, last_seen=djangotime.now())

    def make_update(self, guid, **kwargs):
        kwargs.setdefault("agent", self.agent)
        return baker.make("winupdate.WinUpdate", guid=guid, **kwargs)

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("agents.models.Agent.nats_cmd")
    def test_posix_installing_is_marked_and_always_cleared(self, nats_cmd):
        django_cache.clear()
        guid = "apt:curl:amd64:1"
        self.make_update(guid, action="approve")

        def timeout(*args, **kwargs):
            self.assertEqual(get_installing(self.agent.pk), {guid})
            return "timeout"

        nats_cmd.side_effect = timeout
        self.assertEqual(posix_install_updates_task(self.agent.pk, [guid]), "failed")
        self.assertEqual(get_installing(self.agent.pk), set())

        def fail(*args, **kwargs):
            self.assertEqual(get_installing(self.agent.pk), {guid})
            raise RuntimeError("task failed")

        with patch("winupdate.tasks._posix_install_updates", side_effect=fail):
            with self.assertRaises(RuntimeError):
                posix_install_updates_task(self.agent.pk, [guid])

        self.assertEqual(get_installing(self.agent.pk), set())

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("winupdate.tasks.redis_lock", lock_held)
    def test_posix_retry_keeps_installing_marker(self):
        django_cache.clear()
        guid = "apt:curl:amd64:1"

        with self.assertRaises(Retry):
            posix_install_updates_task(self.agent.pk, [guid])

        self.assertEqual(get_installing(self.agent.pk), {guid})

        with patch.object(posix_install_updates_task, "max_retries", 0):
            self.assertIn(
                "still running", posix_install_updates_task(self.agent.pk, [guid])
            )
        self.assertEqual(get_installing(self.agent.pk), {guid})

    @patch("agents.models.Agent.nats_cmd")
    def test_refresh_imports_inventory_and_updates(self, nats_cmd):
        reply = fixture_reply("debian12_refresh.txt")
        nats_cmd.return_value = reply
        self.agent.needs_reboot = True
        self.agent.save()

        self.assertEqual(posix_refresh_task(self.agent.pk), "ok")

        nats_cmd.assert_called_once_with(build_script_payload("refresh"), timeout=1530)
        sw = InstalledSoftware.objects.get(agent=self.agent)
        self.assertEqual(sw.software, parse_packages_output(reply["stdout"]).software)

        update = WinUpdate.objects.get(agent=self.agent)
        self.assertEqual(update.guid, "apt:libpcre2-8-0:amd64:10.42-1+deb12u1")
        self.assertEqual(update.severity, "Important")
        self.assertEqual(update.categories, ["oldstable-security"])
        self.assertEqual(update.action, "nothing")
        self.assertFalse(update.installed)
        self.agent.refresh_from_db()
        self.assertFalse(self.agent.needs_reboot)

    @patch("agents.models.Agent.nats_cmd")
    def test_scan_updates_existing_and_deletes_stale(self, nats_cmd):
        existing = self.make_update(
            "apt:libpcre2-8-0:amd64:10.42-1+deb12u1", action="approve", severity=""
        )
        stale = self.make_update("apt:old:amd64:1", installed=False)
        done = self.make_update("apt:done:amd64:1", installed=True)
        nats_cmd.return_value = fixture_reply("debian12_scan.txt")

        posix_refresh_task(self.agent.pk, "scan")

        existing.refresh_from_db()
        self.assertEqual(existing.action, "approve")
        self.assertEqual(existing.severity, "Important")
        self.assertFalse(WinUpdate.objects.filter(pk=stale.pk).exists())
        self.assertTrue(WinUpdate.objects.filter(pk=done.pk).exists())
        self.assertEqual(WinUpdate.objects.filter(agent=self.agent).count(), 2)
        self.assertFalse(InstalledSoftware.objects.filter(agent=self.agent).exists())

    @patch("agents.models.Agent.nats_cmd")
    def test_scan_keeps_rows_of_failed_manager(self, nats_cmd):
        apt = self.make_update("apt:curl:amd64:7.88.1-10+deb12u8")
        flatpak = self.make_update("flatpak:org.gimp.GIMP:x86_64:2.10.38")
        brew = self.make_update("brew:git::2.46.0")
        cask = self.make_update("brew-cask:firefox::130.0")
        nats_cmd.return_value = script_reply(
            "E\tapt\tupgrade simulation failed: E: broken\n"
            "E\tbrew\tbrew outdated failed: oops\n"
            "E\tdpkg\tnot a manager\n"
            "R\t0\n"
        )

        self.assertEqual(posix_refresh_task(self.agent.pk, "scan"), "ok")

        self.assertTrue(WinUpdate.objects.filter(pk=apt.pk).exists())
        self.assertTrue(WinUpdate.objects.filter(pk=brew.pk).exists())
        self.assertFalse(WinUpdate.objects.filter(pk=cask.pk).exists())
        self.assertFalse(WinUpdate.objects.filter(pk=flatpak.pk).exists())

    @patch("agents.models.Agent.nats_cmd")
    def test_apt_update_error_does_not_keep_stale_rows(self, nats_cmd):
        stale = self.make_update("apt:curl:amd64:7.88.1-10+deb12u8")
        nats_cmd.return_value = script_reply(
            "E\tapt-update\tapt-get update failed: W: Failed to fetch x\n"
            + PCRE_U
            + "R\t0\n"
        )

        self.assertEqual(posix_refresh_task(self.agent.pk, "scan"), "ok")

        self.assertFalse(WinUpdate.objects.filter(pk=stale.pk).exists())
        self.assertTrue(WinUpdate.objects.filter(guid=PCRE).exists())
        # the scan completed, so this is a warning and not a failure
        logs = DebugLog.objects.filter(agent=self.agent)
        self.assertTrue(logs.filter(message__contains="finished with errors").exists())
        self.assertFalse(logs.filter(log_level=DebugLogLevel.ERROR).exists())

    @patch("agents.models.Agent.nats_cmd")
    def test_scan_carries_actions_to_new_version(self, nats_cmd):
        old = {
            "apt:curl:amd64:1:7.88.1-10": "approve",
            "apt:vim:amd64:2:9.0.1378-2": "ignore",
            "apt:bash:amd64:5.2.15-2": "inherit",
            "apt:zlib1g:i386:1:1.2.13": "approve",
        }
        for guid, action in old.items():
            self.make_update(guid, action=action)
        nats_cmd.return_value = script_reply(
            "U\tapt\tcurl\tamd64\t1:7.88.1-10\t1:7.88.1-11\n"
            "U\tapt\tvim\tamd64\t2:9.0.1378-2\t2:9.0.1378-3\n"
            "U\tapt\tbash\tamd64\t5.2.15-2\t5.2.15-3\n"
            "U\tapt\tzlib1g\tamd64\t1:1.2.13\t1:1.2.14\n"
            "R\t0\n"
        )

        posix_refresh_task(self.agent.pk, "scan")

        self.assertEqual(
            dict(WinUpdate.objects.values_list("guid", "action")),
            {
                "apt:curl:amd64:1:7.88.1-11": "approve",
                "apt:vim:amd64:2:9.0.1378-3": "ignore",
                "apt:bash:amd64:5.2.15-3": "nothing",
                "apt:zlib1g:amd64:1:1.2.14": "nothing",
            },
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_refresh_keeps_inventory_of_failed_sources(self, nats_cmd):
        def sw(source, name, version="1"):
            return {
                "name": name,
                "version": version,
                "publisher": "",
                "install_date": "",
                "size": "",
                "source": source,
                "location": "",
                "uninstall": "",
            }

        baker.make(
            "software.InstalledSoftware",
            agent=self.agent,
            software=[
                sw("dpkg", "bash"),
                sw("snap", "lxd"),
                sw("flatpak", "org.gimp.GIMP"),
                sw("app", "Safari"),
                sw("brew", "git"),
                sw("brew-cask", "firefox"),
            ],
        )
        nats_cmd.return_value = script_reply(
            "S\tdpkg\tbash\t2\n"
            "S\tflatpak\torg.gimp.GIMP\t2\n"
            "S\tbrew-cask\tfirefox\t2\n"
            "E\tsnap-inventory\tcannot communicate with server\n"
            "E\tsystem_profiler\tfailed\n"
            "E\tbrew-inventory\tlist failed\n"
            "E\tflatpak\tremote-ls failed\n"
            "R\t0\n"
        )

        self.assertEqual(posix_refresh_task(self.agent.pk), "ok")

        software = InstalledSoftware.objects.get(agent=self.agent).software
        self.assertCountEqual(
            [(i["source"], i["name"], i["version"]) for i in software],
            [
                ("dpkg", "bash", "2"),
                ("flatpak", "org.gimp.GIMP", "2"),
                ("brew-cask", "firefox", "2"),
                ("snap", "lxd", "1"),
                ("app", "Safari", "1"),
                ("brew", "git", "1"),
            ],
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_inventory_only(self, nats_cmd):
        update = self.make_update("apk:musl:x86_64:1.2.5-r11")
        nats_cmd.return_value = fixture_reply("alpine320_inventory.txt")

        posix_refresh_task(self.agent.pk, "inventory")

        software = InstalledSoftware.objects.get(agent=self.agent).software
        self.assertEqual(len(software), 14)
        self.assertTrue(WinUpdate.objects.filter(pk=update.pk).exists())

    @patch("agents.models.Agent.nats_cmd")
    def test_refresh_failure_keeps_data(self, nats_cmd):
        software = [{"name": "bash"}]
        baker.make("software.InstalledSoftware", agent=self.agent, software=software)
        update = self.make_update("apt:curl:amd64:7.88.1-10+deb12u8")

        for reply in (
            "timeout",
            "natsdown",
            script_reply("", retcode=1),
            script_reply("E\tnone\tno supported package manager found\n", retcode=2),
            script_reply(""),
            # agent timeout with the output collected so far
            script_reply(fixture_reply("debian12_refresh.txt")["stdout"], retcode=98),
        ):
            nats_cmd.return_value = reply
            posix_refresh_task(self.agent.pk, "refresh")

            self.assertEqual(
                InstalledSoftware.objects.get(agent=self.agent).software, software
            )
            self.assertTrue(WinUpdate.objects.filter(pk=update.pk).exists())

    @patch("winupdate.tasks.redis_lock", lock_held)
    @patch("agents.models.Agent.nats_cmd")
    def test_lock_held(self, nats_cmd):
        self.assertIn("already running", posix_refresh_task(self.agent.pk))
        with self.assertRaises(Retry):
            posix_install_updates_task(self.agent.pk, ["apt:curl:amd64:1"])
        self.assertEqual(DebugLog.objects.filter(agent=self.agent).count(), 1)

        with patch.object(posix_install_updates_task, "max_retries", 0):
            r = posix_install_updates_task(self.agent.pk, ["apt:curl:amd64:1"])
        self.assertIn("still running", r)
        self.assertEqual(
            DebugLog.objects.filter(
                agent=self.agent, message__contains="still running"
            ).count(),
            2,
        )
        nats_cmd.assert_not_called()

    @patch("winupdate.tasks.redis_lock")
    @patch("agents.models.Agent.nats_cmd", autospec=True)
    def test_refresh_all(self, nats_cmd, redis_lock):
        ok, timeout, broken, busy = [self.make_agent(AgentPlat.LINUX) for _ in range(4)]
        for agent in (ok, timeout, broken, busy):
            self.make_update("apt:stale:amd64:1", agent=agent)
        released = []

        @contextmanager
        def fake_lock(key, oid):
            acquired = key != f"posix-packages-{busy.pk}"
            try:
                yield acquired
            finally:
                if acquired:
                    released.append(key)

        redis_lock.side_effect = fake_lock
        replies = {
            ok.pk: fixture_reply("debian12_refresh.txt"),
            timeout.pk: "timeout",
            broken.pk: RuntimeError("nats: no responders available for request"),
        }

        def reply(agent, data, timeout=30, wait=True):
            if isinstance(replies[agent.pk], Exception):
                raise replies[agent.pk]
            return replies[agent.pk]

        nats_cmd.side_effect = reply

        posix_refresh_all_task([ok.pk, timeout.pk, broken.pk, busy.pk])

        self.assertCountEqual(
            [c.args[0].pk for c in nats_cmd.call_args_list],
            [ok.pk, timeout.pk, broken.pk],
        )
        for c in nats_cmd.call_args_list:
            self.assertEqual(c.args[1], build_script_payload("refresh"))
            self.assertEqual(c.kwargs, {"timeout": 1530})
        self.assertCountEqual(
            released, [f"posix-packages-{i.pk}" for i in (ok, timeout, broken)]
        )

        self.assertEqual(
            list(WinUpdate.objects.filter(agent=ok).values_list("guid", flat=True)),
            [PCRE],
        )
        self.assertTrue(InstalledSoftware.objects.filter(agent=ok).exists())
        for agent in (timeout, broken, busy):
            self.assertTrue(
                WinUpdate.objects.filter(agent=agent, guid="apt:stale:amd64:1").exists()
            )
            self.assertFalse(InstalledSoftware.objects.filter(agent=agent).exists())

    @patch("winupdate.tasks.redis_lock")
    @patch("agents.models.Agent.nats_cmd", autospec=True)
    def test_refresh_all_releases_locks_per_chunk(self, nats_cmd, redis_lock):
        agents = [self.make_agent(AgentPlat.LINUX) for _ in range(4)]
        released = []
        released_at_call = {}

        @contextmanager
        def fake_lock(key, oid):
            try:
                yield True
            finally:
                released.append(key)

        def reply(agent, data, timeout=30, wait=True):
            released_at_call[agent.pk] = list(released)
            return "timeout"

        redis_lock.side_effect = fake_lock
        nats_cmd.side_effect = reply

        with override_settings(ULRMM_POSIX_REFRESH_CONCURRENCY=2):
            posix_refresh_all_task([a.pk for a in agents])

        first, second = (
            sorted(a.pk for a in agents)[:2],
            sorted(a.pk for a in agents)[2:],
        )
        for pk in first:
            self.assertEqual(released_at_call[pk], [])
        # the first chunk's locks are gone before the second chunk runs its scripts
        for pk in second:
            self.assertCountEqual(
                released_at_call[pk], [f"posix-packages-{i}" for i in first]
            )
        self.assertEqual(len(released), 4)

    @patch("core.management.commands.clear_redis_celery_locks.cache")
    def test_clear_locks_includes_posix(self, cache):
        call_command("clear_redis_celery_locks")
        cache.delete_many_pattern.assert_any_call("posix-packages-*")

    @patch("agents.models.Agent.nats_cmd")
    def test_install_marks_results_before_rescan_import(self, nats_cmd):
        pcre = "apt:libpcre2-8-0:amd64:10.42-1+deb12u1"
        musl = "apk:musl:x86_64:1.2.5-r11"
        self.make_update(pcre, action="approve")
        self.make_update(musl, action="approve")
        baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            reboot_after_install="always",
        )
        nats_cmd.side_effect = [
            fixture_reply("debian12_install.txt"),
            script_reply("R\t1\n"),
        ]

        r = posix_install_updates_task(self.agent.pk, [pcre, "apt:-rf::1", musl], "bob")
        self.assertEqual(r, "ok")

        hist = AgentHistory.objects.get(agent=self.agent)
        self.assertEqual(hist.type, AgentHistoryType.SCRIPT_RUN)
        self.assertEqual(hist.username, "bob")

        # reboot policy is ignored without ULRMM_POSIX_PATCH_AUTOMATION
        self.assertEqual(nats_cmd.call_count, 2)
        payload = build_script_payload("install", [pcre, musl])
        payload["id"] = hist.pk
        self.assertEqual(nats_cmd.call_args_list[0].args[0], payload)
        self.assertEqual(nats_cmd.call_args_list[0].kwargs, {"timeout": 3630})
        self.assertEqual(
            nats_cmd.call_args_list[1].args[0], build_script_payload("scan")
        )

        # installed and gone from the rescan
        update = WinUpdate.objects.get(agent=self.agent, guid=pcre)
        self.assertTrue(update.installed)
        self.assertEqual(update.result, "success")
        # failed and not offered anymore, removed by the rescan import
        self.assertFalse(WinUpdate.objects.filter(guid=musl).exists())

        self.agent.refresh_from_db()
        self.assertTrue(self.agent.needs_reboot)
        self.assertIsNotNone(self.agent.patches_last_installed)

    @patch("agents.models.Agent.nats_cmd")
    def test_uninstall_success(self, nats_cmd):
        baker.make(
            "software.InstalledSoftware",
            agent=self.agent,
            software=[{"name": "curl", "source": "dpkg", "location": ""}],
        )
        nats_cmd.side_effect = [
            script_reply("I\tdpkg:curl\t0\tok\n"),
            script_reply("S\tdpkg\tlibfoo\t1\n"),
        ]

        self.assertEqual(
            posix_uninstall_task(self.agent.pk, "dpkg", "curl", "bob"), "ok"
        )

        hist = AgentHistory.objects.get(agent=self.agent)
        self.assertEqual(hist.type, AgentHistoryType.SCRIPT_RUN)
        self.assertEqual(hist.command, "posix_packages.sh remove dpkg curl")
        self.assertEqual(hist.username, "bob")
        payload = build_script_payload("remove", ["dpkg", "curl"])
        payload["id"] = hist.pk
        self.assertEqual(nats_cmd.call_args_list[0].args[0], payload)
        self.assertEqual(
            InstalledSoftware.objects.get(agent=self.agent).software[0]["name"],
            "libfoo",
        )

    @patch("agents.models.Agent.nats_cmd")
    def test_uninstall_nonzero_and_still_present(self, nats_cmd):
        software = "S\tdpkg\tcurl\t1\n"
        nats_cmd.side_effect = [
            script_reply("I\tdpkg:curl\t1\trefused: required by foo\n"),
            script_reply(software),
        ]
        self.assertEqual(posix_uninstall_task(self.agent.pk, "dpkg", "curl"), "failed")

        nats_cmd.side_effect = [
            script_reply("I\tdpkg:curl\t0\tok\n"),
            script_reply(software),
        ]
        self.assertEqual(posix_uninstall_task(self.agent.pk, "dpkg", "curl"), "failed")

    @patch("agents.models.Agent.nats_cmd")
    def test_uninstall_revalidates_protected_target(self, nats_cmd):
        self.assertEqual(posix_uninstall_task(self.agent.pk, "dpkg", "bash"), "failed")
        nats_cmd.assert_not_called()
        self.assertFalse(AgentHistory.objects.exists())

    @patch("winupdate.tasks.redis_lock", lock_held)
    @patch("agents.models.Agent.nats_cmd")
    def test_uninstall_lock_busy_retries(self, nats_cmd):
        with self.assertRaises(Retry):
            posix_uninstall_task(self.agent.pk, "dpkg", "curl")
        nats_cmd.assert_not_called()

    @patch("agents.models.Agent.nats_cmd")
    def test_install_still_offered_is_failed(self, nats_cmd):
        pcre = "apt:libpcre2-8-0:amd64:10.42-1+deb12u1"
        self.make_update(pcre, action="approve")
        nats_cmd.side_effect = [
            fixture_reply("debian12_install.txt"),
            fixture_reply("debian12_scan.txt"),
        ]

        posix_install_updates_task(self.agent.pk, [pcre])

        update = WinUpdate.objects.get(agent=self.agent, guid=pcre)
        self.assertFalse(update.installed)
        self.assertEqual(update.result, "failed")
        self.assertEqual(update.action, "approve")

    @patch("agents.models.Agent.nats_cmd")
    def test_install_without_rescan(self, nats_cmd):
        ok = "apt:libpcre2-8-0:amd64:10.42-1+deb12u1"
        missing = "apk:musl:x86_64:1.2.5-r11"
        self.make_update(ok, action="approve")
        self.make_update(missing, action="approve")
        nats_cmd.side_effect = [fixture_reply("debian12_install.txt"), "timeout"]

        posix_install_updates_task(self.agent.pk, [ok, missing])

        self.assertTrue(WinUpdate.objects.get(guid=ok).installed)
        self.assertEqual(WinUpdate.objects.get(guid=missing).result, "failed")

        # no reply to the install: nothing is marked and no rescan runs
        WinUpdate.objects.update(result="n/a", installed=False)
        nats_cmd.reset_mock()
        nats_cmd.side_effect = ["timeout"]
        self.assertEqual(posix_install_updates_task(self.agent.pk, [ok]), "failed")
        self.assertEqual(nats_cmd.call_count, 1)
        self.assertEqual(WinUpdate.objects.get(guid=ok).result, "n/a")

    def test_install_no_valid_guids(self):
        r = posix_install_updates_task(self.agent.pk, ["apt:-rf::1", None])
        self.assertIn("No valid", r)
        self.assertFalse(AgentHistory.objects.exists())

    @patch("agents.models.Agent.nats_cmd")
    def test_install_reboot_only_with_automation(self, nats_cmd):
        pcre = "apt:libpcre2-8-0:amd64:10.42-1+deb12u1"
        baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            reboot_after_install="required",
        )
        replies = [fixture_reply("debian12_install.txt"), script_reply("R\t1\n")]

        self.make_update(pcre, action="approve")
        nats_cmd.side_effect = list(replies)
        posix_install_updates_task(self.agent.pk, [pcre])
        self.assertEqual(nats_cmd.call_count, 2)

        WinUpdate.objects.all().delete()
        self.make_update(pcre, action="approve")
        nats_cmd.reset_mock()
        nats_cmd.side_effect = list(replies) + [None]
        with override_settings(ULRMM_POSIX_PATCH_AUTOMATION=True):
            posix_install_updates_task(self.agent.pk, [pcre])

        self.assertEqual(nats_cmd.call_count, 3)
        nats_cmd.assert_called_with({"func": "rebootnow"}, wait=False)

    @override_settings(ULRMM_POSIX_PATCH_AUTOMATION=True)
    @patch("agents.models.Agent.nats_cmd")
    def test_install_timeout_never_reboots(self, nats_cmd):
        baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            reboot_after_install="always",
        )
        self.make_update(PCRE, action="approve")
        nats_cmd.side_effect = [
            script_reply(f"I\t{PCRE}\t0\tok\n", retcode=98),
            script_reply(PCRE_U + "R\t1\n"),
            None,
        ]

        self.assertEqual(posix_install_updates_task(self.agent.pk, [PCRE]), "ok")

        self.assertEqual(nats_cmd.call_count, 2)
        update = WinUpdate.objects.get(agent=self.agent, guid=PCRE)
        self.assertEqual(update.result, "failed")
        self.assertFalse(update.installed)
        self.agent.refresh_from_db()
        self.assertTrue(self.agent.needs_reboot)

    @patch("agents.models.Agent.nats_cmd")
    def test_install_pacman_all_or_nothing(self, nats_cmd):
        a = "pacman:systemd:x86_64:261.3-1"
        b = "pacman:xz:x86_64:5.8.4-1"
        curl = "apt:curl:amd64:7.88.1-10+deb12u8"
        self.make_update(a, action="approve")
        pending = self.make_update(b, action="ignore")
        self.make_update("pacman:done:x86_64:1", installed=True)
        self.make_update(curl, action="approve")
        nats_cmd.side_effect = ["timeout"]

        posix_install_updates_task(self.agent.pk, [a, curl])

        self.assertEqual(nats_cmd.call_args.args[0]["script_args"], ["install", curl])
        # a skip is no failed install, the failed patch options ignore it
        skipped = WinUpdate.objects.get(guid=a)
        self.assertEqual((skipped.result, skipped.fail_count), ("n/a", 0))
        self.assertTrue(
            DebugLog.objects.filter(
                agent=self.agent, message__contains="approved together"
            ).exists()
        )

        # nothing left to install
        nats_cmd.reset_mock()
        self.assertEqual(posix_install_updates_task(self.agent.pk, [a]), "failed")
        nats_cmd.assert_not_called()
        self.assertEqual(AgentHistory.objects.filter(agent=self.agent).count(), 1)

        # every pending pacman update requested
        pending.delete()
        nats_cmd.side_effect = ["timeout"]
        posix_install_updates_task(self.agent.pk, [a, curl])
        self.assertEqual(
            nats_cmd.call_args.args[0]["script_args"], ["install", a, curl]
        )

    @patch("winupdate.tasks.posix_install_updates_task.delay")
    @patch("agents.models.Agent.nats_cmd")
    def test_schedule_task_posix_opt_in(self, nats_cmd, install):
        windows = self.make_agent()
        now = dt.datetime.now(ZoneInfo("UTC"))
        for agent in (self.agent, windows):
            agent.time_zone = "UTC"
            agent.save()
            baker.make(
                "winupdate.WinUpdatePolicy",
                agent=agent,
                run_time_frequency="daily",
                run_time_days=[now.weekday()],
                run_time_hour=now.hour,
            )
        guid = "apt:curl:amd64:7.88.1-10+deb12u8"
        self.make_update(guid, action="approve")
        baker.make("winupdate.WinUpdate", agent=windows, guid="win", action="approve")

        check_agent_update_schedule_task()
        install.assert_not_called()
        nats_cmd.assert_called_once_with(
            {"func": "installwinupdates", "guids": ["win"]}, wait=False
        )

        windows.patches_last_installed = None
        windows.save()
        nats_cmd.reset_mock()
        with override_settings(ULRMM_POSIX_PATCH_AUTOMATION=True):
            check_agent_update_schedule_task()

        install.assert_called_once_with(self.agent.pk, [guid])
        nats_cmd.assert_called_once()

    @patch("winupdate.tasks.time.sleep")
    @patch("winupdate.tasks.posix_refresh_all_task.delay")
    @patch("winupdate.tasks.posix_refresh_task.delay")
    @patch("agents.models.Agent.nats_cmd")
    def test_auto_approve_and_bulk_scan_branch(
        self, nats_cmd, refresh, refresh_all, sleep
    ):
        windows = self.make_agent()
        mac = self.make_agent(AgentPlat.DARWIN)
        baker.make_recipe("agents.agent", plat=AgentPlat.LINUX)  # offline

        auto_approve_updates_task()
        refresh_all.assert_called_once()
        self.assertCountEqual(refresh_all.call_args.args[0], [self.agent.pk, mac.pk])
        refresh.assert_not_called()
        nats_cmd.assert_called_once_with(
            {"func": "getwinupdates", "wua_drivers": True}, wait=False
        )

        refresh.reset_mock()
        nats_cmd.reset_mock()
        bulk_check_for_updates_task([self.agent.pk, windows.pk])
        refresh.assert_called_once_with(self.agent.pk, "scan")
        nats_cmd.assert_called_once_with(
            {"func": "getwinupdates", "wua_drivers": True}, wait=False
        )

    @patch("winupdate.tasks.time.sleep")
    @patch("winupdate.tasks.posix_install_updates_task.delay")
    @patch("agents.models.Agent.nats_cmd")
    def test_bulk_install_branch(self, nats_cmd, install, sleep):
        windows = self.make_agent()
        no_updates = self.make_agent(AgentPlat.DARWIN)
        guid = "apt:curl:amd64:7.88.1-10+deb12u8"
        self.make_update(guid, action="approve")
        self.make_update("apt:bash:amd64:5.2.15-2+b8", action="approve", installed=True)

        bulk_install_updates_task([self.agent.pk, windows.pk, no_updates.pk])

        install.assert_called_once_with(self.agent.pk, [guid])
        # nothing approved on the Windows agent, so nothing is sent
        nats_cmd.assert_not_called()

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("winupdate.tasks.time.sleep")
    @patch("agents.models.Agent.nats_cmd")
    def test_bulk_install_marks_only_after_nats_publish(self, nats_cmd, sleep):
        django_cache.clear()
        windows = self.make_agent()
        update = baker.make(
            "winupdate.WinUpdate", agent=windows, guid="win", action="approve"
        )

        nats_cmd.return_value = "natsdown"
        bulk_install_updates_task([windows.pk])
        self.assertEqual(get_installing(windows.pk), set())

        nats_cmd.return_value = None
        bulk_install_updates_task([windows.pk])
        self.assertEqual(get_installing(windows.pk), {update.guid})


class TestPatchSchedule(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.agent", time_zone="UTC", last_seen=djangotime.now()
        )
        baker.make(
            "winupdate.WinUpdate", agent=self.agent, guid="win", action="approve"
        )
        self.policy = baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            run_time_frequency="monthly",
            run_time_hour=3,
        )

    @patch("winupdate.tasks.dt")
    @patch("agents.models.Agent.nats_cmd")
    def test_monthly_runs_on_the_last_day_of_short_months(self, nats_cmd, mock_dt):
        for run_time_day, date, runs in (
            (31, (2026, 4, 30), True),
            (31, (2026, 4, 29), False),
            (31, (2026, 3, 31), True),
            (31, (2026, 3, 30), False),
            (31, (2026, 2, 28), True),
            (31, (2024, 2, 29), True),
            (31, (2024, 2, 28), False),
            (29, (2024, 2, 29), True),
            (29, (2026, 2, 28), True),
        ):
            with self.subTest(run_time_day=run_time_day, date=date):
                self.policy.run_time_day = run_time_day
                self.policy.save(update_fields=["run_time_day"])
                self.agent.patches_last_installed = None
                self.agent.save(update_fields=["patches_last_installed"])
                nats_cmd.reset_mock()
                mock_dt.datetime.now.return_value = dt.datetime(
                    *date, hour=3, tzinfo=ZoneInfo("UTC")
                )

                check_agent_update_schedule_task()

                if runs:
                    nats_cmd.assert_called_once_with(
                        {"func": "installwinupdates", "guids": ["win"]}, wait=False
                    )
                else:
                    nats_cmd.assert_not_called()

                # the clamped day is never written back to the policy
                self.policy.refresh_from_db()
                self.assertEqual(self.policy.run_time_day, run_time_day)

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("winupdate.tasks.dt")
    @patch("agents.models.Agent.nats_cmd")
    def test_schedule_marks_only_after_nats_publish(self, nats_cmd, mock_dt):
        django_cache.clear()
        now = dt.datetime.now(ZoneInfo("UTC"))
        self.policy.run_time_frequency = "daily"
        self.policy.run_time_days = [now.weekday()]
        self.policy.run_time_hour = now.hour
        self.policy.save()
        mock_dt.datetime.now.return_value = now

        nats_cmd.return_value = "natsdown"
        check_agent_update_schedule_task()
        self.assertEqual(get_installing(self.agent.pk), set())
        self.agent.refresh_from_db()
        self.assertIsNone(self.agent.patches_last_installed)

        nats_cmd.return_value = None
        check_agent_update_schedule_task()
        self.assertEqual(get_installing(self.agent.pk), {"win"})
        self.agent.refresh_from_db()
        self.assertIsNotNone(self.agent.patches_last_installed)


class TestFailedPatchOptions(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent", last_seen=djangotime.now())
        baker.make("winupdate.WinUpdate", agent=self.agent, guid="ok", action="approve")
        baker.make(
            "winupdate.WinUpdate", agent=self.agent, guid="bad", action="approve"
        )
        self.policy = baker.make(
            "winupdate.WinUpdatePolicy",
            agent=self.agent,
            reprocess_failed_inherit=False,
        )

    def automatic(self) -> list:
        return sorted(self.agent.get_approved_update_guids(automatic=True))

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_reprocess_limit(self):
        django_cache.clear()
        self.agent.set_update_result("bad", False)
        bad = self.agent.winupdates.get(guid="bad")
        self.assertEqual((bad.result, bad.fail_count), ("failed", 1))

        # off: the schedule leaves a failed update alone, Install now does not
        self.assertEqual(self.automatic(), ["ok"])
        self.assertEqual(sorted(self.agent.get_approved_update_guids()), ["bad", "ok"])

        self.policy.reprocess_failed = True
        self.policy.reprocess_failed_times = 2
        self.policy.save()
        self.assertEqual(self.automatic(), ["bad", "ok"])
        self.agent.set_update_result("bad", False)
        self.assertEqual(self.automatic(), ["bad", "ok"])
        self.agent.set_update_result("bad", False)
        self.assertEqual(self.automatic(), ["ok"])

        self.agent.set_update_result("bad", True)
        bad.refresh_from_db()
        self.assertEqual((bad.installed, bad.fail_count), (True, 0))

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_policy_override_wins(self):
        top = baker.make("automation.Policy", active=True)
        baker.make(
            "winupdate.WinUpdatePolicy",
            policy=top,
            reprocess_failed=True,
            reprocess_failed_times=5,
        )
        self.agent.policy = top
        self.agent.save()
        self.agent.set_update_result("bad", False)
        self.assertEqual(self.automatic(), ["ok"])
        self.policy.reprocess_failed_inherit = True
        self.policy.save()
        self.assertEqual(self.automatic(), ["bad", "ok"])

    @override_settings(CACHES=LOCMEM_CACHE)
    @patch("winupdate.tasks.patch_failed_email_task.apply_async")
    def test_email_once_per_run(self, apply_async):
        django_cache.clear()
        self.agent.set_update_result("bad", False)
        apply_async.assert_not_called()

        self.policy.email_if_fail = True
        self.policy.save()
        self.agent.set_update_result("bad", False)
        self.agent.set_update_result("ok", False)
        apply_async.assert_called_once()
        self.assertEqual(apply_async.call_args.args[0], (self.agent.pk,))

    @patch("core.models.CoreSettings.send_mail", return_value=("ok", True))
    def test_email_lists_failed_updates(self, send_mail):
        from .tasks import patch_failed_email_task

        patch_failed_email_task(self.agent.pk)
        send_mail.assert_not_called()

        self.agent.winupdates.filter(guid="bad").update(
            result="failed", fail_count=3, title="Bad update"
        )
        patch_failed_email_task(self.agent.pk)
        subject, body = send_mail.call_args.args
        self.assertIn("patch installation failed", subject)
        self.assertTrue(body.endswith(":\n- Bad update (failed 3 times)"), body)


class TestDriverUpdates(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.agent")
        self.policy = baker.make("winupdate.WinUpdatePolicy", agent=self.agent)
        self.authenticate_agent(self.agent)
        self.url = "/api/v3/winupdates/"

    def wua(self, guid, kb="5000001", **extra):
        return {
            "guid": guid,
            "kb_article_ids": [kb] if kb else [],
            "title": f"update {guid}",
            "installed": False,
            "downloaded": False,
            "description": "",
            "severity": "",
            "categories": [],
            "category_ids": [],
            "more_info_urls": [],
            "support_url": "",
            "revision_number": 1,
            **extra,
        }

    def flags(self) -> dict:
        return dict(self.agent.winupdates.values_list("guid", "is_driver"))

    def test_scan_flags_drivers(self):
        updates = [
            self.wua("software", type="software"),
            # a pending driver update has no KB, it still gets a row
            self.wua("driver", kb=None, type="driver"),
            # older agents send no type, installed drivers carry the category
            self.wua(
                "old-agent-driver",
                kb=None,
                installed=True,
                category_ids=[DRIVERS_CATEGORY],
            ),
            self.wua("old-agent-software"),
            # no KB and not a driver: dropped as before
            self.wua("no-kb", kb=None),
        ]
        r = self.client.post(self.url, {"wua_updates": updates}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            self.flags(),
            {
                "software": False,
                "driver": True,
                "old-agent-driver": True,
                "old-agent-software": False,
            },
        )
        driver = self.agent.winupdates.get(guid="driver")
        self.assertIsNone(driver.kb)

        # a known row follows the flag
        updates[0]["type"] = "driver"
        r = self.client.post(self.url, {"wua_updates": updates}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.flags()["software"])

        self.client.force_authenticate(user=self.john_user())
        r = self.client.get(f"/winupdate/{self.agent.agent_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual({u["guid"]: u["is_driver"] for u in r.json()}["driver"], True)

    def john_user(self):
        return self._account("john", "hunter2", is_superuser=True)

    def _rows(self):
        baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            guid="sw",
            kb="KB1",
            severity="",
            installed=False,
        )
        baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            guid="drv",
            kb=None,
            severity="",
            installed=False,
            is_driver=True,
        )

    def approved(self) -> list:
        self.agent.winupdates.update(action="nothing")
        self.agent.approve_updates()
        return sorted(self.agent.get_approved_update_guids())

    def test_approve_drivers_by_agent_policy(self):
        self._rows()
        self.policy.other = "approve"
        for drivers, expected in (
            ("inherit", ["sw"]),
            ("exclude", ["sw"]),
            ("include", ["drv", "sw"]),
        ):
            self.policy.drivers = drivers
            self.policy.save()
            self.assertEqual(self.approved(), expected, drivers)

        # manual approve still works for an excluded driver
        self.policy.drivers = "exclude"
        self.policy.save()
        self.agent.winupdates.filter(guid="drv").update(action="approve")
        self.agent.approve_updates()
        self.assertEqual(sorted(self.agent.get_approved_update_guids()), ["drv", "sw"])

    def test_approve_drivers_through_policy_and_override(self):
        self._rows()
        top = baker.make("automation.Policy", active=True)
        base = baker.make(
            "winupdate.WinUpdatePolicy", policy=top, other="approve", drivers="inherit"
        )
        with patch(
            "agents.models.Agent.get_agent_policies", return_value={"site": top}
        ):
            # inherit at the policy means exclude
            self.assertEqual(self.approved(), ["sw"])
            base.drivers = "include"
            base.save()
            self.assertEqual(self.approved(), ["drv", "sw"])
            # the agent row overrides
            self.policy.drivers = "exclude"
            self.policy.save()
            self.assertEqual(self.approved(), ["sw"])
            base.drivers = "exclude"
            base.save()
            self.policy.drivers = "include"
            self.policy.save()
            self.assertEqual(self.approved(), ["drv", "sw"])

    def test_posix_rows_unaffected(self):
        linux = baker.make_recipe("agents.agent", plat=AgentPlat.LINUX)
        baker.make("winupdate.WinUpdatePolicy", agent=linux, other="approve")
        baker.make(
            "winupdate.WinUpdate",
            agent=linux,
            guid="apt:curl:amd64:8.0",
            kb="curl",
            severity="",
            installed=False,
        )
        linux.approve_updates()
        self.assertEqual(linux.get_approved_update_guids(), ["apt:curl:amd64:8.0"])

    def test_reset_sets_drivers_to_inherit(self):
        self.policy.drivers = "include"
        self.policy.save()
        self.client.force_authenticate(user=self.john_user())
        r = self.client.post("/automation/patchpolicy/reset/", {}, format="json")
        self.assertEqual(r.status_code, 200)
        self.policy.refresh_from_db()
        self.assertEqual(self.policy.drivers, "inherit")

    def test_superseded_cleanup_skips_rows_without_kb(self):
        for guid in ("a", "b"):
            baker.make(
                "winupdate.WinUpdate",
                agent=self.agent,
                guid=guid,
                kb=None,
                title=f"Intel - Net - (Version {guid})",
                is_driver=True,
            )
        for version in ("1.0", "2.0"):
            baker.make(
                "winupdate.WinUpdate",
                agent=self.agent,
                kb="KB9",
                title=f"Defender (Version {version})",
            )
        self.agent.delete_superseded_updates()
        self.assertEqual(self.agent.winupdates.filter(kb=None).count(), 2)
        self.assertEqual(
            list(
                self.agent.winupdates.filter(kb="KB9").values_list("title", flat=True)
            ),
            ["Defender (Version 2.0)"],
        )

    def test_edit_message_names_the_title_without_kb(self):
        self._rows()
        self.client.force_authenticate(user=self.john_user())
        drv = self.agent.winupdates.get(guid="drv")
        drv.title = "Intel - Net - 12.19.2.60"
        drv.save()
        r = self.client.put(
            f"/winupdate/{drv.pk}/", {"action": "approve"}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.data, "Windows update Intel - Net - 12.19.2.60 was changed to approve"
        )

    def test_migration_backfill(self):
        import importlib

        from django.apps import apps

        migration = importlib.import_module(
            "winupdate.migrations.0002_winupdate_is_driver_policy_drivers"
        )
        self.assertEqual(migration.DRIVERS_CATEGORY, DRIVERS_CATEGORY)
        old = baker.make(
            "winupdate.WinUpdate",
            agent=self.agent,
            category_ids=["other", DRIVERS_CATEGORY],
        )
        plain = baker.make("winupdate.WinUpdate", agent=self.agent, category_ids=[])
        migration.flag_drivers(apps, None)
        old.refresh_from_db()
        plain.refresh_from_db()
        self.assertEqual((old.is_driver, plain.is_driver), (True, False))

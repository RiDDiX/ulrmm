# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import fcntl
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

from . import server_ops

NAME = "rmm-backup-2026_10_17__03_00_01.tar"
# the step-up grant lives in the cache
LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM_CACHE)
class ServerOpsBase(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.tmp = Path(tempfile.mkdtemp())
        self.maint = self.tmp / "maint"
        self.backups = self.tmp / "backups"
        self.maint.mkdir()
        for sub in ("", "daily", "weekly", "monthly", "pre-update"):
            (self.backups / sub).mkdir(parents=True, exist_ok=True)
        self.settings_override = override_settings(
            ULRMM_MAINT_DIR=str(self.maint), ULRMM_BACKUP_DIR=str(self.backups)
        )
        self.settings_override.enable()
        cache.clear()
        cache.set(server_ops.PENDING_CACHE_KEY, {"server": {}, "web": {}}, 60)

    def tearDown(self):
        self.settings_override.disable()
        shutil.rmtree(self.tmp)

    def login(self, user, stepup=True):
        token, _ = AuthToken.objects.create(user=user)
        self.client.force_authenticate(user=user, token=token)
        if stepup:
            grant_console_stepup(user)

    def hold_runner_lock(self):
        fd = os.open(self.maint / "lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)

    def put_backup(self, sub, name=NAME, size=10):
        path = self.backups / sub / name
        path.write_bytes(b"x" * size)
        return path


class TestRequestAndLog(ServerOpsBase):
    def test_two_requests_at_once_queue_one(self):
        real = server_ops.busy_with
        errors = []

        def slow_busy_with():
            current = real()
            time.sleep(0.2)
            return current

        def request(action):
            try:
                server_ops.request_action(action)
            except server_ops.MaintError as e:
                errors.append(str(e))

        threads = [
            threading.Thread(target=request, args=(a,)) for a in ("update", "backup")
        ]
        with patch.object(server_ops, "busy_with", slow_busy_with):
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(errors, ["Another maintenance task is queued."])
        self.assertIn((self.maint / "request").read_text(), ("update\n", "backup\n"))

    def test_log_chunk_ends_on_a_whole_character(self):
        (self.maint / "update.log").write_bytes("abcdä€x".encode())
        with patch.object(server_ops, "LOG_CHUNK", 5):
            first = server_ops.read_log("update")
            second = server_ops.read_log("update", first["offset"])
            third = server_ops.read_log("update", second["offset"])
        self.assertEqual((first["text"], first["offset"]), ("abcd", 4))
        self.assertEqual((second["text"], second["offset"]), ("ä€", 9))
        self.assertEqual((third["text"], third["offset"]), ("x", 10))


class TestRunnerHandoff(ServerOpsBase):
    def test_update_needs_stepup_and_writes_one_request(self):
        url = "/core/server/update/"
        self.login(self.john, stepup=False)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIs(r.data["stepup"], True)
        self.assertFalse((self.maint / "request").exists())

        self.login(self.john)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual((self.maint / "request").read_text(), "update\n")
        self.assertEqual(oct((self.maint / "request").stat().st_mode & 0o777), "0o600")
        self.assertTrue(
            AuditLog.objects.filter(message__contains="server update").exists()
        )

        # a second request while the first is queued is refused
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("queued", r.data)

    def test_running_task_blocks_new_requests(self):
        self.login(self.john)
        self.hold_runner_lock()
        (self.maint / "backup.state.json").write_text(
            json.dumps({"state": "running", "started": int(time.time())})
        )
        r = self.client.post("/core/server/update/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("backup is already running", r.data)

    def test_running_state_without_runner_is_interrupted(self):
        # machine rebooted mid-update: state says running, nobody holds the lock
        (self.maint / "update.state.json").write_text(
            json.dumps({"state": "running", "started": int(time.time())})
        )
        self.assertEqual(server_ops.read_state("update")["state"], "interrupted")
        self.assertIsNone(server_ops.busy_with())

    def test_request_drops_previous_run_state(self):
        (self.maint / "update.state.json").write_text(
            json.dumps({"state": "done", "exit_code": 0, "finished": 1})
        )
        server_ops.request_action("update")
        self.assertEqual(server_ops.read_state("update")["state"], "idle")
        self.assertEqual((self.maint / "request").read_text(), "update\n")

    def test_backup_start_is_audited(self):
        self.login(self.john)
        self.assertEqual(self.client.post("/core/server/backups/").status_code, 200)
        self.assertEqual((self.maint / "request").read_text(), "backup\n")
        self.assertTrue(
            AuditLog.objects.filter(
                message__contains="started a server backup"
            ).exists()
        )

    def test_stale_running_state_does_not_block(self):
        (self.maint / "update.state.json").write_text(
            json.dumps({"state": "running", "started": int(time.time()) - 5 * 3600})
        )
        self.assertEqual(server_ops.read_state("update")["state"], "interrupted")
        self.assertIsNone(server_ops.busy_with())

    def test_missing_runner_is_reported(self):
        shutil.rmtree(self.maint)
        self.login(self.john)
        r = self.client.post("/core/server/backups/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("not installed", r.data)

    def test_log_is_read_from_offset_without_ansi(self):
        (self.maint / "update.log").write_bytes(
            b"\x1b[0;32mstep one\x1b[0m\nstep two\n"
        )
        (self.maint / "update.state.json").write_text(
            json.dumps({"state": "done", "exit_code": 0})
        )
        self.login(self.john, stepup=False)
        r = self.client.get("/core/server/tasks/update/log/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["text"], "step one\nstep two\n")
        self.assertEqual(r.data["state"]["state"], "done")
        r = self.client.get(f"/core/server/tasks/update/log/?offset={r.data['offset']}")
        self.assertEqual(r.data["text"], "")
        # an offset past the end (log truncated by a new run) starts over
        r = self.client.get("/core/server/tasks/update/log/?offset=99999")
        self.assertEqual(r.data["text"], "step one\nstep two\n")
        self.assertEqual(
            self.client.get("/core/server/tasks/nope/log/").status_code, 400
        )


class TestBackups(ServerOpsBase):
    def test_list_sorted_newest_first_and_junk_ignored(self):
        old = self.put_backup("daily", "rmm-backup-2026_10_01__00_00_01.tar")
        os.utime(old, (1_700_000_000, 1_700_000_000))
        self.put_backup("pre-update")
        self.put_backup("", "notes.txt")
        (self.backups / "weekly" / NAME).symlink_to("/etc/passwd")
        self.login(self.john, stepup=False)
        r = self.client.get("/core/server/backups/")
        self.assertEqual(r.status_code, 200)
        names = [(b["type"], b["name"]) for b in r.data["backups"]]
        self.assertEqual(names, [("pre-update", NAME), ("daily", old.name)])
        self.assertTrue(r.data["can_download"])

    def test_download_with_stepup_and_audit(self):
        self.put_backup("daily")
        url = f"/core/server/backups/daily/{NAME}/"
        self.login(self.john, stepup=False)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.login(self.john)
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(b"".join(r.streaming_content), b"x" * 10)
        self.assertIn(NAME, r["Content-Disposition"])
        self.assertTrue(
            AuditLog.objects.filter(message__contains="downloaded").exists()
        )

        role = baker.make("accounts.Role", can_manage_server_updates=True)
        tech = baker.make("accounts.User", role=role, is_superuser=False)
        self.login(tech)
        # role holders download and delete like superusers
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(b"".join(r.streaming_content), b"x" * 10)
        self.assertEqual(
            AuditLog.objects.filter(message__contains="downloaded").count(), 2
        )
        r = self.client.get("/core/server/backups/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["can_download"])
        self.assertEqual(self.client.delete(url).status_code, 200)
        self.assertFalse((self.backups / "daily" / NAME).exists())

    def test_delete_needs_stepup(self):
        path = self.put_backup("daily")
        self.login(self.john, stepup=False)
        r = self.client.delete(f"/core/server/backups/daily/{NAME}/")
        self.assertEqual(r.status_code, 403)
        self.assertTrue(path.exists())

    def test_role_superuser_may_download(self):
        self.put_backup("daily")
        role = baker.make("accounts.Role", is_superuser=True)
        admin = baker.make("accounts.User", role=role, is_superuser=False)
        self.login(admin)
        r = self.client.get(f"/core/server/backups/daily/{NAME}/")
        self.assertEqual(r.status_code, 200)

    def test_user_without_role(self):
        user = baker.make("accounts.User", role=None, is_superuser=False)
        self.login(user)
        self.assertEqual(self.client.get("/core/server/backups/").status_code, 403)

    def test_paths_outside_the_backup_dirs_are_refused(self):
        self.login(self.john)
        for kind, name in [
            ("daily", "..%2F..%2Fetc%2Fpasswd"),
            ("nope", NAME),
            ("daily", "rmm-backup-x.tar"),
            ("daily", NAME),  # does not exist
        ]:
            r = self.client.get(f"/core/server/backups/{kind}/{name}/")
            self.assertEqual(r.status_code, 404, (kind, name))
        with self.assertRaises(server_ops.MaintError):
            server_ops.backup_path("daily", "../" + NAME)

    def test_without_permission(self):
        role = baker.make("accounts.Role")
        user = baker.make("accounts.User", role=role, is_superuser=False)
        self.login(user)
        for method, url in [
            ("get", "/core/server/update/"),
            ("post", "/core/server/update/"),
            ("get", "/core/server/backups/"),
            ("put", "/core/server/backups/settings/"),
            ("get", "/core/server/tasks/update/log/"),
        ]:
            self.assertEqual(getattr(self.client, method)(url).status_code, 403, url)

    @override_settings(HOSTED=True)
    def test_hosted_has_no_server_management(self):
        self.login(self.john)
        self.assertEqual(self.client.get("/core/server/backups/").status_code, 403)


class TestBackupSettings(ServerOpsBase):
    def test_defaults_and_round_trip(self):
        self.login(self.john)
        r = self.client.get("/core/server/backups/")
        self.assertEqual(r.data["settings"]["daily_keep_days"], 14)
        self.assertIs(r.data["settings"]["schedule_enabled"], True)

        r = self.client.put(
            "/core/server/backups/settings/",
            {"daily_keep_days": 7, "schedule_time": "03:30", "schedule_enabled": False},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        conf = (self.backups / "backup.conf").read_text().splitlines()
        self.assertIn("DAILY_KEEP_DAYS=7", conf)
        self.assertIn("SCHEDULE_TIME=03:30", conf)
        self.assertIn("SCHEDULE_ENABLED=0", conf)
        self.assertIn("WEEKLY_KEEP_DAYS=60", conf)
        self.assertEqual((self.maint / "request").read_text(), "schedule\n")
        self.assertEqual(server_ops.read_backup_conf()["daily_keep_days"], 7)
        audit = AuditLog.objects.get(message__contains="backup settings")
        self.assertEqual(audit.after_value["daily_keep_days"], 7)

    def test_settings_refused_while_busy_and_nothing_written(self):
        self.login(self.john)
        (self.maint / "request").write_text("backup\n")
        r = self.client.put(
            "/core/server/backups/settings/", {"daily_keep_days": 7}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse((self.backups / "backup.conf").exists())

    def test_settings_need_stepup(self):
        self.login(self.john, stepup=False)
        r = self.client.put(
            "/core/server/backups/settings/", {"daily_keep_days": 7}, format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertFalse((self.backups / "backup.conf").exists())

    def test_invalid_values(self):
        self.login(self.john)
        for body in [
            {"daily_keep_days": 0},
            {"daily_keep_days": "7"},
            {"daily_keep_days": True},
            {"pre_update_keep": 101},
            {"schedule_time": "24:00"},
            {"schedule_time": "3:30"},
            {"schedule_enabled": "yes"},
        ]:
            r = self.client.put("/core/server/backups/settings/", body, format="json")
            self.assertEqual(r.status_code, 400, body)
        self.assertFalse((self.backups / "backup.conf").exists())

    def test_tampered_conf_falls_back_to_defaults(self):
        (self.backups / "backup.conf").write_text(
            "DAILY_KEEP_DAYS=$(reboot)\nSCHEDULE_TIME=99:99\nWEEKLY_KEEP_DAYS=30\n"
        )
        conf = server_ops.read_backup_conf()
        self.assertEqual(conf["daily_keep_days"], 14)
        self.assertEqual(conf["schedule_time"], "00:00")
        self.assertEqual(conf["weekly_keep_days"], 30)

    def test_save_keeps_age_recipients(self):
        (self.backups / "backup.conf").write_text(
            "DAILY_KEEP_DAYS=14\nBACKUP_AGE_RECIPIENTS=/etc/ulrmm/backup.age.pub\n"
        )
        self.login(self.john)
        r = self.client.put(
            "/core/server/backups/settings/", {"daily_keep_days": 7}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        text = (self.backups / "backup.conf").read_text()
        self.assertIn("DAILY_KEEP_DAYS=7\n", text)
        self.assertIn("BACKUP_AGE_RECIPIENTS=/etc/ulrmm/backup.age.pub\n", text)

    def test_encrypted_backup_listed(self):
        self.put_backup("daily", "rmm-backup-2026_10_17__03_00_01.tar.age")
        self.assertEqual(
            [b["name"] for b in server_ops.list_backups()],
            ["rmm-backup-2026_10_17__03_00_01.tar.age"],
        )
        server_ops.backup_path("daily", "rmm-backup-2026_10_17__03_00_01.tar.age")


class TestPendingChanges(ServerOpsBase):
    def test_entries_newer_than_installed(self):
        text = "# Server changelog\n\n## 3.17.10.2026 (2026-10-17)\n\n- c\n\n## 2.17.10.2026 (2026-10-17)\n\n- b\n\n## 1.14.10.2026 (2026-10-14)\n\n- a\n"
        cache.delete(server_ops.PENDING_CACHE_KEY)
        repo = self.tmp / "repo"
        (repo / ".git").mkdir(parents=True)
        with (
            override_settings(
                ULRMM_GIT_URL="https://git.example/x.git", ULRMM_VERSION="1.14.10.2026"
            ),
            self.subTest("server"),
        ):
            from unittest.mock import patch

            with patch.object(
                server_ops,
                "_git",
                side_effect=lambda r, *a, **k: text if a[0] == "show" else "",
            ):
                result = server_ops._component_changes(
                    str(repo), "https://git.example/x.git", "main", "1.14.10.2026"
                )
        self.assertEqual(result["next"], "3.17.10.2026")
        self.assertEqual(
            [r["version"] for r in result["releases"]], ["3.17.10.2026", "2.17.10.2026"]
        )

    def test_refresh_is_throttled(self):
        from unittest.mock import patch

        cache.set(
            server_ops.PENDING_CACHE_KEY,
            {"server": {"x": 1}, "web": {}, "checked": time.time()},
            600,
        )
        with patch.object(server_ops, "_component_changes") as fetch:
            self.assertEqual(
                server_ops.pending_changes(refresh=True)["server"], {"x": 1}
            )
            fetch.assert_not_called()
        cache.set(
            server_ops.PENDING_CACHE_KEY,
            {"server": {"x": 1}, "web": {}, "checked": time.time() - 120},
            600,
        )
        with patch.object(
            server_ops, "_component_changes", return_value={"y": 2}
        ) as fetch:
            self.assertEqual(
                server_ops.pending_changes(refresh=True)["server"], {"y": 2}
            )
            self.assertEqual(fetch.call_count, 2)

    def test_no_remote(self):
        self.assertEqual(
            server_ops._component_changes(str(self.tmp), "", "main", "1"),
            {"error": "no git remote configured"},
        )


class TestReleaseUpdate(ServerOpsBase):
    def test_release_mode_writes_release_json(self):
        self.login(self.john)
        r = self.client.post(
            "/core/server/update/", {"mode": "release", "version": "2.27.10.2026"}
        )
        self.assertEqual(r.status_code, 200)
        req = json.loads((self.maint / "release.json").read_text())
        self.assertEqual(req["version"], "2.27.10.2026")
        self.assertIn("requested_at", req)
        self.assertEqual(
            oct((self.maint / "release.json").stat().st_mode & 0o777), "0o600"
        )
        self.assertEqual((self.maint / "request").read_text(), "update\n")
        self.assertTrue(
            AuditLog.objects.filter(message__contains="release update").exists()
        )

    def test_release_mode_latest_and_bad_version(self):
        self.login(self.john)
        r = self.client.post("/core/server/update/", {"mode": "release"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(
            json.loads((self.maint / "release.json").read_text())["version"]
        )
        (self.maint / "release.json").unlink()
        (self.maint / "request").unlink()
        for bad in ("../x", "latest", "2.27"):
            r = self.client.post(
                "/core/server/update/", {"mode": "release", "version": bad}
            )
            self.assertEqual(r.status_code, 400)
        self.assertFalse((self.maint / "release.json").exists())
        r = self.client.post("/core/server/update/", {"mode": "svn"})
        self.assertEqual(r.status_code, 400)

    def test_release_request_dropped_when_busy(self):
        self.login(self.john)
        (self.maint / "request").write_text("backup\n")
        r = self.client.post("/core/server/update/", {"mode": "release"})
        self.assertEqual(r.status_code, 400)
        self.assertFalse((self.maint / "release.json").exists())

    def test_git_mode_drops_stale_release_json(self):
        self.login(self.john)
        for body in ({"mode": "git"}, {}):
            (self.maint / "release.json").write_text('{"version": null}')
            r = self.client.post("/core/server/update/", body)
            self.assertEqual(r.status_code, 200)
            self.assertFalse((self.maint / "release.json").exists())
            (self.maint / "request").unlink()

    def test_sources_endpoint(self):
        from unittest.mock import patch

        from . import releases

        status = {"active": "github", "latest": "2.27.10.2026", "sources": []}
        with patch.object(releases, "sources_status", return_value=status) as m:
            r = self.client.get("/core/server/update/sources/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["active"], "github")
            m.assert_called_with(False)
            self.client.get("/core/server/update/sources/?refresh=1")
            m.assert_called_with(True)
        user = self.create_user_with_roles([])
        self.login(user)
        self.assertEqual(
            self.client.get("/core/server/update/sources/").status_code, 403
        )

    def test_progress_endpoint(self):
        r = self.client.get("/core/server/update/progress/")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["phase"])
        self.assertEqual(r.json()["state"]["state"], "idle")
        (self.maint / "update.progress.json").write_text(
            json.dumps({"phase": "download", "percent": 40, "bytes": 4, "total": 10})
        )
        (self.maint / "update.state.json").write_text(
            json.dumps({"state": "running", "started": time.time()})
        )
        self.hold_runner_lock()
        data = self.client.get("/core/server/update/progress/").json()
        self.assertEqual((data["phase"], data["percent"]), ("download", 40))
        self.assertEqual(data["state"]["state"], "running")
        (self.maint / "update.progress.json").write_text("{broken")
        self.assertIsNone(
            self.client.get("/core/server/update/progress/").json()["phase"]
        )

    def test_health_is_public(self):
        from rest_framework.test import APIClient

        r = APIClient().get("/core/health/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertEqual(r.json()["status"], "ok")
        self.assertIs(r.json()["db"], True)
        self.assertTrue(r.json()["version"])
        # a stale dashboard token in the header must not turn it into a 401
        r = APIClient().get("/core/health/", HTTP_AUTHORIZATION="Token bogus")
        self.assertEqual(r.status_code, 200)

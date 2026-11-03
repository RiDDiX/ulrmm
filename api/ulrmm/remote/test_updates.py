# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import requests
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone as djangotime
from knox.models import AuthToken
from model_bakery import baker

from accounts.utils import grant_console_stepup
from logs.models import AuditLog, DebugLog
from ulrmm.constants import AgentPlat, AuditObjType, GoArch
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .models import RustDeskPeer, RustDeskRelease, RustDeskSettings
from .tasks import (
    SOURCE_TXT,
    UpdateError,
    _download,
    outdated_peers,
    rustdesk_auto_update_task,
    rustdesk_check_releases_task,
    rustdesk_pin_client_task,
    rustdesk_update_clients_task,
    rustdesk_update_server_task,
)
from .tests import KeyFileMixin, ran
from .utils import pinned_client, render_deploy

NEW = "1.4.10"
NEW_FILES = {
    f"rustdesk-{NEW}-x86_64.msi": b"msi",
    f"rustdesk-{NEW}-x86_64.deb": b"deb!",
    f"rustdesk-{NEW}-0.x86_64.rpm": b"rpm!!",
    f"rustdesk-{NEW}-x86_64.dmg": b"dmg-intel",
    f"rustdesk-{NEW}-aarch64.dmg": b"dmg-arm",
}
SERVER_ZIP = "rustdesk-server-linux-amd64.zip"


class FakeResponse:
    def __init__(self, data=None, body=b"", status=200, url="https://github.com/x"):
        self.data, self.body, self.status_code, self.url = data, body, status, url
        self.history = []

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Error")

    def json(self):
        return self.data

    def iter_content(self, size):
        yield from (self.body[i : i + 3] for i in range(0, len(self.body), 3))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def downloads(files: dict, clock=None, step=0):
    """requests.get stand-in. Body is the file named by the last URL segment.
    With clock, each hit adds step seconds to clock[0]."""

    def get(url, **kwargs):
        name = url.rsplit("/", 1)[1]
        if name not in files:
            return FakeResponse(status=404)
        if clock:
            clock[0] += step
        return FakeResponse(body=files[name])

    return get


def release(component, version, files=None, **kwargs):
    return RustDeskRelease.objects.create(
        component=component,
        version=version,
        assets=[
            {"name": n, "url": f"https://github.com/{n}", "size": len(b)}
            for n, b in (files or {}).items()
        ],
        **kwargs,
    )


@override_settings(CACHES=LOCMEM_CACHE)
class UpdateTestCase(KeyFileMixin, ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.authenticate()
        self.setup_coresettings()
        self.coresettings.agent_debug_level = "info"
        self.coresettings.save()
        self.use_key_file(version="1.1.16")
        RustDeskSettings.objects.create(pk=1, enabled=True, id_server="rd.example.com")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dist = Path(tmp.name)
        override = override_settings(
            AGENTS_DIST_DIR=str(self.dist),
            SELF_BUILT_AGENTS_URL="https://rmm.example.com/agentdist",
        )
        override.enable()
        self.addCleanup(override.disable)

    def version_file(self) -> Path:
        return Path(settings.RUSTDESK_KEY_FILE).parent / "version"


class TestReleaseCheck(UpdateTestCase):
    def github(self, server_tag="1.1.17", client_tag="v1.4.10"):
        answers = {
            "rustdesk-server": {
                "tag_name": server_tag,
                "published_at": "2026-09-01T10:00:00Z",
                "body": "server notes",
                "assets": [
                    {
                        "name": SERVER_ZIP,
                        "browser_download_url": "https://github.com/a.zip",
                        "size": 123,
                    }
                ],
            },
            "rustdesk": {
                "tag_name": client_tag,
                "published_at": "2026-09-02T10:00:00Z",
                "body": "x" * 30000,
                "assets": [],
            },
        }

        def get(url, **kwargs):
            self.assertEqual(kwargs["timeout"], 20)
            self.assertEqual(kwargs["headers"]["User-Agent"], "UniversalLocal RMM")
            repo = url.split("/repos/rustdesk/")[1].split("/")[0]
            self.assertEqual(
                url, f"https://api.github.com/repos/rustdesk/{repo}/releases/latest"
            )
            return FakeResponse(data=answers[repo])

        return get

    @patch("remote.tasks.requests.get")
    def test_check_stores_latest(self, get):
        get.side_effect = self.github()
        self.assertEqual(rustdesk_check_releases_task(), [])
        server = RustDeskRelease.objects.get(component="server", version="1.1.17")
        self.assertEqual(server.notes, "server notes")
        self.assertEqual(server.published_at.isoformat(), "2026-09-01T10:00:00+00:00")
        self.assertEqual(
            server.assets,
            [{"name": SERVER_ZIP, "url": "https://github.com/a.zip", "size": 123}],
        )
        self.assertEqual(
            server.url,
            "https://github.com/rustdesk/rustdesk-server/releases/tag/1.1.17",
        )
        client = RustDeskRelease.objects.get(component="client", version="1.4.10")
        self.assertEqual(len(client.notes), 20000)
        self.assertIsNone(client.mirrored_at)
        self.assertIsNotNone(RustDeskSettings.objects.get().releases_checked_at)

        # again: same rows, the seeded pin is untouched
        rustdesk_check_releases_task()
        self.assertEqual(RustDeskRelease.objects.count(), 4)
        self.assertEqual(pinned_client()[0], "1.4.9")

        r = self.client.get("/core/rustdesk/releases/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["server"]["installed"], "1.1.16")
        self.assertEqual(r.data["server"]["latest"]["version"], "1.1.17")
        self.assertTrue(r.data["server"]["update_available"])
        self.assertEqual(r.data["client"]["pinned"], "1.4.9")
        self.assertEqual(r.data["client"]["latest"]["version"], "1.4.10")
        self.assertTrue(r.data["client"]["update_available"])
        self.assertIsNotNone(r.data["client"]["mirrored_at"])
        self.assertIsNotNone(r.data["releases_checked_at"])

    @patch("remote.tasks.requests.get")
    def test_check_errors_are_logged_not_raised(self, get):
        get.side_effect = requests.ConnectionError("no route")
        errors = rustdesk_check_releases_task()
        self.assertEqual(len(errors), 2)
        self.assertIn("no route", errors[0])
        self.assertEqual(DebugLog.objects.count(), 2)
        self.assertIsNone(RustDeskSettings.objects.get().releases_checked_at)

        get.side_effect = self.github(server_tag="nightly")
        errors = rustdesk_check_releases_task()
        self.assertEqual(len(errors), 1)
        self.assertIn("unexpected tag 'nightly'", errors[0])
        self.assertFalse(RustDeskRelease.objects.filter(version="nightly").exists())

        r = self.client.post("/core/rustdesk/releases/check/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("nightly", r.data)

        get.side_effect = self.github()
        r = self.client.post("/core/rustdesk/releases/check/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["client"]["latest"]["version"], "1.4.10")


class TestPin(UpdateTestCase):
    def setUp(self):
        super().setUp()
        release("client", NEW, NEW_FILES)
        self.out = self.dist / "rustdesk"
        self.out.mkdir()
        (self.out / "rustdesk-1.4.9-x86_64.msi").write_bytes(b"old")
        (self.out / f"rustdesk-{NEW}-x86_64.msi.part").write_bytes(b"stale")

    @patch("remote.tasks.requests.get")
    def test_pin(self, get):
        get.side_effect = downloads(NEW_FILES)
        rustdesk_pin_client_task(NEW, "john")

        urls = [c.args[0] for c in get.call_args_list]
        self.assertEqual(
            urls,
            [
                f"https://github.com/rustdesk/rustdesk/releases/download/{NEW}/{n}"
                for n in NEW_FILES
            ],
        )
        sums = {n: hashlib.sha256(b).hexdigest() for n, b in NEW_FILES.items()}
        self.assertEqual(
            sorted(p.name for p in self.out.iterdir()),
            sorted([*NEW_FILES, "SOURCE.txt", "manifest.json"]),
        )
        self.assertEqual(
            json.loads((self.out / "manifest.json").read_text()),
            {"client_version": NEW, "files": sums},
        )
        self.assertEqual(
            (self.out / "SOURCE.txt").read_text().splitlines(),
            [
                f"RustDesk client {NEW}",
                "License: AGPL-3.0",
                f"Source: https://github.com/rustdesk/rustdesk/tree/{NEW}",
                f"License text: https://github.com/rustdesk/rustdesk/blob/{NEW}/LICENCE",
            ],
        )
        self.assertEqual(pinned_client(), (NEW, sums))
        self.assertIsNotNone(RustDeskRelease.objects.get(version=NEW).mirrored_at)
        audit = AuditLog.objects.get()
        self.assertEqual(audit.username, "john")
        self.assertEqual(audit.object_type, AuditObjType.CORE)
        self.assertEqual(
            audit.message, f"john pinned the RustDesk client 1.4.9 -> {NEW}"
        )

        agent = baker.make_recipe(
            "agents.agent", plat=AgentPlat.WINDOWS, goarch=GoArch.AMD64
        )
        code = render_deploy(
            agent,
            host="rd.example.com",
            config="abc",
            mode="update",
            expect_id="123456789",
        )["payload"]["code"]
        self.assertIn(f"/agentdist/rustdesk/rustdesk-{NEW}-x86_64.msi'", code)
        self.assertIn(sums[f"rustdesk-{NEW}-x86_64.msi"], code)

        # back to the seeded release: verified against its stored sums
        seeded = RustDeskRelease.objects.get(component="client", version="1.4.9")
        get.side_effect = downloads({n: b"tampered" for n in seeded.files})
        with self.assertRaisesRegex(UpdateError, "checksum mismatch"):
            rustdesk_pin_client_task("1.4.9", "john")
        self.assertEqual(pinned_client()[0], NEW)
        self.assertFalse(list(self.out.glob("*1.4.9*")))

    def test_mirror_script_writes_the_same_source_txt(self):
        script = (
            settings.BASE_DIR.parent.parent
            / "riddix/rustdesk/install-rustdesk-server.sh"
        )
        out = subprocess.run(
            [
                "bash",
                "-c",
                'eval "$(sed -n "/^source_txt() {/,/^}/p" "$0")"; source_txt 1.4.9',
                str(script),
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(out, SOURCE_TXT.format(version="1.4.9", tag="1.4.9"))

    @patch("remote.tasks.requests.get")
    def test_size_mismatch_keeps_the_old_pin(self, get):
        get.side_effect = downloads({**NEW_FILES, f"rustdesk-{NEW}-x86_64.deb": b"x"})
        with self.assertRaisesRegex(UpdateError, "1 bytes, the release lists 4"):
            rustdesk_pin_client_task(NEW, "john")
        self.assertEqual(pinned_client()[0], "1.4.9")
        self.assertTrue((self.out / "rustdesk-1.4.9-x86_64.msi").exists())
        self.assertFalse(list(self.out.glob("*.deb*")))
        self.assertFalse((self.out / "manifest.json").exists())
        self.assertIn("failed", AuditLog.objects.get().message)

    @patch("remote.tasks.requests.get")
    def test_http_hop_is_refused(self, get):
        # https at both ends, plain http in between
        hop = FakeResponse(url="http://github.com/x")
        response = FakeResponse(body=b"msi")
        response.history = [FakeResponse(), hop]
        get.return_value = response
        with self.assertRaisesRegex(UpdateError, "redirected to http://github.com/x"):
            rustdesk_pin_client_task(NEW, "john")
        self.assertEqual(pinned_client()[0], "1.4.9")
        self.assertFalse(list(self.out.glob(f"*{NEW}*")))

        get.reset_mock(return_value=True)
        get.return_value = FakeResponse(data={}, url="http://api.github.com/x")
        errors = rustdesk_check_releases_task()
        self.assertEqual(len(errors), 2)
        self.assertIn("redirected to http://", errors[0])

    @patch("remote.tasks.requests.get")
    def test_tag_with_v(self, get):
        RustDeskRelease.objects.filter(version=NEW).update(
            url=f"https://github.com/rustdesk/rustdesk/releases/tag/v{NEW}"
        )
        get.side_effect = downloads(NEW_FILES)
        rustdesk_pin_client_task(NEW, "john")
        for call in get.call_args_list:
            self.assertIn(f"/releases/download/v{NEW}/rustdesk-{NEW}-", call.args[0])
        self.assertEqual(pinned_client()[0], NEW)

    @patch("remote.tasks.time")
    @patch("remote.tasks.requests.get")
    def test_deadline_covers_all_files(self, get, fake_time):
        clock = [1000.0]
        fake_time.monotonic.side_effect = lambda: clock[0]
        # 100 s per file: the third one runs past 240 s
        get.side_effect = downloads(NEW_FILES, clock, 100)
        r = self.client.post(
            "/core/rustdesk/client/pin/", {"version": NEW}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("ran out of time", r.data)
        self.assertEqual(get.call_count, 3)
        # the old pin is untouched, nothing of the new one is left
        self.assertEqual(pinned_client()[0], "1.4.9")
        self.assertEqual(
            [p.name for p in self.out.iterdir()], ["rustdesk-1.4.9-x86_64.msi"]
        )
        self.assertIsNone(RustDeskRelease.objects.get(version=NEW).mirrored_at)
        self.assertFalse(cache.get("rustdesk-pin-lock"))

        # the beat task has 900 s per file
        clock[0] = 1000.0
        get.side_effect = downloads(NEW_FILES, clock, 800)
        rustdesk_pin_client_task(NEW, "auto-update")
        self.assertEqual(pinned_client()[0], NEW)

    @patch("remote.tasks.requests.get")
    def test_view(self, get):
        get.side_effect = downloads(NEW_FILES)
        url = "/core/rustdesk/client/pin/"
        for data in ({}, {"version": "9.9.9"}, {"version": "x" * 40}):
            r = self.client.post(url, data, format="json")
            self.assertEqual(r.status_code, 400, data)
        get.assert_not_called()
        self.assertFalse(AuditLog.objects.exists())

        r = self.client.post(url, {"version": NEW}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["client"]["pinned"], NEW)
        self.assertFalse(r.data["client"]["update_available"])

        user = self.create_user_with_roles(["can_view_core_settings"])
        self.client.force_authenticate(user=user)
        self.check_authorized("get", "/core/rustdesk/releases/")
        for action in ("client/pin/", "releases/check/", "clients/update/"):
            self.check_not_authorized("post", f"/core/rustdesk/{action}")


class TestServerUpdate(UpdateTestCase):
    def setUp(self):
        super().setUp()
        release("server", "1.1.17", {SERVER_ZIP: b"zipbytes"})
        machine = patch("remote.tasks.platform.machine", return_value="x86_64")
        machine.start()
        self.addCleanup(machine.stop)

    def installs(self, version, code=0, out="ok\n", err=""):
        def run(cmd, **kwargs):
            self.cmd, self.kwargs = cmd, kwargs
            self.assertEqual(Path(cmd[-1]).read_bytes(), b"zipbytes")
            if not code:
                self.version_file().write_text(version + "\n")
            return subprocess.CompletedProcess(cmd, code, out, err)

        return run

    @patch("remote.tasks.subprocess.run")
    @patch("remote.tasks.requests.get")
    def test_update(self, get, run):
        get.side_effect = downloads({SERVER_ZIP: b"zipbytes"})
        run.side_effect = self.installs("1.1.17")
        RustDeskSettings.objects.update(id_server="rd.example.com:21116")
        rustdesk_update_server_task("1.1.17", "john")

        self.assertEqual(
            get.call_args.args[0],
            "https://github.com/rustdesk/rustdesk-server/releases/download/"
            f"1.1.17/{SERVER_ZIP}",
        )
        script = (
            settings.BASE_DIR.parent.parent
            / "riddix/rustdesk/install-rustdesk-server.sh"
        )
        self.assertEqual(
            self.cmd[:-1],
            ["sudo", "-n", "bash", str(script), "--host", "rd.example.com"]
            + ["--server-version", "1.1.17", "--server-zip"],
        )
        self.assertTrue(self.cmd[-1].endswith(SERVER_ZIP))
        self.assertFalse(Path(self.cmd[-1]).exists())
        self.assertLessEqual(self.kwargs["timeout"], 600)
        self.assertEqual(
            AuditLog.objects.get().message,
            "john updated the RustDesk server 1.1.16 -> 1.1.17",
        )

        # RUSTDESK_HOST wins: that is the host update.sh passes
        with override_settings(RUSTDESK_HOST="rd.lan"):
            rustdesk_update_server_task("1.1.17", "john")
        self.assertEqual(self.cmd[5], "rd.lan")

    @patch("remote.tasks.subprocess.run")
    @patch("remote.tasks.requests.get")
    def test_failure(self, get, run):
        get.side_effect = downloads({SERVER_ZIP: b"zipbytes"})
        run.side_effect = self.installs(
            "1.1.17", code=1, err="ERROR: hbbs does not report version 1.1.17\n"
        )
        with self.assertRaisesRegex(
            UpdateError, "(?s)exit code 1: .*does not report version"
        ):
            rustdesk_update_server_task("1.1.17", "john")
        self.assertEqual(self.version_file().read_text().strip(), "1.1.16")
        self.assertIn("failed", AuditLog.objects.get().message)
        self.assertTrue(
            DebugLog.objects.filter(
                message__contains="does not report version"
            ).exists()
        )

        with patch("remote.tasks.platform.machine", return_value="ppc64le"):
            with self.assertRaisesRegex(UpdateError, "no build for ppc64le"):
                rustdesk_update_server_task("1.1.17", "john")
        with self.assertRaisesRegex(UpdateError, "not a known release"):
            rustdesk_update_server_task("1.1.99", "john")

    @patch("remote.tasks.subprocess.run")
    @patch("remote.tasks.requests.get")
    def test_view(self, get, run):
        get.side_effect = downloads({SERVER_ZIP: b"zipbytes"})
        run.side_effect = self.installs("1.1.17")
        url = "/core/rustdesk/server/update/"
        # no step-up, then a step-up without a dashboard token
        for token in (True, False):
            if not token:
                self.client.force_authenticate(user=self.john)
                grant_console_stepup(self.john)
            else:
                t, _ = AuthToken.objects.create(user=self.john)
                self.client.force_authenticate(user=self.john, token=t)
            r = self.client.post(url, {"version": "1.1.17"}, format="json")
            self.assertEqual(r.status_code, 403)
            self.assertIs(r.data["stepup"], True)
        run.assert_not_called()

        t, _ = AuthToken.objects.create(user=self.john)
        self.client.force_authenticate(user=self.john, token=t)
        r = self.client.post(url, {"version": "1.1.99"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("not a known release", r.data)
        run.assert_not_called()

        with patch("remote.tasks._download", wraps=_download) as download:
            r = self.client.post(url, {"version": "1.1.17"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["server"]["installed"], "1.1.17")
        self.assertFalse(r.data["server"]["update_available"])
        # download and install fit in the request, the script keeps 120 s
        self.assertEqual(download.call_args.kwargs["seconds"], 120)
        self.assertLessEqual(self.kwargs["timeout"], 240)
        self.assertGreaterEqual(self.kwargs["timeout"], 120)


class TestClientUpdates(UpdateTestCase):
    def setUp(self):
        super().setUp()
        now = djangotime.now()
        self.peers = {}
        for name, version, last_seen in (
            ("outdated", "1.4.8", now),
            ("current", "1.4.9", now),
            ("offline", "1.4.8", now - djangotime.timedelta(days=1)),
            ("unknown", "", now),
        ):
            agent = baker.make_recipe(
                "agents.agent",
                hostname=name,
                plat=AgentPlat.WINDOWS,
                goarch=GoArch.AMD64,
                last_seen=last_seen,
            )
            self.peers[name] = RustDeskPeer.objects.create(
                agent=agent, rustdesk_id="123456789", client_version=version
            )

    @patch("agents.models.Agent.nats_cmd")
    def test_only_online_outdated_peers(self, nats_cmd):
        nats_cmd.return_value = ran("RUSTDESK_OK 123456789 1.4.9")
        r = self.client.get("/core/rustdesk/releases/")
        self.assertEqual(r.data["client"]["outdated_peers"], 2)
        self.assertEqual(r.data["client"]["online_outdated_peers"], 1)

        self.assertEqual(rustdesk_update_clients_task("auto-update"), 1)
        nats_cmd.assert_called_once()
        for name, peer in self.peers.items():
            peer.refresh_from_db()
            self.assertEqual(
                peer.client_version,
                {"outdated": "1.4.9", "current": "1.4.9", "offline": "1.4.8"}.get(
                    name, ""
                ),
            )
        audit = AuditLog.objects.get()
        self.assertEqual(audit.username, "auto-update")
        self.assertEqual(audit.agent, "outdated")

    @patch("agents.models.Agent.nats_cmd")
    def test_failures_are_skipped(self, nats_cmd):
        self.peers["current"].client_version = "1.4.7"
        self.peers["current"].save()
        busy = "setup: busy: a RustDesk session is open on this device"
        nats_cmd.side_effect = [
            ran(f"RUSTDESK_FAIL {busy}"),
            ran("RUSTDESK_OK 123456789 1.4.9"),
        ]
        self.assertEqual(rustdesk_update_clients_task("auto-update"), 1)
        self.assertEqual(nats_cmd.call_count, 2)
        self.assertTrue(DebugLog.objects.filter(message__contains=busy).exists())
        self.assertEqual(AuditLog.objects.count(), 2)

        # an update already running on that device is left alone
        nats_cmd.reset_mock(side_effect=True)
        cache.add(f"rustdesk_deploy_{self.peers['outdated'].agent.agent_id}", 1)
        rustdesk_update_clients_task("auto-update")
        nats_cmd.assert_not_called()

        RustDeskSettings.objects.update(enabled=False)
        self.assertEqual(rustdesk_update_clients_task("auto-update"), 0)

    @patch("agents.models.Agent.nats_cmd")
    def test_updated_meanwhile_is_skipped(self, nats_cmd):
        stale = outdated_peers("1.4.9")
        self.peers["outdated"].client_version = "1.4.9"
        self.peers["outdated"].save()
        with patch("remote.tasks.outdated_peers", return_value=stale):
            self.assertEqual(rustdesk_update_clients_task("auto-update"), 0)
        nats_cmd.assert_not_called()
        self.assertFalse(AuditLog.objects.exists())

    @patch("remote.views.rustdesk_update_clients_task.delay")
    def test_view_queues(self, delay):
        url = "/core/rustdesk/clients/update/"
        RustDeskSettings.objects.update(enabled=False)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("RustDesk is off", r.data)
        RustDeskSettings.objects.update(enabled=True)
        self.use_key_file(key="")
        r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("server key is missing", r.data)
        delay.assert_not_called()

        self.use_key_file()
        r = self.client.post(url)
        self.assertEqual(r.data, {"queued": 1})
        delay.assert_called_once_with("john")

        self.peers["outdated"].delete()
        delay.reset_mock()
        r = self.client.post("/core/rustdesk/clients/update/")
        self.assertEqual(r.data, {"queued": 0})
        delay.assert_not_called()


class TestAutoUpdate(UpdateTestCase):
    @patch("remote.tasks.rustdesk_update_clients_task", return_value=0)
    @patch("remote.tasks.rustdesk_pin_client_task")
    @patch("remote.tasks.rustdesk_update_server_task")
    def test_flags(self, server, pin, clients):
        release("server", "1.1.17")
        release("client", NEW)

        rustdesk_auto_update_task()
        for mock in (server, pin, clients):
            mock.assert_not_called()

        RustDeskSettings.objects.update(auto_update_server=True)
        rustdesk_auto_update_task()
        server.assert_called_once_with("1.1.17")
        pin.assert_not_called()
        clients.assert_not_called()

        server.reset_mock()
        server.side_effect = UpdateError("boom")
        RustDeskSettings.objects.update(
            auto_update_server=False, auto_update_clients=True
        )
        rustdesk_auto_update_task()
        server.assert_not_called()
        pin.assert_called_once_with(NEW)
        clients.assert_called_once_with()

        # nothing newer than what runs: only the peers part
        pin.reset_mock()
        RustDeskSettings.objects.update(
            auto_update_server=True, pinned_client_version=NEW
        )
        self.version_file().write_text("1.1.17\n")
        rustdesk_auto_update_task()
        server.assert_not_called()
        pin.assert_not_called()
        self.assertEqual(clients.call_count, 2)

    def test_settings_put_takes_the_flags(self):
        r = self.client.put(
            "/core/rustdesk/",
            {"auto_update_server": True, "auto_update_clients": True},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["auto_update_server"])
        self.assertTrue(r.data["auto_update_clients"])
        rd = RustDeskSettings.objects.get()
        self.assertTrue(rd.auto_update_server and rd.auto_update_clients)
        audit = AuditLog.objects.get()
        self.assertTrue(audit.after_value["auto_update_clients"])
        self.assertFalse(audit.before_value["auto_update_clients"])

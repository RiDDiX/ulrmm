# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import logging
import os
import subprocess
import time
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker
from rest_framework.authtoken.models import Token

from ulrmm.celery import app
from ulrmm.helpers import get_nats_hosts
from ulrmm.logfilter import SCAN_LIMIT, RedactFilter, redact
from logs.models import DebugLog
from ulrmm.test import LOCMEM_CACHE, NATS_RUNNING, ULRMMTestCase
from ulrmm.utils import (
    nats_config,
    nats_publish_allow,
    nats_signal_wanted,
    reload_nats,
)

OLD, NEW = "1.25.10.2026", settings.SEC_R1_MIN_AGENT


def test_redact():
    for raw, masked in (
        ("Authorization: Token " + "a" * 40, "Authorization: Token ********"),
        ("Bearer eyJhbGciOiJFZERTQSJ9.e30.sig", "Bearer ********"),
        ("Enroll " + "x" * 30 + " refused", "Enroll ******** refused"),
        ("GET /x?access_token=abc&y=1", "GET /x?access_token=********&y=1"),
        ("password=hunter2 user=bob", "password=******** user=bob"),
        ("client_secret=s3 token=t", "client_secret=******** token=********"),
        (
            "key -----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY----- end",
            "key -----BEGIN PRIVATE KEY-----********-----END PRIVATE KEY----- end",
        ),
        # words after Token stay when they cannot be a credential
        ("Token expired", "Token expired"),
    ):
        assert redact(raw) == masked, raw


def test_redact_long_text_is_linear_and_cut():
    text = "a-" * 100_000
    started = time.monotonic()
    out = redact(text)
    assert time.monotonic() - started < 1
    assert out.endswith(f" [{len(text) - SCAN_LIMIT} characters cut]")
    assert len(out) < SCAN_LIMIT + 64
    # a key after a long dash run is still found
    assert redact("x-" * 1000 + " api_key=k1") == "x-" * 1000 + " api_key=********"


def test_redact_cut_drops_half_pem_block():
    pem = "-----BEGIN PRIVATE KEY-----\n" + "A" * 2000
    out = redact("x" * (SCAN_LIMIT - 100) + pem + "\n-----END PRIVATE KEY-----")
    assert "AAAA" not in out and "BEGIN" not in out


def test_filter_masks_args_and_tracebacks():
    try:
        raise ValueError("https://hook.example/?token=topsecret")
    except ValueError:
        record = logging.LogRecord(
            "ulrmm", logging.ERROR, __file__, 1, "%s", ("password=pw1",), True
        )
        import sys

        record.exc_info = sys.exc_info()
    assert RedactFilter().filter(record)
    text = logging.Formatter().format(record)
    assert "pw1" not in text and "topsecret" not in text
    assert "password=********" in text and "token=********" in text


def test_every_handler_redacts():
    handlers = settings.LOGGING["handlers"]
    assert handlers and all("redact" in h.get("filters", []) for h in handlers.values())
    assert settings.LOGGING["filters"]["redact"]["()"] == "ulrmm.logfilter.RedactFilter"


def test_new_settings_defaults():
    assert settings.FIELD_ENCRYPTION_KEYS == [] or isinstance(
        settings.FIELD_ENCRYPTION_KEYS, list
    )
    assert settings.DASHBOARD_TOKEN_MAX_TTL.total_seconds() == 12 * 3600


def test_beat_schedule():
    beat = {v["task"]: v["schedule"] for v in app.conf.beat_schedule.values()}
    assert "core.tasks.refresh_nats_config_task" in beat
    assert "deploy.tasks.prune_security_events" in beat
    assert beat["core.tasks.refresh_nats_config_task"].minute == set(range(0, 60, 5))


def test_publish_allow_follows_the_version():
    ident = "a" * 30
    tail = [f"{ident}.checkin", f"{ident}.cmdoutput.>", f"{ident}.terminal.>"]
    assert nats_publish_allow(ident, NEW) == tail
    assert nats_publish_allow(ident, "3.01.01.2030") == tail
    for old in (OLD, "2.12.0", "", None):
        assert nats_publish_allow(ident, old) == [ident, *tail], old


@override_settings(USE_NATS_STANDARD=True, ALLOWED_HOSTS=["api.example.test"])
def test_websocket_stays_on_loopback():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("NATS_WS_BIND_HOST", None)
        std, ws, connect = get_nats_hosts()
    assert (std, ws, connect) == ("0.0.0.0", "127.0.0.1", "api.example.test")


@patch("ulrmm.utils.time.sleep")
@patch("ulrmm.utils.subprocess.run", return_value=NATS_RUNNING)
class TestNatsConfig(ULRMMTestCase):
    path = os.path.join(settings.BASE_DIR, "nats-rmm.conf")

    def setUp(self):
        self.old = baker.make_recipe("agents.agent", version=OLD)
        self.new = baker.make_recipe("agents.agent", version=NEW)
        for agent in (self.old, self.new):
            Token.objects.create(user=baker.make("accounts.User", agent=agent))

    def users(self):
        with open(self.path) as fh:
            config = json.load(fh)
        return config, {u["user"]: u for u in config["authorization"]["users"]}

    def test_acl_per_version(self, run, sleep):
        reload_nats()
        config, users = self.users()
        old = users[self.old.agent_id]["permissions"]["publish"]["allow"]
        new = users[self.new.agent_id]["permissions"]["publish"]["allow"]
        self.assertIn(self.old.agent_id, old)
        self.assertIn(f"{self.old.agent_id}.checkin", old)
        self.assertNotIn(self.new.agent_id, new)
        self.assertEqual(new[0], f"{self.new.agent_id}.checkin")
        self.assertEqual(config["websocket"]["host"], "127.0.0.1")
        self.assertNotIn("tls", config)

    @override_settings(USE_NATS_STANDARD=True, ALLOWED_HOSTS=["api.example.test"])
    def test_tls_block_needs_tls13(self, run, sleep):
        reload_nats()
        config, _ = self.users()
        self.assertEqual(config["tls"]["min_version"], "1.3")
        self.assertEqual(config["websocket"]["host"], "127.0.0.1")

    def test_refresh_reloads_on_change_only(self, run, sleep):
        from core.tasks import refresh_nats_config_task

        self.assertTrue(reload_nats())
        run.reset_mock()
        self.assertFalse(refresh_nats_config_task())
        run.assert_not_called()

        # natsapi writes the version of an agent that updated itself
        type(self.old).objects.filter(pk=self.old.pk).update(version=NEW)
        self.assertTrue(refresh_nats_config_task())
        self.assertEqual(
            [c.args[0][0] for c in run.call_args_list],
            ["systemctl", "/usr/local/bin/nats-server"],
        )
        _, users = self.users()
        allow = users[self.old.agent_id]["permissions"]["publish"]["allow"]
        self.assertNotIn(self.old.agent_id, allow)


def test_nats_signal_only_to_a_running_unit():
    unit = "LoadState=loaded\nActiveState={}\n"
    for state in ("active", "reloading"):
        assert nats_signal_wanted(unit.format(state)), state
    # update.sh and install.sh write the file while nats is stopped
    for state in ("inactive", "activating", "deactivating", "failed"):
        assert not nats_signal_wanted(unit.format(state)), state
    # no nats unit or no readable answer: send it, a failure gets logged
    for odd in ("LoadState=not-found\nActiveState=inactive\n", "", "x"):
        assert nats_signal_wanted(odd), odd


class TestNatsReloadSignal(ULRMMTestCase):
    def reload(self, state, code=0):
        def run(cmd, **kwargs):
            if cmd[0] == "systemctl":
                out = f"LoadState=loaded\nActiveState={state}\n"
                return subprocess.CompletedProcess(cmd, 0, out, "")
            return subprocess.CompletedProcess(cmd, code, b"", b"")

        with patch("ulrmm.utils.time.sleep"), patch(
            "ulrmm.utils.subprocess.run", side_effect=run
        ) as mocked:
            self.assertTrue(reload_nats())
        return [c.args[0][0] for c in mocked.call_args_list]

    def failures(self):
        return list(
            DebugLog.objects.filter(
                message__startswith="nats-server config reload did not succeed"
            ).values_list("message", flat=True)
        )

    def test_stopped_server_gets_no_signal(self):
        self.assertEqual(self.reload("inactive", code=1), ["systemctl"])
        self.assertEqual(self.failures(), [])

    def test_running_server_is_reloaded(self):
        calls = self.reload("active")
        self.assertEqual(calls, ["systemctl", "/usr/local/bin/nats-server"])
        self.assertEqual(self.failures(), [])

    def test_failed_reload_of_a_running_server_is_logged(self):
        self.reload("active", code=1)
        self.assertEqual(
            self.failures(), ["nats-server config reload did not succeed: exit code 1"]
        )


@override_settings(CACHES=LOCMEM_CACHE)
class TestNatsConfigSkipLog(ULRMMTestCase):
    def setUp(self):
        cache.clear()
        self.no_user = baker.make_recipe("agents.agent", version=NEW)
        self.bad_id = baker.make_recipe("agents.agent", version=NEW)
        type(self.bad_id).objects.filter(pk=self.bad_id.pk).update(agent_id="a.*")

    def skip_logs(self):
        return DebugLog.objects.filter(log_level="critical").count()

    def test_logged_once_per_agent_per_day(self):
        nats_config()
        self.assertEqual(self.skip_logs(), 2)
        nats_config()
        nats_config()
        self.assertEqual(self.skip_logs(), 2)
        # a day later each one is reported again
        cache.clear()
        nats_config()
        self.assertEqual(self.skip_logs(), 4)

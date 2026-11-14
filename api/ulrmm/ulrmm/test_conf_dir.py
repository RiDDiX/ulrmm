# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import os
import tempfile
import threading
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.test import override_settings

from ulrmm.test import NATS_RUNNING, ULRMMTestCase
from ulrmm.utils import reload_nats


class TestConfDir(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_default_is_base_dir(self):
        self.assertEqual(settings.ULRMM_CONF_DIR, "")
        with override_settings(BASE_DIR=self.tmp.name), patch(
            "ulrmm.utils.time.sleep"
        ), patch("ulrmm.utils.subprocess.run", return_value=NATS_RUNNING):
            self.assertTrue(reload_nats())
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "nats-rmm.conf")))

    def test_concurrent_writes_keep_the_newer_config(self):
        agents, others = ["a1"], []

        def config():
            seen = list(agents)
            if seen == ["a1"]:
                # a second enrolment runs while this one builds its config
                agents.append("a2")
                other = threading.Thread(target=reload_nats)
                other.start()
                other.join(timeout=1)
                others.append(other)
            return {"agents": seen}

        with override_settings(
            ULRMM_CONF_DIR=self.tmp.name, ULRMM_NATS_RELOAD=False
        ), patch("ulrmm.utils.nats_config", config):
            reload_nats()
            others[0].join(timeout=10)
        with open(os.path.join(self.tmp.name, "nats-rmm.conf")) as fh:
            self.assertEqual(json.load(fh), {"agents": ["a1", "a2"]})

    def test_both_conf_files_follow_the_setting(self):
        with override_settings(ULRMM_CONF_DIR=self.tmp.name), patch(
            "ulrmm.utils.time.sleep"
        ), patch("ulrmm.utils.subprocess.run", return_value=NATS_RUNNING):
            self.assertTrue(reload_nats())
            call_command("create_natsapi_conf")
        for name, key in (
            ("nats-rmm.conf", "authorization"),
            ("nats-api.conf", "natsurl"),
        ):
            path = os.path.join(self.tmp.name, name)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            with open(path) as fh:
                self.assertIn(key, json.load(fh))

    def test_external_reload_skips_the_signal(self):
        with override_settings(
            ULRMM_CONF_DIR=self.tmp.name, ULRMM_NATS_RELOAD=False
        ), patch("ulrmm.utils.subprocess.run") as run:
            self.assertTrue(reload_nats())
        run.assert_not_called()
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "nats-rmm.conf")))

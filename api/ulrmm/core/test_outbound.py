# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os
from unittest.mock import patch

import requests
from django.core.management import CommandError, call_command
from model_bakery import baker

from logs.models import AuditLog
from ulrmm.constants import ScriptShell
from ulrmm.test import ULRMMTestCase

from .utils import (
    _is_internal_url,
    find_and_replace_db_values_str,
    run_server_script,
    url_guard,
)


class TestOutbound(ULRMMTestCase):
    def test_refused_targets(self):
        for url in (
            "http://0.1.2.3/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "http://[::ffff:127.0.0.1]/",
            "ftp://192.168.178.10/",
        ):
            self.assertTrue(_is_internal_url(url), url)
        self.assertFalse(_is_internal_url("http://192.168.178.10/hook"))

        with patch("core.utils.psutil.net_if_addrs") as addrs:
            addrs.return_value = {
                "eth0": [type("A", (), {"family": 2, "address": "192.168.178.10"})]
            }
            self.assertTrue(_is_internal_url("http://192.168.178.10/hook"))

    def test_guard_checks_the_address_it_connects_to(self):
        # the pre-check said yes, the connection still refuses loopback
        with url_guard(), self.assertRaisesRegex(
            requests.ConnectionError, "may not be reached"
        ):
            requests.get("http://127.0.0.1:9/", timeout=2)

    def test_agent_values_are_escaped(self):
        agent = baker.make_recipe("agents.agent", hostname='pc&x=1#"\\')
        self.assertEqual(
            find_and_replace_db_values_str(
                text="https://h/?n={{agent.hostname}}", instance=agent, escape="url"
            ),
            "https://h/?n=pc%26x%3D1%23%22%5C",
        )
        self.assertEqual(
            find_and_replace_db_values_str(
                text='{"n": "{{agent.hostname}}"}', instance=agent, escape="json"
            ),
            '{"n": "pc&x=1#\\"\\\\"}',
        )

    def test_server_script_environment(self):
        self.setup_coresettings()
        self.coresettings.enable_server_scripts = True
        self.coresettings.save()
        with patch.dict(os.environ, {"ULRMM_TEST_SECRET": "x"}):
            stdout, *_ = run_server_script(
                body='#!/bin/sh\necho "[$ULRMM_TEST_SECRET][$GOOD]"\n',
                args=[],
                env_vars=["GOOD=1"],
                shell=ScriptShell.SHELL,
                timeout=10,
            )
        self.assertEqual(stdout.strip(), "[][1]")

    def test_maintenance_is_audited(self):
        self.authenticate()
        self.setup_coresettings()
        self.assertEqual(self.client.get("/core/clearcache/").status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(message__contains="cleared the server cache")
        )

    def test_maint_mode_takes_one_flag(self):
        with self.assertRaises(CommandError):
            call_command("server_maint_mode", "--enable", "--force-disable")
        with self.assertRaises(CommandError):
            call_command("server_maint_mode")

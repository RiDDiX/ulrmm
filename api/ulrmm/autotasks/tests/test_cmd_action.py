# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.test import SimpleTestCase
from rest_framework.serializers import ValidationError

from autotasks.serializers import _check_cmd_action


class TestCmdAction(SimpleTestCase):
    def action(self, shell):
        return {"type": "cmd", "command": "echo hi", "timeout": 30, "shell": shell}

    def test_custom_placeholder_is_refused(self):
        with self.assertRaisesMessage(ValidationError, "Action 2: enter the path"):
            _check_cmd_action(self.action("custom"), 2)

    def test_real_shells_pass(self):
        for shell in ("cmd", "powershell", "/bin/bash", "/usr/bin/python3", None):
            with self.subTest(shell):
                _check_cmd_action(self.action(shell))

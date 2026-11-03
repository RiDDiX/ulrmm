# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json

from model_bakery import baker

from logs.models import AuditLog, hmac_marker, mask_script_args
from ulrmm.test import ULRMMTestCase


class TestAuditSecrets(ULRMMTestCase):
    def test_mask_script_args(self):
        masked = mask_script_args(
            ["-Password hunter2", "{{global.pw}}", "-Key {{agent.id}} x", "", 5]
        )
        self.assertEqual(masked[0], hmac_marker("-Password hunter2"))
        self.assertEqual(masked[1], "{{global.pw}}")
        self.assertEqual(
            masked[2], f"{hmac_marker('-Key ')}{{{{agent.id}}}}{hmac_marker(' x')}"
        )
        self.assertEqual(masked[3:], ["", "***"])
        self.assertEqual(mask_script_args(None), None)
        self.assertEqual(mask_script_args("-p x"), "***")

    def test_bulk_script_args(self):
        data = {
            "target": "all",
            "mode": "script",
            "args": ["-Password hunter2", "{{global.pw}}"],
            "env_vars": [],
            "script": baker.make("scripts.Script").pk,
        }
        AuditLog.audit_bulk_action("jane", "script", data, [], 0)
        stored = AuditLog.objects.latest("pk").after_value
        self.assertNotIn("hunter2", json.dumps(stored))
        self.assertEqual(stored["args"][1], "{{global.pw}}")
        # the caller keeps its values
        self.assertEqual(data["args"][0], "-Password hunter2")

    def test_test_run_keeps_no_output(self):
        reply = {
            "stdout": "key: s3cr3t\n",
            "stderr": "ü",
            "retcode": 0,
            "execution_time": 1.5,
            "id": 1,
        }
        AuditLog.audit_test_script_run("jane", {"env_vars": []}, reply, None)
        stored = AuditLog.objects.latest("pk").after_value
        self.assertEqual(
            stored,
            {
                "retcode": 0,
                "execution_time": 1.5,
                "stdout_bytes": 12,
                "stderr_bytes": 2,
            },
        )
        AuditLog.audit_test_script_run("jane", {}, "timeout", None)
        self.assertEqual(AuditLog.objects.latest("pk").after_value, "timeout")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from importlib import import_module

from django.apps import apps

from ulrmm.test import ULRMMTestCase

from .models import AuditLog, hmac_marker

MIGRATION = "logs.migrations.0002_auditlog_logs_auditl_entry_t_e8234d_idx_and_more"


def row(**values):
    return AuditLog.objects.create(
        username="john", object_type="script", action="modify", **values
    )


class TestMaskOldEnvValuesMigration(ULRMMTestCase):
    def test_masks_plaintext_items_once(self):
        done = f"KEY={hmac_marker('done')}"
        script = row(
            before_value={"name": "s", "env_vars": ["KEY=secret", done, 7]},
            after_value={"env_vars": [done]},
        )
        template = row(
            after_value={
                "action_env_vars": ["A=1"],
                "resolved_action_env_vars": ["B=2=3", "no-equals"],
            }
        )
        untouched = row(after_value={"env_vars": "text", "other": ["A=1"]})
        not_a_dict = row(after_value=["env_vars"])

        for _ in range(2):
            import_module(MIGRATION).mask_old_env_values(apps, None)
            for audit in (script, template, untouched, not_a_dict):
                audit.refresh_from_db()

            self.assertEqual(
                script.before_value,
                {
                    "name": "s",
                    "env_vars": [f"KEY={hmac_marker('secret')}", done, "***"],
                },
            )
            self.assertEqual(script.after_value, {"env_vars": [done]})
            self.assertEqual(
                template.after_value,
                {
                    "action_env_vars": [f"A={hmac_marker('1')}"],
                    "resolved_action_env_vars": [f"B={hmac_marker('2=3')}", "***"],
                },
            )
            self.assertEqual(
                untouched.after_value, {"env_vars": "text", "other": ["A=1"]}
            )
            self.assertEqual(not_a_dict.after_value, ["env_vars"])

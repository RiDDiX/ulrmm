# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from logs.models import DebugLog
from scripts.models import Script
from ulrmm.constants import ScriptShell
from ulrmm.test import ULRMMTestCase


class TestFalsyPlaceholderValues(ULRMMTestCase):
    def test_false_and_zero_are_values(self):
        agent = baker.make_recipe("agents.agent", maintenance_mode=False)
        agent.check_interval = 0
        args = ["{{agent.maintenance_mode}}", "-i {{agent.check_interval}}"]

        parsed = Script.parse_script_args(agent, ScriptShell.POWERSHELL, args)

        self.assertEqual(parsed, ["$False", "-i 0"])
        self.assertFalse(DebugLog.objects.exists())

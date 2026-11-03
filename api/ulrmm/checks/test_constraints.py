# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.constants import CheckType
from ulrmm.test import ULRMMTestCase

from .models import Check


class TestDiskPath(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_disk_accepts_a_mount_path(self):
        agent = baker.make_recipe("agents.agent", plat="linux")
        payload = {
            "agent": agent.agent_id,
            "check_type": CheckType.DISK_SPACE,
            "disk": "/var/lib/docker",
            "error_threshold": 55,
            "warning_threshold": 0,
            "fails_b4_alert": 3,
        }
        r = self.client.post("/checks/", payload, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Check.objects.get(agent=agent).disk, "/var/lib/docker")

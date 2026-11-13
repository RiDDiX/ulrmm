# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from ulrmm.test import ULRMMTestCase


class TestRunURLActionBody(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_a_body_that_is_not_an_object_is_a_400(self):
        for body in (["agent_id"], "agent_id", 5):
            r = self.client.patch("/core/urlaction/run/", body, format="json")
            self.assertEqual(r.status_code, 400, body)

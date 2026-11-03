# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from logs.models import PendingAction
from ulrmm.constants import PAAction, PAStatus
from ulrmm.test import ULRMMTestCase

INSTALLED = 0x8A150061
REBOOT = 0x8A150109


class TestWingetResult(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe("agents.online_agent")
        self.authenticate_agent(self.agent)

    def action(self, kind=PAAction.WINGET_INSTALL):
        return PendingAction.objects.create(
            agent=self.agent,
            action_type=kind,
            details={"name": "7-Zip", "id": "7zip.7zip", "output": None},
        )

    def patch(self, action, body):
        return self.client.patch(
            f"/api/v4/{self.agent.agent_id}/{action.pk}/wingetresult/",
            body,
            format="json",
        )

    def test_exit_codes(self):
        for code, installed, reboot in (
            (0, True, False),
            (0x8A15002B, True, False),
            (INSTALLED, True, False),
            (REBOOT, True, True),
            (-1, False, False),
            (0x8A150014, False, False),
            (2**32 - 1, False, False),
        ):
            with self.subTest(code=hex(code)):
                action = self.action()
                r = self.patch(action, {"results": "out", "exit_code": code})
                self.assertEqual((r.status_code, r.data), (200, "ok"))
                action.refresh_from_db()
                self.assertEqual(action.status, PAStatus.COMPLETED)
                self.assertEqual(
                    action.details,
                    {
                        "name": "7-Zip",
                        "id": "7zip.7zip",
                        "output": "out",
                        "exit_code": code,
                        "installed": installed,
                        "reboot": reboot,
                    },
                )

    def test_refused(self):
        action = self.action()
        for body in (
            {"results": "x", "exit_code": True},
            {"results": "x", "exit_code": "0"},
            {"results": "x", "exit_code": 2**32},
            {"results": "x"},
            {"exit_code": 0},
        ):
            with self.subTest(body=body):
                self.assertEqual(self.patch(action, body).status_code, 400)
        action.refresh_from_db()
        self.assertEqual(action.status, PAStatus.PENDING)

        self.assertEqual(
            self.patch(action, {"results": "x", "exit_code": 0}).status_code, 200
        )
        # once only
        self.assertEqual(
            self.patch(action, {"results": "y", "exit_code": 0}).status_code, 400
        )
        choco = self.action(PAAction.CHOCO_INSTALL)
        self.assertEqual(
            self.patch(choco, {"results": "x", "exit_code": 0}).status_code, 400
        )

    def test_output_tail_and_other_agent(self):
        action = self.action()
        r = self.patch(action, {"results": "a" * (2**20 + 5), "exit_code": 0})
        self.assertEqual(r.status_code, 200)
        action.refresh_from_db()
        self.assertEqual(len(action.details["output"]), 2**20)

        other = baker.make_recipe("agents.online_agent")
        theirs = PendingAction.objects.create(
            agent=other, action_type=PAAction.WINGET_INSTALL, details={}
        )
        r = self.client.patch(
            f"/api/v4/{other.agent_id}/{theirs.pk}/wingetresult/",
            {"results": "x", "exit_code": 0},
            format="json",
        )
        self.assertEqual(r.status_code, 404)


class TestChocoResult(ULRMMTestCase):
    def test_still_works(self):
        self.setup_coresettings()
        self.setup_client()
        agent = baker.make_recipe("agents.online_agent")
        self.authenticate_agent(agent)
        action = PendingAction.objects.create(
            agent=agent, action_type=PAAction.CHOCO_INSTALL, details={"name": "vlc"}
        )
        r = self.client.patch(
            f"/api/v4/{agent.agent_id}/{action.pk}/chocoresult/",
            {"results": "The install of vlc was successful. installed"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        action.refresh_from_db()
        self.assertTrue(action.details["installed"])
        self.assertEqual(action.status, PAStatus.COMPLETED)

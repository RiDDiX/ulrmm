# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from ulrmm.constants import PAAction
from ulrmm.test import ULRMMTestCase

from .serializers import AuditLogSerializer


class TestReviewFixes(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_unicode_digit_is_bad_input(self):
        data = {"pagination": {"rowsPerPage": "²", "page": 1}}
        r = self.client.patch("/logs/audit/", data, format="json")
        self.assertEqual(r.status_code, 400)

    def test_malformed_pending_details(self):
        agent = baker.make_recipe("agents.agent")
        for kind in (
            PAAction.SCHED_REBOOT,
            PAAction.AGENT_UPDATE,
            PAAction.CHOCO_INSTALL,
            PAAction.WINGET_INSTALL,
        ):
            baker.make(
                "logs.PendingAction", agent=agent, action_type=kind, details=None
            )
        r = self.client.get("/logs/pendingactions/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            {a["description"] for a in r.data},
            {"Device pending reboot", "Agent update", "Software install"},
        )

        action = baker.make(
            "logs.PendingAction",
            agent=agent,
            action_type=PAAction.AGENT_UPDATE,
            details=["not", "a", "dict"],
        )
        r = self.client.delete(f"/logs/pendingactions/{action.id}/")
        self.assertEqual(r.status_code, 200)

    def test_winget_pending_action(self):
        agent = baker.make_recipe("agents.agent")
        action = baker.make(
            "logs.PendingAction",
            agent=agent,
            action_type=PAAction.WINGET_INSTALL,
            details={"name": "7-Zip", "id": "7zip.7zip"},
        )
        self.assertEqual(
            (action.due, action.description), ("ASAP", "7-Zip software install")
        )

    def test_serializer_without_sites_context(self):
        log = baker.make("logs.AuditLog", agent_id="abc")
        self.assertIsNone(AuditLogSerializer(log).data["site"])

    def test_long_number_is_bad_input(self):
        data = {"pagination": {"rowsPerPage": "9" * 5000, "page": 1}}
        r = self.client.patch("/logs/audit/", data, format="json")
        self.assertEqual(r.status_code, 400)

    def _audit(self, **pagination):
        base = {
            "rowsPerPage": 25,
            "page": 1,
            "sortBy": "entry_time",
            "descending": True,
        }
        base.update(pagination)
        return self.client.patch("/logs/audit/", {"pagination": base}, format="json")

    def test_page_below_one_is_bad_input(self):
        for page in (0, -1, "0"):
            r = self._audit(page=page)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "page must be a whole number of at least 1")

    def test_page_past_the_end_gives_last_page(self):
        baker.make("logs.AuditLog", _quantity=3)
        r = self._audit(rowsPerPage=2, page=99)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data["audit_logs"]), 1)

    def test_missing_pagination_keys(self):
        for key in ("sortBy", "descending", "page", "rowsPerPage"):
            data = {
                "rowsPerPage": 25,
                "page": 1,
                "sortBy": "entry_time",
                "descending": False,
            }
            del data[key]
            r = self.client.patch("/logs/audit/", {"pagination": data}, format="json")
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, f"pagination.{key} is required")

    def test_descending_must_be_bool(self):
        for value in ("true", 1, None):
            r = self._audit(descending=value)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.data, "descending must be a boolean")

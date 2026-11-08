# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta
from unittest.mock import patch

from django.test import RequestFactory
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import PendingAction
from logs.tasks import prune_pending_actions
from ulrmm.middleware import (
    AuditMiddleware,
    get_debug_info,
    get_username,
    request_local,
)
from ulrmm.test import ULRMMTestCase


class TestAuditMiddleware(ULRMMTestCase):
    def test_every_request_starts_clean(self):
        request_local.username = "john"
        request_local.debug_info = {"ip": "192.0.2.1"}
        seen = {}

        def view(request):
            seen.update(username=get_username(), debug_info=get_debug_info())
            return "ok"

        AuditMiddleware(view)(RequestFactory().get("/api/v3/checkin/"))
        self.assertEqual(seen, {"username": None, "debug_info": {}})


class TestPendingCount(ULRMMTestCase):
    def test_count_in_scope(self):
        self.authenticate()
        mine = baker.make_recipe("agents.online_agent")
        theirs = baker.make_recipe("agents.online_agent")
        for agent, status in (
            (mine, "pending"),
            (mine, "completed"),
            (theirs, "pending"),
        ):
            baker.make(
                "logs.PendingAction",
                agent=agent,
                action_type="agentupdate",
                status=status,
            )
        url = "/logs/pendingactions/count/"
        self.assertEqual(self.client.get(url).data, {"pending": 2})
        user = self.create_user_with_roles(["can_list_pendingactions"])
        user.role.can_view_sites.set([mine.site])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.client.get(url).data, {"pending": 1})
        self.client.force_authenticate(user=self.create_user_with_roles([]))
        self.assertEqual(self.client.get(url).status_code, 403)


class TestPrunePendingActions(ULRMMTestCase):
    def test_only_old_completed_rows_go(self):
        agent = baker.make_recipe("agents.agent")
        old = djangotime.now() - timedelta(days=31)
        rows = {}
        for name, status, entry_time in (
            ("old completed", "completed", old),
            ("old pending", "pending", old),
            ("new completed", "completed", None),
        ):
            row = baker.make(
                "logs.PendingAction",
                agent=agent,
                action_type="agentupdate",
                status=status,
            )
            if entry_time:
                PendingAction.objects.filter(pk=row.pk).update(entry_time=entry_time)
            rows[row.pk] = name

        self.assertEqual(prune_pending_actions(30), "ok")
        left = PendingAction.objects.values_list("pk", flat=True)
        self.assertEqual(
            sorted(rows[pk] for pk in left), ["new completed", "old pending"]
        )


class TestListCaps(ULRMMTestCase):
    def setUp(self):
        self.authenticate()

    def test_audit_total_is_capped(self):
        baker.make("logs.AuditLog", username="john", _quantity=3)
        search = {
            "pagination": {
                "sortBy": "entry_time",
                "descending": True,
                "page": 1,
                "rowsPerPage": 2,
            }
        }
        r = self.client.patch("/logs/audit/", search, format="json")
        self.assertEqual((r.data["total"], r.data["total_capped"]), (3, False))
        with patch("logs.views.COUNT_CAP", 2):
            r = self.client.patch("/logs/audit/", search, format="json")
        self.assertEqual((r.data["total"], r.data["total_capped"]), (2, True))
        self.assertEqual(len(r.data["audit_logs"]), 2)

    def test_pending_actions_pages(self):
        agent = baker.make_recipe("agents.online_agent")
        baker.make(
            "logs.PendingAction",
            agent=agent,
            action_type="agentupdate",
            _quantity=3,
        )
        url = "/logs/pendingactions/"
        self.assertEqual(len(self.client.get(url).data), 3)
        r = self.client.get(url, {"page": 2, "rows": 2})
        self.assertEqual(r.data["total"], 3)
        self.assertEqual(len(r.data["actions"]), 1)
        self.assertEqual(self.client.get(url, {"page": "x"}).status_code, 400)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.test import RequestFactory
from model_bakery import baker

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

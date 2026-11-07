# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery import baker

from logs.models import AuditLog
from ulrmm.constants import AuditObjType
from ulrmm.test import ULRMMTestCase

from .models import GroupKind


class TestMemberAuditScoped(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.setup_base_instance()

        def agent(hostname, site):
            return baker.make_recipe("agents.agent", hostname=hostname, site=site)

        self.a1 = agent("a-one", self.site1)
        self.a2 = agent("a-two", self.site2)
        self.hidden = agent("b-hidden", self.site3)

    def test_audit_lists_only_visible_members(self):
        group = baker.make("groups.DeviceGroup", name="g", kind=GroupKind.STATIC)
        group.members.set([self.a1, self.hidden])
        user = self.create_user_with_roles(
            ["can_list_agents", "can_manage_device_groups"]
        )
        user.role.can_view_clients.set([self.company1])
        self.client.force_authenticate(user=user)

        members = [self.a1.agent_id, self.a2.agent_id]
        r = self.client.put(f"/groups/{group.pk}/", {"members": members}, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(group.members.count(), 3)

        row = AuditLog.objects.get(
            object_type=AuditObjType.DEVICE_GROUP, after_value__has_key="members"
        )
        self.assertEqual(row.before_value, {"members": ["a-one"]})
        self.assertEqual(row.after_value, {"members": ["a-one", "a-two"]})

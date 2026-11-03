# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from logs.models import AuditLog
from ulrmm.constants import ScriptShell
from ulrmm.test import ULRMMTestCase

from .models import ScriptSnippet


class TestSnippetAudit(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_one_audit_row_per_change(self):
        url = "/scripts/snippets/"
        data = {"name": "snip", "shell": ScriptShell.POWERSHELL, "code": "x"}
        self.assertEqual(self.client.post(url, data, format="json").status_code, 200)
        snippet = ScriptSnippet.objects.get(name="snip")
        for code in ("y", "y"):
            r = self.client.put(f"{url}{snippet.pk}/", {"code": code}, format="json")
            self.assertEqual(r.status_code, 200)
        r = self.client.get(f"{url}{snippet.pk}/")
        self.assertEqual(set(r.data), {"id", "name", "desc", "code", "shell"})
        self.assertEqual(self.client.delete(f"{url}{snippet.pk}/").status_code, 200)

        rows = list(
            AuditLog.objects.filter(
                object_type__in=["script", "scriptsnippet"]
            ).order_by("pk")
        )
        self.assertEqual(
            [(a.object_type, a.action) for a in rows],
            [
                ("scriptsnippet", "add"),
                ("scriptsnippet", "modify"),
                ("scriptsnippet", "delete"),
            ],
        )
        self.assertEqual(rows[1].before_value["code"], "x")
        self.assertEqual(rows[1].after_value["code"], "y")
        self.assertEqual(rows[0].username, "john")

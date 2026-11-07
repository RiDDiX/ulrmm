# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt

from django.utils import timezone as djangotime
from model_bakery import baker

from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase

from .models import Finding, FindingStatus, Source
from .tasks import _record, scan


class TestFindingHistory(ULRMMTestCase):
    def test_old_fixed_and_ignored_findings_are_deleted(self):
        agent = baker.make_recipe("agents.agent", plat=AgentPlat.FREEBSD)
        now = djangotime.now()
        old = now - dt.timedelta(days=91)
        for vuln_id, status, seen in (
            ("old-fixed", FindingStatus.FIXED, old),
            ("new-fixed", FindingStatus.FIXED, now),
            ("old-ignored", FindingStatus.IGNORED, old),
            ("new-ignored", FindingStatus.IGNORED, now),
            ("old-open", FindingStatus.OPEN, old),
        ):
            baker.make(
                "vulns.Finding",
                agent=agent,
                package="openssl",
                version="1",
                vuln_id=vuln_id,
                status=status,
                first_seen=seen,
                last_seen=seen,
            )

        # a scan of chosen agents leaves the history alone
        scan([agent.pk])
        self.assertEqual(Finding.objects.count(), 5)

        scan()
        self.assertEqual(
            sorted(Finding.objects.values_list("vuln_id", flat=True)),
            ["new-fixed", "new-ignored", "old-open"],
        )

    def test_ignored_finding_stays_ignored_while_gone(self):
        agent = baker.make_recipe("agents.agent", plat=AgentPlat.LINUX)
        key = ("openssl", "1", "CVE-2026-1")
        present = {key: "Debian:12"}
        _record(agent, Source.OSV, present, {}, set())
        Finding.objects.update(status=FindingStatus.IGNORED)

        _record(agent, Source.OSV, {}, {}, set())
        self.assertEqual(Finding.objects.get().status, FindingStatus.IGNORED)

        self.assertEqual(_record(agent, Source.OSV, present, {}, set()), [])
        self.assertEqual(Finding.objects.get().status, FindingStatus.IGNORED)

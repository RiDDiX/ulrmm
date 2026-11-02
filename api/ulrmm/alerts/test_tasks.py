# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import timedelta
from functools import partial

from django.utils import timezone as djangotime
from model_bakery import baker

from alerts.models import Alert
from alerts.tasks import prune_resolved_alerts, unsnooze_alerts
from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase


class TestAlertTasks(ULRMMTestCase):
    def test_unsnooze_wakes_only_expired_snoozes(self):
        now = djangotime.now()
        expired, running = (
            baker.make(
                "alerts.Alert",
                alert_type=AlertType.CUSTOM,
                snoozed=True,
                snooze_until=now + offset,
            )
            for offset in (timedelta(minutes=-1), timedelta(hours=1))
        )
        unsnooze_alerts()
        expired.refresh_from_db()
        running.refresh_from_db()
        self.assertEqual((expired.snoozed, expired.snooze_until), (False, None))
        self.assertTrue(running.snoozed)

    def test_prune_counts_age_from_the_resolution(self):
        old = djangotime.now() - timedelta(days=40)
        make = partial(baker.make, "alerts.Alert", alert_type=AlertType.CUSTOM)
        make(resolved=True, resolved_on=old)
        legacy = make(resolved=True, resolved_on=None)
        late = make(resolved=True, resolved_on=djangotime.now())
        still_open = make(resolved=False)
        # alert_time is auto_now_add; age the legacy and late rows by hand
        Alert.objects.filter(pk__in=[legacy.pk, late.pk, still_open.pk]).update(
            alert_time=old
        )

        prune_resolved_alerts(30)
        self.assertEqual(
            set(Alert.objects.values_list("pk", flat=True)), {late.pk, still_open.pk}
        )

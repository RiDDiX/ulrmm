# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from importlib import import_module
from unittest.mock import patch

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from model_bakery import baker

from ulrmm.constants import AlertType
from ulrmm.test import ULRMMTestCase

from .models import Alert

MIGRATION = "alerts.migrations.0004_alert_unique_open_check_alert_and_more"


class TestOneOpenAlert(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        self.check = baker.make_recipe("checks.diskspace_check", agent=self.agent)
        self.task = baker.make("autotasks.AutomatedTask", agent=self.agent)

    def test_second_call_returns_the_open_alert(self):
        first = Alert.create_or_return_check_alert(self.check, agent=self.agent)
        again = Alert.create_or_return_check_alert(self.check, agent=self.agent)
        self.assertEqual(first.pk, again.pk)
        task_alert = Alert.create_or_return_task_alert(self.task, agent=self.agent)
        self.assertEqual(
            Alert.create_or_return_task_alert(self.task, agent=self.agent).pk,
            task_alert.pk,
        )
        self.assertEqual(Alert.objects.filter(resolved=False).count(), 2)

    def test_open_alert_created_meanwhile_is_returned(self):
        theirs = baker.make(
            "alerts.Alert",
            agent=self.agent,
            assigned_check=self.check,
            alert_type=AlertType.CHECK,
        )
        real_filter = Alert.objects.filter
        calls = []

        def misses_once(*args, **kwargs):
            calls.append(kwargs)
            rows = real_filter(*args, **kwargs)
            return rows.none() if len(calls) == 1 else rows

        with patch.object(Alert.objects, "filter", side_effect=misses_once):
            alert = Alert.create_or_return_check_alert(self.check, agent=self.agent)

        self.assertEqual(alert.pk, theirs.pk)
        self.assertEqual(Alert.objects.count(), 1)

    def test_database_refuses_a_second_open_alert(self):
        Alert.objects.create(agent=self.agent, assigned_check=self.check)
        Alert.objects.create(agent=self.agent, assigned_check=self.check, resolved=True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Alert.objects.create(agent=self.agent, assigned_check=self.check)

    def test_reopening_next_to_an_open_alert_is_refused(self):
        old = baker.make(
            "alerts.Alert", agent=self.agent, assigned_check=self.check, resolved=True
        )
        baker.make("alerts.Alert", agent=self.agent, assigned_check=self.check)

        r = self.client.put(f"/alerts/{old.pk}/", {"resolved": False}, format="json")

        self.assertEqual(r.status_code, 400)
        old.refresh_from_db()
        self.assertTrue(old.resolved)


class TestOpenAlertDuplicatesMigration(ULRMMTestCase):
    def test_resolves_all_but_the_newest(self):
        for constraint in Alert._meta.constraints:
            with connection.schema_editor() as editor:
                editor.remove_constraint(Alert, constraint)
        agent = baker.make_recipe("agents.agent")
        check = baker.make_recipe("checks.diskspace_check", agent=agent)
        task = baker.make("autotasks.AutomatedTask", agent=agent)
        checks = [
            Alert.objects.create(agent=agent, assigned_check=check) for _ in range(3)
        ]
        tasks = [
            Alert.objects.create(agent=agent, assigned_task=task) for _ in range(2)
        ]
        outages = [Alert.objects.create(agent=agent) for _ in range(2)]

        for _ in range(2):
            import_module(MIGRATION).resolve_older_duplicates(apps, None)

        open_pks = set(
            Alert.objects.filter(resolved=False).values_list("pk", flat=True)
        )
        self.assertEqual(
            open_pks, {checks[-1].pk, tasks[-1].pk} | {a.pk for a in outages}
        )
        for alert in checks[:-1] + tasks[:-1]:
            alert.refresh_from_db()
            self.assertIsNotNone(alert.resolved_on)

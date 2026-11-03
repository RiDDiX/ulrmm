# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from importlib import import_module

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from model_bakery import baker

from ulrmm.test import ULRMMTestCase

from .models import InstalledSoftware
from .views import _save_inventory

MIGRATION = "software.migrations.0002_installedsoftware_unique_installed_software_agent"


class TestOneInventoryPerAgent(ULRMMTestCase):
    def test_refresh_updates_the_one_row(self):
        agent = baker.make_recipe("agents.agent")
        _save_inventory(agent, [{"name": "a"}])
        _save_inventory(agent, [{"name": "b"}])
        rows = InstalledSoftware.objects.filter(agent=agent)
        self.assertEqual([row.software for row in rows], [[{"name": "b"}]])

        with self.assertRaises(IntegrityError), transaction.atomic():
            InstalledSoftware.objects.create(agent=agent, software=[])

    def test_migration_keeps_the_newest_row(self):
        constraint = InstalledSoftware._meta.constraints[0]
        with connection.schema_editor() as editor:
            editor.remove_constraint(InstalledSoftware, constraint)
        agent, other = baker.make_recipe("agents.agent", _quantity=2)
        rows = [
            InstalledSoftware.objects.create(agent=agent, software=[n])
            for n in range(3)
        ]
        single = InstalledSoftware.objects.create(agent=other, software=[])

        for _ in range(2):
            import_module(MIGRATION).drop_older_duplicates(apps, None)

        self.assertEqual(
            sorted(InstalledSoftware.objects.values_list("pk", flat=True)),
            sorted([rows[-1].pk, single.pk]),
        )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from importlib import import_module

from django.apps import apps
from django.db import connection, models
from model_bakery import baker

from ulrmm.test import ULRMMTestCase

from .models import GlobalKVStore

MIGRATION = "core.migrations.0002_alter_globalkvstore_name"


class TestUniqueKeyStoreName(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_duplicate_name_is_refused(self):
        key = baker.make("core.GlobalKVStore", name="token", value="a")
        other = baker.make("core.GlobalKVStore", name="other", value="b")

        r = self.client.post("/core/keystore/", {"name": "token", "value": "c"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "A key with this name already exists")

        r = self.client.put(f"/core/keystore/{other.pk}/", {"name": "token"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "A key with this name already exists")

        # its own name is not a duplicate
        r = self.client.put(f"/core/keystore/{key.pk}/", {"name": "token"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(GlobalKVStore.objects.filter(name="token").count(), 1)

    def test_other_errors_keep_their_shape(self):
        r = self.client.post("/core/keystore/", {"name": "x" * 26, "value": "v"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.data)


class TestKeyStoreNameMigration(ULRMMTestCase):
    def test_refuses_duplicate_names(self):
        migration = import_module(MIGRATION)
        baker.make("core.GlobalKVStore", name="ok", value="v")
        migration.refuse_duplicate_names(apps, None)

        unique = GlobalKVStore._meta.get_field("name")
        plain = models.CharField(max_length=25)
        plain.set_attributes_from_name("name")
        plain.model = GlobalKVStore
        with connection.schema_editor() as editor:
            editor.alter_field(GlobalKVStore, unique, plain)
        for name in ("b", "b", "a", "a", "ok2"):
            GlobalKVStore.objects.create(name=name, value="v")

        with self.assertRaisesMessage(RuntimeError, "named: a, b"):
            migration.refuse_duplicate_names(apps, None)

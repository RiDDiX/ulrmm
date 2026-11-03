# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.db.migrations.recorder import MigrationRecorder
from django.test import TestCase

REPO = Path(settings.BASE_DIR).parents[1]
SCRIPT = REPO / "riddix" / "scripts" / "db_ahead_check.py"


def load_check():
    spec = importlib.util.spec_from_file_location("db_ahead_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDbAheadCheck(TestCase):
    def setUp(self):
        self.check = load_check()
        # what update.sh lists from the target ref
        paths = sorted(
            str(path.relative_to(REPO))
            for path in (REPO / "api" / "ulrmm").glob("*/migrations/[0-9]*.py")
        )
        handle, self.listing = tempfile.mkstemp()
        self.addCleanup(os.remove, self.listing)
        with os.fdopen(handle, "w") as f:
            f.write("\n".join(paths))

    def run_check(self, *args):
        with patch.object(sys, "argv", ["db_ahead_check.py", *args]):
            return self.check.main()

    def test_squashed_reporting_migrations_do_not_block_a_switch(self):
        recorded = set(
            MigrationRecorder.Migration.objects.filter(app="reporting").values_list(
                "app", "name"
            )
        )
        replaced = self.check.replaced_migrations(self.listing, str(REPO))
        self.assertIn(("reporting", "0001_initial"), recorded)
        self.assertLessEqual(
            {
                ("reporting", "0001_initial"),
                ("reporting", "0002_alter_reporttemplate_type"),
                ("reporting", "0003_alter_reporthtmltemplate_name_and_more"),
                ("reporting", "0004_reportdataquery_created_by_and_more"),
            },
            replaced,
        )

        self.assertEqual(self.run_check(self.listing, str(REPO)), 0)
        # without the tree the replaced names count as ahead
        self.assertEqual(self.run_check(self.listing), 1)

    def test_a_newer_database_is_still_refused(self):
        MigrationRecorder.Migration.objects.create(app="reporting", name="0099_newer")
        self.assertEqual(self.run_check(self.listing, str(REPO)), 1)

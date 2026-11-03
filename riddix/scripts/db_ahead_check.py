#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Refuse a code switch when the database is ahead of the code.

Compares the migrations recorded in django_migrations with the migration files
the target tree ships. Applied migrations whose file is missing mean the DB was
built by newer (or different) code - migrating on top of that silently leaves
tables nobody owns.

Runs with the *old* instance venv, before anything is checked out:

    python db_ahead_check.py <file with target migration paths> [<tree>]

The file is what "git ls-tree -r --name-only <ref> -- api/ulrmm" prints,
filtered to */migrations/NNNN*.py. <tree> is a directory holding those files
as the target ref has them; with it, migrations that a target squash lists in
"replaces" count as shipped. Exit 0 = safe, 1 = do not switch.
"""

import ast
import os
import sys

API_DIR = os.environ.get("ULRMM_API_DIR", "/rmm/api/ulrmm")
sys.path.insert(0, API_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ulrmm.settings")

# migration was deleted later. old dbs still have the django_migrations row.
KNOWN_ORPHANS = {("scripts", "0006_auto_20201210_2145")}


def target_migrations(path):
    """{(app_label, migration_name)} from a list of repo paths."""
    found = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.endswith(".py") or "/migrations/" not in line:
                continue
            parts = line.split("/")
            i = parts.index("migrations")
            app = parts[i - 1]
            name = parts[-1][: -len(".py")]
            if name == "__init__":
                continue
            found.add((app, name))
    return found


def replaced_migrations(path, tree):
    """{(app_label, migration_name)} the target's squashed migrations replace.

    Django records the replaced names next to the squash, and databases that
    applied the originals keep their rows, so both must count as shipped.
    """
    found = set()
    with open(path) as f:
        paths = [line.strip() for line in f if line.strip().endswith(".py")]
    for rel in paths:
        try:
            with open(os.path.join(tree, rel)) as f:
                module = ast.parse(f.read())
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(module):
            if not isinstance(node, ast.Assign):
                continue
            if not any(getattr(t, "id", None) == "replaces" for t in node.targets):
                continue
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError, RecursionError):
                continue
            if isinstance(value, (list, tuple)):
                found.update(
                    tuple(item)
                    for item in value
                    if isinstance(item, (list, tuple))
                    and len(item) == 2
                    and all(isinstance(part, str) for part in item)
                )
    return found


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: db_ahead_check.py <migration list file> [<tree>]")
        return 2

    import django

    django.setup()

    from django.apps import apps
    from django.db.migrations.recorder import MigrationRecorder

    target = target_migrations(sys.argv[1])
    if not target:
        print("no migrations found in the target tree")
        return 2
    replaced = set()
    if len(sys.argv) == 3:
        replaced = replaced_migrations(sys.argv[1], sys.argv[2])

    # only apps the target tree actually ships; django/knox/allauth migrations
    # live in site-packages and are none of our business here
    target_apps = {app for app, _ in target}
    installed = {a.label for a in apps.get_app_configs()}

    applied = {
        (m.app, m.name)
        for m in MigrationRecorder.Migration.objects.all()
        if m.app in target_apps and m.app in installed
    }

    ahead = sorted(applied - target - replaced - KNOWN_ORPHANS)

    if ahead:
        print("database is ahead of the target code:")
        for app, name in ahead:
            print(f"  {app}.{name}")
        return 1

    pending = sorted(target - applied)
    print(f"database is compatible, {len(pending)} migration(s) pending")
    for app, name in pending[:20]:
        print(f"  {app}.{name}")
    if len(pending) > 20:
        print(f"  ... and {len(pending) - 20} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())

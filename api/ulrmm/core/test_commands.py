# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import ast
import importlib
from fnmatch import fnmatch
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.test import SimpleTestCase
from model_bakery import baker

from ulrmm.test import ULRMMTestCase


def run(*args) -> str:
    out = StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


class TestCoreCommands(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_get_config_prints_one_value(self):
        self.assertEqual(run("get_config", "api"), settings.ALLOWED_HOSTS[0] + "\n")
        self.assertEqual(
            run("get_config", "dbname"), settings.DATABASES["default"]["NAME"] + "\n"
        )
        self.assertEqual(run("get_config", "meshsite"), settings.MESH_SITE + "\n")
        self.assertEqual(run("get_config", "nonsense"), "")

    @patch("core.management.commands.bulk_restart_agents.sleep")
    @patch(
        "core.management.commands.bulk_restart_agents.get_mesh_ws_url",
        return_value="wss://mesh",
    )
    @patch(
        "core.management.commands.bulk_restart_agents.get_agent_url",
        return_value="https://dl/agent",
    )
    @patch("agents.models.Agent.recover")
    def test_bulk_restart_recovers_both_services(self, recover, *_):
        agent = baker.make_recipe("agents.online_agent")
        out = run("bulk_restart_agents")
        self.assertIn(agent.hostname, out)
        recover.assert_any_call(
            "agent", "wss://mesh", wait=False, agent_url="https://dl/agent"
        )
        recover.assert_any_call("mesh", "", wait=False)
        self.assertEqual(recover.call_count, 2)


class TestLockList(SimpleTestCase):
    def test_every_redis_lock_id_is_cleared(self):
        from core.management.commands.clear_redis_celery_locks import (
            LOCK_PATTERNS,
            LOCKS,
        )

        def cleared(lock_id: str) -> bool:
            return lock_id in LOCKS or any(fnmatch(lock_id, p) for p in LOCK_PATTERNS)

        base = Path(settings.BASE_DIR)
        seen = 0
        for path in base.rglob("*.py"):
            rel = path.relative_to(base)
            if {"tests", "golden", "migrations"} & set(
                rel.parts
            ) or rel.name.startswith("test"):
                continue
            tree = ast.parse(path.read_text())
            module = ".".join(rel.with_suffix("").parts)
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "id", None) == "redis_lock"
                    and node.args
                ):
                    continue
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    lock_id = arg.value
                elif isinstance(arg, ast.Name):
                    lock_id = getattr(importlib.import_module(module), arg.id)
                elif isinstance(arg, ast.Call):
                    func = getattr(importlib.import_module(module), arg.func.id)
                    lock_id = func(1)
                elif isinstance(arg, ast.JoinedStr):
                    lock_id = f"{arg.values[0].value}1"
                else:
                    self.fail(f"{rel}:{node.lineno}: lock id not understood")
                seen += 1
                self.assertTrue(cleared(lock_id), f"{rel}:{node.lineno}: {lock_id}")
        self.assertGreater(seen, 30)

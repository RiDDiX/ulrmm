# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import io
import json
import os
import subprocess
import tempfile
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from model_bakery import baker
from rest_framework.exceptions import ValidationError as BadRequest

from alerts.models import AlertTemplate
from autotasks.models import AutomatedTask
from checks.models import Check
from logs.models import AuditLog, mask_env_vars
from ulrmm.constants import AuditActionType, AuditObjType, ScriptShell, ScriptType
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.utils import git_auth_env

from core.utils import run_server_script

from .models import RETIRED_CATEGORY, Script, check_env_vars
from .views import LIBRARY_SYNC_LOCK


class TestScriptVariables(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_variables_round_trip(self):
        data = {
            "name": "With variables",
            "shell": ScriptShell.SHELL,
            "script_body": "#!/bin/sh\necho $Url",
            "variables": [
                {"name": "Url", "label": "URL", "type": "string"},
                {
                    "name": "MODE",
                    "label": "Mode",
                    "type": "select",
                    "options": ["a", "b"],
                    "default": "b",
                    "required": True,
                    "help": "Pick one",
                },
            ],
        }
        resp = self.client.post("/scripts/", data, format="json")
        self.assertEqual(resp.status_code, 200)
        script = Script.objects.get(name="With variables")
        expected = [
            {
                "name": "Url",
                "label": "URL",
                "type": "string",
                "required": False,
                "default": "",
                "options": [],
                "help": "",
            },
            {
                "name": "MODE",
                "label": "Mode",
                "type": "select",
                "required": True,
                "default": "b",
                "options": ["a", "b"],
                "help": "Pick one",
            },
        ]
        self.assertEqual(script.variables, expected)
        resp = self.client.get(f"/scripts/{script.pk}/", format="json")
        self.assertEqual(resp.data["variables"], expected)
        resp = self.client.get("/scripts/", format="json")
        self.assertEqual(resp.data[0]["variables"], expected)

        resp = self.client.put(
            f"/scripts/{script.pk}/", {"variables": []}, format="json"
        )
        self.assertEqual(resp.status_code, 200)
        script.refresh_from_db()
        self.assertEqual(script.variables, [])

    def test_variables_validation(self):
        script = baker.make("scripts.Script", variables=[])
        ok = {"name": "A", "label": "A", "type": "string"}
        bad = [
            ("not a list", "list"),
            ([ok] * 31, "at most 30"),
            (["x"], "not an object"),
            ([{**ok, "extra": 1}], "unknown key extra"),
            ([{**ok, "name": "1A"}], "name must"),
            ([{**ok, "name": "A" * 41}], "name must"),
            ([{**ok, "name": "A-B"}], "name must"),
            ([{**ok, "name": "A\n"}], "name must"),
            ([ok, {**ok, "name": "a"}], "declared twice"),
            ([{**ok, "type": "file"}], "type must"),
            ([{**ok, "label": ""}], "label"),
            ([{**ok, "label": "x" * 61}], "label"),
            ([{**ok, "help": "x" * 201}], "help"),
            ([{**ok, "required": "yes"}], "required"),
            ([{**ok, "default": 5}], "default must"),
            ([{**ok, "default": "x" * 1001}], "default must"),
            ([{**ok, "type": "checkbox", "default": "yes"}], "valid checkbox"),
            ([{**ok, "type": "integer", "default": "1.5"}], "valid integer"),
            ([{**ok, "type": "decimal", "default": "1,5"}], "valid decimal"),
            ([{**ok, "type": "select"}], "1-50 options"),
            ([{**ok, "type": "select", "options": [""]}], "1-50 options"),
            ([{**ok, "type": "select", "options": ["x" * 101]}], "1-50 options"),
            ([{**ok, "type": "select", "options": ["a"] * 51}], "1-50 options"),
            (
                [{**ok, "type": "select", "options": ["a"], "default": "b"}],
                "not one of the options",
            ),
            ([{**ok, "options": ["a"]}], "only belong to select"),
            ([{**ok, "options": None}], "options must be a list"),
            ([{**ok, "options": 0}], "options must be a list"),
            ([{**ok, "options": False}], "options must be a list"),
            ([{**ok, "type": "select", "options": "ab"}], "options must be a list"),
            ([{**ok, "default": "a\x00b"}], "NUL"),
            ([{**ok, "label": "a\x00"}], "NUL"),
            ([{**ok, "help": "\x00"}], "NUL"),
            ([{**ok, "type": "select", "options": ["a\x00"]}], "NUL"),
            ([{**ok, "type": "integer", "default": "\u0661\u0662"}], "valid integer"),
            ([{**ok, "type": "decimal", "default": "\u0663.\u0665"}], "valid decimal"),
        ]
        for variables, message in bad:
            with self.subTest(message=message):
                resp = self.client.put(
                    f"/scripts/{script.pk}/", {"variables": variables}, format="json"
                )
                self.assertEqual(resp.status_code, 400)
                self.assertIn(message, str(resp.data["variables"]))

        good = [
            {**ok, "name": "_x9", "type": "integer", "default": "-3"},
            {**ok, "name": "D", "type": "decimal", "default": "2.50"},
            {**ok, "name": "C", "type": "checkbox", "default": "false"},
        ]
        resp = self.client.put(
            f"/scripts/{script.pk}/", {"variables": good}, format="json"
        )
        self.assertEqual(resp.status_code, 200)

    def test_password_variable(self):
        pw = {"name": "ADMIN_PASSWORD", "label": "Password", "type": "password"}
        data = {
            "name": "With password",
            "shell": ScriptShell.SHELL,
            "script_body": "#!/bin/sh\n",
            "variables": [pw],
        }
        resp = self.client.post("/scripts/", data, format="json")
        self.assertEqual(resp.status_code, 200)
        script = Script.objects.get(name="With password")
        resp = self.client.get(f"/scripts/{script.pk}/", format="json")
        self.assertEqual(resp.data["variables"][0]["type"], "password")
        self.assertEqual(resp.data["variables"][0]["default"], "")

        resp = self.client.put(
            f"/scripts/{script.pk}/",
            {"variables": [{**pw, "default": "hunter2"}]},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("cannot have a default", str(resp.data["variables"]))
        script.refresh_from_db()
        self.assertEqual(script.variables[0]["default"], "")

    def test_builtin_variables_read_only(self):
        script = baker.make("scripts.Script", script_type=ScriptType.BUILT_IN)
        resp = self.client.put(
            f"/scripts/{script.pk}/",
            {"variables": [{"name": "A", "label": "A", "type": "string"}]},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        script.refresh_from_db()
        self.assertEqual(script.variables, [])


class TestEnvVarSplit(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.enable_server_scripts = True
        self.coresettings.save()

    def test_value_keeps_equals_signs(self):
        agent = baker.make_recipe("agents.agent", public_ip="12.12.12.12")
        env_vars = [
            "URL=https://example.com/a?b=1&c=2",
            "B64=YWJjZA==",
            "IP={{agent.public_ip}}=x",
            "EMPTY=",
            "NOEQUALS",
            None,
            5,
        ]
        self.assertEqual(
            [
                "URL=https://example.com/a?b=1&c=2",
                "B64=YWJjZA==",
                "IP=12.12.12.12=x",
                "EMPTY=",
            ],
            Script.parse_script_env_vars(
                agent=agent, shell=ScriptShell.SHELL, env_vars=env_vars
            ),
        )

    def test_server_script_env_keeps_equals_signs(self):
        stdout, stderr, _, retcode = run_server_script(
            body='#!/bin/sh\nprintf \'%s|%s\' "$URL" "$B64"\n',
            args=[],
            env_vars=["URL=https://example.com/a?b=1&c=2", "B64=YWJjZA=="],
            shell=ScriptShell.SHELL,
            timeout=30,
        )
        self.assertEqual((retcode, stderr), (0, ""))
        self.assertEqual(stdout, "https://example.com/a?b=1&c=2|YWJjZA==")


class TestLoadCommunityScripts(ULRMMTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "scripts").mkdir()
        settings = override_settings(SCRIPTS_DIR=tmp.name)
        settings.enable()
        self.addCleanup(settings.disable)

    def entry(self, n, **kwargs):
        filename = kwargs.pop("filename", f"linux_test_{n}.sh")
        path = self.root / "scripts" / filename
        if not path.exists():
            path.write_text(f"#!/bin/sh\necho {n}\n")
        return {
            "guid": f"00000000-0000-4000-8000-{n:012d}",
            "filename": filename,
            "name": f"Script {n}",
            "description": f"Description {n}",
            "shell": "shell",
            "category": "Linux / System",
            "supported_platforms": ["linux"],
            "default_timeout": 60,
            **kwargs,
        }

    def load(self, manifest=None):
        if manifest is not None:
            (self.root / "community_scripts.json").write_text(json.dumps(manifest))
        out = io.StringIO()
        with redirect_stdout(out):
            self.result = Script.load_community_scripts()
        return out.getvalue()

    def builtin(self, n):
        return Script.objects.get(guid=f"00000000-0000-4000-8000-{n:012d}")

    def test_new_updated_removed_retired(self):
        variables = [{"name": "WARN_PERCENT", "label": "Warn", "type": "integer"}]
        out = self.load(
            [self.entry(n) for n in range(1, 6)]
            + [self.entry(6, variables=variables, env=["MODE=a=b"])]
        )
        self.assertIn("Adding new community script: Script 6", out)
        self.assertEqual(
            self.result,
            {"added": 6, "updated": 0, "removed": 0, "retired": 0, "skipped": 0},
        )
        self.assertEqual(
            Script.objects.filter(script_type=ScriptType.BUILT_IN).count(), 6
        )
        six = self.builtin(6)
        self.assertEqual(six.env_vars, ["MODE=a=b"])
        self.assertEqual(six.variables[0]["default"], "")
        self.assertEqual(six.script_body, "#!/bin/sh\necho 6\n")

        check = baker.make("checks.Check", script=self.builtin(2))
        baker.make(
            "autotasks.AutomatedTask",
            actions=[{"type": "cmd", "command": "x"}],
        )
        baker.make(
            "autotasks.AutomatedTask",
            actions=[{"type": "script", "script": self.builtin(3).pk}],
        )
        baker.make("alerts.AlertTemplate", action=self.builtin(4))
        baker.make("alerts.AlertTemplate", resolved_action=self.builtin(5))
        one_pk = self.builtin(1).pk

        out = self.load([self.entry(6, name="Renamed"), self.entry(7)])
        self.assertEqual(
            self.result,
            {"added": 1, "updated": 1, "removed": 1, "retired": 4, "skipped": 0},
        )
        self.assertFalse(Script.objects.filter(pk=one_pk).exists())
        for n in (2, 3, 4, 5):
            script = self.builtin(n)
            self.assertEqual(script.script_type, ScriptType.USER_DEFINED)
            self.assertEqual(script.category, "Retired community scripts")
            self.assertEqual(script.name, f"Script {n}")
            self.assertIn(f"as user script: Script {n}", out)
        self.assertIn("Removing 1 community scripts", out)
        check.refresh_from_db()
        self.assertEqual(check.script.name, "Script 2")
        six.refresh_from_db()
        self.assertEqual(six.name, "Renamed")
        self.assertEqual(six.script_type, ScriptType.BUILT_IN)
        self.assertEqual(self.builtin(7).script_type, ScriptType.BUILT_IN)

    def test_missing_or_empty_manifest_changes_nothing(self):
        self.load([self.entry(1)])
        for manifest, message in (
            (None, "No such file"),
            ("[]", "no loadable entries"),
            ("{", "Expecting"),
            ('{"a": 1}', "not a list"),
            ('[{"guid": "x"}]', "no loadable entries"),
        ):
            with self.subTest(message=message):
                path = self.root / "community_scripts.json"
                path.unlink(missing_ok=True)
                if manifest is not None:
                    path.write_text(manifest)
                out = self.load()
                self.assertIn("nothing changed", out)
                self.assertIn(message, out)
                self.assertIn(message, self.result["error"])
                self.assertEqual(self.builtin(1).name, "Script 1")

        with override_settings(SCRIPTS_DIR=str(self.root / "missing")):
            self.assertIn("nothing changed", self.load())
        self.assertTrue(Script.objects.filter(guid=self.builtin(1).guid).exists())

    def test_bad_entry_is_skipped(self):
        self.load([self.entry(1), self.entry(2)])
        missing_key = self.entry(3)
        del missing_key["shell"]
        manifest = [
            self.entry(1),
            self.entry(2, filename="linux_test_2.sh"),
            missing_key,
            self.entry(4, shell="fish"),
            self.entry(5, filename="linux_test_5.sh"),
            self.entry(6, variables=[{"name": "A", "type": "string"}]),
            self.entry(7, filename="../escape.sh"),
            "not an object",
            self.entry(8, default_timeout="soon"),
        ]
        (self.root / "scripts" / "linux_test_2.sh").unlink()
        (self.root / "scripts" / "linux_test_5.sh").write_bytes(b"\xff\xfe")
        out = self.load(manifest)
        self.assertEqual(out.count("Skipping community script"), 8)
        self.assertEqual(self.result["skipped"], 8)
        self.assertIn("Script 3 (linux_test_3.sh): missing shell", out)
        self.assertIn("Script 4 (linux_test_4.sh): shell", out)
        self.assertIn("Script 6 (linux_test_6.sh): variable A: label", out)
        self.assertEqual(
            sorted(
                Script.objects.filter(script_type=ScriptType.BUILT_IN).values_list(
                    "name", flat=True
                )
            ),
            ["Script 1", "Script 2"],
        )

    def test_two_entries_share_one_file(self):
        self.load(
            [
                self.entry(1, filename="linux_test_shared.sh", env=["MODE=a"]),
                self.entry(2, filename="linux_test_shared.sh", env=["MODE=b"]),
            ]
        )
        one, two = self.builtin(1), self.builtin(2)
        self.assertEqual(one.script_body, two.script_body)
        self.assertEqual((one.env_vars, two.env_vars), (["MODE=a"], ["MODE=b"]))

    def test_password_variable(self):
        pw = {"name": "ADMIN_PASSWORD", "label": "Password", "type": "password"}
        out = self.load(
            [
                self.entry(1, variables=[pw]),
                self.entry(2, variables=[{**pw, "default": "x"}]),
            ]
        )
        self.assertEqual(self.builtin(1).variables[0]["type"], "password")
        self.assertIn(
            "Script 2 (linux_test_2.sh): variable ADMIN_PASSWORD: a password "
            "cannot have a default",
            out,
        )
        self.assertEqual(self.result["skipped"], 1)

    def test_bad_types_and_nul_are_skipped(self):
        var = {"name": "A", "label": "A", "type": "string"}
        (self.root / "scripts" / "linux_test_5.sh").write_bytes(b"#!/bin/sh\n\x00\n")
        out = self.load(
            [
                self.entry(1),
                self.entry(2, args="-Force"),
                self.entry(3, env={"A": 1}),
                self.entry(4, supported_platforms=[None]),
                self.entry(5),
                self.entry(6, description="a\x00b"),
                self.entry(7, variables=[{**var, "options": None}]),
                self.entry(8, default_timeout=1e400),
            ]
        )
        self.assertEqual(out.count("Skipping community script"), 7)
        self.assertIn("(linux_test_2.sh): args must be a list of text", out)
        self.assertIn("(linux_test_3.sh): env must be a list of text", out)
        self.assertIn("(linux_test_4.sh): supported_platforms must be a list", out)
        self.assertIn("(linux_test_5.sh): file contains a NUL character", out)
        self.assertIn("(linux_test_6.sh): entry contains a NUL character", out)
        self.assertIn("(linux_test_7.sh): variable A: options must be a list", out)
        self.assertIn("(linux_test_8.sh): ", out)
        self.assertEqual((self.result["added"], self.result["skipped"]), (1, 7))

    @patch.object(Script, "full_clean")
    def test_save_error_skips_only_that_entry(self, _):
        self.load([self.entry(1)])
        out = self.load(
            [self.entry(1, name="One"), self.entry(2, default_timeout=-1)]
            + [self.entry(3)]
        )
        self.assertIn("Skipping community script Script 2 (linux_test_2.sh):", out)
        self.assertEqual(
            self.result,
            {"added": 1, "updated": 1, "removed": 0, "retired": 0, "skipped": 1},
        )
        self.assertEqual(self.builtin(1).name, "One")
        self.assertTrue(Script.objects.filter(name="Script 3").exists())
        self.assertFalse(Script.objects.filter(name="Script 2").exists())

    def test_retired_script_comes_back(self):
        self.load([self.entry(1), self.entry(2)])
        two = self.builtin(2)
        check = baker.make("checks.Check", script=two)
        self.load([self.entry(1)])
        self.assertEqual(self.builtin(2).category, RETIRED_CATEGORY)
        # UI copy has no guid; the loader leaves it alone
        clone = baker.make(
            "scripts.Script",
            name="Script 2",
            category=RETIRED_CATEGORY,
            script_type=ScriptType.USER_DEFINED,
        )
        self.assertIsNone(clone.guid)

        self.load([self.entry(1), self.entry(2, name="Two")])
        self.assertEqual(self.result["added"], 0)
        self.assertEqual(Script.objects.filter(guid=two.guid).count(), 1)
        two.refresh_from_db()
        self.assertEqual(
            (two.script_type, two.category, two.name),
            (ScriptType.BUILT_IN, "Linux / System", "Two"),
        )
        check.refresh_from_db()
        self.assertEqual(check.script_id, two.pk)
        clone.refresh_from_db()
        self.assertEqual(
            (clone.script_type, clone.category, clone.name),
            (ScriptType.USER_DEFINED, RETIRED_CATEGORY, "Script 2"),
        )

        # user moved it out of retired, so the loader does not take it back
        self.load([self.entry(1)])
        Script.objects.filter(pk=two.pk).update(category="Mine")
        self.load([self.entry(1), self.entry(2)])
        self.assertEqual(self.result["added"], 1)
        self.assertEqual(Script.objects.get(pk=two.pk).category, "Mine")

    def test_duplicate_guid(self):
        out = self.load(
            [self.entry(1), {**self.entry(2), "guid": self.entry(1)["guid"]}]
        )
        self.assertIn(
            "Skipping community script Script 2 (linux_test_2.sh): guid "
            "00000000-0000-4000-8000-000000000001 is already used by Script 1 "
            "(linux_test_1.sh)",
            out,
        )
        self.assertEqual((self.result["added"], self.result["skipped"]), (1, 1))
        self.assertEqual(self.builtin(1).name, "Script 1")

    def test_symlinks_are_refused(self):
        (self.root / "secret.py").write_text("SECRET_KEY = 'x'\n")
        (self.root / "scripts" / "linux_test_2.sh").symlink_to(self.root / "secret.py")
        (self.root / "scripts" / "linux_test_3.sh").symlink_to("linux_test_1.sh")
        out = self.load([self.entry(n) for n in (1, 2, 3)])
        for n in (2, 3):
            self.assertIn(
                f"(linux_test_{n}.sh): file is a symlink or outside the scripts", out
            )
        self.assertEqual((self.result["added"], self.result["skipped"]), (1, 2))
        self.assertFalse(Script.objects.filter(script_body__contains="SECRET").exists())

        other = Path(tempfile.mkdtemp(dir=self.root))
        (other / "scripts").symlink_to(self.root / "scripts")
        with override_settings(SCRIPTS_DIR=str(other)):
            (other / "community_scripts.json").write_text(json.dumps([self.entry(1)]))
            out = self.load()
        self.assertIn("file is a symlink or outside the scripts directory", out)
        self.assertIn("no loadable entries", out)


def git(cwd, *args) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
        + ["-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


class TestCommunityLibrarySync(ULRMMTestCase):
    url = "/scripts/community/sync/"

    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.lib = self.tmp / "lib"
        self.lib.mkdir()
        self.upstream = self.tmp / "ulrmm-scripts.git"
        (self.upstream / "scripts").mkdir(parents=True)
        git(self.upstream, "init", "-q", "-b", "main")
        self.first = self.commit({1: "one"})
        settings = override_settings(
            SCRIPTS_DIR=str(self.lib),
            ULRMM_SCRIPTS_GIT_URL=str(self.upstream),
            ULRMM_GIT_URL="",
            ULRMM_GIT_TOKEN="",
        )
        settings.enable()
        self.addCleanup(settings.disable)

    def commit(self, scripts: dict[int, str]) -> str:
        manifest = []
        for n, text in scripts.items():
            filename = f"linux_test_{n}.sh"
            (self.upstream / "scripts" / filename).write_text(
                f"#!/bin/sh\necho {text}\n"
            )
            manifest.append(
                {
                    "guid": f"00000000-0000-4000-8000-{n:012d}",
                    "filename": filename,
                    "name": f"Script {n}",
                    "description": "Test",
                    "shell": "shell",
                    "category": "Linux / System",
                    "supported_platforms": ["linux"],
                }
            )
        (self.upstream / "community_scripts.json").write_text(json.dumps(manifest))
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "-q", "-m", "scripts")
        return git(self.upstream, "rev-parse", "HEAD")

    def body(self, n: int) -> str:
        return Script.objects.get(name=f"Script {n}").script_body

    def test_sync_and_resync(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(
            r.data,
            {
                "commit": self.first,
                "added": 1,
                "updated": 0,
                "removed": 0,
                "retired": 0,
                "skipped": 0,
                "message": f"Library at {self.first[:7]}: 1 added, 0 updated, "
                "0 removed, 0 retired, 0 skipped",
            },
        )
        self.assertEqual(self.body(1), "#!/bin/sh\necho one\n")

        second = self.commit({1: "uno", 2: "two"})
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["commit"], second)
        self.assertEqual((r.data["added"], r.data["updated"]), (1, 1))
        self.assertEqual(self.body(1), "#!/bin/sh\necho uno\n")
        self.assertEqual(self.body(2), "#!/bin/sh\necho two\n")
        self.assertEqual(git(self.lib, "rev-parse", "HEAD"), second)

        audit = AuditLog.objects.filter(object_type=AuditObjType.SCRIPT).latest("id")
        self.assertEqual(audit.username, "john")
        self.assertEqual(audit.before_value, {"commit": self.first})
        self.assertEqual(audit.after_value["commit"], second)
        self.assertEqual(audit.after_value["added"], 1)

    def test_clone_of_an_unrelated_repository(self):
        other = self.tmp / "other"
        other.mkdir()
        git(other, "init", "-q", "-b", "main")
        (other / "stale.sh").write_text("old")
        git(other, "add", "-A")
        git(other, "commit", "-q", "-m", "old")
        self.lib.rmdir()
        git(self.tmp, "clone", "-q", str(other), str(self.lib))
        (self.lib / "untracked.txt").write_text("x")

        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(r.data["commit"], self.first)
        self.assertFalse((self.lib / "stale.sh").exists())
        self.assertFalse((self.lib / "untracked.txt").exists())
        self.assertEqual(
            git(self.lib, "remote", "get-url", "origin"), str(self.upstream)
        )
        self.assertEqual(self.body(1), "#!/bin/sh\necho one\n")

    def test_fetch_failure_changes_nothing(self):
        self.client.post(self.url)
        self.commit({1: "uno"})
        before = list(Script.objects.values_list("pk", "name", "script_body"))
        audits = AuditLog.objects.count()
        missing = self.tmp / "tok123" / "ulrmm.git"
        with override_settings(
            ULRMM_SCRIPTS_GIT_URL="",
            ULRMM_GIT_URL=str(missing),
            ULRMM_GIT_TOKEN="tok123",
        ):
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("Script library not synced, fetch failed:", r.data)
        self.assertIn("/***/ulrmm-scripts.git", r.data)
        self.assertNotIn("tok123", r.data)
        self.assertEqual(
            list(Script.objects.values_list("pk", "name", "script_body")), before
        )
        self.assertEqual(AuditLog.objects.count(), audits)
        self.assertEqual(git(self.lib, "rev-parse", "HEAD"), self.first)

    def test_url_from_settings(self):
        with override_settings(
            ULRMM_SCRIPTS_GIT_URL="", ULRMM_GIT_URL=str(self.tmp / "ulrmm.git")
        ):
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(
            git(self.lib, "remote", "get-url", "origin"), str(self.upstream)
        )

        with override_settings(ULRMM_SCRIPTS_GIT_URL="", ULRMM_GIT_URL=""):
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("no library configured", r.data)

        with override_settings(
            ULRMM_SCRIPTS_GIT_URL="https://u:secret@git.example.com/o/s.git"
        ):
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("must not carry credentials", r.data)
        self.assertNotIn("secret", r.data)

    def test_empty_library_is_not_loaded(self):
        self.client.post(self.url)
        (self.upstream / "community_scripts.json").write_text("[]")
        git(self.upstream, "commit", "-q", "-am", "empty")
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not loaded, nothing changed: no loadable entries", r.data)
        self.assertTrue(Script.objects.filter(name="Script 1").exists())

    def test_needs_manage_scripts(self):
        self.client.force_authenticate(
            user=self.create_user_with_roles(["can_list_scripts"])
        )
        self.check_not_authorized("post", self.url)
        self.assertFalse(Script.objects.exists())

        self.client.force_authenticate(
            user=self.create_user_with_roles(["can_manage_scripts"])
        )
        self.assertEqual(self.client.post(self.url).status_code, 200)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_one_sync_at_a_time(self):
        cache.delete(LIBRARY_SYNC_LOCK)
        cache.add(LIBRARY_SYNC_LOCK, 1, 60)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("being synced already", r.data)
        self.assertFalse(Script.objects.exists())

        cache.delete(LIBRARY_SYNC_LOCK)
        self.assertEqual(self.client.post(self.url).status_code, 200)
        self.assertIsNone(cache.get(LIBRARY_SYNC_LOCK))
        with override_settings(ULRMM_SCRIPTS_GIT_URL=str(self.tmp / "missing")):
            self.assertEqual(self.client.post(self.url).status_code, 400)
        self.assertIsNone(cache.get(LIBRARY_SYNC_LOCK))

    @override_settings(
        ULRMM_GIT_URL="https://Git.Example.com/o/ulrmm.git",
        ULRMM_GIT_TOKEN="tok123",
        ULRMM_GIT_USER="",
    )
    def test_token_only_for_the_server_host(self):
        with git_auth_env("https://git.example.com/o/ulrmm-scripts.git") as env:
            askpass = env["GIT_ASKPASS"]
            for prompt, answer in (("Username for x", "git"), ("Password", "tok123")):
                out = subprocess.run(
                    [askpass, prompt], env=env, capture_output=True, text=True
                )
                self.assertEqual(out.stdout, f"{answer}\n")
        self.assertFalse(Path(askpass).exists())

        for url in ("https://other.example.com/o/s.git", str(self.upstream)):
            with git_auth_env(url) as env:
                self.assertNotIn("ULRMM_GIT_TOKEN", env)

        with self.assertRaises(RuntimeError):
            with git_auth_env("https://git.example.com/o/s.git") as env:
                askpass = env["GIT_ASKPASS"]
                raise RuntimeError
        self.assertFalse(Path(askpass).exists())

    def test_set_url_error_is_reported(self):
        self.assertEqual(self.client.post(self.url).status_code, 200)
        (self.lib / ".git" / "config.lock").write_text("")
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 400)
        self.assertIn("set remote failed", r.data)
        self.assertIn("could not lock config file", r.data)
        self.assertNotIn("already exists", r.data)

    def test_token_reaches_an_http_remote(self):
        token = "tok-" + os.urandom(8).hex()
        server = ThreadingHTTPServer(("127.0.0.1", 0), GitHttpHandler)
        server.root = str(self.tmp)
        server.auth = "Basic " + base64.b64encode(f"git:{token}".encode()).decode()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"

        argv = []
        real_run = subprocess.run

        def run(cmd, *args, **kwargs):
            argv.append(cmd)
            return real_run(cmd, *args, **kwargs)

        for sent, status in ((token, 200), ("wrong", 400), (token, 200)):
            with self.subTest(sent=sent), override_settings(
                ULRMM_SCRIPTS_GIT_URL="",
                ULRMM_GIT_URL=f"{base}/ulrmm.git",
                ULRMM_GIT_TOKEN=sent,
                ULRMM_GIT_USER="",
            ), patch("scripts.views.subprocess.run", side_effect=run):
                r = self.client.post(self.url)
            self.assertEqual(r.status_code, status, r.data)
            self.assertNotIn(token, json.dumps(r.data))
            if status == 400:
                self.assertIn("fetch failed", r.data)
        self.assertEqual(r.data["commit"], self.first)
        self.assertEqual(self.body(1), "#!/bin/sh\necho one\n")
        self.assertTrue(any("fetch" in cmd for cmd in argv))
        self.assertNotIn(token, json.dumps(argv))
        config = (self.lib / ".git" / "config").read_text()
        self.assertIn(f"{base}/ulrmm-scripts.git", config)
        self.assertNotIn(token, config)


class GitHttpHandler(BaseHTTPRequestHandler):
    """git smart http with basic auth, through git-http-backend"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != self.server.auth:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="git"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path, _, query = self.path.partition("?")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        env = {
            "PATH": os.environ["PATH"],
            "GIT_PROJECT_ROOT": self.server.root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
            "GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
            "REMOTE_USER": "git",
        }
        out = subprocess.run(
            ["git", "http-backend"], input=body, env=env, capture_output=True
        ).stdout
        head, _, rest = out.partition(b"\r\n\r\n")
        headers = [line.partition(":")[::2] for line in head.decode().split("\r\n")]
        status = next((v for k, v in headers if k.lower() == "status"), "200")
        self.send_response(int(status.split()[0]))
        for k, v in headers:
            if k and k.lower() != "status":
                self.send_header(k, v.strip())
        self.send_header("Content-Length", str(len(rest)))
        self.end_headers()
        self.wfile.write(rest)

    do_POST = do_GET


class TestTestScriptAudit(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def assert_masked(self, value):
        self.assertNotIn("hunter2", json.dumps(value))

    def assert_hashed(self, entries, names):
        self.assertEqual(len(entries), len(names))
        for entry, name in zip(entries, names):
            self.assertRegex(entry, rf"^{name}=hmac:[0-9a-f]{{16}}$")

    def test_mask_env_vars(self):
        masked = mask_env_vars(
            ["PASSWORD=hunter2", "URL=https://x/?a=b", "hunter2", None, "OLD=hunter2"]
        )
        self.assert_hashed(masked[:2], ["PASSWORD", "URL"])
        self.assertEqual(masked[2:4], ["***", "***"])
        # same value, same hash, so a changed value shows in the diff
        self.assertEqual(masked[0].split("=")[1], masked[4].split("=")[1])
        self.assertNotEqual(masked[0].split("=")[1], masked[1].split("=")[1])
        self.assert_masked(masked)
        for value, masked in (([], []), (None, None), ("PW=hunter2", "***")):
            self.assertEqual(mask_env_vars(value), masked)

    # step-up covered by core.tests.TestServerScriptStepUp
    @patch("core.views.stepup_denied", return_value=None)
    @patch("agents.models.Agent.nats_cmd", return_value="ok")
    def test_test_script_views(self, *_):
        self.coresettings.enable_server_scripts = True
        self.coresettings.save()
        agent = baker.make_recipe("agents.agent")
        data = {
            "code": "#!/bin/sh\necho ok\n",
            "timeout": 30,
            "args": [],
            "shell": ScriptShell.SHELL,
            "run_as_user": False,
            "env_vars": ["PASSWORD=hunter2", "URL=https://x/?a=b"],
        }
        for url in (f"/scripts/{agent.agent_id}/test/", "/core/serverscript/test/"):
            with self.subTest(url=url):
                r = self.client.post(url, data, format="json")
                self.assertEqual(r.status_code, 200)
                entry = AuditLog.objects.latest("pk")
                self.assertEqual(entry.action, AuditActionType.EXEC_SCRIPT)
                self.assert_hashed(entry.before_value["env_vars"], ["PASSWORD", "URL"])
                self.assert_masked(entry.before_value)

    def test_bulk_action(self):
        data = {"target": "all", "mode": "script", "env_vars": ["PW=hunter2"]}
        data["script"] = baker.make("scripts.Script").pk
        AuditLog.audit_bulk_action("jane", "script", data, [], 0)
        entry = AuditLog.objects.latest("pk")
        self.assert_hashed(entry.after_value["env_vars"], ["PW"])
        self.assertEqual(data["env_vars"], ["PW=hunter2"])

    def test_audit_serializers(self):
        env = ["PW=hunter2"]
        check = baker.make("checks.Check", env_vars=env)
        task = baker.make(
            "autotasks.AutomatedTask",
            actions=[
                {"type": "script", "script": 1, "env_vars": env},
                {"type": "cmd", "command": "whoami"},
            ],
        )
        template = baker.make(
            "alerts.AlertTemplate",
            action_env_vars=env,
            resolved_action_env_vars=env,
        )
        for value in (
            Check.serialize(check),
            AutomatedTask.serialize(task),
            AlertTemplate.serialize(template),
        ):
            self.assert_masked(value)
        self.assert_hashed(Check.serialize(check)["env_vars"], ["PW"])
        self.assert_hashed(
            AutomatedTask.serialize(task)["actions"][0]["env_vars"], ["PW"]
        )
        self.assert_hashed(
            AlertTemplate.serialize(template)["resolved_action_env_vars"], ["PW"]
        )
        # the row still has the value the run uses
        check.refresh_from_db()
        self.assertEqual(check.env_vars, env)


LIBRARY_VARIABLES = [{"name": "LICENSE", "label": "License", "type": "string"}]


class TestScriptEnvVarsAndTestPerms(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.agent = baker.make_recipe("agents.online_agent")
        self.data = {
            "code": "#!/bin/sh\necho ok\n",
            "timeout": 30,
            "args": [],
            "shell": ScriptShell.SHELL,
            "run_as_user": False,
            "env_vars": ["GOOD=1"],
        }
        self.library = baker.make(
            "scripts.Script",
            name="AV install",
            script_type=ScriptType.BUILT_IN,
            env_vars=["PRODUCT=eset"],
            variables=LIBRARY_VARIABLES,
        )

    def test_check_env_vars(self):
        denied = (
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "Path",
            "PSModulePath",
            "PS4",
            "BASH_ENV",
            "ENV",
            "node_options",
            "PYTHONPATH",
            "DENO_PERMISSIONS",
            "ComSpec",
            "COR_PROFILER_PATH",
            "cor_enable_profiling",
            "CORECLR_PROFILER_PATH",
            "COMPlus_ETWEnabled",
            "DOTNET_STARTUP_HOOKS",
            "windir",
            "ProgramFiles",
            "ProgramData",
            "SystemDrive",
            "IFS",
            "TMPDIR",
            "1A",
            "A-B",
            "A B",
            "A" * 65,
            "",
        )
        for name in denied:
            with self.subTest(name=name), self.assertRaises(BadRequest):
                check_env_vars(["GOOD=1", f"{name}=x"])
        with self.assertRaises(BadRequest):
            check_env_vars([None])
        check_env_vars(None)
        check_env_vars(["GOOD=1", "_x=", "PATHNAME=1", "HOMEDIR=2", "A" * 64 + "=x"])

    def test_library_script_takes_its_own_names(self):
        check_env_vars(["PRODUCT=x", "license=y"], self.library)
        with self.assertRaises(BadRequest):
            check_env_vars(["OTHER=1"], self.library)
        # user script accepts OTHER. a library script with no variables rejects it
        check_env_vars(["OTHER=1"], baker.make("scripts.Script"))
        no_vars = baker.make("scripts.Script", script_type=ScriptType.BUILT_IN)
        with self.assertRaises(BadRequest):
            check_env_vars(["OTHER=1"], no_vars)
        check_env_vars([], no_vars)

    def test_parse_never_forwards_denied_names(self):
        env = ["LD_PRELOAD=/tmp/x.so", "GOOD=1", "Path=C:\\x", "BAD-NAME=1"]
        self.assertEqual(
            Script.parse_script_env_vars(self.agent, ScriptShell.SHELL, env),
            ["GOOD=1"],
        )

    @patch("agents.models.Agent.nats_cmd", return_value="ok")
    def test_test_script_needs_manage_scripts_or_send_cmd(self, nats_cmd):
        url = f"/scripts/{self.agent.agent_id}/test/"
        other = baker.make("clients.Client")
        cases = (
            (["can_run_scripts"], 403),
            (["can_manage_scripts", "can_send_cmd"], 403),
            (["can_run_scripts", "can_manage_scripts"], 200),
            (["can_run_scripts", "can_send_cmd"], 200),
        )
        for flags, status in cases:
            with self.subTest(flags=flags):
                self.client.force_authenticate(user=self.create_user_with_roles(flags))
                r = self.client.post(url, self.data, format="json")
                self.assertEqual(r.status_code, status)
        # script flags still go through the client check
        user = self.create_user_with_roles(["can_run_scripts", "can_manage_scripts"])
        user.role.can_view_clients.set([other])
        self.client.force_authenticate(user=user)
        self.assertEqual(
            self.client.post(url, self.data, format="json").status_code, 403
        )
        self.assertEqual(nats_cmd.call_count, 2)

    @patch("agents.models.Agent.nats_cmd", return_value="ok")
    def test_test_script_rejects_denied_names(self, nats_cmd):
        url = f"/scripts/{self.agent.agent_id}/test/"
        data = {**self.data, "env_vars": ["GOOD=1", "LD_PRELOAD=/tmp/x.so"]}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("LD_PRELOAD", str(r.data))
        nats_cmd.assert_not_called()
        self.assertFalse(AuditLog.objects.filter(agent_id=self.agent.agent_id).exists())

    def test_saved_env_vars_are_checked(self):
        count = Script.objects.count()
        data = {
            "name": "x",
            "shell": ScriptShell.SHELL,
            "script_body": "#!/bin/sh\n",
            "env_vars": ["BASH_ENV=/tmp/x"],
        }
        self.assertEqual(
            self.client.post("/scripts/", data, format="json").status_code, 400
        )
        self.assertEqual(Script.objects.count(), count)

        from alerts.serializers import AlertTemplateSerializer
        from autotasks.serializers import TaskSerializer
        from checks.serializers import CheckSerializer

        check = baker.make_recipe("checks.script_check", script=self.library)
        task = baker.make("autotasks.AutomatedTask", agent=self.agent)
        template = baker.make("alerts.AlertTemplate", action=self.library)
        action = {"type": "script", "script": self.library.pk, "script_args": []}
        action["timeout"] = 30
        for serializer, good, bad in (
            (CheckSerializer, {"env_vars": ["LICENSE=1"]}, {"env_vars": ["OTHER=1"]}),
            (
                TaskSerializer,
                {"actions": [{**action, "env_vars": ["PRODUCT=1"]}]},
                {"actions": [{**action, "env_vars": ["NODE_OPTIONS=x"]}]},
            ),
            (
                AlertTemplateSerializer,
                {"action_env_vars": ["LICENSE=1"]},
                {"action_env_vars": ["OTHER=1"]},
            ),
        ):
            instance = {
                CheckSerializer: check,
                TaskSerializer: task,
                AlertTemplateSerializer: template,
            }[serializer]
            with self.subTest(serializer=serializer.__name__):
                s = serializer(instance=instance, data=good, partial=True)
                self.assertTrue(s.is_valid(), s.errors)
                s = serializer(instance=instance, data=bad, partial=True)
                self.assertFalse(s.is_valid())

    @patch("agents.views.bulk_script_task.delay")
    @patch("agents.models.Agent.run_script", return_value="ok")
    def test_run_and_bulk_check_names(self, run_script, bulk):
        url = f"/agents/{self.agent.agent_id}/runscript/"
        data = {
            "script": self.library.pk,
            "output": "wait",
            "args": [],
            "timeout": 30,
            "run_as_user": False,
            "env_vars": ["PRODUCT=x", "LICENSE=y"],
        }
        self.assertEqual(self.client.post(url, data, format="json").status_code, 200)
        for env in (["OTHER=1"], ["LD_PRELOAD=/tmp/x.so"]):
            data["env_vars"] = env
            self.assertEqual(
                self.client.post(url, data, format="json").status_code, 400
            )
        self.assertEqual(run_script.call_count, 1)

        data = {
            "mode": "script",
            "target": "agents",
            "agents": [self.agent.agent_id],
            "monType": "all",
            "osType": "all",
            "script": self.library.pk,
            "args": [],
            "timeout": 30,
            "run_as_user": False,
            "env_vars": ["OTHER=1"],
        }
        r = self.client.post("/agents/actions/bulk/", data, format="json")
        self.assertEqual(r.status_code, 400)
        bulk.assert_not_called()

    def test_server_script_never_gets_denied_names(self):
        self.coresettings.enable_server_scripts = True
        self.coresettings.save()
        stdout, *_ = run_server_script(
            body='#!/bin/sh\necho "[$BASH_ENV][$GOOD]"\n',
            args=[],
            env_vars=["BASH_ENV=/tmp/x", "GOOD=1"],
            shell=ScriptShell.SHELL,
            timeout=10,
        )
        self.assertEqual(stdout.strip(), "[][1]")

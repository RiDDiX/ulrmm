# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import re
from collections import defaultdict
from pathlib import Path

from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import DatabaseError, models, transaction
from django.db.models.fields import CharField, TextField
from rest_framework.exceptions import ValidationError as BadRequest

from logs.models import BaseAuditModel, mask_env_vars
from ulrmm.constants import ScriptShell, ScriptType
from ulrmm.utils import replace_arg_db_values

# one placeholder per argument; the greedy group spans the first {{ to the last }}
ARG_PLACEHOLDER = re.compile(r"\{\{(.*)\}\}")
SNIPPET_PLACEHOLDER = re.compile(r"\{\{\s*(.+?)\s*\}\}")


def _substitute(text: str, agent, shell, quotes: bool):
    """text with its placeholder resolved, None when it has none, "" when the
    lookup came back empty."""
    found = ARG_PLACEHOLDER.search(text)
    if not found:
        return None
    value = replace_arg_db_values(
        string=found.group(1), instance=agent, shell=shell, quotes=quotes
    )
    if not value:
        return ""
    # spliced in as text: backslashes in a value are not regex escapes
    return text[: found.start()] + value + text[found.end() :]


class Script(BaseAuditModel):
    guid = models.CharField(max_length=64, null=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True, default="")
    filename = models.CharField(max_length=255, null=True, blank=True)
    shell = models.CharField(
        max_length=100, choices=ScriptShell.choices, default=ScriptShell.POWERSHELL
    )
    script_type = models.CharField(
        max_length=100, choices=ScriptType.choices, default=ScriptType.USER_DEFINED
    )
    args = ArrayField(
        TextField(null=True, blank=True), null=True, blank=True, default=list
    )
    env_vars = ArrayField(
        TextField(null=True, blank=True), null=True, blank=True, default=list
    )
    syntax = TextField(null=True, blank=True)
    favorite = models.BooleanField(default=False)
    category = models.CharField(max_length=100, null=True, blank=True)
    script_body = models.TextField(blank=True, default="")
    # kept for the API shape, never written
    script_hash = models.CharField(max_length=100, null=True, blank=True)
    # legacy rows only, post_update_tasks moves them to script_body
    code_base64 = models.TextField(blank=True, default="")
    default_timeout = models.PositiveIntegerField(default=90)
    hidden = models.BooleanField(default=False)
    supported_platforms = ArrayField(
        CharField(max_length=20), null=True, blank=True, default=list
    )
    run_as_user = models.BooleanField(default=False)
    variables = models.JSONField(default=list, blank=True)

    def __str__(self):
        return self.name

    @property
    def code_no_snippets(self) -> str:
        return self.script_body or ""

    @property
    def code(self) -> str:
        return self.replace_with_snippets(self.code_no_snippets)

    @classmethod
    def replace_with_snippets(cls, code: str) -> str:
        names = {m.group(1) for m in SNIPPET_PLACEHOLDER.finditer(code)}
        if not names:
            return code
        snippets = dict(
            ScriptSnippet.objects.filter(name__in=names).values_list("name", "code")
        )
        if not snippets:
            return code
        return SNIPPET_PLACEHOLDER.sub(
            lambda m: snippets.get(m.group(1), m.group(0)), code
        )

    @staticmethod
    def serialize(script):
        from .serializers import ScriptSerializer

        data = dict(ScriptSerializer(script).data)
        # default values of env vars are often license keys
        data["env_vars"] = mask_env_vars(data.get("env_vars"))
        return data

    @classmethod
    def parse_script_args(cls, agent, shell: str, args: list[str] = []) -> list[str]:
        if not args:
            return []
        parsed = []
        for arg in args:
            replaced = _substitute(arg, agent, shell, quotes=shell != ScriptShell.CMD)
            # an empty lookup leaves the placeholder text for the script to see
            parsed.append(replaced or arg)
        return parsed

    @classmethod
    def parse_script_env_vars(
        cls, agent, shell: str, env_vars: list[str] = []
    ) -> list[str]:
        if not env_vars:
            return []
        parsed = []
        for env_var in env_vars:
            if not isinstance(env_var, str):
                continue
            env_key, sep, env_val = env_var.partition("=")
            # saved before env names were checked; dropped here
            if (
                not sep
                or not ENV_NAME.fullmatch(env_key)
                or ENV_DENIED.fullmatch(env_key)
            ):
                continue

            replaced = _substitute(env_val, agent, shell, quotes=False)
            if replaced is None:
                parsed.append(env_var)
            elif replaced:
                parsed.append(f"{env_key}={replaced}")
            # an empty lookup drops the whole variable
        return parsed

    @classmethod
    def load_community_scripts(cls) -> dict:
        """Load the library in SCRIPTS_DIR. Counts added, updated, removed,
        retired and skipped, or {"error": reason} when nothing changed."""
        from django.conf import settings

        root = Path(settings.SCRIPTS_DIR)
        try:
            manifest = json.loads((root / "community_scripts.json").read_text("utf-8"))
        except (OSError, ValueError) as e:
            return _not_loaded(e)
        if not isinstance(manifest, list):
            return _not_loaded("manifest is not a list")

        loaded, skipped, seen, bad = [], set(), {}, 0
        for entry in manifest:
            guid = entry.get("guid") if isinstance(entry, dict) else None
            guid = guid if isinstance(guid, str) else None
            if guid in seen:
                obj, error = None, f"guid {guid} is already used by {seen[guid]}"
            else:
                obj, error = _community_entry(entry, root / "scripts")
            if guid is not None:
                seen.setdefault(guid, _entry_label(entry))
            if error:
                bad += 1
                if guid is not None:
                    skipped.add(guid)
                print(f"Skipping community script {_entry_label(entry)}: {error}")
            else:
                loaded.append(obj)
        if not loaded:
            return _not_loaded("no loadable entries")

        added = updated = 0
        with transaction.atomic():
            # checked above; one savepoint per row so a bad save does not
            # roll the others back
            for obj in loaded:
                new = obj.pk is None
                try:
                    with transaction.atomic():
                        obj.save()
                except (DatabaseError, TypeError, ValueError) as e:
                    bad += 1
                    skipped.add(obj.guid)
                    print(f"Skipping community script {obj.name} ({obj.filename}): {e}")
                    continue
                if new:
                    print(f"Adding new community script: {obj.name}")
                added += new
                updated += not new

            keep = {obj.guid for obj in loaded} | skipped
            removed = cls.objects.filter(script_type=ScriptType.BUILT_IN).exclude(
                guid__in=keep
            )
            referenced = _referenced_script_pks()
            retired = 0
            for script in removed.filter(pk__in=referenced):
                print(f"Keeping removed community script as user script: {script.name}")
                script.script_type = ScriptType.USER_DEFINED
                script.category = RETIRED_CATEGORY
                script.save(update_fields=["script_type", "category"])
                retired += 1
            _, deleted = removed.exclude(pk__in=referenced).delete()
        count = deleted.get(cls._meta.label, 0)
        if count:
            print(
                f"Removing {count} community scripts that were removed from the library"
            )
        return {
            "added": added,
            "updated": updated,
            "removed": count,
            "retired": retired,
            "skipped": bad,
        }


class ScriptSnippet(BaseAuditModel):
    name = models.CharField(max_length=40, unique=True)
    desc = models.CharField(max_length=50, blank=True, default="")
    code = models.TextField(default="")
    shell = models.CharField(
        max_length=15, choices=ScriptShell.choices, default=ScriptShell.POWERSHELL
    )

    def __str__(self):
        return self.name

    @staticmethod
    def serialize(snippet):
        from . import serializers

        return serializers.ScriptSnippetSerializer(snippet).data


ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# hooks that run code or swap a binary before the script starts
# (COR_PROFILER_PATH loads a dll into powershell, PERL5OPT/RUBYOPT/
# JAVA_TOOL_OPTIONS load code into those interpreters, OPENSSL_CONF loads
# engines), and the windows dirs library scripts build paths from.
# case-insensitive, same as windows. The agent keeps the same list.
ENV_DENIED = re.compile(
    r"(LD_|DYLD_|PYTHON|DENO_|PS|COR_|CORECLR_|COMPLUS_|DOTNET_).*"
    r"|PATH|BASH_ENV|ENV|SHELL|HOME|NODE_OPTIONS"
    r"|PERL5OPT|PERL5LIB|PERLLIB|RUBYOPT|RUBYLIB"
    r"|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS"
    r"|OPENSSL_CONF|OPENSSL_MODULES|GCONV_PATH|XDG_CONFIG_HOME|XDG_DATA_HOME"
    r"|GIT_SSH_COMMAND|SSLKEYLOGFILE"
    r"|PROMPT_COMMAND|IFS|TMP|TEMP|TMPDIR|SYSTEMROOT|COMSPEC|PATHEXT|HOSTNAME"
    r"|USERNAME|USER|LOGNAME"
    r"|WINDIR|SYSTEMDRIVE|PROGRAMFILES|PROGRAMW6432|COMMONPROGRAMFILES"
    r"|COMMONPROGRAMW6432|PROGRAMDATA|ALLUSERSPROFILE|USERPROFILE|APPDATA"
    r"|LOCALAPPDATA",
    re.IGNORECASE,
)


def check_env_vars(env_vars, script=None) -> None:
    """400 if the name is denied or not a plain identifier. Library scripts
    only take their variables and their own env names. With none declared,
    nothing else is accepted. User scripts take any allowed name."""
    declared = None
    if script and script.script_type == ScriptType.BUILT_IN:
        declared = {v["name"].upper() for v in script.variables} | {
            e.partition("=")[0].upper() for e in script.env_vars or [] if e
        }
    for env_var in env_vars or []:
        name = env_var.partition("=")[0] if isinstance(env_var, str) else ""
        if not ENV_NAME.fullmatch(name) or ENV_DENIED.fullmatch(name):
            raise BadRequest(f"{name[:64]!r} cannot be set as an environment variable.")
        if declared is not None and name.upper() not in declared:
            raise BadRequest(f"{name} is not a variable of {script.name}.")


VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,39}")
VAR_TYPES = {
    "string",
    "text",
    "integer",
    "decimal",
    "checkbox",
    "select",
    "ip",
    "date",
    "datetime",
    "password",
}
VAR_DEFAULTS = {"required": False, "default": "", "options": [], "help": ""}
DEFAULT_RE = {
    "checkbox": re.compile(r"true|false"),
    "integer": re.compile(r"-?[0-9]+"),
    "decimal": re.compile(r"-?[0-9]+(\.[0-9]+)?"),
}
RETIRED_CATEGORY = "Retired community scripts"


def clean_variables(variables) -> list[dict]:
    """Check the variable list and fill name, label, type, required, default,
    options, help. ValueError names the variable."""
    if not isinstance(variables, list) or len(variables) > 30:
        raise ValueError("variables must be a list of at most 30")
    out, seen = [], set()
    for i, var in enumerate(variables, 1):
        if not isinstance(var, dict):
            raise ValueError(f"variable {i} is not an object")
        var = {**VAR_DEFAULTS, **var}
        name = var.get("name")
        where = f"variable {name if isinstance(name, str) and name else i}"
        if unknown := var.keys() - VAR_DEFAULTS.keys() - {"name", "label", "type"}:
            raise ValueError(f"{where}: unknown key {sorted(unknown)[0]}")
        if not isinstance(name, str) or not VAR_NAME.fullmatch(name):
            raise ValueError(
                f"{where}: name must start with a letter or _ and use only "
                "letters, digits and _ (at most 40)"
            )
        if name.upper() in seen:
            raise ValueError(f"{where} is declared twice")
        seen.add(name.upper())
        label, vtype, default = var.get("label"), var.get("type"), var["default"]
        if not isinstance(label, str) or not 1 <= len(label) <= 60:
            raise ValueError(f"{where}: label is required, at most 60 characters")
        if vtype not in VAR_TYPES:
            raise ValueError(f"{where}: type must be one of {sorted(VAR_TYPES)}")
        if not isinstance(var["required"], bool):
            raise ValueError(f"{where}: required must be true or false")
        if not isinstance(var["help"], str) or len(var["help"]) > 200:
            raise ValueError(f"{where}: help must be text of at most 200 characters")
        if not isinstance(default, str) or len(default) > 1000:
            raise ValueError(
                f"{where}: default must be text of at most 1000 characters"
            )
        if default and vtype == "password":
            raise ValueError(
                f"{where}: a password cannot have a default, it is entered at run time"
            )
        if default and vtype in DEFAULT_RE and not DEFAULT_RE[vtype].fullmatch(default):
            raise ValueError(f"{where}: default is not a valid {vtype}")
        options = var["options"]
        if not isinstance(options, list):
            raise ValueError(f"{where}: options must be a list")
        if vtype == "select":
            if not 1 <= len(options) <= 50 or not all(
                isinstance(o, str) and 0 < len(o) <= 100 for o in options
            ):
                raise ValueError(
                    f"{where}: select needs 1-50 options of 1-100 characters"
                )
            if default and default not in options:
                raise ValueError(f"{where}: default is not one of the options")
        elif options:
            raise ValueError(f"{where}: options only belong to select")
        if any("\x00" in s for s in (label, var["help"], default, *options)):
            raise ValueError(f"{where}: text must not contain NUL characters")
        out.append({k: var[k] for k in ("name", "label", "type", *VAR_DEFAULTS)})
        out[-1]["options"] = list(options)
    return out


def _not_loaded(reason) -> dict:
    print(f"Community scripts not loaded, nothing changed: {reason}")
    return {"error": str(reason)}


def _entry_label(entry) -> str:
    if not isinstance(entry, dict):
        return repr(entry)[:80]
    return f"{entry.get('name', '?')} ({entry.get('filename', '?')})"


def _community_entry(entry, scripts_dir: Path):
    """One manifest entry: (unsaved Script, None) or (None, reason)."""
    if not isinstance(entry, dict):
        return None, "entry is not an object"
    if missing := {"guid", "filename", "name", "description", "shell"} - entry.keys():
        return None, f"missing {', '.join(sorted(missing))}"
    for key in ("args", "env", "supported_platforms"):
        value = entry.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return None, f"{key} must be a list of text"
    if _has_nul(entry):
        return None, "entry contains a NUL character"
    path = scripts_dir / str(entry["filename"])
    if path.parent != scripts_dir:
        return None, "filename must not contain a path"
    if path.resolve() != scripts_dir.parent.resolve() / scripts_dir.name / path.name:
        return None, "file is a symlink or outside the scripts directory"
    try:
        body = path.read_bytes().decode("utf-8")
        variables = clean_variables(entry.get("variables", []))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return None, str(e)
    if "\x00" in body:
        return None, "file contains a NUL character"
    scripts = Script.objects.filter(guid=entry["guid"])
    obj = (
        scripts.filter(script_type=ScriptType.BUILT_IN).first()
        # guid is set only by the loader, so this row was retired by it
        or scripts.filter(
            script_type=ScriptType.USER_DEFINED, category=RETIRED_CATEGORY
        ).first()
        or Script()
    )
    fields = {
        "script_type": ScriptType.BUILT_IN,
        "guid": entry["guid"],
        "name": entry["name"],
        "description": entry["description"],
        "shell": entry["shell"],
        "filename": entry["filename"],
        "script_body": body,
        "category": entry.get("category", "Community"),
        "default_timeout": entry.get("default_timeout", 90),
        "args": entry.get("args", []),
        "env_vars": entry.get("env", []),
        "syntax": entry.get("syntax", ""),
        "run_as_user": entry.get("run_as_user", False),
        "supported_platforms": entry.get("supported_platforms", []),
        "variables": variables,
    }
    for k, v in fields.items():
        setattr(obj, k, v)
    try:
        obj.full_clean()
    except ValidationError as e:
        return None, "; ".join(f"{k}: {' '.join(v)}" for k, v in e.message_dict.items())
    except (TypeError, ValueError, OverflowError) as e:
        return None, str(e) or type(e).__name__
    return obj, None


def _has_nul(value) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_nul(v) for v in value)
    return False


def script_uses() -> dict[int, list[int]]:
    """pk -> [checks, tasks, alert templates] that still run the script. One
    scan for the loader and the delete guard, so both agree."""
    from alerts.models import AlertTemplate
    from autotasks.models import AutomatedTask
    from checks.models import Check

    uses: dict[int, list[int]] = defaultdict(lambda: [0, 0, 0])
    for pk in Check.objects.filter(script__isnull=False).values_list(
        "script", flat=True
    ):
        uses[pk][0] += 1
    for actions in AutomatedTask.objects.exclude(actions=[]).values_list(
        "actions", flat=True
    ):
        if not isinstance(actions, list):
            continue
        for pk in {
            int(a["script"])
            for a in actions
            if isinstance(a, dict)
            and a.get("type") == "script"
            and str(a.get("script")).isdigit()
        }:
            uses[pk][1] += 1
    for pks in AlertTemplate.objects.values_list("action", "resolved_action"):
        for pk in {pk for pk in pks if pk is not None}:
            uses[pk][2] += 1
    return dict(uses)


def _referenced_script_pks() -> set[int]:
    return set(script_uses())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Check that every version string agrees with the canonical VERSION file,
and the MeshCentral and NATS pins of docker/ with settings.py.

Standard library only and no Django: this runs in the gate, where the api
virtualenv is not necessarily importable and the web and agent repositories are
plain checkouts under this tree.

    riddix/scripts/check_versions.py --web ulrmm-web --agent ulrmm-agent
    riddix/scripts/check_versions.py --next [server|agent]

X.DD.MM.YYYY (1.23.09.2026). Day and month are zero padded.
X is the nth release that day, from 1.
"""

import argparse
import ast
import datetime
import json
import re
import sys
from pathlib import Path

DATED = re.compile(r"^([1-9]\d*)\.(\d{2})\.(\d{2})\.(\d{4})$")
FORMAT = "X.DD.MM.YYYY"
REPO = Path(__file__).resolve().parents[2]


def valid_version(ver):
    m = DATED.match(ver) if isinstance(ver, str) else None
    if not m:
        return False
    _, day, month, year = (int(g) for g in m.groups())
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return True


def next_version(current, today):
    """Same day bumps X. Any other day starts at 1.DD.MM.YYYY."""
    stamp = today.strftime("%d.%m.%Y")
    x, _, date = current.partition(".")
    if valid_version(current) and date == stamp:
        return f"{int(x) + 1}.{stamp}"
    return f"1.{stamp}"


def assigned_value(tree, name):
    """The right hand side of the *last* module level `name = ...`, or None.

    The last one is what wins at import time, so that is the one to judge.
    """
    found = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            found = node.value
    return found


def first_match(path, pattern, rows, what):
    """The first capture of `pattern` in `path`, or None with a row added."""
    try:
        text = path.read_text()
    except OSError as e:
        rows.append((what, f"unreadable ({e.strerror})", "a readable file", path))
        return None
    m = re.search(pattern, text, re.M)
    if not m:
        rows.append((what, "not found", "a version string", path))
        return None
    return m.group(1)


def check(repo, web, agent):
    rows = []

    version_file = repo / "VERSION"
    try:
        version = version_file.read_text().strip()
    except OSError:
        rows.append(("VERSION", "missing", "the product version", version_file))
        return rows, None
    if not valid_version(version):
        rows.append(("VERSION", version, FORMAT, version_file))

    settings_file = repo / "api" / "ulrmm" / "ulrmm" / "settings.py"
    try:
        settings_src = settings_file.read_text()
        settings_tree = ast.parse(settings_src)
    except (OSError, SyntaxError) as e:
        rows.append(
            (
                "settings.py",
                f"unreadable ({type(e).__name__})",
                "a parseable file",
                settings_file,
            )
        )
        return rows, version

    # ULRMM_VERSION must be derived from VERSION, not spelled out a second time
    node = assigned_value(settings_tree, "ULRMM_VERSION")
    if node is None:
        rows.append(
            ("ULRMM_VERSION", "not assigned", "read from VERSION", settings_file)
        )
    elif isinstance(node, ast.Constant):
        rows.append(
            ("ULRMM_VERSION", repr(node.value), "read from VERSION", settings_file)
        )
    elif "VERSION" not in (ast.get_source_segment(settings_src, node) or ""):
        rows.append(
            (
                "ULRMM_VERSION",
                "unrelated expression",
                "read from VERSION",
                settings_file,
            )
        )

    node = assigned_value(settings_tree, "LATEST_AGENT_VER")
    agent_ver = node.value if isinstance(node, ast.Constant) else None
    if not valid_version(agent_ver):
        rows.append(("LATEST_AGENT_VER", str(agent_ver), FORMAT, settings_file))
        agent_ver = None

    # third-party pins the Compose stack spells out a second time
    for what, path, pattern, name in (
        (
            "mesh Dockerfile",
            repo / "docker" / "mesh" / "Dockerfile",
            r"^ARG MESH_VER=(\S+)",
            "MESH_VER",
        ),
        (
            "compose.yml nats",
            repo / "docker" / "compose.yml",
            r"^\s*image:\s*nats:([0-9.]+)",
            "NATS_SERVER_VER",
        ),
    ):
        node = assigned_value(settings_tree, name)
        want = node.value if isinstance(node, ast.Constant) else None
        found = first_match(path, pattern, rows, what)
        if found is not None and found != want:
            rows.append((what, found, f"{name} {want}", path))

    if web:
        pkg = Path(web) / "package.json"
        try:
            found = json.loads(pkg.read_text()).get("version")
        except (OSError, ValueError) as e:
            found = f"unreadable ({e})"
        if found != version:
            rows.append(("web package.json", str(found), version, pkg))

    if agent and agent_ver:
        agent = Path(agent)
        found = first_match(
            agent / "main.go",
            r'^\s*version\s*=\s*"([^"]+)"',
            rows,
            "agent main.go",
        )
        if found is not None and found != agent_ver:
            rows.append(("agent main.go", found, agent_ver, agent / "main.go"))

        # setup.nsi builds the installer; setup.iss is the fallback packer and
        # is checked for as long as the agent repo still ships it
        build = agent / "build"
        for name, pattern in (
            ("setup.nsi", r'^\s*!define\s+MyAppVersion\s+"([^"]+)"'),
            ("setup.iss", r'^\s*#define\s+MyAppVersion\s+"([^"]+)"'),
        ):
            path = build / name
            if name == "setup.iss" and not path.exists():
                continue
            found = first_match(path, pattern, rows, name)
            if found is not None and found != agent_ver:
                rows.append((f"{name} MyAppVersion", found, agent_ver, path))

    return rows, version


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", default=REPO, type=Path, help="server repository root")
    p.add_argument("--web", help="web repo checkout")
    p.add_argument("--agent", help="ulrmm-agent checkout")
    p.add_argument(
        "--next",
        nargs="?",
        const="server",
        choices=("server", "agent"),
        help="print the version the next release gets, then exit",
    )
    args = p.parse_args(argv)

    if args.next:
        if args.next == "server":
            current = (args.repo / "VERSION").read_text().strip()
        else:
            settings = args.repo / "api" / "ulrmm" / "ulrmm" / "settings.py"
            node = assigned_value(ast.parse(settings.read_text()), "LATEST_AGENT_VER")
            current = getattr(node, "value", "")
        print(next_version(str(current), datetime.date.today()))
        return 0

    rows, version = check(args.repo, args.web, args.agent)
    if not rows:
        print(f"versions consistent ({version})")
        return 0

    width = max(len(r[0]) for r in rows)
    print("version mismatches:")
    for what, found, expected, path in rows:
        print(f"  {what:<{width}}  found {found!s:<22} expected {expected}  [{path}]")
    return 1


if __name__ == "__main__":
    sys.exit(main())

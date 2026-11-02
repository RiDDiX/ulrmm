# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Versions and changelogs for the dashboard's About panel.

Each repository keeps a CHANGELOG.md with "## <version> (<date>)" headings
followed by "- " items. The server reads its own file, the agent source that
build_agents.sh checks out and the script library in SCRIPTS_DIR. The web
interface ships its own file in the bundle.
"""

import re
from pathlib import Path

from django.conf import settings

HEADING = re.compile(r"^##\s+(\S+)(?:\s+\((\d{4}-\d{2}-\d{2})\))?\s*$")
MAX_RELEASES = 100
MAX_BYTES = 512 * 1024


def parse_changelog(text: str) -> list[dict]:
    releases: list[dict] = []
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            if len(releases) == MAX_RELEASES:
                break
            releases.append({"version": m[1], "date": m[2], "items": []})
        elif releases and line.startswith("- "):
            releases[-1]["items"].append(line[2:].strip())
    return releases


def read_changelog(path: Path) -> list[dict]:
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            return parse_changelog(f.read(MAX_BYTES))
    except OSError:
        return []


def agent_source_dir() -> Path:
    # same default as riddix/agents/build_agents.sh
    root = getattr(settings, "ULRMM_AGENT_ROOT", "/opt/ulrmm-agents")
    return Path(root) / "src"


def about() -> dict:
    scripts = read_changelog(Path(settings.SCRIPTS_DIR) / "CHANGELOG.md")
    return {
        "product": "UniversalLocal RMM",
        "components": [
            {
                "key": "server",
                "name": "Server",
                "version": settings.ULRMM_VERSION,
                "changelog": read_changelog(
                    settings.BASE_DIR.parent.parent / "CHANGELOG.md"
                ),
            },
            {
                "key": "agent",
                "name": "Agent",
                "version": settings.LATEST_AGENT_VER,
                "changelog": read_changelog(agent_source_dir() / "CHANGELOG.md"),
            },
            {
                "key": "scripts",
                "name": "Script library",
                # the library has no version numbers, its newest entry dates it
                "version": scripts[0]["version"] if scripts else None,
                "changelog": scripts,
            },
        ],
    }

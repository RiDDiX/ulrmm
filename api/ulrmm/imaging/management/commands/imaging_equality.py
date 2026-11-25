# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

COLUMNS = (
    "destination",
    "network_mode",
    "compression",
    "compression_level",
    "schedule_time",
    "timezone",
    "keep_last",
    "volumes",
    "next_run",
)
# columns that exist before and after the backup engine migrations
QUERY = f"""
SELECT a.agent_id, p.id IS NOT NULL, {", ".join(f"p.{c}" for c in COLUMNS)}
FROM agents_agent a LEFT JOIN imaging_profile p ON p.agent_id = a.id
ORDER BY a.agent_id
"""


def _rows():
    with connection.cursor() as cursor:
        cursor.execute(QUERY)
        out = {}
        for agent_id, has_profile, *values in cursor.fetchall():
            row = dict(zip(COLUMNS, values))
            row["volumes"] = (
                json.loads(row["volumes"])
                if isinstance(row["volumes"], str)
                else row["volumes"]
            )
            for key in ("schedule_time", "next_run"):
                row[key] = row[key].isoformat() if row[key] else None
            out[agent_id] = {"has_profile": has_profile, **row}
    return out


class Command(BaseCommand):
    help = "Dump the backup columns of every device, or compare them after the first resolve."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=("dump", "compare"))
        parser.add_argument("file")

    def handle(self, *args, **options):
        if options["action"] == "dump":
            with open(options["file"], "w", encoding="utf-8") as f:
                json.dump(_rows(), f, indent=1, sort_keys=True)
            return
        from agents.models import Agent
        from imaging.models import Profile
        from imaging.resolver import resolve_now

        with open(options["file"], encoding="utf-8") as f:
            before = json.load(f)
        resolve_now(list(Agent.objects.values_list("pk", flat=True)), cause="enrol")
        after = _rows()
        profiles = {
            p.agent.agent_id: p for p in Profile.objects.select_related("agent")
        }
        differences = []
        for agent_id, old in before.items():
            new = after.get(agent_id)
            profile = profiles.get(agent_id)
            if new is None:
                differences.append(f"{agent_id}: the device is gone")
            elif not old["has_profile"]:
                if (
                    profile is None
                    or profile.effective.get("schedule") != {"kind": "none"}
                    or new["next_run"] is not None
                ):
                    differences.append(
                        f"{agent_id}: a device without settings got a schedule"
                    )
            else:
                changed = [c for c in COLUMNS if old[c] != new[c]]
                # a schedule without a due time gets one at the first resolve
                if (
                    changed == ["next_run"]
                    and old["schedule_time"]
                    and not old["next_run"]
                ):
                    self.stdout.write(
                        f"{agent_id}: expected, next_run set to {new['next_run']}"
                    )
                    continue
                differences += [
                    f"{agent_id}: {c} {old[c]!r} -> {new[c]!r}" for c in changed
                ]
        for line in differences:
            self.stdout.write(line)
        if differences:
            raise CommandError(f"{len(differences)} differences.", returncode=1)
        self.stdout.write(f"{len(before)} devices equal.")

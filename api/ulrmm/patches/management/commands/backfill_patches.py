# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from agents.models import Agent
from patches.mirror import sync_agent_updates
from patches.models import ACTOR_MIGRATED, PatchPolicy
from ulrmm.constants import AGENT_DEFER
from winupdate.models import WinUpdate, WinUpdatePolicy

INHERIT = "inherit"
SEVERITY_FIELDS = ("critical", "important", "moderate", "low", "other")
# the legacy "other" bucket matches severity == "" exactly, which is "none"
# and not "unknown" (design 3.4)
RULE_SEVERITIES = dict(zip(SEVERITY_FIELDS, (*SEVERITY_FIELDS[:4], "none")))
RULE_ACTIONS = {"approve": "approve", "ignore": "reject", "manual": "require_manual"}
# the legacy vocabulary onto the one design 8.5 uses
REBOOT_MODES = {"never": "never", "required": "when_required", "always": "always"}


def all_inherit(old: WinUpdatePolicy) -> bool:
    return (
        all(
            getattr(old, i) == INHERIT
            for i in (*SEVERITY_FIELDS, "run_time_frequency", "reboot_after_install")
        )
        and old.reprocess_failed_inherit
    )


def policy_fields(old: WinUpdatePolicy) -> dict:
    window = {
        "start_hour": old.run_time_hour,
        "duration_minutes": 120,
        "timezone": "agent",
    }
    if old.run_time_frequency == "monthly":
        windows = [{"day_of_month": old.run_time_day, **window}]
    elif old.run_time_frequency == INHERIT:
        windows = None
    else:
        windows = [{"days": old.run_time_days or [], **window}]

    rules = [
        {"severity": severity, "action": RULE_ACTIONS[getattr(old, field)]}
        for field, severity in RULE_SEVERITIES.items()
        if getattr(old, field) in RULE_ACTIONS
    ]

    return {
        "auto_approve": rules or None,
        "windows": windows,
        "reboot": (
            None
            if old.reboot_after_install == INHERIT
            else {"mode": REBOOT_MODES.get(old.reboot_after_install, "never")}
        ),
        "retry": (
            None
            if old.reprocess_failed_inherit
            else {
                "max_attempts": (
                    old.reprocess_failed_times if old.reprocess_failed else 0
                ),
                "email_if_fail": old.email_if_fail,
            }
        ),
    }


def backfill_policies() -> dict:
    counts = {"policies": 0, "policies_skipped": 0}

    for old in WinUpdatePolicy.objects.all():
        # the agent row get_patch_policy() creates on first read holds no
        # decision, and a row attached to nothing, or to both, has nowhere to
        # go in a chain that reads one attachment point at a time
        if bool(old.agent_id) == bool(old.policy_id) or (
            old.agent_id and all_inherit(old)
        ):
            counts["policies_skipped"] += 1
            continue

        PatchPolicy.objects.update_or_create(
            agent_id=old.agent_id,
            policy_id=old.policy_id,
            defaults=policy_fields(old),
        )
        counts["policies"] += 1

    return counts


class Command(BaseCommand):
    help = "Backfill the patch records from the existing windows update rows"

    def handle(self, *args, **kwargs):
        counts = {"created": 0, "updated": 0, "unchanged": 0, "duplicates": 0}

        agents = Agent.objects.defer(*AGENT_DEFER).filter(
            pk__in=WinUpdate.objects.values("agent_id")
        )
        for agent in agents.iterator():
            for key, value in sync_agent_updates(agent, ACTOR_MIGRATED).items():
                counts[key] += value

        counts.update(backfill_policies())

        self.stdout.write(
            self.style.SUCCESS(
                f"{counts['created']} created, {counts['updated']} updated, "
                f"{counts['unchanged']} unchanged, "
                f"{counts['duplicates']} duplicate rows collapsed, "
                f"{counts['policies']} policies mapped, "
                f"{counts['policies_skipped']} policies skipped"
            )
        )

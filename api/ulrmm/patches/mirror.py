# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Mapping from WinUpdate rows onto Patch/PatchDevice, shared by the T-1
backfill command and the T-2 ingest mirror.

WinUpdate stays the source of truth (design 3.2). The mirror runs on ingest
only - after a windows scan and after a posix import - so a decision or a
result written between two scans (approve_updates, set_update_result, an
operator edit) reaches the shadow rows on the next scan of that agent instead
of on every write to the row.
"""

from typing import TYPE_CHECKING

from django.db import transaction
from django.db.models import Q
from django.utils import timezone as djangotime

from ulrmm.constants import DebugLogType

from .models import (
    ACTOR_MIRRORED,
    MIGRATED_REJECTION_REASON,
    OSFamily,
    Patch,
    PatchApproval,
    PatchDevice,
    PatchErrorKind,
    PatchEvent,
    PatchEventType,
    PatchSeverity,
    PatchState,
)

if TYPE_CHECKING:
    from agents.models import Agent
    from winupdate.models import WinUpdate

# guid prefix of a posix row to the family it belongs to. The keys are the
# package managers posix.py accepts in a guid
POSIX_FAMILIES = {
    "apt": OSFamily.DEBIAN,
    "dnf": OSFamily.RHEL,
    "yum": OSFamily.RHEL,
    "zypper": OSFamily.SUSE,
    "pacman": OSFamily.ARCH,
    "apk": OSFamily.ALPINE,
    "flatpak": OSFamily.PORTABLE,
    "snap": OSFamily.PORTABLE,
    "brew": OSFamily.DARWIN,
    "brew-cask": OSFamily.DARWIN,
    "softwareupdate": OSFamily.DARWIN,
    "pkg": OSFamily.FREEBSD,
}

CANDIDATE_KEY = ("provider", "package", "arch", "candidate_version", "origin")
KEY_FIELDS = ("external_id", *CANDIDATE_KEY)

DEVICE_FIELDS = (
    "state",
    "approval",
    "approval_reason",
    "attempts",
    "last_error_kind",
    "installed_at",
)

# a closed record is history: reopening one would rewrite it (design 7)
TERMINAL_STATES = (
    PatchState.INSTALLED,
    PatchState.SKIPPED,
    PatchState.SUPERSEDED,
    PatchState.OBSOLETE,
)

# catalogue data the provider can restate, unlike the identity fields
MUTABLE_FIELDS = ("package", "severity", "security", "advisories")

EVENT_TYPES = {
    PatchApproval.APPROVED: PatchEventType.APPROVED,
    PatchApproval.REJECTED: PatchEventType.REJECTED,
    PatchApproval.UNDECIDED: PatchEventType.DISCOVERED,
}


def patch_fields(update: "WinUpdate") -> dict:
    """The Patch identity and metadata one WinUpdate row belongs to."""
    guid = update.guid or ""
    parts = guid.split(":", 3)

    if len(parts) == 4 and parts[0] in POSIX_FAMILIES:
        manager, name, arch, version = parts
        fields = {
            "os_family": POSIX_FAMILIES[manager],
            "provider": manager,
            "package": name[:255],
            "arch": arch,
            "candidate_version": version,
            "external_id": "",
        }
    else:
        fields = {
            "os_family": OSFamily.WINDOWS,
            "provider": "wua",
            "package": (update.title or "")[:255],
            "arch": "",
            "candidate_version": str(update.revision_number or ""),
            "external_id": guid,
        }

    severity = (update.severity or "").lower()
    if severity not in PatchSeverity.values:
        # the legacy "other" bucket is severity == "", a known absence
        severity = PatchSeverity.UNKNOWN if severity else PatchSeverity.NONE

    categories = update.categories or []
    fields.update(
        origin="",
        severity=severity,
        security=severity in ("critical", "important", "moderate", "low")
        or any("security" in str(c).lower() for c in categories),
        advisories=[i for i in (update.kb_article_ids or []) if i],
    )
    return fields


def identity_key(fields: dict) -> tuple:
    if fields["external_id"]:
        return (fields["provider"], fields["external_id"])

    return tuple(fields[i] for i in CANDIDATE_KEY)


def device_fields(update: "WinUpdate") -> dict:
    """WinUpdate action/installed/result onto the lifecycle fields."""
    if update.action == "approve":
        approval, reason = PatchApproval.APPROVED, ""
    elif update.action == "ignore":
        approval, reason = PatchApproval.REJECTED, MIGRATED_REJECTION_REASON
    else:
        # neither "nothing" nor "inherit" is a decision someone made
        approval, reason = PatchApproval.UNDECIDED, ""

    failed = update.result == "failed"
    if update.installed:
        state = PatchState.INSTALLED
    elif failed:
        state = PatchState.FAILED
    elif approval == PatchApproval.APPROVED:
        state = PatchState.APPROVED
    elif approval == PatchApproval.REJECTED:
        state = PatchState.REJECTED
    else:
        state = PatchState.DISCOVERED

    return {
        "state": state,
        "approval": approval,
        "approval_reason": reason,
        # a failed row counts at least its own attempt
        "attempts": max(update.fail_count, 1 if failed else 0),
        "last_error_kind": PatchErrorKind.UNKNOWN if failed else "",
        "installed_at": update.date_installed if update.installed else None,
    }


def _load_patches(query: Q) -> dict:
    return {
        identity_key({i: getattr(patch, i) for i in KEY_FIELDS}): patch
        for patch in Patch.objects.filter(query)
    }


@transaction.atomic
def sync_agent_updates(agent: "Agent", actor: str) -> dict:
    """Bring the patch records of one agent in line with its WinUpdate rows.

    Atomic because a record written without its event reads as unchanged on
    the next run, and the event would then never be written at all (design 7
    invariant 3).
    """
    counts = {"created": 0, "updated": 0, "unchanged": 0, "duplicates": 0}

    # duplicate (agent, identity) rows collapse to the newest one, the same
    # row .last() picks everywhere else
    newest: dict = {}
    for update in agent.winupdates.order_by("id"):  # type: ignore
        fields = patch_fields(update)
        key = identity_key(fields)
        if key in newest:
            counts["duplicates"] += 1
        newest[key] = (update, fields)

    patches: dict = {}
    if newest:
        query = Q()
        for update, fields in newest.values():
            if fields["external_id"]:
                query |= Q(
                    provider=fields["provider"], external_id=fields["external_id"]
                )
            else:
                query |= Q(**{i: fields[i] for i in CANDIDATE_KEY})

        patches = _load_patches(query)
        missing = [f for key, (_, f) in newest.items() if key not in patches]
        if missing:
            Patch.objects.bulk_create(
                [Patch(**i) for i in missing], ignore_conflicts=True
            )
            patches = _load_patches(query)

    current = {i.pk for i in patches.values()}
    # the records of this scan plus every open record it no longer offers, so
    # a row the update table dropped can be closed instead of standing still
    records = list(
        PatchDevice.objects.filter(agent=agent)
        .filter(Q(patch_id__in=current) | ~Q(state__in=TERMINAL_STATES))
        .select_related("patch")
    )
    existing = {i.patch_id: i for i in records}

    created, changed, first_events, chained = [], [], [], []
    refreshed = []
    for key, (update, fields) in newest.items():
        patch = patches[key]
        target = device_fields(update)
        record = existing.get(patch.pk)

        # a rescan can restate the severity or the advisories of an identity
        # the catalogue already holds, and the rules read them
        metadata = {i: fields[i] for i in MUTABLE_FIELDS}
        if any(getattr(patch, k) != v for k, v in metadata.items()):
            for field, value in metadata.items():
                setattr(patch, field, value)
            refreshed.append(patch)

        if record is None:
            record = PatchDevice(patch=patch, agent=agent, **target)
            created.append(record)
            first_events.append(
                (
                    record,
                    {
                        "event_type": EVENT_TYPES[record.approval],
                        "to_state": record.state,
                        "candidate_version": patch.candidate_version,
                        "payload": {"action": update.action},
                    },
                )
            )
            continue

        diff = {k: v for k, v in target.items() if getattr(record, k) != v}
        if not diff:
            counts["unchanged"] += 1
            continue

        was = record.state
        for field, value in diff.items():
            setattr(record, field, value)
        changed.append(record)

        # an approval the mirror writes needs the reserved actor on it, and a
        # result that moved the state is a transition of its own
        if "approval" in diff:
            moved = {
                "event_type": EVENT_TYPES[record.approval],
                "payload": {"action": update.action},
            }
        elif "state" in diff:
            moved = {
                "event_type": PatchEventType.TRANSACTION_FINISHED,
                "payload": {"result": update.result},
            }
        else:
            continue

        chained.append(
            (
                record,
                {
                    "from_state": was,
                    "to_state": record.state,
                    "candidate_version": patch.candidate_version,
                    **moved,
                },
            )
        )

    # a newer candidate of the same package is a succession, anything else the
    # scan stopped offering is simply gone (design 7)
    succeeded = {(i.provider, i.package, i.arch) for i in patches.values()}
    for record in records:
        if record.patch_id in current:
            continue

        was = record.state
        patch = record.patch
        if (patch.provider, patch.package, patch.arch) in succeeded:
            record.state = PatchState.SUPERSEDED
            event_type = PatchEventType.SUPERSEDED
        else:
            record.state = PatchState.OBSOLETE
            event_type = PatchEventType.OBSOLETE

        changed.append(record)
        chained.append(
            (
                record,
                {
                    "event_type": event_type,
                    "from_state": was,
                    "to_state": record.state,
                    "candidate_version": patch.candidate_version,
                    "payload": {},
                },
            )
        )

    PatchDevice.objects.bulk_create(created)
    PatchDevice.objects.bulk_update(changed, DEVICE_FIELDS)
    Patch.objects.bulk_update(refreshed, MUTABLE_FIELDS)
    Patch.objects.filter(pk__in=current).update(last_seen=djangotime.now())

    extra = {"approval_semantics": "script_path"} if actor == ACTOR_MIRRORED else {}

    # a created record starts its chain, so the predecessor save() would look
    # up is known to be empty and the lookup can go
    rows = [
        PatchEvent(
            patch_device=record,
            actor=actor,
            prev_hash="",
            **{**fields, "payload": {**fields["payload"], **extra}},
        )
        for record, fields in first_events
    ]
    for row in rows:
        row.hash = row.compute_hash()
    PatchEvent.objects.bulk_create(rows)

    for record, fields in chained:
        PatchEvent.objects.create(
            patch_device=record,
            actor=actor,
            **{**fields, "payload": {**fields["payload"], **extra}},
        )

    counts["created"] = len(created)
    counts["updated"] = len(changed)
    return counts


def mirror_agent_updates(agent: "Agent") -> None:
    """T-2: mirror an ingest into the patch records. Never breaks the ingest."""
    from logs.models import DebugLog

    try:
        sync_agent_updates(agent, ACTOR_MIRRORED)
    except Exception as e:
        DebugLog.error(
            agent=agent,
            log_type=DebugLogType.WIN_UPDATES,
            message=f"Mirroring the updates of {agent.hostname} into the patch records failed: {e}",
        )

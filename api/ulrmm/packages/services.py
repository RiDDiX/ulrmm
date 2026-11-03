# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import uuid
from collections import Counter

from django.core.cache import cache
from django.utils import timezone as djangotime

from agents.utils import nobody_logged_in
from logs.models import AuditLog
from ulrmm.constants import (
    AgentPlat,
    AuditActionType,
    AuditObjType,
)
from ulrmm.middleware import get_debug_info

from .jobs import PKGJOB_MIN_AGENT, supports_job
from .models import InstallState, PackageInstall, PackageKind, RunAs, SoftwarePackage
from .tasks import install_batch_task
from .utils import BATCH_QUEUED_TTL, batch_key


def start_installs(
    user,
    package: SoftwarePackage,
    agents: list,
    run_as,
    target: dict | None = None,
    *,
    requested_by: str = "",
) -> dict:
    """One PackageInstall per agent, one task for the batch, one audit row.
    target is the bulk selection, requested_by names a server feature in
    place of the user. ValueError text goes back to the user."""
    username = requested_by or user.username
    if run_as not in RunAs.values:
        raise ValueError("Choose System / Administrator or Current logged-in user.")
    if run_as == RunAs.USER and package.plat != AgentPlat.WINDOWS:
        raise ValueError(
            "Only Windows packages can install as the logged-in user. "
            "macOS and Linux packages always install as root."
        )
    if run_as == RunAs.USER and package.kind == PackageKind.DRIVER:
        raise ValueError("Drivers install as system.")
    if run_as == RunAs.USER and package.kind == PackageKind.ARCHIVE:
        raise ValueError("Archives install as system.")
    if not agents:
        raise ValueError("No agents were found meeting the selected criteria")

    batch = uuid.uuid4()
    now = djangotime.now()
    rows = []
    for agent in agents:
        state, detail = InstallState.QUEUED, ""
        if agent.plat != package.plat:
            state, detail = InstallState.SKIPPED, f"not a {package.plat} agent"
        elif not agent.is_online:
            state, detail = InstallState.SKIPPED, "offline"
        elif package.kind == PackageKind.ARCHIVE and not supports_job(agent):
            state = InstallState.SKIPPED
            detail = f"archives need agent {PKGJOB_MIN_AGENT} or newer"
        elif run_as == RunAs.USER and nobody_logged_in(agent):
            state, detail = InstallState.REFUSED, "nobody is logged in"
        rows.append(
            PackageInstall(
                package=package,
                package_name=package.name,
                agent=agent,
                batch=batch,
                run_as=run_as,
                state=state,
                detail=detail,
                requested_by=username,
                finished=None if state == InstallState.QUEUED else now,
            )
        )
    PackageInstall.objects.bulk_create(rows)

    counts = Counter(row.state for row in rows)
    result = {
        "batch": str(batch),
        "queued": counts[InstallState.QUEUED],
        "skipped": counts[InstallState.SKIPPED],
        "refused": counts[InstallState.REFUSED],
    }
    single = agents[0] if len(agents) == 1 else None
    AuditLog.objects.create(
        username=username,
        agent=single.hostname if single else None,
        agent_id=single.agent_id if single else None,
        object_type=AuditObjType.AGENT if single else AuditObjType.BULK,
        action=AuditActionType.EXEC_COMMAND,
        message=(
            f"{username} installs package {package.name} as {run_as} on "
            f"{result['queued']} agents ({result['skipped']} skipped, "
            f"{result['refused']} refused), batch {batch}"
        ),
        debug_info=get_debug_info(),
        after_value={
            "batch": str(batch),
            "package": package.name,
            "sha256": package.sha256,
            "run_as": run_as,
            **(target or {}),
            # the rows go with their agent, this stays
            **{
                state: [row.agent.hostname for row in rows if row.state == state]
                for state in (
                    InstallState.QUEUED,
                    InstallState.SKIPPED,
                    InstallState.REFUSED,
                )
            },
        },
    )

    if result["queued"]:
        cache.set(batch_key(batch), 1, BATCH_QUEUED_TTL)
        install_batch_task.delay(str(batch))
    return result

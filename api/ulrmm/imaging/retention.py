# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Which verified points of one device and target retention keeps (contract 8.1)."""

from datetime import UTC, datetime

TIERS = (
    ("hourly", "%Y-%m-%d %H"),
    ("daily", "%Y-%m-%d"),
    ("weekly", "%G-W%V"),
    ("monthly", "%Y-%m"),
    ("yearly", "%Y"),
)


def when(point):
    # points from before the snapshot time existed count by their creation; a
    # snapshot time ahead of the server clock never makes a point the newest
    at = point.snapshot_at
    return at if at and at <= datetime.now(UTC) else point.created_at


def plan(points, keep_last, gfs, zone, open_ids):
    """{point id: [rule, ...]}; a point without rules is deleted."""
    order = sorted(
        points, key=lambda p: (when(p), p.created_at, str(p.id)), reverse=True
    )
    rules = {p.id: [] for p in order}
    if order:
        rules[order[0].id].append("newest")
    for p in order:
        if p.protected:
            rules[p.id].append("protected")
        if p.id in open_ids:
            rules[p.id].append("restore")
    for p in order[:keep_last]:
        rules[p.id].append("keep_last")
    for tier, fmt in TIERS:
        n = gfs.get(tier, 0)
        if not n:
            continue
        seen = []
        for p in order:
            key = when(p).astimezone(zone).strftime(fmt)
            if key in seen:
                continue
            if len(seen) == n:
                break
            seen.append(key)
            rules[p.id].append(f"{tier} {key}")
    if not keep_last and not any(gfs.get(tier, 0) for tier, _ in TIERS):
        for p in order:
            rules[p.id].append("all")
    return rules

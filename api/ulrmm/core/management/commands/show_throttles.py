# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import time

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand

_PERIODS = {
    "second": 1,
    "sec": 1,
    "s": 1,
    "minute": 60,
    "min": 60,
    "m": 60,
    "hour": 3600,
    "hr": 3600,
    "h": 3600,
    "day": 86400,
    "d": 86400,
}


def _parse_rate(rate):
    if not rate:
        return None, None
    num, _, period = rate.partition("/")
    try:
        limit = int(num)
    except ValueError:
        return None, None
    return limit, _PERIODS.get(period, _PERIODS.get(period.rstrip("s"), 60))


def _fmt_retry(seconds):
    seconds = int(seconds)
    if seconds <= 0:
        return "-"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


class Command(BaseCommand):
    help = "Show the active rate-limit throttles"

    def handle(self, *args, **options):
        rates = settings.REST_FRAMEWORK.get("DEFAULT_THROTTLE_RATES", {})
        now = time.time()

        keys = list(cache.iter_keys_pattern("throttle_*"))
        if not keys:
            self.stdout.write("No active login throttles found.")
            return

        rows = []
        for raw in sorted(keys):
            key = raw.decode() if isinstance(raw, bytes) else str(raw)
            if key.startswith(":1:"):
                key = key[3:]

            scope = next((s for s in rates if key.startswith(f"throttle_{s}_")), None)
            if scope is None:
                continue
            limit, window = _parse_rate(rates.get(scope))
            if limit is None:
                continue

            history = cache.get(key) or []
            active = [ts for ts in history if ts > now - window]
            attempts = len(active)
            remaining = max(0, limit - attempts)
            throttled = attempts >= limit
            retry = "-"
            if throttled and active:
                retry = _fmt_retry(window - (now - min(active)))

            client = key[len(f"throttle_{scope}_") :]
            rows.append(
                {
                    "status": "THROTTLED" if throttled else "OK",
                    "scope": scope,
                    "client": client,
                    "attempts": f"{attempts}/{limit}",
                    "period": rates[scope].split("/")[1],
                    "remaining": str(remaining),
                    "retry": retry,
                }
            )

        if not rows:
            self.stdout.write("No active throttle entries found.")
            return

        header = (
            f"{'Status':<12} {'Throttle':<18} {'Client':<18} "
            f"{'Attempts':<12} {'Remaining':<10} Retry After"
        )
        self.stdout.write(header)
        self.stdout.write("-" * 90)
        for row in rows:
            self.stdout.write(
                f"{row['status']:<12} {row['scope']:<18} {row['client']:<18} "
                f"{row['attempts']} per {row['period']:<12} "
                f"{row['remaining']:<10} {row['retry']}"
            )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""next run times for schedules. pure stdlib.

rule = MaintenanceSchedule-like. starts in device tz. dst: spring gap shifts forward, fall ambiguous runs at first.
"""

import calendar
import datetime as dt
from itertools import islice

HORIZON_DAYS = 800


def matches(rule, day: dt.date) -> bool:
    if day in rule.excluded_dates:
        return False
    if rule.frequency == "once":
        return day in rule.dates
    if (rule.start_date and day < rule.start_date) or (
        rule.end_date and day > rule.end_date
    ):
        return False
    if rule.frequency == "daily":
        return True
    if rule.frequency == "weekly":
        return day.weekday() in rule.weekdays

    last = calendar.monthrange(day.year, day.month)[1]
    if rule.month_day:
        # the 31st runs on the last day of shorter months, like the patch policy
        return day.day == min(rule.month_day, last)
    if day.weekday() != rule.month_weekday:
        return False
    if rule.month_week == -1:
        return day.day > last - 7
    return (day.day - 1) // 7 + 1 == rule.month_week


def _starts(rule, tz, first: dt.date, days: int):
    for i in range(days):
        day = first + dt.timedelta(days=i)
        if matches(rule, day):
            local = dt.datetime.combine(day, rule.run_time, tzinfo=tz)
            yield local.astimezone(dt.timezone.utc)


def upcoming(rule, tz, after: dt.datetime, span: dt.timedelta, limit: int):
    """UTC starts of the next `limit` windows that are still open at `after`."""
    first = (after - span).astimezone(tz).date() - dt.timedelta(days=1)
    starts = (s for s in _starts(rule, tz, first, HORIZON_DAYS) if s + span > after)
    return list(islice(starts, limit))


def current(rule, tz, now: dt.datetime, span: dt.timedelta):
    """UTC start of the window open at `now`, or None."""
    first = (now - span).astimezone(tz).date() - dt.timedelta(days=1)
    days = (now.astimezone(tz).date() - first).days + 1
    return next(
        (s for s in _starts(rule, tz, first, days) if s <= now < s + span), None
    )

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Predicates deciding whether a scheduled task is due in the current minute.

Two styles coexist: the legacy predicates read a task model and the agent's
timezone and use the ``ulrmm.constants`` bitmask tables; the new ones take
plain values (a ``datetime.time``, a ``tzinfo`` and lists of ints). Both
compare to minute granularity only.
"""

import calendar
from datetime import datetime, time, tzinfo
from zoneinfo import ZoneInfo

from ulrmm.constants import MONTH_DAYS, WEEKS
from ulrmm.helpers import is_month_in_bitmask, is_weekday_in_bitmask

LAST_DAY_OF_MONTH = 32
LAST_WEEK_OF_MONTH = 5

_WEEK_NUMBER_TO_NAME = {
    1: "First Week",
    2: "Second Week",
    3: "Third Week",
    4: "Fourth Week",
}


def _week_of_month(day: int) -> int:
    return (day - 1) // 7 + 1


def _last_week_of_month(year: int, month: int) -> int:
    days_in_month = calendar.monthrange(year, month)[1]
    return (days_in_month - 1) // 7 + 1


# --- legacy (task object) predicates --------------------------------------


def _agent_now(agent, current_time: datetime) -> datetime:
    return current_time.astimezone(ZoneInfo(agent.timezone))


def _hm_match(moment: datetime, run_time_date) -> bool:
    return moment.hour == run_time_date.hour and moment.minute == run_time_date.minute


def should_run_daily_task(task, agent, current_time: datetime) -> bool:
    return _hm_match(_agent_now(agent, current_time), task.run_time_date)


def should_run_once_task(task, agent, current_time: datetime) -> bool:
    tz = ZoneInfo(agent.timezone)
    scheduled = task.run_time_date.replace(tzinfo=tz, second=0, microsecond=0)
    now = current_time.astimezone(tz).replace(second=0, microsecond=0)
    return scheduled == now


def should_run_weekly_task(task, agent, current_time: datetime) -> bool:
    now = _agent_now(agent, current_time)
    if not is_weekday_in_bitmask(now.weekday(), task.run_time_bit_weekdays):
        return False
    return _hm_match(now, task.run_time_date)


def should_run_monthly_dow_task(task, agent, current_time: datetime) -> bool:
    now = _agent_now(agent, current_time)
    if not is_weekday_in_bitmask(now.weekday(), task.run_time_bit_weekdays):
        return False
    if not is_month_in_bitmask(now.month, task.monthly_months_of_year):
        return False

    week = _week_of_month(now.day)
    if week == _last_week_of_month(now.year, now.month):
        week_bit = WEEKS["Last Week"]
    else:
        week_bit = WEEKS[_WEEK_NUMBER_TO_NAME[week]]
    if not (week_bit & task.monthly_weeks_of_month):
        return False
    return _hm_match(now, task.run_time_date)


def should_run_monthly_task(task, agent, current_time: datetime) -> bool:
    now = _agent_now(agent, current_time)
    if not is_month_in_bitmask(now.month, task.monthly_months_of_year):
        return False

    days_in_month = calendar.monthrange(now.year, now.month)[1]
    if now.day == days_in_month and (
        MONTH_DAYS["Last Day"] & task.monthly_days_of_month
    ):
        return _hm_match(now, task.run_time_date)
    if MONTH_DAYS[str(now.day)] & task.monthly_days_of_month:
        return _hm_match(now, task.run_time_date)
    return False


# --- new (parameter object) predicates ------------------------------------


def _time_match(moment: datetime, run_time: time) -> bool:
    return moment.hour == run_time.hour and moment.minute == run_time.minute


def should_run_daily(
    *, run_time: time, current_time: datetime, timezone: tzinfo
) -> bool:
    return _time_match(current_time.astimezone(timezone), run_time)


def should_run_weekly(
    *, run_time: time, weekdays, current_time: datetime, timezone: tzinfo
) -> bool:
    now = current_time.astimezone(timezone)
    if now.weekday() not in weekdays:
        return False
    return _time_match(now, run_time)


def should_run_monthly_dow(
    *, run_time: time, weekdays, weeks, months, current_time: datetime, timezone: tzinfo
) -> bool:
    now = current_time.astimezone(timezone)
    if now.weekday() not in weekdays:
        return False
    if now.month not in months:
        return False

    week = _week_of_month(now.day)
    if week == _last_week_of_month(now.year, now.month):
        week = LAST_WEEK_OF_MONTH
    if week not in weeks:
        return False
    return _time_match(now, run_time)


def should_run_monthly(
    *, run_time: time, days, months, current_time: datetime, timezone: tzinfo
) -> bool:
    now = current_time.astimezone(timezone)
    if now.month not in months:
        return False

    days_in_month = calendar.monthrange(now.year, now.month)[1]
    if now.day == days_in_month and LAST_DAY_OF_MONTH in days:
        return _time_match(now, run_time)
    if now.day in days:
        return _time_match(now, run_time)
    return False

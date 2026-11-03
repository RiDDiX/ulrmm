# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
from typing import List, Optional
from zoneinfo import ZoneInfo

from django.db.models import Q
from django.utils import timezone as djangotime

from core.utils import get_core_settings
from ulrmm.celery import app
from ulrmm.constants import MonthlyType, ScheduleType
from ulrmm.logger import logger
from ulrmm import scheduler
from ulrmm.utils import get_default_timezone

from .models import ReportHistory, ReportSchedule
from .serializers import EXTENSION_RE
from .utils import run_scheduled_report

# a schedule that ran this recently is not started again
LOCK_SECONDS = 55

ATTACHMENT_TYPES = ("pdf", "html", "plaintext")


@app.task
def prune_report_history_task(older_than_days: int) -> str:
    cutoff = djangotime.now() - dt.timedelta(days=older_than_days)
    ReportHistory.objects.filter(date_created__lt=cutoff).delete()
    return "ok"


def schedule_zone(name: Optional[str], default: ZoneInfo) -> ZoneInfo:
    if name:
        try:
            return ZoneInfo(name)
        except (ValueError, KeyError, OSError):
            pass
    return default


def is_due(schedule, now: dt.datetime, zone: ZoneInfo) -> bool:
    match schedule.schedule_type:
        case ScheduleType.DAILY:
            return scheduler.should_run_daily(
                run_time=schedule.run_time, current_time=now, timezone=zone
            )
        case ScheduleType.WEEKLY:
            return scheduler.should_run_weekly(
                run_time=schedule.run_time,
                weekdays=schedule.run_time_weekdays or [],
                current_time=now,
                timezone=zone,
            )
        case ScheduleType.MONTHLY if schedule.monthly_type == MonthlyType.WEEKS:
            return scheduler.should_run_monthly_dow(
                run_time=schedule.run_time,
                weekdays=schedule.run_time_weekdays or [],
                weeks=schedule.monthly_weeks_of_month or [],
                months=schedule.monthly_months_of_year or [],
                current_time=now,
                timezone=zone,
            )
        case ScheduleType.MONTHLY:
            return scheduler.should_run_monthly(
                run_time=schedule.run_time,
                days=schedule.monthly_days_of_month or [],
                months=schedule.monthly_months_of_year or [],
                current_time=now,
                timezone=zone,
            )
    return False


def claim(schedule: ReportSchedule, now: dt.datetime) -> bool:
    """Set locked_at unless another runner did so in the last LOCK_SECONDS."""
    stale = now - dt.timedelta(seconds=LOCK_SECONDS)
    return bool(
        ReportSchedule.objects.filter(pk=schedule.pk)
        .filter(Q(locked_at__isnull=True) | Q(locked_at__lt=stale))
        .update(locked_at=now)
    )


@app.task
def scheduled_reports_runner() -> None:
    now = djangotime.now()
    default_zone = get_default_timezone()

    due: List[ReportSchedule] = []
    schedules = ReportSchedule.objects.filter(enabled=True).select_related(
        "report_template", "schedule", "owner"
    )
    for schedule in schedules:
        try:
            zone = schedule_zone(schedule.timezone, default_zone)
            if not is_due(schedule.schedule, now, zone):
                continue
        except Exception as error:
            logger.error(f"Report schedule {schedule.pk} could not be checked: {error}")
            continue

        if not claim(schedule, now):
            logger.info(
                f"Report schedule {schedule.name} already executed too recently, skipping"
            )
            continue
        due.append(schedule)

    for schedule in due:
        try:
            _, error = run_scheduled_report(schedule=schedule)
            if error:
                logger.error(f"Report schedule {schedule.name} failed: {error}")
        except Exception as error:
            logger.error(f"Report schedule {schedule.name} failed: {error}")


def _one_line(value: Optional[str]) -> Optional[str]:
    return " ".join(value.splitlines()) if value else value


@app.task
def email_report(
    template_name: str,
    recipients: Optional[List[str]] = None,
    body: Optional[str] = None,
    subject: Optional[str] = None,
    attachment_name: Optional[str] = None,
    report_link: Optional[str] = None,
    attachment: Optional[str] = None,
    attachment_type: Optional[str] = None,
    attachment_extension: Optional[str] = None,
    include_report_link: bool = False,
) -> None:
    subject = _one_line(subject) or f"Scheduled Report: {template_name}"
    body = body or "Your report is attached."
    # schedules saved before email_settings were validated can hold anything
    if not (
        isinstance(attachment_extension, str)
        and EXTENSION_RE.fullmatch(attachment_extension)
    ):
        attachment_extension = None
    if attachment_type == "html" and include_report_link is True and report_link:
        body += f"\n\nView the report online:\n\n{report_link}"

    content = attachment
    if attachment is not None and attachment_type == "pdf":
        # pdf bytes travel base64 encoded through the json broker
        content = base64.b64decode(attachment)
    if attachment_type not in ATTACHMENT_TYPES:
        content = None

    message, ok = get_core_settings().send_mail(
        subject=subject,
        body=body,
        attachment=content,
        attachment_filename=_one_line(attachment_name) or template_name,
        attachment_type=attachment_type,
        attachment_extension=attachment_extension,
        override_recipients=recipients or [],
    )
    if not ok:
        logger.error(f"Report email for {template_name} was not sent: {message}")

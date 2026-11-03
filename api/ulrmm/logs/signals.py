# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import datetime

from django.db.models.signals import post_init
from django.dispatch import receiver

from ulrmm.constants import PAAction, PAStatus
from ulrmm.helpers import date_is_in_past

from .models import PendingAction


@receiver(post_init, sender=PendingAction)
def complete_past_reboots(sender, instance, **kwargs) -> None:
    """A scheduled reboot whose time has passed is done; mark it on load."""
    if not instance.pk:
        return
    if instance.get_deferred_fields() & {"action_type", "status", "details"}:
        return
    if instance.action_type != PAAction.SCHED_REBOOT:
        return
    if instance.status != PAStatus.PENDING:
        return
    try:
        when = datetime.strptime(instance.details["time"], "%Y-%m-%d %H:%M:%S")
        passed = date_is_in_past(datetime_obj=when, agent_tz=instance.agent.timezone)
    except (KeyError, TypeError, ValueError):
        # malformed details must not break every load of this row
        return
    if passed:
        instance.status = PAStatus.COMPLETED
        PendingAction.objects.filter(pk=instance.pk, status=PAStatus.PENDING).update(
            status=PAStatus.COMPLETED
        )

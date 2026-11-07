# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import datetime as dt

from django.db.models import F
from django.utils import timezone as djangotime

from alerts.models import Alert
from alerts.tasks import notify_once
from core.utils import get_core_settings
from ulrmm.celery import app
from ulrmm.constants import NETMON_POLL_LOCK, AlertSeverity
from ulrmm.utils import redis_lock

from .models import DeviceStatus, NetworkDevice, probe_scope
from .probe import clean, probe_all

FAILING = (DeviceStatus.DOWN, DeviceStatus.DEGRADED)


def record(device: NetworkDevice, result: dict, checked: dt.datetime) -> None:
    """Stores a probe result and raises or resolves the device's alert."""
    status = result["status"]
    if status in FAILING:
        device.fail_count += 1
    elif status == DeviceStatus.UP:
        device.fail_count = 0
    device.status = status
    device.last_checked = checked
    device.last_result = result
    # update(), so the poller never lands in the audit log
    NetworkDevice.objects.filter(pk=device.pk).update(
        status=status,
        fail_count=device.fail_count,
        last_checked=device.last_checked,
        last_result=result,
    )

    if status in FAILING and device.fail_count >= device.fails_b4_alert:
        Alert.handle_alert_failure(device)
    elif (
        status == DeviceStatus.UP
        and Alert.objects.filter(network_device=device, resolved=False).exists()
    ):
        Alert.handle_alert_resolve(device)


@app.task(soft_time_limit=55)
def poll_network_devices() -> str:
    with redis_lock(NETMON_POLL_LOCK, poll_network_devices.app.oid) as acquired:
        if not acquired:
            return "already running"

        now = djangotime.now()
        devices = [
            d
            for d in NetworkDevice.objects.filter(enabled=True)
            .select_related("site__client")
            .order_by(F("last_checked").asc(nulls_first=True))
            # a few seconds early, the beat fires once a minute
            if not d.last_checked
            or d.last_checked + dt.timedelta(seconds=d.interval - 5) <= now
        ]
        if not devices:
            return "ok"

        networks, own = probe_scope()
        targets, due = [], []
        for device in devices:
            try:
                targets.append(device.probe_target(networks, own))
                due.append(device)
            except ValueError as e:
                error = {"status": DeviceStatus.ERROR, "error": str(e), "ports": {}}
                record(device, error, now)

        for device, result in zip(due, asyncio.run(probe_all(targets))):
            if result:
                record(device, result, now)

    return "ok"


def _notify(pk: int, channel: str, resolved: bool, alert_interval=None) -> str:
    alert = (
        Alert.objects.select_related("network_device__site__client")
        .filter(pk=pk, network_device__isnull=False)
        .first()
    )
    if not alert:
        return "alert not found"

    field = f"{'resolved_' if resolved else ''}{channel}_sent"
    return notify_once(
        alert, field, lambda: _send(alert, channel, resolved), alert_interval
    )


def _send(alert: Alert, channel: str, resolved: bool) -> tuple[str, bool]:
    device = alert.network_device
    site = device.site
    if resolved:
        state = "is back up"
    else:
        # a failing monitor raises the severity, the device still answers
        down = alert.severity == AlertSeverity.ERROR
        if down and device.status != DeviceStatus.DEGRADED:
            state = "is down"
        else:
            state = "is degraded"
    # user and device supplied text, one printable line
    subject = clean(f"{site.client.name}, {site.name}, {device} {state}", 200)
    text = subject
    if not resolved and (summary := device.summary()):
        text += f": {summary}"

    core = get_core_settings()
    template = device.get_alert_template()
    if channel == "email":
        return core.send_mail(subject, text, alert_template=template)
    return core.send_sms(text, alert_template=template)


@app.task
def network_alert_email_task(pk: int, alert_interval=None) -> str:
    return _notify(pk, "email", False, alert_interval)


@app.task
def network_alert_sms_task(pk: int, alert_interval=None) -> str:
    return _notify(pk, "sms", False, alert_interval)


@app.task
def network_resolved_email_task(pk: int) -> str:
    return _notify(pk, "email", True)


@app.task
def network_resolved_sms_task(pk: int) -> str:
    return _notify(pk, "sms", True)

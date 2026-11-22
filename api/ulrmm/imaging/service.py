# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from accounts.utils import has_superuser_rights
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType, AuditObjType, GoArch
from ulrmm.permissions import agent_perm_check

from .models import ACTIVE_STATUSES, Image, NativeInventory, Pairing

CHANGED_PATH = "Waiting for the configured internal imaging ingress."


def agent_allowed(user, agent, *flags):
    if (
        not user.is_authenticated
        or not user.is_active
        or user.is_installer_user
        or user.agent_id
        or user.block_dashboard_login
    ):
        return False
    if has_superuser_rights(user):
        return True
    role = user.role
    return bool(
        role
        and any(getattr(role, flag) for flag in flags)
        and agent_perm_check(user)(agent)
    )


def capability(agent):
    report = NativeInventory.objects.filter(agent=agent).first()
    if report:
        data = report.capability
        return {
            "supported": bool(
                data.get("method")
                and data.get("source_id")
                and data.get("device_uuid")
                and (data.get("ready") or data["method"] == "linux-offline-disk-v1")
            ),
            "reason": data["reason"],
            "native": data,
            "observed_at": report.observed_at,
        }

    if agent.plat != AgentPlat.LINUX:
        return {
            "supported": False,
            "reason": "Waiting for this device to report its native backup capability.",
        }
    if agent.goarch and agent.goarch != GoArch.AMD64:
        return {
            "supported": False,
            "reason": "Linux recovery requires an x86-64 device with a DMI system UUID.",
        }
    return {
        "supported": True,
        "reason": (
            "Offline recovery checks for an x86-64 device, DMI system UUID, and a clean single "
            "Linux disk with an ext4 system partition."
        ),
    }


def storage_encryption(destination):
    confirmed = destination in settings.ULRMM_IMAGING_ENCRYPTED_DESTINATIONS
    if confirmed:
        return "Backup volume encryption confirmed by the storage administrator."
    return "No application-layer encryption. Encryption of this backup volume is unconfirmed."


def origin(mode):
    raw = (
        settings.ULRMM_IMAGING_INTERNAL_ORIGIN
        if mode == "internal"
        else settings.ULRMM_IMAGING_PUBLIC_ORIGIN
    ).rstrip("/")
    url = urlsplit(raw)
    if (
        url.scheme == "https"
        and url.hostname
        and not url.username
        and not url.password
        and not url.path
        and not url.query
        and not url.fragment
    ):
        return f"https://{url.netloc.lower()}"
    return ""


def check_path(request, mode):
    if (
        not request.is_secure()
        or origin(mode) != f"https://{request.get_host().lower()}"
    ):
        raise PermissionDenied(
            CHANGED_PATH
            if mode == "internal"
            else "Use the configured HTTPS imaging origin."
        )
    if mode == "internal":
        try:
            peer = ip_address(request.META.get("ULRMM_IMAGING_INTERNAL_PEER", ""))
            networks = [
                ip_network(entry) for entry in settings.ULRMM_IMAGING_INTERNAL_CIDRS
            ]
        except ValueError:
            raise PermissionDenied(CHANGED_PATH) from None
        if not any(peer in network for network in networks):
            raise PermissionDenied(CHANGED_PATH)


def next_run(profile, after):
    if profile.schedule_time is None:
        return None
    local = after.astimezone(ZoneInfo(profile.timezone))
    candidate = datetime.combine(local.date(), profile.schedule_time, local.tzinfo)
    if candidate.astimezone(UTC) <= after:
        candidate += timedelta(days=1)
    return candidate.astimezone(UTC)


def queue_capture(profile, username, operator=None):
    image = Image.objects.filter(
        agent=profile.agent, status__in=ACTIVE_STATUSES
    ).first()
    if image:
        return image
    operator = operator or profile.operator
    # An offline Linux point is claimed by its rescue pairing, not the operator.
    if (
        operator is None
        and not Pairing.objects.filter(
            agent=profile.agent, expires_at__gt=timezone.now()
        ).exists()
    ):
        audit(
            profile.agent,
            username,
            "Client imaging capture skipped: no backup operator is left. Save the imaging configuration again.",
        )
        return None
    native = capability(profile.agent).get("native")
    if not profile.policy_id and Pairing.objects.filter(agent=profile.agent).exists():
        native = None
    if native:
        native = {
            **native,
            "storage_encryption": storage_encryption(profile.destination),
        }
    image = Image.objects.create(
        native=native,
        operator=operator,
        **(
            {
                "disk_id": native["source_id"],
                "device_uuid": native["device_uuid"],
                "reason": (native["reason"] or "Waiting for the native agent.")[:255],
            }
            if native
            else {}
        ),
        agent=profile.agent,
        destination=profile.destination,
        network_mode=profile.network_mode,
        compression=profile.compression,
        compression_level=profile.compression_level,
    )
    audit(
        profile.agent,
        username,
        f"Client imaging capture queued for image {image.id}.",
        AuditActionType.ADD,
    )
    if native:
        from .tasks import wake_imaging_agent

        transaction.on_commit(
            lambda: wake_imaging_agent.delay(profile.agent.agent_id), robust=True
        )
    return image


def audit(agent, username, message, action=AuditActionType.MODIFY):
    AuditLog.objects.create(
        object_type=AuditObjType.AGENT,
        action=action,
        message=message,
        username=username,
        agent=agent.hostname if agent else "",
        agent_id=agent.agent_id if agent else "",
    )


def set_status(image, status, reason):
    image.status = status
    image.reason = reason
    image.updated_at = timezone.now()
    image.save(update_fields=["status", "reason", "updated_at"])

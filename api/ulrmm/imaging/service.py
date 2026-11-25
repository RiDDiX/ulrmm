# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from django.conf import settings
from django.db import transaction
from django.db.models import BigIntegerField, Sum
from django.db.models.expressions import RawSQL
from django.db.models.functions import Cast
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from accounts.utils import has_superuser_rights
from logs.models import AuditLog
from ulrmm.constants import AgentPlat, AuditActionType, AuditObjType, GoArch
from ulrmm.permissions import agent_perm_check

from .models import (
    ACTIVE_STATUSES,
    LINUX_FILES_METHOD,
    LINUX_OFFLINE_METHOD,
    SELECTABLE_KINDS,
    BackupPolicy,
    DeviceBackupState,
    Image,
    ImageBlock,
    ImagePart,
    ImageStatus,
    NativeInventory,
    Pairing,
    Profile,
    StorageTarget,
    Trigger,
)

CHANGED_PATH = "Waiting for the configured internal imaging ingress."
VOLUME_KEYS = {"id", "mount", "kind", "size"}
BAD_REPORT = (
    "The last capability report of this device is incomplete. "
    "Waiting for the next report of the agent."
)
NO_INTERNAL = (
    "Internal-only transfers need the internal imaging listener "
    "(ULRMM_IMAGING_INTERNAL_ORIGIN and ULRMM_IMAGING_INTERNAL_CIDRS). "
    "Choose internet upload or set up the listener."
)


def has_flag(user, *flags):
    """An active dashboard user whose role holds one of the flags."""
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
    return bool(role and any(getattr(role, flag) for flag in flags))


def agent_allowed(user, agent, *flags):
    return has_flag(user, *flags) and (
        has_superuser_rights(user) or agent_perm_check(user)(agent)
    )


def covers(target, client_id, site_id):
    """Whether a target (a resolver table entry) holds points of this client and site."""
    return (
        target["scope"] == "global"
        or (target["scope"] == "client" and target["client"] == client_id)
        or (target["scope"] == "site" and target["site"] == site_id)
    )


def not_covered(target):
    return f"Backup target {target['name']} does not cover this device."


def capability(agent):
    report = NativeInventory.objects.filter(agent=agent).first()
    if report:
        data = report.capability
        volumes = data.get("volumes", [])
        # a report stored by an older server or agent lacks keys the server reads;
        # the next poll replaces it
        if not isinstance(volumes, list) or not all(
            isinstance(v, dict) and VOLUME_KEYS <= set(v) for v in volumes
        ):
            return {"supported": False, "reason": BAD_REPORT}
        return {
            "supported": bool(
                data.get("method")
                and data.get("source_id")
                and data.get("device_uuid")
                and (data.get("ready") or data["method"] == LINUX_OFFLINE_METHOD)
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


def internal_available():
    return bool(origin("internal") and settings.ULRMM_IMAGING_INTERNAL_CIDRS)


def backup_rows(agent, lock=False):
    """(Profile, DeviceBackupState) of a device, created when missing."""
    target = StorageTarget.objects.filter(is_default=True).first()
    profiles = Profile.objects.select_for_update() if lock else Profile.objects
    profile, _ = profiles.get_or_create(
        agent=agent,
        defaults={
            "network_mode": "internet",
            "target": target,
            "destination": target.name if target else "images",
        },
    )
    states = (
        DeviceBackupState.objects.select_for_update()
        if lock
        else DeviceBackupState.objects
    )
    state, _ = states.get_or_create(agent=agent)
    return profile, state


def update_usage(agent, state):
    """Stored bytes of a device per target, and the target totals."""
    usage = {}
    for target_id in (
        Image.objects.filter(agent=agent, target__isnull=False)
        .values_list("target_id", flat=True)
        .distinct()
    ):
        # the device's own parts first, so the block table is never scanned
        parts = ImagePart.objects.filter(
            image__agent=agent, image__target_id=target_id
        ).values("block_id")
        total = ImageBlock.objects.filter(pk__in=parts).aggregate(
            total=Sum("stored_size")
        )["total"]
        usage[str(target_id)] = total or 0
    touched = set(state.usage) | set(usage)
    state.usage = usage
    state.save(update_fields=["usage", "updated_at"])
    for key in touched:
        used = DeviceBackupState.objects.aggregate(
            total=Sum(
                Cast(RawSQL("usage ->> %s", (key,)), BigIntegerField()), default=0
            )
        )["total"]
        StorageTarget.objects.filter(pk=int(key)).update(used_bytes=used)


def usage_later(agent_pk):
    """Recompute a device's usage after the commit, outside the image locks."""

    def recompute():
        from agents.models import Agent

        agent = Agent.objects.filter(pk=agent_pk).first()
        if agent is not None:
            update_usage(agent, backup_rows(agent)[1])

    transaction.on_commit(recompute, robust=True)


def keep_blocks(image):
    # dropped parts leave their blocks to the sweep; a fresh grace lets the next run reuse them
    ImageBlock.objects.filter(imagepart__image=image).update(created_at=timezone.now())


def script_names(ids):
    from scripts.models import Script

    return dict(Script.objects.filter(pk__in=set(ids)).values_list("pk", "name"))


def masked_hooks(hooks, show_args, names=None):
    """Hooks for an answer: env values never, args only for script users; the
    script name for everyone."""
    if names is None:
        names = script_names(h["script_id"] for h in hooks)
    out = []
    for hook in hooks:
        row = {k: v for k, v in hook.items() if k not in ("args", "env_vars")}
        script = names.get(hook["script_id"], "")
        row["script_name"] = getattr(script, "name", script)
        if show_args:
            row["args"] = hook.get("args", [])
        else:
            row["args_count"] = len(hook.get("args", []))
        row["env_vars"] = [
            {"name": name, "value": "", "has_value": bool(value)}
            for name, _, value in (e.partition("=") for e in hook.get("env_vars", []))
        ]
        out.append(row)
    return out


def script_hash(script):
    return hashlib.sha256((script.shell + "\x00" + script.code).encode()).hexdigest()


def suspended_hooks(hooks, pinned, origin=None, scripts=None):
    """Hooks whose script changed or is gone since its hash was pinned."""
    from scripts.models import Script

    if scripts is None:
        scripts = Script.objects.in_bulk([h["script_id"] for h in hooks])
    out = []
    for hook in hooks:
        script = scripts.get(hook["script_id"])
        current = script_hash(script) if script else ""
        if not script or current != (pinned or {}).get(str(hook["script_id"])):
            out.append(
                {
                    "script_id": hook["script_id"],
                    "name": script.name if script else "",
                    "script_name": script.name if script else "",
                    "sha256": current,
                    **(
                        {"origin": {"level": origin["level"], "id": origin["id"]}}
                        if origin
                        else {}
                    ),
                }
            )
    return out


def keyed_hooks(hooks, sources, where):
    """Hooks of a save with their server keys, a kept environment value taken
    from the stored hook with the same key (contract 19.26 and 19.29)."""
    from rest_framework.exceptions import ValidationError

    out, used = [], set()
    for hook in hooks:
        key = hook.get("key")
        match = next(
            (h for source in sources for h in source if key and h.get("key") == key),
            None,
        )
        if match is None or key in used:
            match, key = None, secrets.token_hex(4)
        used.add(key)
        env = []
        for entry in hook["env_vars"]:
            if isinstance(entry, str):
                env.append(entry)
                continue
            stored = [
                e
                for e in (match or {}).get("env_vars", [])
                if e.partition("=")[0] == entry["name"]
            ]
            if not stored:
                raise ValidationError(
                    {
                        where: {
                            "hooks": [
                                f"Environment value {entry['name']} has no stored value."
                            ]
                        }
                    }
                )
            env.append(stored[0])
        out.append({**hook, "key": key, "env_vars": env})
    return out


def raise_alert(agent, state, kind, severity, message, body=""):
    """One open backup alert per device and kind (contract 10.1); `message` is
    fixed per kind, the device's own text goes to `body` only."""
    from alerts.models import Alert
    from notify.dispatch import dispatch

    if (
        kind in state.alerts
        and Alert.objects.filter(pk=state.alerts[kind], resolved=False).exists()
    ):
        return
    # a flapping condition reopens its alert of the last hour instead of a new one
    recent = (
        Alert.objects.filter(
            agent=agent,
            alert_type="backup",
            message=message,
            alert_time__gte=timezone.now() - timedelta(hours=1),
        )
        .order_by("-alert_time")
        .first()
    )
    if recent:
        Alert.objects.filter(pk=recent.pk).update(resolved=False, resolved_on=None)
        state.alerts = {**state.alerts, kind: recent.pk}
        return
    alert = Alert.objects.create(
        agent=agent, alert_type="backup", severity=severity, message=message
    )
    state.alerts = {**state.alerts, kind: alert.pk}
    dispatch(
        {
            "source": "backup",
            "severity": severity,
            "title": f"{agent.hostname}: {message}",
            "body": body or message,
            "agent": agent,
            "alert": alert,
            "dedupe_key": f"alert:{alert.pk}:{severity}",
            "dedupe_hours": 0,
        }
    )


def clear_alert(state, kind):
    from alerts.models import Alert
    from notify.dispatch import notify_alert

    alerts = dict(state.alerts)
    pk = alerts.pop(kind, None)
    state.alerts = alerts
    alert = pk and Alert.objects.filter(pk=pk, resolved=False).first()
    if alert:
        alert.resolve()
        notify_alert(alert, resolved=True)


def scope_blockers(clients=(), sites=(), groups=(), tags=()):
    """The refusal text when a backup policy or target names one of these."""
    from django.db.models import Q

    hit = Q(client__in=clients) | Q(site__in=sites) | Q(site__client__in=clients)
    policies = BackupPolicy.objects.filter(
        hit | Q(group__in=groups) | Q(tag__in=tags)
    ).order_by("name")
    targets = StorageTarget.objects.filter(hit).order_by("name")
    parts = []
    if names := list(policies.values_list("name", flat=True)):
        parts.append(f"the backup policies {', '.join(names)}")
    if names := list(targets.values_list("name", flat=True)):
        parts.append(f"the backup targets {', '.join(names)}")
    return f"Remove {' and '.join(parts)} first." if parts else ""


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


def queue_capture(profile, username, operator=None, trigger=Trigger.MANUAL):
    scheduled = trigger != Trigger.MANUAL
    active = Image.objects.filter(agent=profile.agent, status__in=ACTIVE_STATUSES)
    if not scheduled and (image := active.first()):
        return image
    # a point that a verification or a claim holds is open; the schedule never
    # waits on it (untested: a held row lock needs a second database connection)
    image = active.select_for_update(skip_locked=True).first()
    if image is None and active.exists():
        return None
    replaced = None
    if image:
        # only an unclaimed waiting native point of a schedule or event gives way
        if not (
            image.native
            and image.native.get("method") != LINUX_OFFLINE_METHOD
            and image.trigger in (Trigger.SCHEDULE, Trigger.EVENT)
            and image.status == ImageStatus.WAITING
            and not image.transfer_set.filter(
                direction="capture", expires_at__gt=timezone.now()
            ).exists()
        ):
            # the scheduler tries again soon, so an open point writes no audit row
            return None
        replaced = image.pk
        keep_blocks(image)
        image.delete()
        usage_later(profile.agent_id)
    # scheduled and event points run on the policy's authority (9.2)
    operator = None if scheduled else operator or profile.operator
    # An offline Linux point is claimed by its rescue pairing, not the operator.
    if (
        not scheduled
        and operator is None
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
    failed = ""
    if not profile.policy_id and Pairing.objects.filter(agent=profile.agent).exists():
        native = None
        if profile.volumes:
            # the paired offline capture holds the system disk only
            failed = (
                "Selected volumes need the live backup. "
                "Unpair offline capture or untick the volumes."
            )
    if native:
        native = {
            **native,
            "storage_encryption": storage_encryption(profile.destination),
        }
    volumes_from_policy = profile.policy_id is not None
    if profile.effective:
        from .resolver import effective

        level = effective(profile.agent)["fields"]["volumes"]["origin"]["level"]
        volumes_from_policy = level != "device"
    if native and native["method"] == LINUX_FILES_METHOD:
        volumes = native.get("volumes", [])
        by_mount = {v["mount"]: v for v in volumes}
        include = [v["id"] for v in volumes if v["kind"] == "system"]
        missing = []
        for selector in profile.volumes:
            v = by_mount.get(selector)
            if v and v["kind"] in SELECTABLE_KINDS:
                include.append(v["id"])
            elif not v or v["kind"] != "system":
                missing.append(selector)
        native.update(
            include=include,
            missing=missing,
            stream_limit=sum(v["size"] for v in volumes if v["id"] in include),
        )
        # a policy's selectors may not exist on every device, the device's own must
        if missing and not volumes_from_policy:
            gone = by_mount.get(missing[0])
            failed = (
                f"Selected volume {missing[0]} cannot be backed up: {gone['reason']}"
                if gone and gone["kind"] != "unmounted" and gone.get("reason")
                else f"Selected volume {missing[0]} is not mounted."
            )[:255]
    elif native and native["method"] == LINUX_OFFLINE_METHOD and profile.volumes:
        # the offline image holds the system disk only
        native["missing"] = list(profile.volumes)
        if not volumes_from_policy:
            failed = (
                f"Selected volumes need the live backup. {native.get('reason') or ''}"
            ).strip()[:255]
    from .resolver import table

    target = table()["targets"].get(profile.target_id)
    site = profile.agent.site
    if target and not covers(target, site.client_id, site.pk):
        failed = not_covered(target)
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
        target_id=profile.target_id,
        client_id=profile.agent.site.client_id,
        trigger=trigger,
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
    if replaced:
        audit(
            profile.agent,
            username,
            f"Waiting backup point {replaced} replaced by {image.id}.",
        )
    if failed:
        set_status(image, ImageStatus.FAILED, failed)
        audit(profile.agent, username, f"Image {image.id} failed: {failed}")
    elif native:
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
    if status in (ImageStatus.FAILED, ImageStatus.VERIFYING):
        from .runs import point_changed

        point_changed(image)

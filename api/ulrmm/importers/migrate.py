# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Moves imported devices over: the source runs the ulrmm installer on them.

Windows and Linux get a one-liner that loads the installer from a
deployment link made for this run (one per site and agent type, valid for
DEPLOY_DAYS, as many enrollments as devices). macOS gets the installer
token command of the Install Agent dialog, valid for DEPLOY_DAYS as well.
The link or token passes through the other RMM and its logs, which is why
both expire and are capped. Enrolled agents link through link.on_enroll."""

import base64
import datetime as dt
from collections import defaultdict

from django.conf import settings
from django.db import transaction
from django.utils import timezone as djangotime
from knox.models import AuthToken

from accounts.models import User
from clients.models import Deployment, InstallerToken
from deploy import signing
from logs.models import AuditLog
from ulrmm.constants import AgentMonType, AgentPlat, AuditActionType, AuditObjType

from .models import ImportedDevice, MigrateState
from .sources import SourceError, for_source

DEPLOY_DAYS = 3


class MigrateError(Exception):
    pass


def _installer_user():
    user = User.objects.filter(is_installer_user=True).order_by("pk").first()
    if user is None:
        raise MigrateError("No installer user exists. Run create_installer_user first.")
    return user


def _deployment(source, site, mon_type: str, goarch: str, count: int, expiry):
    with transaction.atomic():
        deployment = Deployment.objects.create(
            site=site,
            name=f"Import from {source.name}"[:100],
            expiry=expiry,
            mon_type=mon_type,
            goarch=goarch,
            install_flags={"power": False, "ping": False, "rdp": False},
            max_enrollments=count,
        )
        AuditLog.objects.create(
            username="importer",
            object_type=AuditObjType.SITE,
            action=AuditActionType.ADD,
            message=f"importer added a deployment for site {site.name}",
            after_value={
                "source": source.name,
                "mon_type": mon_type,
                "expiry": expiry.isoformat(),
                "max_enrollments": count,
            },
        )
    return deployment


def deploy_link(deployment, fmt: str, arch: str = "") -> str:
    q = f"fmt={fmt}" + (f"&arch={arch}" if arch else "")
    return f"{signing.api_url()}/clients/{deployment.uid}/deploy/?{q}"


def windows_command(deployment, arch: str) -> str:
    url = deploy_link(deployment, "ps1", arch)
    return (
        "[Net.ServicePointManager]::SecurityProtocol = "
        "[Net.SecurityProtocolType]::Tls12; "
        f"Invoke-RestMethod -UseBasicParsing '{url}' | Invoke-Expression"
    )


def linux_command(deployment) -> str:
    url = deploy_link(deployment, "sh")
    f = "/tmp/ulrmm-install.sh"
    return (
        f"curl -fsSL --proto '=https' --proto-redir '=https' -o {f} '{url}' "
        f"&& bash {f}; rc=$?; rm -f {f}; exit $rc"
    )


def mac_command(site, mon_type: str, goarch: str, installer, hours: int):
    """(command, token row) of the Install Agent dialog's macOS method."""
    from agents import views

    auth_token, token = AuthToken.objects.create(
        user=installer, expiry=dt.timedelta(hours=hours)
    )
    InstallerToken.objects.create(auth_token=auth_token, site=site)
    response = views._installer_body(
        method="mac",
        plat=AgentPlat.DARWIN,
        inno=views.agent_artifact(settings.LATEST_AGENT_VER, AgentPlat.DARWIN, goarch),
        download_url=views.get_install_agent_url(goarch=goarch, plat=AgentPlat.DARWIN),
        client=str(site.client_id),
        site=str(site.pk),
        agent_type=mon_type,
        api=signing.api_url(),
        token=token,
        switches={"rdp": False, "ping": False, "power": False},
        server_cert=views.self_signed_cert_pem(),
        goarch=goarch,
    )
    return response.data["cmd"], auth_token


def detached(plat: str, command: str) -> str:
    """The installer runs longer than other RMMs wait for a command and
    would be killed at their timeout; this starts it on its own and returns
    at once. Its output goes to /tmp/ulrmm-import.log on Linux and macOS."""
    if plat == AgentPlat.WINDOWS:
        encoded = base64.b64encode(command.encode("utf-16-le")).decode()
        return (
            "Start-Process -WindowStyle Hidden -FilePath powershell.exe "
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',"
            f"'-EncodedCommand','{encoded}'"
        )
    f = "/tmp/ulrmm-import.sh"
    # the file holds the link or token, it removes itself
    body = f"trap 'rm -f {f}' EXIT\n{command}\n"
    encoded = base64.b64encode(body.encode()).decode()
    return (
        f"umask 077 && echo {encoded} | base64 --decode > {f} && "
        "S=$(command -v setsid || true) && "
        f"(cd /tmp && $S nohup bash {f} > /tmp/ulrmm-import.log 2>&1 < /dev/null &)"
    )


def _arch(device, plat: str) -> str:
    if plat == AgentPlat.WINDOWS:
        return device.goarch if device.goarch in ("amd64", "386") else "amd64"
    if plat == AgentPlat.DARWIN:
        return device.goarch if device.goarch in ("amd64", "arm64") else "arm64"
    return ""


def _fail(device, error: str) -> None:
    device.migrate_state = MigrateState.FAILED
    device.migrate_error = error[:500]
    device.save(update_fields=["migrate_state", "migrate_error"])


def send(source, device_ids) -> dict:
    """Sends the installer to the chosen devices that are not linked yet."""
    if getattr(settings, "ULRMM_INSECURE", False):
        raise MigrateError("Not available in insecure mode")
    client = for_source(source)
    installer = _installer_user()
    devices = list(
        ImportedDevice.objects.filter(
            source=source, pk__in=device_ids, agent=None
        ).select_related("site__client")
    )
    result = {"sent": 0, "failed": 0, "skipped": len(device_ids) - len(devices)}

    groups = defaultdict(list)
    for d in devices:
        if d.site is None:
            _fail(d, "no site, assign one first")
            result["failed"] += 1
            continue
        if d.plat not in client.PUSH_PLATS:
            _fail(
                d,
                f"{source.get_kind_display()} cannot run commands on {d.plat or 'this platform'}",
            )
            result["failed"] += 1
            continue
        mon = d.monitoring_type or AgentMonType.WORKSTATION
        groups[(d.site, d.plat, mon, _arch(d, d.plat))].append(d)

    expiry = djangotime.now() + dt.timedelta(days=DEPLOY_DAYS)
    for (site, plat, mon, arch), batch in groups.items():
        url = ""
        try:
            if plat == AgentPlat.DARWIN:
                command, credential = mac_command(
                    site, mon, arch, installer, DEPLOY_DAYS * 24
                )
            else:
                credential = _deployment(
                    source, site, mon, arch or "amd64", len(batch), expiry
                )
                if plat == AgentPlat.WINDOWS:
                    command = windows_command(credential, arch)
                    url = deploy_link(credential, "ps1", arch)
                else:
                    command = linux_command(credential)
                    url = deploy_link(credential, "sh")
        except Exception as e:
            for d in batch:
                _fail(d, f"no installer: {e}")
            result["failed"] += len(batch)
            continue
        sent = 0
        for d in batch:
            try:
                client.push(d.ref, plat, detached(plat, command), url)
            except SourceError as e:
                _fail(d, str(e))
                result["failed"] += 1
                continue
            d.migrate_state = MigrateState.SENT
            d.migrate_error = ""
            d.sent_at = djangotime.now()
            d.save(update_fields=["migrate_state", "migrate_error", "sent_at"])
            sent += 1
        result["sent"] += sent
        if not sent:
            # a link or token nobody got is not left lying around
            credential.delete()
    return result

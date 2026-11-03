# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import socket
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Optional

import psutil
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models

from core.utils import get_core_settings
from logs.models import BaseAuditModel
from remote.utils import decrypt_secret
from ulrmm.constants import AlertSeverity, AlertType
from ulrmm.helpers import has_script_actions, has_webhook
from ulrmm.models import PermissionQuerySet

from .probe import AUTH_PROTOCOLS, address_error, clean, own_ok

if TYPE_CHECKING:
    from alerts.models import Alert, AlertTemplate

# never change: stored secrets could no longer be decrypted
HKDF_INFO = b"netmon.NetworkDevice.snmp"
MAX_DEVICES = 256


class SnmpVersion(models.TextChoices):
    OFF = "off", "Off"
    V2C = "v2c", "v2c"
    V3 = "v3", "v3 (authPriv, AES-128)"


class DeviceStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    UP = "up", "Up"
    DEGRADED = "degraded", "Degraded"
    DOWN = "down", "Down"
    ERROR = "error", "Error"


def probe_scope() -> tuple[set[IPv4Network], set[IPv4Address]]:
    """(probeable nets, own addrs). attached privates + NETMON_ALLOWED_NETWORKS."""
    from agents.utils import server_networks

    own = {
        IPv4Address(a.address)
        for addrs in psutil.net_if_addrs().values()
        for a in addrs
        if a.family == socket.AF_INET
    }
    nets = {
        n
        for n in server_networks()
        if n.is_private and not n.is_loopback and not n.is_link_local
    }
    nets |= {IPv4Network(n) for n in getattr(settings, "NETMON_ALLOWED_NETWORKS", ())}
    return nets, own


class NetworkDevice(BaseAuditModel):
    objects = PermissionQuerySet.as_manager()

    site = models.ForeignKey(
        "clients.Site", related_name="network_devices", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    # an IPv4 literal, never a name, see probe.address_error
    host = models.GenericIPAddressField(protocol="IPv4")
    enabled = models.BooleanField(default=True)
    maintenance_mode = models.BooleanField(default=False)
    interval = models.PositiveIntegerField(default=300)  # seconds
    ping = models.BooleanField(default=True)
    tcp_ports = ArrayField(models.PositiveIntegerField(), default=list, blank=True)
    snmp_version = models.CharField(
        max_length=5, choices=SnmpVersion.choices, default=SnmpVersion.OFF
    )
    snmp_port = models.PositiveIntegerField(default=161)
    snmp_v3_user = models.CharField(max_length=32, blank=True, default="")
    snmp_v3_auth_proto = models.CharField(
        max_length=10,
        choices=[
            (k, "SHA-1" if k == "sha" else f"SHA-{k[3:]}") for k in AUTH_PROTOCOLS
        ],
        default="sha256",
    )
    # Fernet token of {"community"} or {"auth_key", "priv_key"}, never returned
    snmp_secret = models.TextField(blank=True, default="")
    # HTTP(S) and DNS monitors, validated by serializers.MonitorSerializer
    monitors = models.JSONField(default=list, blank=True)
    fails_b4_alert = models.PositiveIntegerField(default=2)
    dashboard_alert = models.BooleanField(default=False)
    email_alert = models.BooleanField(default=False)
    text_alert = models.BooleanField(default=False)

    # written by the poller with update(), left out of the audit log
    status = models.CharField(
        max_length=10, choices=DeviceStatus.choices, default=DeviceStatus.PENDING
    )
    last_checked = models.DateTimeField(null=True, blank=True)
    fail_count = models.PositiveIntegerField(default=0)
    last_result = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.host})"

    @staticmethod
    def serialize(device):
        from . import serializers

        return serializers.NetworkDeviceAuditSerializer(device).data

    def secret(self) -> dict:
        """Raises cryptography.fernet.InvalidToken after a SECRET_KEY change."""
        if not self.snmp_secret:
            return {}
        return json.loads(decrypt_secret(self.snmp_secret, HKDF_INFO))

    def probe_target(self, networks, own) -> dict:
        """Arguments for probe.probe. ValueError says why this device is not
        probed. The address is checked again here, the networks can change."""
        target = {
            "host": self.host,
            "ping": self.ping,
            "tcp_ports": list(self.tcp_ports),
            "snmp": self.snmp_version != SnmpVersion.OFF,
            "monitors": list(self.monitors),
        }
        if reason := address_error(self.host, networks, own, own_ok(target)):
            raise ValueError(reason)
        if target["snmp"]:
            try:
                secret = self.secret()
            except Exception:
                secret = {}
            keys = ("community",) if self.snmp_version == SnmpVersion.V2C else ()
            keys = keys or ("auth_key", "priv_key")
            if not all(secret.get(k) for k in keys):
                raise ValueError("The SNMP credentials must be entered again.")
            target["snmp"] = {
                "port": self.snmp_port,
                "version": self.snmp_version,
                "secret": {k: secret[k] for k in keys},
                "user": self.snmp_v3_user,
                "auth_proto": self.snmp_v3_auth_proto,
            }
        else:
            target["snmp"] = None
        return target

    def summary(self) -> str:
        """One line about the last result for notifications."""
        r = self.last_result or {}
        parts = []
        if r.get("error"):
            parts.append(r["error"])
        if r.get("ping") is False:
            parts.append("no ping reply")
        closed = [p for p, is_open in (r.get("ports") or {}).items() if not is_open]
        if closed:
            parts.append("closed: " + ", ".join(closed))
        if (r.get("snmp") or {}).get("error"):
            parts.append("SNMP: " + r["snmp"]["error"])
        for m in r.get("monitors") or []:
            if m.get("status") != "ok":
                parts.append(f"{m.get('label')}: {m.get('message')}")
        return clean("; ".join(parts), 300)

    @property
    def alert_severity(self) -> str:
        # a failing monitor is an error, a certificate warning is not
        monitors = (self.last_result or {}).get("monitors") or []
        if self.status == DeviceStatus.DOWN or any(
            m.get("status") == "error" for m in monitors
        ):
            return AlertSeverity.ERROR
        return AlertSeverity.WARNING

    def get_alert_template(self) -> "Optional[AlertTemplate]":
        # site, then client, then the default. Devices use the check settings.
        site = self.site
        for template in (
            site.alert_template,
            site.client.alert_template,
            get_core_settings().alert_template,
        ):
            if (
                template
                and template.is_active
                and not template.excluded_sites.filter(pk=site.pk).exists()
                and not template.excluded_clients.filter(pk=site.client_id).exists()
            ):
                return template
        return None

    def should_create_alert(self, alert_template) -> bool:
        if any((self.dashboard_alert, self.email_alert, self.text_alert)):
            return True
        if not alert_template:
            return False
        always = (
            alert_template.check_always_alert,
            alert_template.check_always_email,
            alert_template.check_always_text,
        )
        return (
            any(always)
            or has_webhook(alert_template, "check")
            or has_script_actions(alert_template, "check")
        )

    def get_or_create_alert_if_needed(self, alert_template) -> "Optional[Alert]":
        from alerts.models import Alert

        if self.maintenance_mode:
            return None
        alert = Alert.objects.filter(network_device=self, resolved=False).last()
        if alert or not self.should_create_alert(alert_template):
            return alert
        return Alert.objects.create(
            network_device=self,
            alert_type=AlertType.NETWORK,
            severity=self.alert_severity,
            message=clean(
                f"{self} in {self.site.client.name}, {self.site.name} failed its network checks.",
                500,
            ),
            hidden=True,
        )

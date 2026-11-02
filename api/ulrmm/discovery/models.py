# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

# never change: stored communities could no longer be decrypted
HKDF_INFO = b"discovery.Scan.snmp_community"


class ScanStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


class DeviceState(models.TextChoices):
    NEW = "new", "New"
    AGENT = "agent", "Agent"
    NETMON = "netmon", "Network monitoring"
    IGNORED = "ignored", "Ignored"


class Scan(models.Model):
    networks = models.JSONField(default=list)
    ports = models.JSONField(default=list)
    # Fernet token. left out of responses, deleted when the scan ends
    snmp_community = models.TextField(blank=True, default="")
    snmp = models.BooleanField(default=False)
    status = models.CharField(
        max_length=10, choices=ScanStatus.choices, default=ScanStatus.QUEUED
    )
    started_by = models.CharField(max_length=255, blank=True, default="")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    hosts_total = models.PositiveIntegerField(default=0)
    hosts_up = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True, default="")

    def __str__(self) -> str:
        return f"scan {self.pk} of {', '.join(self.networks)}"


class DiscoveredDevice(models.Model):
    ip = models.GenericIPAddressField(protocol="IPv4", unique=True)
    # set for hosts on a network this server is attached to
    mac = models.CharField(max_length=17, blank=True, default="")
    hostname = models.CharField(max_length=255, blank=True, default="")
    open_ports = models.JSONField(default=list)
    snmp = models.JSONField(default=dict)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField()
    last_scan = models.ForeignKey(
        Scan, null=True, blank=True, related_name="devices", on_delete=models.SET_NULL
    )
    state = models.CharField(
        max_length=10, choices=DeviceState.choices, default=DeviceState.NEW
    )
    # what the last scan matched, kept even while ignored
    agent = models.ForeignKey(
        "agents.Agent",
        null=True,
        blank=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )
    netmon_device = models.ForeignKey(
        "netmon.NetworkDevice",
        null=True,
        blank=True,
        related_name="+",
        on_delete=models.SET_NULL,
    )
    note = models.CharField(max_length=255, blank=True, default="")
    # from the UniFi/OPNsense sync, see integrations.tasks.link
    vlan_id = models.PositiveIntegerField(null=True, blank=True)
    vlan_name = models.CharField(max_length=64, blank=True, default="")
    switch = models.CharField(max_length=128, blank=True, default="")
    port = models.CharField(max_length=32, blank=True, default="")

    def __str__(self) -> str:
        return self.ip

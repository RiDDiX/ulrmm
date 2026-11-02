# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from ulrmm.models import PermissionQuerySet


class Level(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    UNKNOWN = "unknown", "Unknown"


class FindingStatus(models.TextChoices):
    OPEN = "open", "Open"
    FIXED = "fixed", "Fixed"
    IGNORED = "ignored", "Ignored"


class Source(models.TextChoices):
    OSV = "osv", "OSV"
    MSRC = "msrc", "MSRC"
    NVD = "nvd", "NVD"
    VUXML = "vuxml", "VuXML"


class Lookup(models.Model):
    """OSV querybatch answer for one package version, shared by all agents."""

    ecosystem = models.CharField(max_length=64)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=255)
    # [{"id", "modified"}]
    result = models.JSONField(default=list)
    fetched_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["ecosystem", "name", "version"], name="vulns_lookup_unique"
            )
        ]


class Advisory(models.Model):
    vuln_id = models.CharField(max_length=100, unique=True)
    summary = models.CharField(max_length=500, blank=True, default="")
    # text as published (database_specific.severity, Ubuntu priority, ...)
    severity = models.CharField(max_length=32, blank=True, default="")
    # highest CVSS 3.x base score
    score = models.FloatField(null=True, blank=True)
    level = models.CharField(
        max_length=10, choices=Level.choices, default=Level.UNKNOWN
    )
    # {"<ecosystem>|<package>": [fixed versions]}
    fixed = models.JSONField(default=dict)
    modified = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField()

    def __str__(self):
        return self.vuln_id


class Finding(models.Model):
    objects = PermissionQuerySet.as_manager()

    agent = models.ForeignKey(
        "agents.Agent", related_name="vuln_findings", on_delete=models.CASCADE
    )
    package = models.CharField(max_length=255)
    version = models.CharField(max_length=255)
    ecosystem = models.CharField(max_length=64)
    vuln_id = models.CharField(max_length=100)
    advisory = models.ForeignKey(
        Advisory, null=True, blank=True, on_delete=models.SET_NULL
    )
    status = models.CharField(
        max_length=10, choices=FindingStatus.choices, default=FindingStatus.OPEN
    )
    source = models.CharField(max_length=8, choices=Source.choices, default=Source.OSV)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent", "package", "version", "vuln_id"],
                name="vulns_finding_unique",
            )
        ]

    def __str__(self):
        return f"{self.vuln_id} {self.package} {self.version}"


class AgentScan(models.Model):
    agent = models.OneToOneField(
        "agents.Agent", related_name="vuln_scan", on_delete=models.CASCADE
    )
    ecosystem = models.CharField(max_length=64, blank=True, default="")
    scanned_at = models.DateTimeField()
    packages = models.PositiveIntegerField(default=0)
    # packages whose lookup failed this run, their findings were left as they were
    unchecked = models.PositiveIntegerField(default=0)
    # Windows and macOS apps that cpe_map does not know
    unmapped = models.PositiveIntegerField(default=0)


class MsrcMap(models.Model):
    """KB -> CVEs of one monthly MSRC security update document."""

    month = models.CharField(max_length=16)
    kb = models.CharField(max_length=16)
    # [{"id", "title", "severity", "score"}]
    cves = models.JSONField(default=list)
    fetched_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["month", "kb"], name="vulns_msrcmap_unique")
        ]


class NvdLookup(models.Model):
    """NVD answer for one CPE name, shared by all agents."""

    cpe = models.CharField(max_length=255, unique=True)
    # [{"id", "summary", "score", "severity", "fixed"}]
    result = models.JSONField(default=list)
    fetched_at = models.DateTimeField()

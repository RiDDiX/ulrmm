# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from logs.models import BaseAuditModel
from ulrmm.constants import AgentPlat

MIN_TIMEOUT = 60
MAX_TIMEOUT = 7200
# archives carry large manual setups
MAX_ARCHIVE_TIMEOUT = 4 * 60 * 60


class PackageKind(models.TextChoices):
    EXE = "exe", "EXE"
    MSI = "msi", "MSI"
    MSIX = "msix", "MSIX"
    APPX = "appx", "AppX"
    PKG = "pkg", "macOS pkg"
    DEB = "deb", "deb"
    RPM = "rpm", "rpm"
    DRIVER = "driver", "Driver package"
    ARCHIVE = "archive", "Archive"


class RunAs(models.TextChoices):
    SYSTEM = "system", "System / Administrator"
    USER = "user", "Current logged-in user"


class InstallState(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    REBOOT_REQUIRED = "reboot_required", "Reboot required"
    FAILED = "failed", "Failed"
    REFUSED = "refused", "Refused"
    SKIPPED = "skipped", "Skipped"


OPEN_STATES = (InstallState.QUEUED, InstallState.RUNNING)

# bundles install like their single-package kind, the file name keeps the ext
EXTENSIONS = {
    ".exe": PackageKind.EXE,
    ".msi": PackageKind.MSI,
    ".msix": PackageKind.MSIX,
    ".msixbundle": PackageKind.MSIX,
    ".appx": PackageKind.APPX,
    ".appxbundle": PackageKind.APPX,
    ".pkg": PackageKind.PKG,
    ".deb": PackageKind.DEB,
    ".rpm": PackageKind.RPM,
    # INF drivers, zip or cab. a zip is an archive when the upload says so
    ".zip": PackageKind.DRIVER,
    ".cab": PackageKind.DRIVER,
    ".7z": PackageKind.ARCHIVE,
    ".tar.gz": PackageKind.ARCHIVE,
    ".tgz": PackageKind.ARCHIVE,
}
# how the agent unpacks an archive, by file name
ARCHIVE_TYPES = {".zip": "zip", ".7z": "7z", ".tar.gz": "tar.gz", ".tgz": "tar.gz"}

PLATS = {
    PackageKind.EXE: AgentPlat.WINDOWS,
    PackageKind.MSI: AgentPlat.WINDOWS,
    PackageKind.MSIX: AgentPlat.WINDOWS,
    PackageKind.APPX: AgentPlat.WINDOWS,
    PackageKind.PKG: AgentPlat.DARWIN,
    PackageKind.DEB: AgentPlat.LINUX,
    PackageKind.RPM: AgentPlat.LINUX,
    PackageKind.DRIVER: AgentPlat.WINDOWS,
}
# an archive gets its platform from the upload
ARCHIVE_PLATS = (AgentPlat.WINDOWS, AgentPlat.LINUX, AgentPlat.DARWIN)

# only these get PKG_ARGS, an archive passes them to its command
ARGS_KINDS = (PackageKind.EXE, PackageKind.MSI, PackageKind.ARCHIVE)


def default_success_codes() -> list[int]:
    return [0]


def default_reboot_codes() -> list[int]:
    return [3010, 1641]


class SoftwarePackage(BaseAuditModel):
    name = models.CharField(max_length=255, unique=True)
    # sanitized upload name, see utils.clean_filename
    filename = models.CharField(max_length=120)
    kind = models.CharField(max_length=8, choices=PackageKind.choices)
    plat = models.CharField(max_length=16, choices=AgentPlat.choices)
    # also the file name on disk
    sha256 = models.CharField(max_length=64, unique=True)
    size = models.BigIntegerField()
    default_args = models.CharField(max_length=1024, blank=True, default="")
    allow_unsigned = models.BooleanField(default=False)
    timeout = models.PositiveIntegerField(
        default=1800,
        validators=[
            MinValueValidator(MIN_TIMEOUT),
            MaxValueValidator(MAX_ARCHIVE_TIMEOUT),
        ],
    )
    # archives: a path inside the archive, or msiexec.exe, powershell.exe,
    # pwsh.exe, sh, bash
    command = models.CharField(max_length=255, blank=True, default="")
    success_codes = models.JSONField(default=default_success_codes)
    reboot_codes = models.JSONField(default=default_reboot_codes)
    # how a baseline sees it installed, see software/detect.py
    detection = models.JSONField(null=True, blank=True)
    vendor = models.CharField(max_length=255, blank=True, default="")
    version = models.CharField(max_length=64, blank=True, default="")

    def __str__(self) -> str:
        return self.name

    @property
    def file_path(self) -> str:
        return os.path.join(settings.PACKAGES_DIR, self.sha256)

    @staticmethod
    def serialize(package):
        from . import serializers

        return serializers.SoftwarePackageSerializer(package).data


class PackageInstall(models.Model):
    package = models.ForeignKey(
        SoftwarePackage,
        related_name="installs",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    package_name = models.CharField(max_length=255)
    agent = models.ForeignKey(
        "agents.Agent", related_name="package_installs", on_delete=models.CASCADE
    )
    batch = models.UUIDField(db_index=True)
    run_as = models.CharField(max_length=8, choices=RunAs.choices)
    state = models.CharField(
        max_length=16, choices=InstallState.choices, default=InstallState.QUEUED
    )
    exit_code = models.IntegerField(null=True, blank=True)
    # as the endpoint reported it: Valid, NotSigned, AppxEnforced, ...
    signature = models.CharField(max_length=32, blank=True, default="")
    signer = models.CharField(max_length=255, blank=True, default="")
    detail = models.CharField(max_length=500, blank=True, default="")
    output = models.TextField(blank=True, default="")
    requested_by = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)
    started = models.DateTimeField(null=True, blank=True)
    finished = models.DateTimeField(null=True, blank=True)
    # agent jobs only (jobs.py): the download progress the agent reports
    done_bytes = models.BigIntegerField(null=True, blank=True)
    total_bytes = models.BigIntegerField(null=True, blank=True)

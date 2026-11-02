# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from logs.models import BaseAuditModel
from ulrmm.constants import AgentPlat
from ulrmm.models import PermissionQuerySet


class ChocoSoftware(models.Model):
    chocos = models.JSONField()
    added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{len(self.chocos)} - {self.added}"


class InstalledSoftware(models.Model):
    objects = PermissionQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    agent = models.ForeignKey("agents.Agent", on_delete=models.CASCADE)
    software = models.JSONField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent"], name="unique_installed_software_agent"
            )
        ]

    def __str__(self):
        return self.agent.hostname

    @classmethod
    def latest_for(cls, agent) -> "InstalledSoftware | None":
        # one row per agent by convention; with duplicates the newest counts,
        # the same row vulns.tasks reads
        return cls.objects.filter(agent=agent).order_by("-pk").first()


class InstalledDrivers(models.Model):
    """Latest driver inventory of a Windows agent, see software/drivers.py."""

    agent = models.OneToOneField(
        "agents.Agent",
        primary_key=True,
        related_name="driver_inventory",
        on_delete=models.CASCADE,
    )
    received = models.DateTimeField()
    # {"drivers": [...], "problems": [...], "errors": [...]}
    data = models.JSONField(default=dict)

    def __str__(self):
        return self.agent.hostname


class WingetCatalog(models.Model):
    """The winget community index as [[id, name, version], ...], see winget.py."""

    packages = models.JSONField(default=list)
    etag = models.CharField(max_length=128, blank=True, default="")
    sha256 = models.CharField(max_length=64, blank=True, default="")
    # lastwritetime of the index, unix seconds
    index_time = models.BigIntegerField(null=True, blank=True)
    checked = models.DateTimeField(null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=255, blank=True, default="")

    def __str__(self):
        return f"{len(self.packages)} - {self.updated}"

    @classmethod
    def load(cls) -> "WingetCatalog":
        return cls.objects.get_or_create(pk=1)[0]


class DriverCatalog(models.Model):
    """Microsoft Update Catalog search result for one hardware id, see catalog.py."""

    hwid = models.CharField(max_length=100, primary_key=True)
    checked = models.DateTimeField()
    # last fetch failed; entries stay from the last good one
    error = models.CharField(max_length=255, blank=True, default="")
    entries = models.JSONField(default=list)

    def __str__(self):
        return self.hwid


class SdioIndex(models.Model):
    """State of the SDIO driver pack indexes, see sdio.py."""

    etag = models.CharField(max_length=128, blank=True, default="")
    # creation date of the torrent, unix seconds
    torrent_time = models.BigIntegerField(null=True, blank=True)
    checked = models.DateTimeField(null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=255, blank=True, default="")
    files = models.IntegerField(default=0)
    # pack file names the web seed serves, checked on every refresh
    http_packs = models.JSONField(default=list)
    # of those, the packs whose first and last piece can be checked too
    full_packs = models.JSONField(default=list)

    def __str__(self):
        return f"{self.files} - {self.updated}"

    @classmethod
    def load(cls) -> "SdioIndex":
        return cls.objects.get_or_create(pk=1)[0]


class SdioCatalog(models.Model):
    """SDIO pack drivers for one hardware id of the fleet."""

    hwid = models.CharField(max_length=200, primary_key=True)
    checked = models.DateTimeField()
    entries = models.JSONField(default=list)

    def __str__(self):
        return self.hwid


class SdioApproval(models.Model):
    """A pack driver version approved for every device with this hardware id."""

    hwid = models.CharField(max_length=200)
    version = models.CharField(max_length=64)
    desc = models.CharField(max_length=255, blank=True, default="")
    provider = models.CharField(max_length=128, blank=True, default="")
    date = models.CharField(max_length=10, blank=True, default="")
    created_by = models.CharField(max_length=255, blank=True, default="")
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["hwid", "version"], name="unique_sdio_approval"
            )
        ]

    def __str__(self):
        return f"{self.hwid} {self.version}"


class SdioJob(models.Model):
    """Approved pack drivers sent to one agent, see sdio.py."""

    id = models.CharField(max_length=32, primary_key=True)
    agent = models.ForeignKey(
        "agents.Agent", related_name="sdio_jobs", on_delete=models.CASCADE
    )
    state = models.CharField(max_length=16)
    detail = models.CharField(max_length=500, blank=True, default="")
    items = models.JSONField(default=list)
    results = models.JSONField(default=list)
    output = models.TextField(blank=True, default="")
    # download progress of the current pack, bytes
    done = models.BigIntegerField(default=0)
    total = models.BigIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.agent_id} {self.state}"


BASELINE_PLATS = [
    (p.value, p.label) for p in (AgentPlat.WINDOWS, AgentPlat.LINUX, AgentPlat.DARWIN)
]
ITEM_MIN_TIMEOUT = 60
ITEM_MAX_TIMEOUT = 4 * 60 * 60


class BaselineSource(models.TextChoices):
    WINGET = "winget", "winget"
    CHOCO = "choco", "Chocolatey"
    PACKAGE = "package", "Hosted package"
    LINUX_PKG = "linux_pkg", "Linux package"


class BaselineStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    INSTALLING = "installing", "Installing"
    INSTALLED = "installed", "Installed"
    FAILED = "failed", "Failed"
    UNSUPPORTED = "unsupported", "Unsupported"


class Baseline(BaseAuditModel):
    """Software an agent installs after setup or through its policies, see
    baselines.py."""

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=500, blank=True, default="")
    plat = models.CharField(max_length=16, choices=BASELINE_PLATS)
    enabled = models.BooleanField(default=True)
    policies = models.ManyToManyField(
        "automation.Policy", related_name="baselines", blank=True
    )
    deployments = models.ManyToManyField(
        "clients.Deployment", related_name="baselines", blank=True
    )

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def serialize(baseline):
        # a dict is the state from before a change, see baseline_views.py
        if isinstance(baseline, dict):
            return baseline
        saved = baseline.pk is not None
        return {
            "name": baseline.name,
            "description": baseline.description,
            "plat": baseline.plat,
            "enabled": baseline.enabled,
            "items": (
                list(
                    baseline.items.order_by("order", "pk").values(
                        "source", "ref", "name", "detection", "required", "timeout"
                    )
                )
                if saved
                else []
            ),
            "policies": (
                sorted(baseline.policies.values_list("pk", flat=True)) if saved else []
            ),
            "deployments": (
                sorted(baseline.deployments.values_list("pk", flat=True))
                if saved
                else []
            ),
        }


class BaselineItem(models.Model):
    baseline = models.ForeignKey(
        Baseline, related_name="items", on_delete=models.CASCADE
    )
    order = models.PositiveIntegerField(default=0)
    source = models.CharField(max_length=16, choices=BaselineSource.choices)
    # winget id, chocolatey name, package pk or distribution package name
    ref = models.CharField(max_length=255)
    name = models.CharField(max_length=255, blank=True, default="")
    # None: the default of the source, see detect.py
    detection = models.JSONField(null=True, blank=True)
    required = models.BooleanField(default=True)
    timeout = models.PositiveIntegerField(
        default=1800,
        validators=[
            MinValueValidator(ITEM_MIN_TIMEOUT),
            MaxValueValidator(ITEM_MAX_TIMEOUT),
        ],
    )

    def __str__(self) -> str:
        return f"{self.baseline_id} {self.source} {self.ref}"


class BaselineState(models.Model):
    """One item on one agent."""

    agent = models.ForeignKey(
        "agents.Agent", related_name="baseline_states", on_delete=models.CASCADE
    )
    item = models.ForeignKey(
        BaselineItem, related_name="states", on_delete=models.CASCADE
    )
    status = models.CharField(
        max_length=16, choices=BaselineStatus.choices, default=BaselineStatus.PENDING
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    detected_version = models.CharField(max_length=255, blank=True, default="")
    detail = models.CharField(max_length=500, blank=True, default="")
    updated = models.DateTimeField(auto_now=True)
    # the install that runs right now: winget/choco or a hosted package
    action = models.ForeignKey(
        "logs.PendingAction",
        related_name="+",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    install = models.ForeignKey(
        "packages.PackageInstall",
        related_name="+",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["agent", "item"], name="unique_baseline_state"
            )
        ]

    def __str__(self) -> str:
        return f"{self.agent_id} {self.item_id} {self.status}"

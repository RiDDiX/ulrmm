# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt

from django.db import models
from django.utils import timezone as djangotime

from logs.models import BaseAuditModel

# the library scripts the rotation runs, by agent platform
SCRIPTS = {
    "windows": "win_users_laps_rotate.ps1",
    "linux": "linux_users_laps_rotate.sh",
    "darwin": "mac_users_laps_rotate.sh",
}


class LapsPolicy(BaseAuditModel):
    # no site: the global policy. a site policy replaces it for that site
    site = models.OneToOneField(
        "clients.Site",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="laps_policy",
    )
    enabled = models.BooleanField(default=False)
    account = models.CharField(max_length=20, default="ulrmm-admin")
    create_if_missing = models.BooleanField(default=True)
    rotate_days = models.PositiveIntegerField(default=30)
    length = models.PositiveIntegerField(default=24)
    # 0 keeps the schedule after a reveal
    rotate_after_reveal_hours = models.PositiveIntegerField(default=4)

    def __str__(self) -> str:
        return f"local admin policy of {self.site or 'all sites'}"

    @staticmethod
    def serialize(policy):
        from . import serializers

        return serializers.LapsPolicySerializer(policy).data

    @classmethod
    def for_site(cls, site_id) -> "LapsPolicy | None":
        return (
            cls.objects.filter(site_id=site_id).first()
            or cls.objects.filter(site__isnull=True).first()
        )


class LapsState(models.Model):
    agent = models.OneToOneField(
        "agents.Agent", on_delete=models.CASCADE, related_name="laps_state"
    )
    account = models.CharField(max_length=20, blank=True, default="")
    # empty or past: due at the next hourly run while the agent is online
    next_rotation = models.DateTimeField(null=True, blank=True)
    last_rotation = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True, default="")
    credential = models.ForeignKey(
        "vault.Credential",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    # sent to the device, not yet confirmed: Fernet token with vault HKDF_INFO.
    # the next run sends it again, so a lost reply cannot lose the password
    pending_secret = models.TextField(blank=True, default="")
    pending_at = models.DateTimeField(null=True, blank=True)
    pending_account = models.CharField(max_length=20, blank=True, default="")

    def __str__(self) -> str:
        return f"local admin of {self.agent_id}"


def after_reveal(credential) -> None:
    """A revealed local admin password is rotated after the policy's hours."""
    if not credential.agent_id:
        return
    state = LapsState.objects.filter(credential=credential).first()
    if not state:
        return
    policy = LapsPolicy.for_site(credential.agent.site_id)
    if not (policy and policy.enabled and policy.rotate_after_reveal_hours):
        return
    when = djangotime.now() + dt.timedelta(hours=policy.rotate_after_reveal_hours)
    if state.next_rotation is None or when < state.next_rotation:
        LapsState.objects.filter(pk=state.pk).update(next_rotation=when)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models


class RustDeskSettings(models.Model):
    """hbbs/hbbr settings. Singleton, pk 1.

    The row is created on the first save, not on read.
    """

    enabled = models.BooleanField(default=False)
    id_server = models.CharField(max_length=255, blank=True, default="")
    # empty: the client falls back to the ID server's host
    relay_server = models.CharField(max_length=255, blank=True, default="")
    auto_update_server = models.BooleanField(default=False)
    auto_update_clients = models.BooleanField(default=False)
    # mirrored under <dist>/rustdesk/
    pinned_client_version = models.CharField(max_length=32, default="1.4.9")
    releases_checked_at = models.DateTimeField(null=True, blank=True)


class RustDeskPeer(models.Model):
    agent = models.OneToOneField(
        "agents.Agent", on_delete=models.CASCADE, related_name="rustdesk_peer"
    )
    rustdesk_id = models.CharField(max_length=32, blank=True, default="")
    # Fernet token from remote.utils.encrypt_secret, not the password
    password = models.TextField(blank=True, default="")
    client_version = models.CharField(max_length=32, blank=True, default="")
    deployed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")


class RustDeskRelease(models.Model):
    component = models.CharField(
        max_length=16, choices=(("server", "Server"), ("client", "Client"))
    )
    # tag without a leading v
    version = models.CharField(max_length=32)
    published_at = models.DateTimeField(null=True, blank=True)
    url = models.CharField(max_length=255, blank=True, default="")
    notes = models.TextField(blank=True, default="")
    # [{name, url, size}] from the release
    assets = models.JSONField(default=list, blank=True)
    # {name: sha256} hashed on this host when mirrored
    files = models.JSONField(default=dict, blank=True)
    mirrored_at = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["component", "version"], name="unique_rustdesk_release"
            )
        ]

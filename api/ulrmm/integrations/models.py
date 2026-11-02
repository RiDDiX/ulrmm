# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from logs.models import BaseAuditModel, hmac_marker

# never change: stored secrets could no longer be decrypted
UNIFI_INFO = b"integrations.UniFi.secret"
OPNSENSE_INFO = b"integrations.Opnsense.secret"


class Integration(BaseAuditModel):
    # one row each, pk 1, see get()
    url = models.CharField(max_length=255, blank=True, default="")
    verify_tls = models.BooleanField(default=True)
    enabled = models.BooleanField(default=False)
    # networks seen at the last sync: [{vlan_id, name, subnet}]
    vlans = models.JSONField(default=list, blank=True)
    last_sync = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True, default="")

    SECRETS: tuple = ()

    class Meta:
        abstract = True

    @classmethod
    def get(cls):
        if obj := cls.objects.filter(pk=1).first():
            return obj
        # bulk_create skips save(), which would audit a row nobody edited yet
        cls.objects.bulk_create([cls(pk=1)], ignore_conflicts=True)
        return cls.objects.get(pk=1)

    @classmethod
    def serialize(cls, obj):
        from django.forms.models import model_to_dict

        ret = model_to_dict(obj, exclude=("vlans", "last_sync", "last_error"))
        # the log shows that a secret changed, never the secret
        ret.update({k: hmac_marker(getattr(obj, k)) for k in cls.SECRETS})
        return ret


class UniFiController(Integration):
    site = models.CharField(max_length=64, default="default")
    username = models.CharField(max_length=128, blank=True, default="")
    # Fernet tokens. an api key is used instead of the login when set
    password = models.TextField(blank=True, default="")
    api_key = models.TextField(blank=True, default="")

    SECRETS = ("password", "api_key")

    def __str__(self) -> str:
        return "UniFi controller"


class OpnsenseFirewall(Integration):
    # Fernet tokens of the API key pair
    api_key = models.TextField(blank=True, default="")
    api_secret = models.TextField(blank=True, default="")

    SECRETS = ("api_key", "api_secret")

    def __str__(self) -> str:
        return "OPNsense firewall"


class NetworkClient(models.Model):
    mac = models.CharField(max_length=17, unique=True)
    ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True, default="")
    vlan_id = models.PositiveIntegerField(null=True, blank=True)
    vlan_name = models.CharField(max_length=64, blank=True, default="")
    switch = models.CharField(max_length=128, blank=True, default="")
    port = models.CharField(max_length=32, blank=True, default="")
    ap = models.CharField(max_length=128, blank=True, default="")
    ssid = models.CharField(max_length=64, blank=True, default="")
    # "unifi", "opnsense" or both comma separated
    source = models.CharField(max_length=20, blank=True, default="")
    last_seen = models.DateTimeField()

    def __str__(self) -> str:
        return self.mac

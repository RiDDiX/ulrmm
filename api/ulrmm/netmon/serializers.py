# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import hmac
import json
import re
from ipaddress import ip_address

from django.conf import settings
from rest_framework import serializers

from remote.utils import encrypt_secret

from .models import HKDF_INFO, NetworkDevice, SnmpVersion, probe_scope
from .probe import (
    MAX_MONITORS,
    PATH_RE,
    QTYPES,
    STATUS_RE,
    address_error,
    is_hostname,
    own_ok,
    status_ranges,
)

# written by the poller, not by a user
VOLATILE = ("status", "last_checked", "fail_count", "last_result")
_PRINTABLE_RE = re.compile(r"[ -~]+")
_USER_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
SECRET_KEYS = ("community", "auth_key", "priv_key")
HTTP_KEYS = (
    "type",
    "scheme",
    "port",
    "path",
    "method",
    "server_name",
    "status",
    "allow_self_signed",
    "warn_days",
    "error_days",
)
DNS_KEYS = ("type", "query", "record", "expect")
HOSTNAME_ERROR = "A host name like nas.example.lan, no URL, port, user or address."


class MonitorSerializer(serializers.Serializer):
    """http(s), dns or printer monitor. always targets the device's ipv4
    literal. printer reads the supply levels over the device's SNMP."""

    type = serializers.ChoiceField(("http", "dns", "printer"))
    scheme = serializers.ChoiceField(("https", "http"), default="https")
    port = serializers.IntegerField(min_value=1, max_value=65535, required=False)
    path = serializers.CharField(default="/", max_length=256, trim_whitespace=False)
    method = serializers.ChoiceField(("GET", "HEAD"), default="GET")
    # SNI, certificate check and Host header, never used to connect
    server_name = serializers.CharField(default="", allow_blank=True, max_length=253)
    status = serializers.CharField(default="200-399", max_length=64)
    allow_self_signed = serializers.BooleanField(default=False)
    warn_days = serializers.IntegerField(min_value=0, max_value=365, default=21)
    error_days = serializers.IntegerField(min_value=0, max_value=365, default=7)
    query = serializers.CharField(default="", allow_blank=True, max_length=253)
    record = serializers.ChoiceField(tuple(QTYPES), default="A")
    expect = serializers.ListField(
        child=serializers.IPAddressField(), max_length=8, default=list
    )
    # percent left at or under which a supply is low
    threshold = serializers.IntegerField(min_value=1, max_value=99, default=15)

    def validate_path(self, value):
        if not PATH_RE.fullmatch(value):
            raise serializers.ValidationError(
                "Starts with /, printable ASCII without spaces."
            )
        return value

    def validate_server_name(self, value):
        value = value.lower()
        if value and not is_hostname(value):
            raise serializers.ValidationError(HOSTNAME_ERROR)
        return value

    def validate_query(self, value):
        value = value.lower()
        if value and not is_hostname(value):
            raise serializers.ValidationError(HOSTNAME_ERROR)
        return value

    def validate_status(self, value):
        value = value.replace(" ", "")
        if not STATUS_RE.fullmatch(value) or any(
            low > high for low, high in status_ranges(value)
        ):
            raise serializers.ValidationError(
                "Codes or ranges from 100 to 599, e.g. 200-399, 401."
            )
        return value

    def validate(self, attrs):
        if attrs["type"] == "printer":
            return {"type": "printer", "threshold": attrs["threshold"]}
        if attrs["type"] == "dns":
            if not attrs["query"]:
                raise serializers.ValidationError({"query": "Required."})
            version = 4 if attrs["record"] == "A" else 6
            expect = {ip_address(a) for a in attrs["expect"]}
            if any(a.version != version for a in expect):
                raise serializers.ValidationError(
                    {"expect": f"IPv{version} addresses for {attrs['record']}."}
                )
            attrs["expect"] = [str(a) for a in sorted(expect)]
            return {k: attrs[k] for k in DNS_KEYS}

        if attrs["error_days"] > attrs["warn_days"]:
            raise serializers.ValidationError(
                {"error_days": "At most the warning days."}
            )
        attrs.setdefault("port", 443 if attrs["scheme"] == "https" else 80)
        return {k: attrs[k] for k in HTTP_KEYS}


class NetworkDeviceSerializer(serializers.ModelSerializer):
    client_name = serializers.ReadOnlyField(source="site.client.name")
    site_name = serializers.ReadOnlyField(source="site.name")
    # secrets go in, never out. Empty keeps the stored one.
    snmp_community = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=64
    )
    snmp_auth_key = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=128
    )
    snmp_priv_key = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=128
    )
    snmp_secret_clear = serializers.BooleanField(write_only=True, required=False)
    snmp_secret_set = serializers.SerializerMethodField()
    monitors = serializers.ListField(
        child=serializers.DictField(), max_length=MAX_MONITORS, required=False
    )

    class Meta:
        model = NetworkDevice
        exclude = ("snmp_secret",)
        read_only_fields = VOLATILE + (
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )

    def get_snmp_secret_set(self, obj) -> bool:
        return bool(obj.snmp_secret)

    def validate_monitors(self, value):
        # on its own, so a partial update still gets the defaults
        monitors = MonitorSerializer(data=value, many=True)
        if not monitors.is_valid():
            # DRF >= 3.16 reports {index: errors} for the failing items only
            errs = monitors.errors
            pairs = errs.items() if isinstance(errs, dict) else enumerate(errs)
            i, errors = next((i, e) for i, e in pairs if e)
            field, messages = next(iter(errors.items()))
            raise serializers.ValidationError(
                f"Monitor {i + 1}, {field.replace('_', ' ')}: {messages[0]}"
            )
        return monitors.validated_data

    def validate_interval(self, value):
        if not 60 <= value <= 86400:
            raise serializers.ValidationError("Between 60 and 86400 seconds.")
        return value

    def validate_tcp_ports(self, value):
        if len(value) > 8 or len(set(value)) != len(value):
            raise serializers.ValidationError("Up to 8 different ports.")
        if not all(1 <= p <= 65535 for p in value):
            raise serializers.ValidationError("Ports are 1 to 65535.")
        return sorted(value)

    def validate_snmp_port(self, value):
        if not 1 <= value <= 65535:
            raise serializers.ValidationError("Ports are 1 to 65535.")
        return value

    def validate_fails_b4_alert(self, value):
        if not 1 <= value <= 100:
            raise serializers.ValidationError("Between 1 and 100.")
        return value

    def validate(self, attrs):
        device = self.instance

        def get(key, default):
            if key in attrs:
                return attrs[key]
            return getattr(device, key) if device else default

        version = get("snmp_version", SnmpVersion.OFF)
        if version == SnmpVersion.V2C:
            keys = ["community"]
        elif version == SnmpVersion.V3:
            keys = ["auth_key", "priv_key"]
            if not _USER_RE.fullmatch(get("snmp_v3_user", "")):
                raise serializers.ValidationError(
                    {"snmp_v3_user": "1 to 32 letters, digits, dot, dash, underscore."}
                )
        else:
            keys = []

        # the server's own address only for its own certificate, see own_ok
        host = get("host", "")
        networks, own = probe_scope()
        checks = {
            "ping": get("ping", True),
            "tcp_ports": get("tcp_ports", []),
            "snmp": bool(keys),
            "monitors": get("monitors", []),
        }
        if "host" in attrs or host in {str(a) for a in own}:
            if reason := address_error(host, networks, own, own_ok(checks)):
                raise serializers.ValidationError({"host": reason})

        clear = attrs.pop("snmp_secret_clear", False)
        entered = {k: attrs.pop(f"snmp_{k}", "") for k in SECRET_KEYS}
        # a stored secret only goes where it was entered for, a new target
        # needs it entered again
        target = ("host", "snmp_port")
        if version == SnmpVersion.V3:
            target += ("snmp_v3_user",)
        moved = device and any(get(f, None) != getattr(device, f) for f in target)
        stored = {} if clear or moved or not device else _stored(device)
        secret = {k: entered[k] or stored.get(k, "") for k in keys}
        for k, value in secret.items():
            if not value:
                raise serializers.ValidationError({f"snmp_{k}": "Required."})
            if not _PRINTABLE_RE.fullmatch(value):
                raise serializers.ValidationError({f"snmp_{k}": "Printable ASCII."})
            if k != "community" and len(value) < 8:
                raise serializers.ValidationError(
                    {f"snmp_{k}": "At least 8 characters."}
                )
        # only the secrets of the chosen version are kept, an unchanged one
        # keeps its token
        if secret != stored or not secret:
            attrs["snmp_secret"] = (
                encrypt_secret(json.dumps(secret), HKDF_INFO) if secret else ""
            )

        if not keys and any(m["type"] == "printer" for m in checks["monitors"]):
            raise serializers.ValidationError(
                {
                    "monitors": "A printer monitor reads the supplies over SNMP, turn SNMP on."
                }
            )
        if not (checks["ping"] or checks["tcp_ports"] or keys or checks["monitors"]):
            raise serializers.ValidationError(
                "Turn on ping, a TCP port, SNMP or a monitor, or the device is"
                " never checked."
            )
        return attrs


def _stored(device) -> dict:
    try:
        return device.secret()
    except Exception:
        return {}  # unreadable after a SECRET_KEY change, entered again


class NetworkDeviceAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkDevice
        exclude = VOLATILE

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # the log shows that the secret changed, never the secret
        token = instance.snmp_secret
        ret["snmp_secret"] = (
            "hmac:"
            + hmac.new(
                settings.SECRET_KEY.encode(), token.encode(), hashlib.sha256
            ).hexdigest()[:16]
            if token
            else None
        )
        return ret

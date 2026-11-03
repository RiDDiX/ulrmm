# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
from ipaddress import IPv4Network, collapse_addresses

from rest_framework import serializers

from netmon.models import probe_scope
from remote.utils import encrypt_secret

from .models import HKDF_INFO, DiscoveredDevice, Scan

MAX_ADDRESSES = 4096
MAX_PORTS = 16
DEFAULT_PORTS = [22, 80, 161, 443, 445, 3389, 5900, 8080, 8443]
_PRINTABLE_RE = re.compile(r"[ -~]+")


class ScanSerializer(serializers.ModelSerializer):
    networks = serializers.ListField(
        child=serializers.CharField(max_length=18), min_length=1, max_length=32
    )
    ports = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=65535),
        max_length=MAX_PORTS,
        required=False,
    )
    # write-only
    snmp_community = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=64
    )

    class Meta:
        model = Scan
        fields = (
            "id",
            "networks",
            "ports",
            "snmp_community",
            "snmp",
            "status",
            "started_by",
            "started_at",
            "finished_at",
            "hosts_total",
            "hosts_up",
            "error",
        )
        read_only_fields = (
            "snmp",
            "status",
            "started_by",
            "started_at",
            "finished_at",
            "hosts_total",
            "hosts_up",
            "error",
        )

    def validate_networks(self, value):
        # IPv4 literals. hostnames are not looked up
        try:
            nets = list(collapse_addresses(IPv4Network(n, strict=False) for n in value))
        except (TypeError, ValueError):
            raise serializers.ValidationError(
                "IPv4 networks in CIDR notation, e.g. 192.168.1.0/24."
            )
        if sum(n.num_addresses for n in nets) > MAX_ADDRESSES:
            raise serializers.ValidationError(
                f"At most {MAX_ADDRESSES} addresses per scan."
            )
        allowed, _ = probe_scope()
        for net in nets:
            if not any(net.subnet_of(a) for a in allowed):
                names = ", ".join(str(a) for a in sorted(allowed)) or "none"
                raise serializers.ValidationError(
                    f"{net} is outside the networks the server may scan ({names})."
                )
        return [str(n) for n in nets]

    def validate_ports(self, value):
        return sorted(set(value)) or DEFAULT_PORTS

    def validate_snmp_community(self, value):
        if value and not _PRINTABLE_RE.fullmatch(value):
            raise serializers.ValidationError("Printable ASCII.")
        return value

    def validate(self, attrs):
        community = attrs.pop("snmp_community", "")
        attrs.setdefault("ports", DEFAULT_PORTS)
        attrs["snmp"] = bool(community)
        attrs["snmp_community"] = (
            encrypt_secret(community, HKDF_INFO) if community else ""
        )
        return attrs


class DiscoveredDeviceSerializer(serializers.ModelSerializer):
    agent_id = serializers.SerializerMethodField()
    agent_hostname = serializers.SerializerMethodField()
    netmon_id = serializers.ReadOnlyField(source="netmon_device_id")

    class Meta:
        model = DiscoveredDevice
        exclude = ("agent", "netmon_device")

    def _agent(self, obj):
        # context "agents": pks of the agents the user may see
        return obj.agent if obj.agent_id in self.context.get("agents", ()) else None

    def get_agent_id(self, obj):
        agent = self._agent(obj)
        return agent.agent_id if agent else None

    def get_agent_hostname(self, obj):
        agent = self._agent(obj)
        return agent.effective_name if agent else None

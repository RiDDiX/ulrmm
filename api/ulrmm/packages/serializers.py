# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re
import shlex

from rest_framework import serializers

from software import detect
from ulrmm.constants import AgentPlat

from .jobs import COMMANDS
from .models import (
    ARGS_KINDS,
    MAX_TIMEOUT,
    PackageInstall,
    PackageKind,
    SoftwarePackage,
    default_reboot_codes,
    default_success_codes,
)

MAX_CODES = 32
_PATH_RE = re.compile(r"[A-Za-z0-9._()+ -]+(?:[/\\][A-Za-z0-9._()+ -]+)*")


def _printable(value: str) -> str:
    if not value.isprintable():
        raise serializers.ValidationError("No line breaks or control characters.")
    return value


def _codes(value):
    if (
        not isinstance(value, list)
        or len(value) > MAX_CODES
        or not all(
            isinstance(c, int) and not isinstance(c, bool) and -(2**31) <= c < 2**32
            for c in value
        )
    ):
        raise serializers.ValidationError(
            f"Give at most {MAX_CODES} exit codes as whole numbers."
        )
    return sorted(set(value))


def _command_error(command: str, plat: str) -> str:
    if command in COMMANDS.get(plat, ()):
        return ""
    parts = re.split(r"[/\\]", command)
    if not _PATH_RE.fullmatch(command) or any(p in (".", "..") for p in parts):
        names = ", ".join(COMMANDS.get(plat, ()))
        return f"Give a path inside the archive, like setup/install.exe, or {names}."
    return ""


class SoftwarePackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwarePackage
        fields = "__all__"
        # set from the uploaded file, never from the request
        read_only_fields = (
            "filename",
            "kind",
            "plat",
            "sha256",
            "size",
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )

    def validate_name(self, value):
        return _printable(value)

    def validate_default_args(self, value):
        return _printable(value)

    def validate_vendor(self, value):
        return _printable(value)

    def validate_version(self, value):
        return _printable(value)

    def validate_success_codes(self, value):
        return _codes(value)

    def validate_reboot_codes(self, value):
        return _codes(value)

    def validate(self, attrs):
        instance = self.instance
        kind = instance.kind if instance else self.context.get("kind")
        plat = instance.plat if instance else self.context.get("plat")

        def value(key, default):
            return attrs.get(key, getattr(instance, key) if instance else default)

        errors = {}
        if attrs.get("default_args") and kind not in ARGS_KINDS:
            errors["default_args"] = (
                "Only Windows exe and msi packages and archives take arguments."
            )
        command = value("command", "")
        if kind == PackageKind.ARCHIVE:
            if not command:
                errors["command"] = "Name what runs from the archive."
            elif problem := _command_error(command, plat):
                errors["command"] = problem
            if plat != AgentPlat.WINDOWS:
                try:
                    shlex.split(value("default_args", ""))
                except ValueError:
                    errors["default_args"] = "The arguments have an open quote."
        else:
            if command:
                errors["command"] = "Only archives run a command."
            for key, default in (
                ("success_codes", default_success_codes()),
                ("reboot_codes", default_reboot_codes()),
            ):
                if key in attrs and attrs[key] != default:
                    errors[key] = "Exit codes are set for archives only."
            if value("timeout", 0) > MAX_TIMEOUT:
                errors["timeout"] = (
                    f"Ensure this value is less than or equal to {MAX_TIMEOUT}."
                )
        if set(value("success_codes", [0])) & set(value("reboot_codes", [])):
            errors["reboot_codes"] = "An exit code cannot mean success and reboot."
        if "detection" in attrs:
            try:
                attrs["detection"] = detect.clean(attrs["detection"], plat)
            except serializers.ValidationError as e:
                errors["detection"] = e.detail
        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class PackageInstallSerializer(serializers.ModelSerializer):
    agent_id = serializers.ReadOnlyField(source="agent.agent_id")
    hostname = serializers.ReadOnlyField(source="agent.hostname")

    class Meta:
        model = PackageInstall
        exclude = ("agent",)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from core.models import (
    DELL_API_INFO,
    NVD_KEY_INFO,
    EncryptedTextField,
    recrypt_column,
)

# plain TextFields holding remote.utils.encrypt_secret tokens
TOKEN_COLUMNS = (
    ("agents.Agent", "uninstall_code", "agents.models", "UNINSTALL_CODE_INFO"),
    ("deploy.AgentCredential", "legacy_nats", "deploy.tokens", "LEGACY_NATS_INFO"),
    ("deploy.CommandKey", "seed", "deploy.signing", "CMD_KEY_INFO"),
    ("assets.License", "key", "assets.models", "HKDF_INFO"),
    ("discovery.Scan", "snmp_community", "discovery.models", "HKDF_INFO"),
    ("encryption.RecoveryKey", "key", "encryption.utils", "_KEY_INFO"),
    (
        "integrations.OpnsenseFirewall",
        "api_key",
        "integrations.models",
        "OPNSENSE_INFO",
    ),
    (
        "integrations.OpnsenseFirewall",
        "api_secret",
        "integrations.models",
        "OPNSENSE_INFO",
    ),
    ("integrations.UniFiController", "api_key", "integrations.models", "UNIFI_INFO"),
    ("integrations.UniFiController", "password", "integrations.models", "UNIFI_INFO"),
    ("netmon.NetworkDevice", "snmp_secret", "netmon.models", "HKDF_INFO"),
    ("notify.Channel", "secret", "notify.models", "HKDF_INFO"),
    ("remote.RustDeskPeer", "password", "remote.utils", "_HKDF_INFO"),
    ("vault.Credential", "secret", "vault.models", "HKDF_INFO"),
)


def columns():
    """(model, field, info, plain) of every encrypted column."""
    from importlib import import_module

    found = []
    for model in apps.get_models():
        for field in model._meta.concrete_fields:
            if isinstance(field, EncryptedTextField):
                found.append((model, field.name, field.hkdf_info, True))
    core = apps.get_model("core", "CoreSettings")
    found.append((core, "nvd_api_key", NVD_KEY_INFO, False))
    found += [(core, name, info, False) for name, info in DELL_API_INFO.items()]
    for label, field, module, name in TOKEN_COLUMNS:
        info = getattr(import_module(module), name)
        found.append((apps.get_model(label), field, info, False))
    return found


class Command(BaseCommand):
    help = (
        "Encrypts every encrypted column again with the current field key. "
        "Rotation: put a new key (base64 of 32 random bytes) first in "
        "FIELD_ENCRYPTION_KEYS in local_settings.py and keep the old ones "
        "behind it, restart the services, run this command, then remove the "
        "old keys and restart again. Values that no key opens are reported, "
        "left as they are and make the command fail; do not remove an old key "
        "then. Values changed while it runs keep their newer value."
    )

    def handle(self, *args, **kwargs):
        lost = []
        with transaction.atomic():
            for model, field, info, plain in columns():
                rewritten, unreadable, skipped = recrypt_column(
                    connection, model, field, info, plain=plain
                )
                label = f"{model._meta.label}.{field}"
                line = f"{label}: {rewritten} re-encrypted"
                if skipped:
                    line += f", {skipped} changed meanwhile (left as written)"
                if unreadable:
                    line += f", {unreadable} unreadable"
                    lost.append(f"{label} ({unreadable})")
                self.stdout.write(line)
        if lost:
            raise CommandError(
                "values no configured key decrypts: "
                + ", ".join(lost)
                + ". Restore the key they were written with, or enter them again "
                "(two-factor keys: manage.py reset_2fa)."
            )

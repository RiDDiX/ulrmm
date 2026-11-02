# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations

LEGACY_NATS_INFO = b"ulrmm legacy nats v1"


def forwards(apps, schema_editor):
    from deploy.tokens import digest
    from remote.utils import encrypt_secret

    Token = apps.get_model("authtoken", "Token")
    AgentCredential = apps.get_model("deploy", "AgentCredential")
    tokens = Token.objects.select_related("user").exclude(user__agent=None)
    for token in tokens.iterator():
        AgentCredential.objects.update_or_create(
            agent_id=token.user.agent_id,
            defaults={
                "kind": "legacy",
                "access_digest": digest(token.key),
                "legacy_nats": encrypt_secret(token.key, LEGACY_NATS_INFO),
            },
        )
    tokens.delete()


def backwards(apps, schema_editor):
    from cryptography.fernet import InvalidToken
    from remote.utils import decrypt_secret

    Token = apps.get_model("authtoken", "Token")
    User = apps.get_model("accounts", "User")
    AgentCredential = apps.get_model("deploy", "AgentCredential")
    for cred in AgentCredential.objects.exclude(legacy_nats="").iterator():
        user = User.objects.filter(agent_id=cred.agent_id).first()
        if user is None:
            continue
        try:
            key = decrypt_secret(cred.legacy_nats, LEGACY_NATS_INFO)
        except InvalidToken:
            continue
        Token.objects.update_or_create(user=user, defaults={"key": key})


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_encrypt_totp_key"),
        ("authtoken", "0004_alter_tokenproxy_options"),
        ("deploy", "0006_agent_credentials"),
    ]

    operations = [migrations.RunPython(forwards, backwards)]

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from deploy import pki
from deploy.models import MtlsMode


class Command(BaseCommand):
    help = "Creates the agent client certificate CA in AGENT_CA_DIR when missing"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset-certs-if-new",
            action="store_true",
            help="a new CA revokes every stored agent certificate and sets the "
            "mode to optional (restore without the old CA)",
        )

    def handle(self, *args, **kwargs):
        try:
            created, fingerprint = pki.ensure_ca()
        except (OSError, pki.CAUnavailable) as e:
            raise CommandError(f"agent CA in {settings.AGENT_CA_DIR}: {e}")

        self.stdout.write(f"{'created' if created else 'present'} {fingerprint}")
        if created and kwargs["reset_certs_if_new"]:
            revoked = pki.revoke()
            sec = pki.security_settings()
            sec.mtls_mode = MtlsMode.OPTIONAL
            sec.save()
            self.stdout.write(f"revoked {revoked} agent certificates, mode optional")

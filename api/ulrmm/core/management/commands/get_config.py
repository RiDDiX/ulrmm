# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from urllib.parse import urlparse

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Print a single configuration value for shell consumption"

    def add_arguments(self, parser):
        parser.add_argument("name", type=str)

    def handle(self, *args, **options):
        from core.models import CoreSettings
        from ulrmm.helpers import get_certs
        from ulrmm.util_settings import (
            get_backend_url,
            get_root_domain,
            get_webdomain,
        )

        name = options["name"]
        db = settings.DATABASES["default"]
        value = None

        if name == "api":
            value = settings.ALLOWED_HOSTS[0]
        elif name == "rootdomain":
            value = get_root_domain(settings.ALLOWED_HOSTS[0])
        elif name == "version":
            value = settings.ULRMM_VERSION
        elif name == "meshver":
            value = settings.MESH_VER
        elif name == "natsver":
            value = settings.NATS_SERVER_VER
        elif name == "frontend":
            value = settings.CORS_ORIGIN_WHITELIST[0]
        elif name == "backend_url":
            value = get_backend_url(
                settings.ALLOWED_HOSTS[0],
                settings.ULRMM_PROTO,
                settings.ULRMM_BACKEND_PORT,
            )
        elif name == "webdomain":
            value = get_webdomain(settings.CORS_ORIGIN_WHITELIST[0])
        elif name == "djangoadmin":
            value = f"https://{settings.ALLOWED_HOSTS[0]}/{settings.ADMIN_URL}"
        elif name == "setuptoolsver":
            value = settings.SETUPTOOLS_VER
        elif name == "wheelver":
            value = settings.WHEEL_VER
        elif name in ("dbname", "dbuser", "dbpw", "dbhost", "dbport"):
            value = {
                "dbname": db["NAME"],
                "dbuser": db["USER"],
                "dbpw": db["PASSWORD"],
                "dbhost": db["HOST"],
                "dbport": db["PORT"],
            }[name]
        elif name in ("meshsite", "meshuser", "meshtoken", "meshdomain"):
            core = CoreSettings.objects.first()
            if core:
                if name == "meshsite":
                    value = core.mesh_site
                elif name == "meshuser":
                    value = core.mesh_username
                elif name == "meshtoken":
                    value = core.mesh_token
                else:
                    value = urlparse(core.mesh_site or "").netloc
        elif name in ("certfile", "keyfile"):
            cert_file, key_file = get_certs()
            value = cert_file if name == "certfile" else key_file

        if value is not None:
            self.stdout.write(str(value))

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Write the nats-api configuration file consumed by the Go service"

    def handle(self, *args, **options):
        from ulrmm.helpers import get_nats_server_password, get_nats_url
        from ulrmm.utils import _write_conf_atomic

        self.stdout.write("Creating configuration for nats-api...")

        db = settings.DATABASES["default"]
        sslmode = getattr(settings, "DB_SSL", None) or os.getenv("DB_SSL") or "disable"
        config = {
            "key": get_nats_server_password(),
            "natsurl": get_nats_url(),
            "user": db["USER"],
            "pass": db["PASSWORD"],
            "host": db["HOST"],
            "port": int(db["PORT"] or 5432),
            "dbname": db["NAME"],
            "sslmode": sslmode,
        }

        # holds the db password: written 0600 from the start, then swapped in
        conf_dir = settings.ULRMM_CONF_DIR or settings.BASE_DIR
        _write_conf_atomic(os.path.join(conf_dir, "nats-api.conf"), config)

        self.stdout.write("Configuration for nats-api created successfully")

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import math
import os

import psutil
from django.conf import settings
from django.core.management.base import BaseCommand


def _bool(value) -> str:
    return "true" if value else "false"


class Command(BaseCommand):
    help = "Write the uwsgi app.ini file"

    def handle(self, *args, **options):
        self.stdout.write("Creating uwsgi conf...")

        base = settings.BASE_DIR

        try:
            gib = math.ceil(psutil.virtual_memory().total / (1024**3))
            if gib <= 2:
                max_requests, workers = 15, 6
            elif gib <= 4:
                max_requests, workers = 75, 20
            else:
                max_requests, workers = 100, 40
        except Exception:
            max_requests, workers = 50, 10

        try:
            cheaper_initial = 3 if psutil.cpu_count() == 1 else 4
        except Exception:
            cheaper_initial = 4

        def g(key, default):
            return getattr(settings, key, default)

        values = {
            "chdir": str(base),
            "module": "ulrmm.wsgi",
            "home": str(os.path.join(os.path.dirname(str(base)), "env")),
            "master": _bool(g("UWSGI_MASTER", True)),
            "enable-threads": _bool(g("UWSGI_ENABLE_THREADS", True)),
            "socket": str(os.path.join(str(base), "ulrmm.sock")),
            "harakiri": str(g("UWSGI_HARAKIRI", 300)),
            "chmod-socket": str(g("UWSGI_CHMOD_SOCKET", 660)),
            "buffer-size": str(g("UWSGI_BUFFER_SIZE", 65535)),
            "vacuum": _bool(g("UWSGI_VACUUM", True)),
            "die-on-term": _bool(g("UWSGI_DIE_ON_TERM", True)),
            "max-requests": str(g("UWSGI_MAX_REQUESTS", max_requests)),
            "disable-logging": _bool(g("UWSGI_DISABLE_LOGGING", True)),
            "worker-reload-mercy": str(g("UWSGI_RELOAD_MERCY", 30)),
            "cheaper-algo": "busyness",
            "cheaper": str(g("UWSGI_CHEAPER", 4)),
            "cheaper-initial": str(g("UWSGI_CHEAPER_INITIAL", cheaper_initial)),
            "workers": str(g("UWSGI_MAX_WORKERS", workers)),
            "cheaper-step": str(g("UWSGI_CHEAPER_STEP", 1)),
            "cheaper-overload": str(g("UWSGI_CHEAPER_OVERLOAD", 3)),
            "cheaper-busyness-min": str(g("UWSGI_BUSYNESS_MIN", 5)),
            "cheaper-busyness-max": str(g("UWSGI_BUSYNESS_MAX", 10)),
            "listen": str(g("UWSGI_LISTEN_QUEUE", 1024)),
        }

        if g("UWSGI_DEBUG", False):
            values["stats"] = "/tmp/stats.socket"
            values["cheaper-busyness-verbose"] = "true"
        if g("UWSGI_THUNDER_LOCK", False):
            values["thunder-lock"] = "true"

        lines = ["[uwsgi]"] + [f"{key} = {value}" for key, value in values.items()]
        with open(os.path.join(str(base), "app.ini"), "w") as fh:
            fh.write("\n".join(lines) + "\n")

        self.stdout.write("Created uwsgi conf")

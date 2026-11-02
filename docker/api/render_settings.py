#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Writes /settings/local_settings.py for the compose stack from the
environment, the way install.sh and the install_lib ensure_* helpers do.
An existing file only gets the keys it lacks appended; values are never
rewritten (a new pepper or field key would lock agents and columns out)."""

import base64
import json
import os
import re
import secrets
import string
import sys

PATH = "/settings/local_settings.py"
TOKEN_FILE = "/mesh-data/ulrmm-logintokenkey"
ALNUM = string.ascii_letters + string.digits


def rand(n: int) -> str:
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def b64() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def env(name: str, default: str | None = None) -> str:
    val = os.environ.get(name, default)
    if val is None or val == "":
        sys.exit(f"render_settings: {name} is not set")
    return val


def s(val: str) -> str:
    return json.dumps(val)


def entries() -> list[tuple[str, str]]:
    api, app, mesh = env("API_DOMAIN"), env("APP_DOMAIN"), env("MESH_DOMAIN")
    with open(TOKEN_FILE) as fh:
        token_key = fh.read().strip()
    db = (
        "{\n"
        "    'default': {\n"
        "        'ENGINE': 'django.db.backends.postgresql',\n"
        "        'NAME': 'ulrmm',\n"
        "        'USER': 'ulrmm',\n"
        f"        'PASSWORD': {s(env('POSTGRES_PASSWORD'))},\n"
        "        'HOST': 'db',\n"
        "        'PORT': '5432',\n"
        "    }\n"
        "}"
    )
    out = [
        ("SECRET_KEY", s(rand(80))),
        ("DEBUG", "False"),
        ("ALLOWED_HOSTS", f"[{s(api)}]"),
        ("ADMIN_URL", s(rand(70) + "/")),
        ("CORS_ORIGIN_WHITELIST", f"[{s('https://' + app)}]"),
        ("DATABASES", db),
        ("REDIS_HOST", s("redis")),
        ("REDIS_PASSWORD", s(env("REDIS_PASSWORD"))),
        ("NATS_SERVER_PASSWORD", s(secrets.token_hex(32))),
        ("ENROLL_SIGNING_KEY", s(b64())),
        ("FIELD_ENCRYPTION_KEYS", f"[{s(b64())}]"),
        ("AGENT_TOKEN_PEPPERS", f"[{s(b64())}]"),
        ("MESH_USERNAME", s(env("MESH_USERNAME", "ulrmm-mesh"))),
        ("MESH_SITE", s("https://" + mesh)),
        ("MESH_TOKEN_KEY", s(token_key)),
        ("MESH_HOST", s("mesh")),
        ("ULRMM_CONF_DIR", s("/conf")),
        ("ULRMM_NATS_RELOAD", "False"),
        ("ULRMM_DISABLE_WEB_TERMINAL", "True"),
        ("ULRMM_GIT_URL", s("")),
        ("ULRMM_SCRIPTS_GIT_URL", s(env("ULRMM_SCRIPTS_REPO"))),
        ("ULRMM_AGENT_GIT_URL", s(env("ULRMM_AGENT_REPO"))),
        ("ULRMM_AGENT_PUBIP_URL", s(f"https://{api}/pubip")),
        ("CERT_FILE", s("/certs/fullchain.pem")),
        ("KEY_FILE", s("/certs/privkey.pem")),
    ]
    if env("ULRMM_TLS", "own") == "selfsigned":
        out.append(("ULRMM_INSECURE", "True"))
    out.append(("ADMIN_ENABLED", "False"))
    return out


def main() -> None:
    existing = ""
    if os.path.exists(PATH):
        with open(PATH) as fh:
            existing = fh.read()
    else:
        with open(PATH, "w") as fh:
            fh.write(
                "# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid\n"
                "# SPDX-License-Identifier: FSL-1.1-ALv2\n"
            )
    os.chmod(PATH, 0o600)
    added = []
    with open(PATH, "a") as fh:
        for key, literal in entries():
            if re.search(rf"^{key}\s*=", existing, re.M):
                continue
            fh.write(f"\n{key} = {literal}\n")
            added.append(key)
    print(f"render_settings: {PATH} " + (", ".join(added) or "unchanged"))


if __name__ == "__main__":
    main()

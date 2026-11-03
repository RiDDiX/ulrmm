# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

SECRET_KEY = "<REDACTED>"

DEBUG = False

ALLOWED_HOSTS = ['api.riddix.de']

ADMIN_URL = "<REDACTED>"

CORS_ORIGIN_WHITELIST = [
    "https://rmm.riddix.de"
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': "<REDACTED>",
        'USER': "<REDACTED>",
        'PASSWORD': "<REDACTED>",
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

MESH_USERNAME = "<REDACTED>"
MESH_SITE = "https://mesh.riddix.de"
ADMIN_ENABLED = False
CERT_FILE = "/home/ulrmm/wildcard/fullchain.pem"
KEY_FILE = "/home/ulrmm/wildcard/privkey.pem"
MESH_TOKEN_KEY = "<REDACTED>"

# MeshCentral host for control and agent download (port MESH_PORT, 4430).
# Native install: 127.0.0.1; Compose stack: the service name "mesh".
# MESH_HOST = "127.0.0.1"

# Directory for nats-rmm.conf and nats-api.conf. Empty = api/ulrmm (BASE_DIR);
# Compose stack: the shared volume /conf.
# ULRMM_CONF_DIR = "/rmm/api/ulrmm"

# False makes reload_nats skip "nats-server -signal reload" after writing
# nats-rmm.conf; in the Compose stack the nats service reloads the file itself
# (docker/nats/reload-watch.sh).
# ULRMM_NATS_RELOAD = True

# --- Repository settings ------------------------------------------------------
# Where update.sh fetches code and what the dashboard checks for updates.
# update.sh writes these lines itself when called with --git-url/--branch/--token.
# Empty = no update check in the dashboard.
ULRMM_GIT_URL = "https://github.com/RiDDiX/ulrmm.git"
ULRMM_GIT_BRANCH = "main"
ULRMM_WEB_GIT_URL = "https://github.com/RiDDiX/ulrmm-web.git"
ULRMM_WEB_GIT_BRANCH = "main"
# Access token for private repositories. Gitea takes it as the basic-auth
# password, the user name does not matter. The token lives only here and in
# the backups.
ULRMM_GIT_USER = "git"
ULRMM_GIT_TOKEN = "<REDACTED>"

# Where the self-built agents are served: the nginx location that serves
# /opt/ulrmm-agents/dist. Empty = <backend URL>/agentdist.
SELF_BUILT_AGENTS_URL = "https://api.riddix.de/agentdist"

# Endpoints the agent must not ask third parties for. Compiled in at build
# time; a change means rebuild and roll out.
# /pubip is defined in rmm.conf. ULRMM_AGENT_PY_URL empty = the Python mirror
# that build_agents.sh creates under <SELF_BUILT_AGENTS_URL>/python.
ULRMM_AGENT_PUBIP_URL = "https://api.riddix.de/pubip"
ULRMM_AGENT_PY_URL = ""

# Agent source for build_agents.sh. Default: ULRMM_GIT_URL with ulrmm-agent.git
# as the last path element, branch main. Token: ULRMM_GIT_TOKEN.
# ULRMM_AGENT_GIT_URL = "https://git.example.com/you/ulrmm-agent.git"
# ULRMM_AGENT_GIT_REF = "main"

# Only needed when the built agents are not under /opt/ulrmm-agents/dist; the
# self-healing endpoint reads the SHA256 of the current builds there.
# AGENTS_DIST_DIR = "/opt/ulrmm-agents/dist"

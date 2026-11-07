# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os
import sys
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from corsheaders.defaults import default_headers
from django.core.exceptions import ImproperlyConfigured

from ulrmm.util_settings import get_backend_url, get_root_domain, get_webdomain

BASE_DIR = Path(__file__).resolve().parent.parent

SCRIPTS_DIR = "/opt/ulrmm-community-scripts"

# nginx serves this tree under /private/
private_dir = os.path.join(BASE_DIR, "ulrmm", "private")
LOG_DIR = os.path.join(private_dir, "log")
EXE_DIR = os.path.join(private_dir, "exe")
# base installer images of the ISO builder; build outputs go to jobs/
ISO_DIR = os.path.join(private_dir, "iso")
# uploaded software packages, named by their sha256
PACKAGES_DIR = os.path.join(private_dir, "packages")
# SDIO torrent and driver pack indexes, fetched again when missing
SDIO_DIR = os.path.join(private_dir, "sdio")

LINUX_AGENT_SCRIPT = BASE_DIR / "core" / "agent_linux.sh"
FREEBSD_AGENT_SCRIPT = BASE_DIR / "core" / "agent_freebsd.sh"

MAC_UNINSTALL = BASE_DIR / "core" / "mac_uninstall.sh"

AUTH_USER_MODEL = "accounts.User"

# product version, from VERSION in the repo root.
# update.sh, the version check and the dashboard read that file.
VERSION_FILE = BASE_DIR.parent.parent / "VERSION"
if not VERSION_FILE.is_file():
    raise ImproperlyConfigured(
        f"VERSION file not found at {VERSION_FILE}. It carries the product version "
        "the server reports to the dashboard, the API and every agent installer. "
        "Deploy it together with the code."
    )

# latest release
ULRMM_VERSION = VERSION_FILE.read_text().strip()

# bump this version everytime vue code is changed
# to alert user they need to manually refresh their browser
APP_VER = "0.0.203"

LATEST_AGENT_VER = "1.07.11.2026"

# first agent that installs from winget, older ones only get Chocolatey
WINGET_MIN_AGENT = "3.20.10.2026"

# first agent that stays awake on AC power (macOS)
KEEPAWAKE_AC_MIN_AGENT = "2.03.11.2026"

# first agent that installs approved SDIO pack drivers
SDIO_MIN_AGENT = "5.20.10.2026"

# first agent that checks in on <agent_id>.checkin, verifies signed updates
# and pins the server certificates; older ones keep publishing on <agent_id>
SEC_R1_MIN_AGENT = "2.25.10.2026"

# first agent with an identity key, nkey login and signed, encrypted commands.
# The "sec2" capability of the identity decides the protocol; this only feeds
# UI hints and the coverage text.
SEC_R2_MIN_AGENT = "3.25.10.2026"

MESH_VER = "1.2.4"

NATS_SERVER_VER = "2.14.4"

# Optional script runtimes the agent installs next to itself. *_VERSION is
# fetched from the project's GitHub releases unless *_URL is set. *_URL must be
# a plain, unauthenticated download of the ready binary; {OS}, {ARCH} and
# {VERSION} are replaced with GOOS, GOARCH and the version, and Windows agents
# append ".exe" themselves, e.g. https://example.com/nu/{OS}/{ARCH}/{VERSION}/nu
# *_SHA256 is the binary's sha256 and overrides the built-in digests; it is
# required with *_URL, without it the agent refuses to install the runtime.
INSTALL_NUSHELL = True
INSTALL_NUSHELL_VERSION = "0.112.2"
INSTALL_NUSHELL_URL = ""
INSTALL_NUSHELL_SHA256 = ""
# False runs nu with --no-config-file so a user config cannot change how
# scripts behave; True points --config/--env-config at the agent directory,
# which plugins need (nushell issue 10754).
NUSHELL_ENABLE_CONFIG = False

INSTALL_DENO = True
INSTALL_DENO_VERSION = "v1.46.3"
INSTALL_DENO_URL = ""
INSTALL_DENO_SHA256 = ""
# space separated deno permission flags, e.g. "--allow-net --allow-env"
DENO_DEFAULT_PERMISSIONS = "--allow-all"

# update.sh rebuilds the virtualenv whenever this number changes
PIP_VER = "49"

SETUPTOOLS_VER = "83.0.0"
WHEEL_VER = "0.47.0"

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

ASGI_APPLICATION = "ulrmm.asgi.application"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
# no translations are shipped
USE_I18N = False
USE_TZ = True

STATIC_URL = "/static/"

STATIC_ROOT = f"{BASE_DIR}/static"
STATICFILES_DIRS = [f"{BASE_DIR}/ulrmm/static/"]

REST_KNOX = dict(
    TOKEN_TTL=timedelta(hours=5), AUTO_REFRESH=True, MIN_REFRESH_INTERVAL=600
)
# a dashboard login ends this long after it started, refreshed or not
DASHBOARD_TOKEN_MAX_TTL = timedelta(hours=12)

# feature switches, local_settings turns them on
DEBUG = ADMIN_ENABLED = HOSTED = SWAGGER_ENABLED = False
REDIS_HOST = "127.0.0.1"
REDIS_PASSWORD = ""
# MeshCentral control and agent download host (MESH_PORT); docker/ sets "mesh"
MESH_HOST = "127.0.0.1"
# where nats-rmm.conf and nats-api.conf are written; empty = BASE_DIR, docker/ sets "/conf"
ULRMM_CONF_DIR = ""
# False skips "nats-server -signal reload" after writing nats-rmm.conf
ULRMM_NATS_RELOAD = True
ULRMM_LOG_LEVEL = "ERROR"
ULRMM_LOG_TO = "file"
ULRMM_PROTO = "https"
ULRMM_BACKEND_PORT = None
# only for deployments behind proxies in addition to the bundled nginx
ULRMM_TRUST_X_FORWARDED_FOR = False
ULRMM_CHECK_CREDS_MIN_THROTTLE = 10
ULRMM_CHECK_CREDS_DAY_THROTTLE = 300
ULRMM_LOGIN_MIN_THROTTLE = 10
ULRMM_LOGIN_DAY_THROTTLE = 300
ULRMM_BRANDING_THROTTLE = 120
ULRMM_POSIX_PATCH_AUTOMATION = False

# git remote for update.sh and the dashboard update check.
# update.sh writes these from --git-url/--branch/--token.
# Empty ULRMM_GIT_URL skips the check.
ULRMM_GIT_URL = ""
ULRMM_GIT_BRANCH = ""
ULRMM_GIT_USER = ""
ULRMM_GIT_TOKEN = ""
ULRMM_WEB_GIT_URL = ""
ULRMM_WEB_GIT_BRANCH = ""
# script library (branch main). Empty = ulrmm-scripts.git next to ULRMM_GIT_URL.
ULRMM_SCRIPTS_GIT_URL = ""

# Signed releases for the dashboard update (core/releases.py). Every source
# is asked, dashboard repos included; the newest verified release wins.
# None = GitHub, plus the developer's Gitea once ULRMM_RELEASE_GITEA_TOKEN is
# set (its API refuses anonymous calls). A list in local_settings.py replaces
# both.
ULRMM_RELEASE_SOURCES = None
ULRMM_RELEASE_GITHUB_TOKEN = ""
ULRMM_RELEASE_GITEA_TOKEN = ""
# hosts of added repositories that may resolve to a LAN address
ULRMM_RELEASE_TRUSTED_HOSTS: list[str] = []

# Where this instance serves agents built by riddix/agents/build_agents.sh.
# Empty = <backend url>/agentdist. install.sh and restore.sh put that in rmm.conf.
# Set this when the files live somewhere else.
# File names: ulrmm/agent_ident.py agent_artifact().
SELF_BUILT_AGENTS_URL = ""

# Ed25519 seed (base64, 32 bytes) for enrollment tokens. install.sh/update.sh
# generate it; a new key means rebuilding the agents (brand.go holds the
# public key) and invalidates every installer handed out before.
ENROLL_SIGNING_KEY = ""
# base64 32-byte keys for the encrypted database columns, the first one
# encrypts. Empty: the key derived from SECRET_KEY, as before. install.sh and
# update.sh generate one; rotate_field_keys re-encrypts with a new first key.
FIELD_ENCRYPTION_KEYS: list[str] = []
# base64 32-byte HMAC keys for the agent token digests, the first one makes
# new digests, every one is tried on lookup (at most 3). install.sh and
# update.sh generate one; to rotate put a new key first and drop the old one
# once every agent refreshed its tokens (AGENT_REFRESH_TTL at the latest).
AGENT_TOKEN_PEPPERS: list[str] = []
# agent tokens, offline recovery and the command sessions
AGENT_ACCESS_TTL = timedelta(days=7)
AGENT_REFRESH_TTL = timedelta(days=60)
OFFLINE_GRACE = timedelta(days=30)
E2E_REKEY_SECONDS = 3600
E2E_REKEY_BYTES = 64 << 20
E2E_REKEY_MESSAGES = 100_000
E2E_CLOCK_WINDOW = 30
# agent client certificate CA (ca.key, ca.pem); nginx reads ca.pem
AGENT_CA_DIR = "/etc/ulrmm/agent-ca"

# Baked in by riddix/agents/build_agents.sh. A change means rebuild and rollout.
# Empty pubip: agent still looks up a public IP. Empty python url: <agents dist url>/python.
#   ULRMM_AGENT_PUBIP_URL: caller's IP as plain text. rmm.conf has "location = /pubip".
#     ULRMM_AGENT_PUBIP_URL = "https://api.example.com/pubip"
#   ULRMM_AGENT_PY_URL: py3.x.y_amd64.zip / _386.zip for the windows agent.
ULRMM_AGENT_PUBIP_URL = ""
ULRMM_AGENT_PY_URL = ""

# agent identity: service name, install dir, config paths, registry key,
# task prefix, artifact names, Inno AppId. The agent build reads the same values.
# Another reported identity gets no artifacts.
AGENT_SVC_NAME = "ulrmm-agent"
AGENT_WIN_EXE = "ulrmm-agent.exe"
AGENT_WIN_PROG_DIR = "ULRMM Agent"
AGENT_WIN_REG_KEY = "UniversalLocalRMM"
AGENT_NIX_BIN = "ulrmm-agent"
AGENT_NIX_DIR = "/opt/ulrmm-agent"
AGENT_NIX_CONF = "/etc/ulrmm-agent"
AGENT_NIX_SVC = "ulrmm-agent.service"
AGENT_MAC_PLIST_LABEL = "ulrmm-agent"
AGENT_TASK_PREFIX = "ULRMM_"
AGENT_ARTIFACT_NAME = "ulrmm-agent"
AGENT_INNO_APPID = "{{61D095D9-C6CE-4D60-B192-4C6699822C40}"

# extra nets for netmon (e.g. ["10.20.0.0/16"]); default=server's private nets only.
NETMON_ALLOWED_NETWORKS: list[str] = []

ALLOWED_HOSTS = []
CORS_ORIGIN_WHITELIST = []
# chunked package uploads send Content-Range from the dashboard origin
CORS_ALLOW_HEADERS = (*default_headers, "content-range")
CORS_EXPOSE_HEADERS = ("X-Sha256", "X-Volume-Label")

from sso.settings import *  # noqa

with suppress(ImportError):
    from .local_settings import *  # noqa

in_ci = "GHACTIONS" in os.environ
if in_ci:
    print("-----------------------GHACTIONS----------------------------")
    ci_db = "pipeline"
    DATABASES = {
        "default": dict(
            ENGINE="django.db.backends.postgresql",
            NAME=ci_db,
            USER=ci_db,
            PASSWORD=f"{ci_db}123456",
            HOST="127.0.0.1",
            PORT="",
        )
    }
    SECRET_KEY = "abcdefghijklmnoptravis123456789"
    ALLOWED_HOSTS = ["api.example.com"]
    ADMIN_URL = "abc123456/"
    CORS_ORIGIN_WHITELIST = ["https://rmm.example.com"]
    MESH_USERNAME = "pipeline"
    MESH_SITE = "https://example.com"
    MESH_TOKEN_KEY = "bd65e957a1e70c622d32523f61508400d6cd0937001a7ac12042227eba0b9ed625233851a316d4f489f02994145f74537a331415d00047dbbf13d940f556806dffe7a8ce1de216dc49edbad0c1a7399c"
    REDIS_HOST = "localhost"
    ENROLL_SIGNING_KEY = "dWxybW0tdGVzdC1lbnJvbGwtc2lnbmluZy1rZXktMzI="

ULRMM_ROOT_DOMAIN = get_root_domain(ALLOWED_HOSTS[0])
frontend_domain = get_webdomain(CORS_ORIGIN_WHITELIST[0]).split(":")[0]

ALLOWED_HOSTS.append(frontend_domain)

if DEBUG:
    ALLOWED_HOSTS.append("*")

backend_url = get_backend_url(ALLOWED_HOSTS[0], ULRMM_PROTO, ULRMM_BACKEND_PORT)

# session cookie stays on the api host. the dashboard on its own subdomain
# reads the csrf cookie and posts it back for the SSO login.
CSRF_COOKIE_DOMAIN = ULRMM_ROOT_DOMAIN
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = "DENY"
dashboard_origin = CORS_ORIGIN_WHITELIST[0]
CSRF_TRUSTED_ORIGINS = [dashboard_origin, backend_url]
HEADLESS_FRONTEND_URLS = {
    "socialaccount_login_error": dashboard_origin + "/account/provider/callback"
}

if in_ci:
    DEBUG = ADMIN_ENABLED = False

# DRF >= 3.18 reads JSON and form bodies through request.body, which applies
# this cap (Django default 2.5 MB). Large reports, scripts and imports never
# had it; nginx client_max_body_size (300M, 64k on the anonymous POSTs) is the limit
DATA_UPLOAD_MAX_MEMORY_SIZE = None

REST_FRAMEWORK = {
    # throttle key is the client address. X-Forwarded-For is client-controlled
    # unless ULRMM_TRUST_X_FORWARDED_FOR (more proxies in front of nginx)
    "NUM_PROXIES": None if ULRMM_TRUST_X_FORWARDED_FOR else 0,
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "ulrmm.auth.DashboardTokenAuthentication",
        "ulrmm.auth.APIAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_RATES": {
        "check_creds_min": f"{ULRMM_CHECK_CREDS_MIN_THROTTLE}/minute",
        "login_min": f"{ULRMM_LOGIN_MIN_THROTTLE}/minute",
        "check_creds_day": f"{ULRMM_CHECK_CREDS_DAY_THROTTLE}/day",
        "login_day": f"{ULRMM_LOGIN_DAY_THROTTLE}/day",
        "branding": f"{ULRMM_BRANDING_THROTTLE}/minute",
        "netmon_test": "10/minute",
        "vault_reveal": "30/minute",
        "pendingaction_cancel": "30/minute",
        "installer": "60/minute",
        "deploy_download": "600/hour",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "UniversalLocal RMM API",
    "DESCRIPTION": "Simple and Fast remote monitoring and management tool",
    "VERSION": ULRMM_VERSION,
    "AUTHENTICATION_WHITELIST": ["ulrmm.auth.APIAuthentication"],
}


if not DEBUG:
    # no browsable API outside development
    REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = (
        "rest_framework.renderers.JSONRenderer",
    )

django_apps = """
    django.contrib.auth django.contrib.contenttypes django.contrib.sessions
    django.contrib.staticfiles channels rest_framework rest_framework.authtoken
    knox corsheaders
""".split()
project_apps = """
    apiv3 apiv4 clients agents checks services winupdate software core branding
    patches remote netmon metrics groups timeline discovery vulns vault
    encryption nix dashboard laps integrations notify assets appupdates
    packages deploy automation autotasks logs scripts alerts sso reporting
    importers
""".split()
INSTALLED_APPS = [
    *django_apps,
    "accounts",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.openid_connect",
    "allauth.headless",
    *project_apps,
]

# requirepass in redis.conf, same value as REDIS_PASSWORD in local_settings
REDIS_URL = f"redis://{REDIS_HOST}:6379"
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{quote(REDIS_PASSWORD, safe='')}@{REDIS_HOST}:6379"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [REDIS_URL],
        },
    },
}


# silence cache key length warnings
import warnings  # noqa

from django.core.cache import CacheKeyWarning  # noqa

warnings.simplefilter("ignore", CacheKeyWarning)

CACHES = {
    "default": {
        "BACKEND": "ulrmm.cache.ULRMMRedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "parser_class": "redis.connection._HiredisParser",
            "pool_class": "redis.BlockingConnectionPool",
            "db": "10",
        },
    }
}

MIDDLEWARE = [
    # defaults: nosniff, referrer-policy, opener policy. HSTS stays on nginx.
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "ulrmm.middleware.LogIPMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "ulrmm.middleware.AuditMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

if SWAGGER_ENABLED:
    INSTALLED_APPS.append("drf_spectacular")

if DEBUG:
    # daphne must come first so runserver serves ASGI
    INSTALLED_APPS = ["daphne", *INSTALLED_APPS, "django_extensions", "silk"]
    MIDDLEWARE = ["silk.middleware.SilkyMiddleware", *MIDDLEWARE]

if ADMIN_ENABLED:
    INSTALLED_APPS.extend(["django.contrib.admin", "django.contrib.messages"])
    MIDDLEWARE.append("django.contrib.messages.middleware.MessageMiddleware")


ROOT_URLCONF = "ulrmm.urls"


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "DIRS": [],
        "OPTIONS": {
            "context_processors": [
                f"django.{mod}.context_processors.{name}"
                for mod, name in (
                    ("template", "debug"),
                    ("template", "request"),
                    ("contrib.auth", "auth"),
                    ("contrib.messages", "messages"),
                )
            ]
        },
    }
]

WSGI_APPLICATION = "ulrmm.wsgi.application"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": f"django.contrib.auth.password_validation.{validator}"}
    for validator in (
        "UserAttributeSimilarityValidator",
        "MinimumLengthValidator",
        "CommonPasswordValidator",
        "NumericPasswordValidator",
    )
]


def get_log_level() -> str:
    return os.environ.get("ULRMM_LOG_LEVEL", ULRMM_LOG_LEVEL)


def _log_handler(level: str, handler_class: str, **target) -> dict:
    return {
        "class": handler_class,
        "level": level,
        "formatter": "verbose",
        "filters": ["redact"],
        **target,
    }


def configure_logging_handler(level: str, name: str) -> dict:
    if os.getenv("ULRMM_LOG_TO", ULRMM_LOG_TO) == "stdout":
        return _log_handler(level, "logging.StreamHandler", stream=sys.stdout)
    path = os.path.join(LOG_DIR, name)
    return _log_handler(level, "logging.FileHandler", filename=path)


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact": {"()": "ulrmm.logfilter.RedactFilter"}},
    "formatters": {
        "verbose": {
            "format": "[%(asctime)s] %(levelname)s [%(filename)s:%(funcName)s:%(lineno)d] %(message)s",
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
    },
    "handlers": {
        "file": configure_logging_handler("ERROR", "django_debug.log"),
        "ulrmm": configure_logging_handler(get_log_level(), "ulrmm_debug.log"),
    },
    "loggers": {
        "django.request": {"handlers": ["file"], "level": "ERROR", "propagate": True},
        "ulrmm": {"handlers": ["ulrmm"], "level": get_log_level(), "propagate": False},
    },
}

# history samples kept by metrics.tasks.prune_metrics_task
METRICS_RETENTION_DAYS = 30

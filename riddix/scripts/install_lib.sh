# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# shellcheck shell=bash
# sourced by install.sh and restore.sh.
# Builds clone urls, writes them to local_settings.py under the names
# update.sh and build_agents.sh already read, builds the frontend, then
# calls build_agents.sh. Also writes the systemd units, celery.conf and rmm.conf.
#
# Caller sets GREEN/YELLOW/RED/NC, local_settings, SCRIPTS_DIR, SELF_DIR,
# non_interactive and arg_* before resolve_repos, and manage() before
# ensure_agent_ca.
#
# update.sh sources the copy from the ref it is about to deploy, before it
# stops services. Until then it uses its own ls_get/ls_set, askpass and
# frontend build.

ULRMM_GITEA_BASE='https://git.riddix.de/RiDDiX'
ULRMM_GITHUB_BASE='https://github.com/RiDDiX'
ULRMM_DEFAULT_BRANCH='main'
ULRMM_DEFAULT_SERVER_REPO='ulrmm'
ULRMM_DEFAULT_AGENT_REPO='ulrmm-agent'
ULRMM_DEFAULT_SCRIPTS_REPO='ulrmm-scripts'
WEB_DIR='/opt/ulrmm-web'
WEB_SRC="${WEB_DIR}/src"
AGENT_ROOT='/opt/ulrmm-agents'
# AGENT_CA_DIR in settings.py; nginx reads ca.pem from here
AGENT_CA_DIR='/etc/ulrmm/agent-ca'
# Debian and Ubuntu redis-server read only this file
REDIS_CONF=${REDIS_CONF:-/etc/redis/redis.conf}
# frontend CSP header: Content-Security-Policy enforces the policy,
# Content-Security-Policy-Report-Only only reports to the browser console
FRONTEND_CSP_HEADER='Content-Security-Policy'

# sha256 pins for downloads that are built or run as-is.
# nats-server version is NATS_SERVER_VER in settings.py. A new one needs
# its sums here (from the release SHA256SUMS) or it is not installed.
PYTHON_VER='3.12.13'
PYTHON_SHA256='0816c4761c97ecdb3f50a3924de0a93fd78cb63ee8e6c04201ddfaedca500b0b'
NATS_PINNED_VER='2.14.4'
NATS_SHA256_amd64='20f9d6a199560f243610908bcccea2e27e9f47213242d1c609ca46d1d73e91ea'
NATS_SHA256_arm64='2143f4317ac8e1dd42793c912fa09b405c7036ba181b2a3002b74501d13562b0'

lib_info() { printf >&2 '%b%s%b\n' "$GREEN" "$*" "$NC"; }
lib_warn() { printf >&2 '%b%s%b\n' "$YELLOW" "$*" "$NC"; }
# optional lib_cleanup, called from lib_die. Not an EXIT trap: git_auth sets one.
lib_die() {
  printf >&2 '%bERROR: %s%b\n' "$RED" "$*" "$NC"
  if declare -F lib_cleanup >/dev/null; then
    lib_cleanup
  fi
  exit 1
}

# read a NAME = "value" entry from local_settings.py, or from the file in $2
ls_get() {
  local f=${2:-$local_settings}
  [ -f "$f" ] || return 0
  grep -E "^${1}[[:space:]]*=[[:space:]]*[\"']" "$f" 2>/dev/null | tail -1 | sed -E "s/^[^=]*=[[:space:]]*[\"']([^\"']*)[\"'].*/\\1/"
}

# same shape as update.sh. Value is appended, not passed through sed
# (the token would show up in argv).
ls_set() {
  local key="$1" val="$2"
  case "$val" in
  *\"* | *\\* | *$'\n'*)
    lib_die "$key must not contain quotes, backslashes or newlines."
    ;;
  esac
  touch "$local_settings"
  # it holds the git token; every service reads it as its owner
  chmod 600 "$local_settings"
  sed -i -E "/^${key}[[:space:]]*=/d" "$local_settings"
  printf '\n%s = "%s"\n' "$key" "$val" >>"$local_settings"
}

ask() {
  local answer=''
  if [ "${non_interactive:-false}" != true ]; then
    printf >&2 '%b%s%b [%s]: ' "$YELLOW" "$1" "$NC" "$2"
    read -r answer
  fi
  printf '%s' "${answer:-$2}"
}

# --source gitea|github or --git-base <url>, no trailing slash.
# Known hosts ignore owner case. Store one spelling so update.sh's
# origin compare does not flap.
git_base() {
  local base b
  if [ -n "$2" ]; then
    base=$2
  else
    case "${1,,}" in
    '' | github) base=$ULRMM_GITHUB_BASE ;;
    gitea) base=$ULRMM_GITEA_BASE ;;
    *) return 1 ;;
    esac
  fi
  base=${base%/}
  for b in "$ULRMM_GITHUB_BASE" "$ULRMM_GITEA_BASE"; do
    if [ "${base,,}" = "${b,,}" ]; then
      base=$b
    fi
  done
  printf '%s' "$base"
}

repo_url() { printf '%s/%s.git' "$1" "${2%.git}"; }

url_host() {
  local h=${1#*://}
  h=${h%%/*}
  printf '%s' "${h,,}"
}

unsafe_value() {
  case "$1" in
  *[[:space:]\"\'\\]*) return 0 ;;
  esac
  return 1
}

ASKPASS_FILE=''
askpass_cleanup() {
  if [ -n "$ASKPASS_FILE" ]; then
    rm -f "$ASKPASS_FILE"
  fi
  ASKPASS_FILE=''
}

# https + token via GIT_ASKPASS. Not in argv, the remote url or .git/config.
# Only for the host of the server repo. Any other host gets nothing.
git_auth() {
  local url=$1
  shift
  if [ -n "$GIT_TOKEN" ] && [ "$(url_host "$url")" = "$(url_host "$GIT_URL")" ]; then
    if [ -z "$ASKPASS_FILE" ]; then
      ASKPASS_FILE=$(mktemp -p "" "rmmaskpass_XXXXXXXXXX")
      chmod 700 "$ASKPASS_FILE"
      cat >"$ASKPASS_FILE" <<'EOF'
#!/bin/sh
case "$1" in
*[Uu]sername*) printf '%s\n' "${ULRMM_ASKPASS_USER:-git}" ;;
*) printf '%s\n' "${ULRMM_ASKPASS_TOKEN}" ;;
esac
EOF
      trap askpass_cleanup EXIT
    fi
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS_FILE" ULRMM_ASKPASS_USER="$GIT_USER" \
      ULRMM_ASKPASS_TOKEN="$GIT_TOKEN" git -c credential.helper= "$@"
  else
    GIT_TERMINAL_PROMPT=0 git -c credential.helper= "$@"
  fi
}

# arg_* -> GIT_BASE, *_REPO, GIT_URL/WEB_GIT_URL/AGENT_GIT_URL, branches, user,
# token. Asks for what is missing unless non_interactive=true.
resolve_repos() {
  if [ -z "$arg_git_base" ] && [ -z "$arg_source" ]; then
    arg_source=$(ask "Install source, github or gitea" github)
  fi
  GIT_BASE=$(git_base "$arg_source" "$arg_git_base") || lib_die "--source must be github or gitea, not '${arg_source}'."
  SERVER_REPO=${arg_server_repo:-$(ask "Server repository" "$ULRMM_DEFAULT_SERVER_REPO")}
  WEB_REPO=${arg_web_repo:-$(ask "Web repository" "${SERVER_REPO%.git}-web")}
  AGENT_REPO=${arg_agent_repo:-$(ask "Agent repository" "$ULRMM_DEFAULT_AGENT_REPO")}
  SERVER_REPO=${SERVER_REPO%.git} WEB_REPO=${WEB_REPO%.git} AGENT_REPO=${AGENT_REPO%.git}
  GIT_BRANCH=${arg_branch:-$(ask "Branch" "$ULRMM_DEFAULT_BRANCH")}
  WEB_GIT_BRANCH=${arg_web_branch:-$GIT_BRANCH}
  AGENT_GIT_REF=${arg_agent_branch:-$GIT_BRANCH}
  GIT_USER=${arg_git_user:-git}
  SCRIPTS_GIT_URL=${arg_scripts_git_url:-$(repo_url "$GIT_BASE" "$ULRMM_DEFAULT_SCRIPTS_REPO")}

  local v
  for v in "$GIT_BASE" "$SCRIPTS_GIT_URL"; do
    case "$v" in
    http://*@* | https://*@*) lib_die "$v: no credentials in urls, the token goes in with --token or --token-file." ;;
    http://?* | https://?*) ;;
    *) lib_die "$v is not an http(s) url." ;;
    esac
    ! unsafe_value "$v" || lib_die "'$v' contains spaces, quotes or backslashes."
  done
  for v in "$SERVER_REPO" "$WEB_REPO" "$AGENT_REPO"; do
    [[ $v =~ ^[A-Za-z0-9._-]+$ ]] || lib_die "'$v' is not a repository name."
  done
  for v in "$GIT_BRANCH" "$WEB_GIT_BRANCH" "$AGENT_GIT_REF"; do
    [[ $v =~ ^[A-Za-z0-9._/-]+$ ]] || lib_die "'$v' is not a branch name."
  done
  ! unsafe_value "$GIT_USER" || lib_die "--git-user contains spaces, quotes or backslashes."

  GIT_URL=$(repo_url "$GIT_BASE" "$SERVER_REPO")
  WEB_GIT_URL=$(repo_url "$GIT_BASE" "$WEB_REPO")
  AGENT_GIT_URL=$(repo_url "$GIT_BASE" "$AGENT_REPO")

  GIT_TOKEN=''
  if [ -n "$arg_token_file" ]; then
    [ -r "$arg_token_file" ] || lib_die "cannot read the token file ${arg_token_file}."
    GIT_TOKEN=$(tr -d '[:space:]' <"$arg_token_file")
  elif [ -n "$arg_token" ]; then
    GIT_TOKEN=$arg_token
  elif [ "${non_interactive:-false}" != true ]; then
    read -rsp "Read token for ${GIT_BASE} (blank for public repositories): " GIT_TOKEN
    echo >&2
  fi
  arg_token=''
  ! unsafe_value "$GIT_TOKEN" || lib_die "the token contains spaces, quotes or backslashes."
}

# shallow fetch before this host is changed. Checks url, branch, token, VERSION.
# Stops if these scripts differ from the branch.
# $@ = paths relative to the repo root.
repo_preflight() {
  local tmp f want have
  tmp=$(mktemp -d)
  git init -q --bare "$tmp"
  lib_info "Checking ${GIT_URL} (${GIT_BRANCH})"
  if ! git_auth "$GIT_URL" -C "$tmp" fetch --quiet --depth=1 "$GIT_URL" "+refs/heads/${GIT_BRANCH}:refs/ulrmm/target"; then
    rm -rf "$tmp"
    lib_die "could not fetch branch ${GIT_BRANCH} from ${GIT_URL}. Check --source/--git-base, --server-repo, --branch and, for a private repository, the token."
  fi
  TARGET_COMMIT=$(git -C "$tmp" rev-parse refs/ulrmm/target)
  TARGET_VERSION=$(git -C "$tmp" show refs/ulrmm/target:VERSION 2>/dev/null | tr -d '[:space:]')
  for f in "$@"; do
    want=$(git -C "$tmp" rev-parse -q --verify "refs/ulrmm/target:${f}" 2>/dev/null)
    have=$(git hash-object --no-filters "${SELF_DIR}/${f}")
    if [ "$want" != "$have" ]; then
      rm -rf "$tmp"
      lib_die "${f} in ${SELF_DIR} is not the one on ${GIT_BRANCH} (${TARGET_COMMIT:0:8}). Bring this checkout to ${GIT_BRANCH} (git -C ${SELF_DIR} pull) and start again."
    fi
  done
  rm -rf "$tmp"
  [ -n "$TARGET_VERSION" ] || lib_die "${GIT_BRANCH} has no VERSION file, it is not a UniversalLocal RMM branch."

  git_auth "$WEB_GIT_URL" ls-remote --exit-code "$WEB_GIT_URL" "refs/heads/${WEB_GIT_BRANCH}" >/dev/null ||
    lib_die "no branch ${WEB_GIT_BRANCH} in ${WEB_GIT_URL} (or the token cannot read it). Check --web-repo/--web-branch."
  if [ "${skip_agent_build:-false}" != true ]; then
    git_auth "$AGENT_GIT_URL" ls-remote --exit-code "$AGENT_GIT_URL" "refs/heads/${AGENT_GIT_REF}" "refs/tags/${AGENT_GIT_REF}" >/dev/null ||
      lib_die "no branch or tag ${AGENT_GIT_REF} in ${AGENT_GIT_URL} (or the token cannot read it). Check --agent-repo/--agent-branch, or use --skip-agent-build."
  fi
  lib_info "UniversalLocal RMM ${TARGET_VERSION} from ${GIT_URL} (${GIT_BRANCH}, ${TARGET_COMMIT:0:8})"
}

clone_repos() {
  sudo mkdir -p /rmm "$SCRIPTS_DIR" "$WEB_DIR"
  sudo chown "${USER}:${USER}" /rmm "$SCRIPTS_DIR" "$WEB_DIR"

  git_auth "$GIT_URL" clone --quiet --branch "$GIT_BRANCH" "$GIT_URL" /rmm/ ||
    lib_die "cloning ${GIT_URL} failed."
  git -C /rmm config user.email "admin@example.com"
  git -C /rmm config user.name "Bob"

  if git_auth "$SCRIPTS_GIT_URL" clone --quiet "$SCRIPTS_GIT_URL" "${SCRIPTS_DIR}/"; then
    git -C "$SCRIPTS_DIR" config user.email "admin@example.com"
    git -C "$SCRIPTS_DIR" config user.name "Bob"
    # update.sh checks out main
    git -C "$SCRIPTS_DIR" checkout --quiet main
  else
    lib_warn "cloning ${SCRIPTS_GIT_URL} failed, the community scripts are missing. update.sh fetches them again."
  fi

  git_auth "$WEB_GIT_URL" clone --quiet --branch "$WEB_GIT_BRANCH" "$WEB_GIT_URL" "$WEB_SRC" ||
    lib_die "cloning ${WEB_GIT_URL} failed."
}

# full urls, under the names update.sh and build_agents.sh read.
# Base and repo names are stored as ULRMM_* too. Neither script reads those.
write_repo_settings() {
  ls_set ULRMM_GIT_URL "$GIT_URL"
  ls_set ULRMM_GIT_BRANCH "$GIT_BRANCH"
  ls_set ULRMM_GIT_USER "$GIT_USER"
  if [ -n "$GIT_TOKEN" ]; then
    ls_set ULRMM_GIT_TOKEN "$GIT_TOKEN"
  fi
  ls_set ULRMM_WEB_GIT_URL "$WEB_GIT_URL"
  ls_set ULRMM_WEB_GIT_BRANCH "$WEB_GIT_BRANCH"
  ls_set ULRMM_AGENT_GIT_URL "$AGENT_GIT_URL"
  ls_set ULRMM_AGENT_GIT_REF "$AGENT_GIT_REF"
  ls_set ULRMM_GIT_BASE "$GIT_BASE"
  ls_set ULRMM_GIT_SERVER_REPO "$SERVER_REPO"
  ls_set ULRMM_GIT_WEB_REPO "$WEB_REPO"
  ls_set ULRMM_GIT_AGENT_REPO "$AGENT_REPO"
  ls_set ULRMM_SCRIPTS_GIT_URL "$SCRIPTS_GIT_URL"
}

# the server's own NATS user gets a password of its own instead of SECRET_KEY
ensure_nats_password() {
  if [ -z "$(ls_get NATS_SERVER_PASSWORD)" ]; then
    ls_set NATS_SERVER_PASSWORD "$(openssl rand -hex 32)"
  fi
}

# Ed25519 seed of the enrollment tokens. The agents carry its public key
# (brand.go): a new one needs an agent build and voids every installer handed out.
ensure_enroll_key() {
  if [ -z "$(ls_get ENROLL_SIGNING_KEY)" ]; then
    ls_set ENROLL_SIGNING_KEY "$(openssl rand -base64 32)"
  fi
}

# keys of the encrypted database columns (FIELD_ENCRYPTION_KEYS, first one
# encrypts). Without them the key comes from SECRET_KEY. A new key goes first,
# then manage.py rotate_field_keys re-encrypts; see its --help.
ensure_field_keys() {
  grep -q '^FIELD_ENCRYPTION_KEYS' "$local_settings" 2>/dev/null && return 0
  touch "$local_settings" && chmod 600 "$local_settings" &&
    printf '\nFIELD_ENCRYPTION_KEYS = ["%s"]\n' "$(openssl rand -base64 32)" >>"$local_settings"
}

# HMAC keys of the agent token digests (AGENT_TOKEN_PEPPERS, first one makes
# new digests). Runs before manage.py migrate: the migration that moves the
# agent tokens to digests reads it. A lost pepper logs every agent out.
ensure_token_pepper() {
  grep -q '^AGENT_TOKEN_PEPPERS' "$local_settings" 2>/dev/null && return 0
  touch "$local_settings" && chmod 600 "$local_settings" &&
    printf '\nAGENT_TOKEN_PEPPERS = ["%s"]\n' "$(openssl rand -base64 32)" >>"$local_settings"
}

# age encrypts the backups (backup.conf BACKUP_AGE_RECIPIENTS)
ensure_age() {
  command -v age >/dev/null || sudo apt install -y age
}

# CA of the agent client certificates; manage.py creates it when missing.
# $@ goes to the command (update.sh, restore.sh: --reset-certs-if-new).
ensure_agent_ca() {
  sudo install -d -m 0755 -o "$USER" -g "$(id -gn)" "$AGENT_CA_DIR" || return 1
  manage ensure_agent_ca "$@"
}

# same as update.sh: npm ci && npm run build in /opt/ulrmm-web/src.
# Returns 1 on failure. The install continues; update.sh --force rebuilds.
build_web() {
  local node_major pkg_ver
  WEB_COMMIT=$(git -C "$WEB_SRC" rev-parse HEAD)
  pkg_ver=$(grep -m1 '"version"' "${WEB_SRC}/package.json" | awk -F'"' '{print $4}')
  if [ "$pkg_ver" != "$TARGET_VERSION" ]; then
    lib_warn "WARNING: frontend version '${pkg_ver:-unknown}' does not match server version '${TARGET_VERSION}'. Continuing."
  fi
  node_major=$(node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')
  if ! command -v npm >/dev/null || ! [[ "$node_major" =~ ^[0-9]+$ ]] || [ "$node_major" -lt 18 ]; then
    lib_warn "ERROR: need node 18 or newer to build the dashboard, got '${node_major:-none}'."
    return 1
  fi
  lib_info "Building the frontend (${WEB_COMMIT:0:8}), this takes a few minutes..."
  rm -rf "${WEB_SRC}/dist"
  if ! (cd "$WEB_SRC" && npm ci && npm run build) || [ ! -f "${WEB_SRC}/dist/index.html" ]; then
    lib_warn "ERROR: frontend build failed or produced no dist/index.html."
    return 1
  fi
}

# $1 = backend domain. Assembled next to the live tree and swapped with mv.
deploy_web() {
  sudo mkdir -p /var/www/rmm
  sudo rm -rf /var/www/rmm/dist.new /var/www/rmm/dist.old
  if ! sudo cp -r "${WEB_SRC}/dist" /var/www/rmm/dist.new; then
    lib_warn "ERROR: could not copy the frontend (disk full?)."
    sudo rm -rf /var/www/rmm/dist.new
    return 1
  fi
  echo "window._env_ = {PROD_URL: \"https://${1}\"}" | sudo tee /var/www/rmm/dist.new/env-config.js >/dev/null
  sudo chown www-data:www-data -R /var/www/rmm/dist.new
  if [ -d /var/www/rmm/dist ]; then
    sudo mv /var/www/rmm/dist /var/www/rmm/dist.old
  fi
  sudo mv /var/www/rmm/dist.new /var/www/rmm/dist
  # not inside the docroot: it would be served at https://<frontend>/.ulrmm-web-commit
  echo "${WEB_COMMIT}" | sudo tee /var/www/rmm/.ulrmm-web-commit >/dev/null
}

# Unit texts. User and group are whoever runs the installer; update.sh
# refuses to run as anyone else.
MAINT_DIR=${MAINT_DIR:-/var/lib/ulrmm-maint}

# one [Unit]/[Service]/[Install] file. $1 description suffix, $2 After=,
# $3 RestartSec=, $4 group, the rest are extra [Service] lines.
_service_unit() {
  local what=$1 after=$2 restart=$3 group=$4
  shift 4
  printf '[Unit]\nDescription=UniversalLocal RMM %s\nAfter=%s\n\n[Service]\n' "$what" "$after"
  printf 'User=%s\nGroup=%s\n' "$USER" "$group"
  printf '%s\n' "$@"
  printf 'Restart=always\nRestartSec=%s\n\n[Install]\nWantedBy=multi-user.target\n' "$restart"
}

unit_text() {
  local api=/rmm/api/ulrmm venv=/rmm/api/env/bin
  local path_env="Environment=\"PATH=${venv}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\""
  local db=postgresql.service
  # the celery units read their settings from celery.conf at start
  local celery_cmd='${CELERY_BIN} -A $CELERY_APP multi'
  local celery_args='--pidfile=${CELERYD_PID_FILE} --logfile=${CELERYD_LOG_FILE} --loglevel="${CELERYD_LOG_LEVEL}" $CELERYD_OPTS'
  case "$1" in
  rmm)
    _service_unit "uwsgi daemon" "network.target $db" 10s www-data \
      "WorkingDirectory=$api" "$path_env" "ExecStart=${venv}/uwsgi --ini app.ini"
    ;;
  daphne)
    _service_unit "uvicorn daemon v1" network.target 3s www-data \
      "WorkingDirectory=$api" "$path_env" \
      "ExecStart=${venv}/uvicorn --uds /rmm/daphne.sock --forwarded-allow-ips='*' --no-access-log ulrmm.asgi:application" \
      "ExecStartPre=rm -f /rmm/daphne.sock" "ExecStartPre=rm -f /rmm/daphne.sock.lock"
    ;;
  nats)
    _service_unit "NATS Server" network.target 5s "$USER" Type=simple PrivateTmp=true LimitNOFILE=1000000 \
      "ExecStart=/usr/local/bin/nats-server -c ${api}/nats-rmm.conf" \
      'ExecReload=/usr/bin/kill -s HUP $MAINPID' 'ExecStop=/usr/bin/kill -s SIGINT $MAINPID'
    ;;
  nats-api)
    _service_unit "Nats Api v1" "nats.service $db" 5s "$USER" Type=simple ExecStart=/usr/local/bin/nats-api
    ;;
  celery)
    _service_unit "Celery Service V2" "network.target redis-server.service $db" 10s "$USER" Type=forking \
      EnvironmentFile=/etc/conf.d/celery.conf "WorkingDirectory=$api" \
      "ExecStart=/bin/sh -c '${celery_cmd} start \$CELERYD_NODES ${celery_args}'" \
      "ExecStop=/bin/sh -c '\${CELERY_BIN} multi stopwait \$CELERYD_NODES --pidfile=\${CELERYD_PID_FILE} --loglevel=\"\${CELERYD_LOG_LEVEL}\"'" \
      "ExecReload=/bin/sh -c '${celery_cmd} restart \$CELERYD_NODES ${celery_args}'"
    ;;
  celerybeat)
    _service_unit "Celery Beat Service V4" "network.target redis-server.service $db" 10s "$USER" Type=simple \
      EnvironmentFile=/etc/conf.d/celery.conf "WorkingDirectory=$api" \
      "ExecStart=/bin/sh -c '\${CELERY_BIN} -A \${CELERY_APP} beat --pidfile=\${CELERYBEAT_PID_FILE} --logfile=\${CELERYBEAT_LOG_FILE} --loglevel=\${CELERYD_LOG_LEVEL}'" \
      "ExecStartPre=rm -f ${api}/beat.pid" "ExecStartPre=rm -f ${api}/celerybeat-schedule"
    ;;
  meshcentral)
    _service_unit "MeshCentral Server" "network.target $db nginx.service" 10s "$USER" Type=simple \
      WorkingDirectory=/meshcentral Environment=NODE_ENV=production UMask=0077 LimitNOFILE=1000000 \
      "ExecStart=/usr/bin/node node_modules/meshcentral"
    ;;
  ulrmm-maint)
    cat <<EOF
[Unit]
Description=UniversalLocal RMM maintenance runner (dashboard updates and backups)
After=network.target $db

[Service]
Type=oneshot
User=${USER}
Group=${USER}
Environment=HOME=${HOME}
WorkingDirectory=${HOME}
ExecStart=/rmm/riddix/scripts/maint_runner.sh
TimeoutStartSec=infinity
EOF
    ;;
  ulrmm-maint-path)
    cat <<EOF
[Unit]
Description=UniversalLocal RMM maintenance requests from the dashboard

[Path]
PathExists=${MAINT_DIR}/request
Unit=ulrmm-maint.service

[Install]
WantedBy=multi-user.target
EOF
    ;;
  *) return 1 ;;
  esac
}

# EnvironmentFile of the celery units
celery_conf_text() {
  local pair
  for pair in \
    CELERY_APP=ulrmm \
    CELERY_BIN=/rmm/api/env/bin/celery \
    CELERYD_MULTI=multi \
    CELERYD_NODES=w1 \
    "CELERYD_OPTS=--time-limit=86400 --autoscale=20,2" \
    CELERYD_LOG_LEVEL=ERROR \
    CELERYD_LOG_FILE=/var/log/celery/%n%I.log \
    CELERYD_PID_FILE=/rmm/api/ulrmm/%n.pid \
    CELERYBEAT_LOG_FILE=/var/log/celery/beat.log \
    CELERYBEAT_PID_FILE=/rmm/api/ulrmm/beat.pid; do
    printf '%s="%s"\n' "${pair%%=*}" "${pair#*=}"
  done
}

# the six /rmm units, celery.conf and the maintenance runner units.
# update.sh rewrites them every run.
# meshcentral.service is written by install.sh and restore.sh only.
# Local changes go in drop-ins (systemctl edit). These files get overwritten.
write_units() {
  local u
  sudo mkdir -p /etc/conf.d || return 1
  for u in rmm daphne celery celerybeat nats nats-api; do
    unit_text "$u" | sudo tee "/etc/systemd/system/${u}.service" >/dev/null || return 1
  done
  celery_conf_text | sudo tee /etc/conf.d/celery.conf >/dev/null || return 1
  # dashboard update/backup requests land in MAINT_DIR; the path unit hands
  # them to the runner, outside the web processes that an update restarts
  sudo install -d -o "$USER" -g "$USER" -m 700 "$MAINT_DIR" || return 1
  unit_text ulrmm-maint | sudo tee /etc/systemd/system/ulrmm-maint.service >/dev/null || return 1
  unit_text ulrmm-maint-path | sudo tee /etc/systemd/system/ulrmm-maint.path >/dev/null || return 1
  sudo systemctl daemon-reload
  sudo systemctl enable --now ulrmm-maint.path >/dev/null 2>&1 || return 1
}

# X25519MLKEM768 needs nginx running with OpenSSL 3.5 or newer
nginx_ecdh_curve() {
  local line
  line=$("$(command -v nginx || echo /usr/sbin/nginx)" -V 2>&1 | grep -m1 'with OpenSSL')
  if { [[ $line =~ running\ with\ OpenSSL\ ([0-9]+)\.([0-9]+) ]] ||
    [[ $line =~ built\ with\ OpenSSL\ ([0-9]+)\.([0-9]+) ]]; } &&
    ((BASH_REMATCH[1] > 3 || (BASH_REMATCH[1] == 3 && BASH_REMATCH[2] >= 5))); then
    echo X25519MLKEM768:X25519:prime256v1:secp384r1
  else
    echo X25519:prime256v1:secp384r1
  fi
}

# TLS 1.2 only with ECDHE and AEAD (older PowerShell and browsers), TLS 1.3
# with the 256-bit suites. $1 indent.
nginx_tls_text() {
  cat <<EOF
${1}ssl_protocols TLSv1.2 TLSv1.3;
${1}ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
${1}ssl_prefer_server_ciphers on;
${1}ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
${1}ssl_ecdh_curve $(nginx_ecdh_curve);
EOF
}

# access log format $1 without the secrets in URLs: installer links, package
# download tokens, SSO code/state and access_token= queries. Named per site,
# nginx reads each site file on its own.
log_format_text() {
  cat <<EOF
map \$request_uri \$${1}_uri {
    "~^/clients/[^/?]+/deploy/(?<${1}_rest>.*)\$" "/clients/-/deploy/\$${1}_rest";
    "~^/packages/download/[^/?]+/(?<${1}_rest>.*)\$" "/packages/download/-/\$${1}_rest";
    "~^/deploy/iso/download/[^/?]+/(?<${1}_rest>.*)\$" "/deploy/iso/download/-/\$${1}_rest";
    "~*^(?<${1}_path>[^?]*)\?(.*[&;])?(code|state|access_token)=" "\$${1}_path?-";
    default \$request_uri;
}

map \$http_referer \$${1}_ref {
    "~^(?<${1}_rpath>[^?]*)\?" "\$${1}_rpath?-";
    default \$http_referer;
}

log_format ${1} '\$remote_addr - \$remote_user [\$time_local] "\$request_method \$${1}_uri \$server_protocol" '
    '\$status \$body_bytes_sent "\$${1}_ref" "\$http_user_agent"';
EOF
}

# nginx.conf of install.sh, restore.sh and update.sh
nginx_conf_text() {
  local i='        '
  cat <<EOF
user www-data; worker_processes auto;
pid /run/nginx.pid;
worker_rlimit_nofile 1000000;
include /etc/nginx/modules-enabled/*.conf;

events {
${i}worker_connections 4096;
}

http {
${i}include /etc/nginx/mime.types;
${i}default_type application/octet-stream;
${i}server_names_hash_bucket_size 256;
${i}types_hash_max_size 2048;
${i}sendfile on;
${i}tcp_nopush on;
${i}gzip on;
${i}error_log /var/log/nginx/error.log;
${i}access_log /var/log/nginx/access.log;
$(nginx_tls_text "$i")
${i}include /etc/nginx/conf.d/*.conf;
${i}include /etc/nginx/sites-enabled/*;
}
EOF
}

# add_header lines, $1 indent, then any of hsts nosniff referrer deny
nginx_headers() {
  local indent=$1 h
  shift
  for h; do
    case $h in
    hsts) h='Strict-Transport-Security "max-age=31536000; includeSubDomains"' ;;
    nosniff) h='X-Content-Type-Options nosniff' ;;
    referrer) h='Referrer-Policy strict-origin-when-cross-origin' ;;
    deny) h='X-Frame-Options DENY' ;;
    esac
    printf '%sadd_header %s always;\n' "$indent" "$h"
  done
}

# websocket capable proxy_pass to $1, 8 spaces deep
nginx_upgrade_proxy() {
  local i='        '
  printf '%sproxy_pass %s;\n%sproxy_http_version 1.1;\n' "$i" "$1" "$i"
  printf '%sproxy_set_header %s;\n' "$i" 'Upgrade $http_upgrade' "$i" 'Connection "upgrade"' \
    "$i" 'Host $host' "$i" 'X-Forwarded-For $remote_addr'
}

# uwsgi_pass to the API with the agent certificate result, 8 spaces deep
nginx_uwsgi_api() {
  local i='        '
  printf '%suwsgi_pass  ulrmm;\n%sinclude     /etc/nginx/uwsgi_params;\n' "$i" "$i"
  printf '%suwsgi_param SSL_CLIENT_%s;\n' "$i" 'VERIFY $ssl_client_verify' "$i" 'FINGERPRINT $ssl_client_fingerprint'
}

# plain http server that only sends $1 to https
nginx_to_https() {
  printf 'server {\n    server_name %s;\n    listen 80;\n    listen [::]:80;\n' "$1"
  printf '    return 301 https://$server_name$request_uri;\n}\n'
}

# $1 backend domain, $2 frontend domain, $3 certificate, $4 key
rmm_nginx_conf() {
  local all_headers=(hsts nosniff referrer deny)
  local cors="add_header \"Access-Control-Allow-Origin\" \"https://${2}\";"
  cat <<EOF
server_tokens off;

upstream ulrmm {
    server unix:////rmm/api/ulrmm/ulrmm.sock;
}

# requests of the agents and API scripts stay out of the access log
map \$http_user_agent \$ignore_ua {
    default 1;
    "~^ulrmm/" 0;
    "~go-resty.*" 0;
    "~python-requests.*" 0;
}

$(log_format_text ulrmm_api)

$(nginx_to_https "$1")

server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl;
    server_name ${1};
    access_log /rmm/api/ulrmm/ulrmm/private/log/access.log ulrmm_api if=\$ignore_ua;
    error_log /rmm/api/ulrmm/ulrmm/private/log/error.log;
    client_max_body_size 300M;
    ssl_certificate ${3};
    ssl_certificate_key ${4};
    # agent client certificates. Django and natsauth decide on SSL_CLIENT_VERIFY;
    # optional_no_ca lets a certificate of a replaced CA through as FAILED
    # instead of refusing every request of that agent.
    ssl_client_certificate ${AGENT_CA_DIR}/ca.pem;
    ssl_verify_client optional_no_ca;
    ssl_verify_depth 1;

$(nginx_tls_text "    ")
$(nginx_headers "    " "${all_headers[@]}")

    location / {
$(nginx_uwsgi_api)
        uwsgi_ignore_client_abort on;
        uwsgi_read_timeout 300s;
    }

    location = /api/v3/natsauth/ {
        internal;
$(nginx_uwsgi_api)
        uwsgi_param ULRMM_NATS_URI \$request_uri;
        uwsgi_pass_request_body off;
        uwsgi_param CONTENT_LENGTH "";
    }

    # the agents ask us for their public ip instead of a third party
    location = /pubip {
        default_type text/plain;
        return 200 "\$remote_addr\n";
    }

    location /static/ {
        ${cors}
        root /rmm/api/ulrmm;
    }

    # self-built agent binaries and the windows agents' python, see riddix/agents/
    location /agentdist/ {
        default_type application/octet-stream;
        alias ${AGENT_ROOT}/dist/;
    }

    location /private/ {
        internal;
        ${cors}
        alias /rmm/api/ulrmm/ulrmm/private/;
    }

    location /assets/ {
        internal;
        alias /opt/ulrmm-reporting/assets/;
        # add_header here replaces the server level headers, so they are repeated.
        # nosniff and the sandbox CSP set by Django are lost on X-Accel-Redirect.
        ${cors}
$(nginx_headers "        " "${all_headers[@]}")
        add_header Content-Security-Policy "sandbox" always;
    }

    location ~ ^/ws/ {
        # the dashboard token is in the query string
        access_log off;
$(nginx_upgrade_proxy http://unix:/rmm/daphne.sock)
        proxy_redirect off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Host \$server_name;
    }

    location ~ ^/natsws {
        # required mode: only with a valid agent certificate
        auth_request /api/v3/natsauth/;
        # /natsws/<agent id>: natsauth checks the id, nats-server gets /natsws
        rewrite ^/natsws/[A-Za-z0-9_-]+\$ /natsws break;
$(nginx_upgrade_proxy http://127.0.0.1:9235)
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host:\$server_port;
    }
}
EOF
}

# $1 mesh domain, $2 certificate, $3 key. HSTS and CSP come from MeshCentral.
mesh_nginx_conf() {
  cat <<EOF
$(nginx_to_https "$1")

server {
    server_name ${1};
    listen 443 ssl;
    listen [::]:443 ssl;
    ssl_certificate ${2};
    ssl_certificate_key ${3};
    ssl_session_cache shared:WEBSSL:10m;
    # remote control links carry a mesh login token in the query string
    access_log off;
    proxy_read_timeout 330s;
    proxy_send_timeout 330s;

$(nginx_tls_text "    ")
$(nginx_headers "    " nosniff referrer)

    location / {
$(nginx_upgrade_proxy http://127.0.0.1:4430/)
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host:\$server_port;
        proxy_set_header CF-Connecting-IP "";
    }
}
EOF
}

# $1 frontend domain, $2 api domain, $3 mesh domain, $4 certificate, $5 key
frontend_nginx_conf() {
  # form-action https: covers the SSO hop: the login form posts to the API,
  # which redirects to whatever identity provider is configured
  local csp="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' https://${2} wss://${2}; frame-src 'self' https://${3} https://${2} blob:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://${2} https:"
  local outer
  outer="$(nginx_headers "    " hsts nosniff referrer deny)
    add_header ${FRONTEND_CSP_HEADER} \"${csp}\" always;"
  cat <<EOF
$(log_format_text ulrmm_web)

server {
    server_name ${1};
    listen 443 ssl;
    listen [::]:443 ssl;
    ssl_certificate ${4};
    ssl_certificate_key ${5};
    charset utf-8;
    access_log /var/log/nginx/frontend-access.log ulrmm_web;
    error_log  /var/log/nginx/frontend-error.log;

${outer}
$(nginx_tls_text "    ")

    location / {
        root /var/www/rmm/dist;
        try_files \$uri \$uri/ /index.html;
        # a location with its own add_header drops the server level ones
$(sed 's/^/    /' <<<"$outer")
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma "no-cache";
    }
}

server {
    server_name ${1};
    listen 80;
    listen [::]:80;
    if (\$host = ${1}) {
        return 301 https://\$host\$request_uri;
    }
    return 404;
}
EOF
}

# update.sh: rewrite /etc/nginx/sites-available/<name>.conf from stdin.
# certificate and key stay as they are. old file kept as <name>.conf.prev.
# changed paths are added to NGINX_REFRESHED.
refresh_site() {
  local f="/etc/nginx/sites-available/${1}.conf" cert key new
  [ -f "$f" ] || return 0
  cert=$(sudo awk '$1=="ssl_certificate"{sub(/;$/,"",$2);print $2;exit}' "$f")
  key=$(sudo awk '$1=="ssl_certificate_key"{sub(/;$/,"",$2);print $2;exit}' "$f")
  if [ -z "$cert" ] || [ -z "$key" ]; then
    lib_warn "WARNING: no ssl_certificate in ${f}, left as it is."
    return 0
  fi
  shift
  new=$(mktemp) || return 1
  "$@" "$cert" "$key" >"$new" || { rm -f "$new"; return 1; }
  if ! sudo cmp -s "$new" "$f" && sudo cp -p "$f" "${f}.prev"; then
    # nginx -t accepts an empty file. put the old one back if tee fails.
    if sudo tee "$f" <"$new" >/dev/null; then
      NGINX_REFRESHED+=("$f")
    else
      sudo mv -f "${f}.prev" "$f"
    fi
  fi
  rm -f "$new"
}

# meshcentral.service sits outside write_units. MESH_CHANGED when the text differs.
write_mesh_unit() {
  local new
  new=$(mktemp) || return 1
  unit_text meshcentral >"$new"
  if ! sudo cmp -s "$new" /etc/systemd/system/meshcentral.service; then
    sudo tee /etc/systemd/system/meshcentral.service <"$new" >/dev/null && sudo systemctl daemon-reload && MESH_CHANGED=1
  fi
  rm -f "$new"
}

# shellcheck disable=SC2034 # MESH_CHANGED is read by update.sh
# bind loopback, MPS off, key files mode 600. sets MESH_CHANGED=1 on change.
# a db export next to a postgres config holds the login cookie key.
# moved under /var/backups and kept.
harden_mesh() {
  local dir=/meshcentral/meshcentral-data cfg tmp
  cfg="$dir/config.json"
  [ -f "$cfg" ] || return 0
  if command -v jq >/dev/null; then
    tmp=$(mktemp) || return 1
    if jq '.settings.portBind="127.0.0.1" | .settings.redirPortBind="127.0.0.1" | .settings.mpsPort=0' "$cfg" >"$tmp" && [ -s "$tmp" ] &&
      ! jq -e --slurpfile n "$tmp" '. == $n[0]' "$cfg" >/dev/null; then
      cp "$cfg" ~/"meshcfg-$(date "+%Y%m%dT%H%M%S").bak"
      cat "$tmp" >"$cfg" && MESH_CHANGED=1
    fi
    rm -f "$tmp"
    if [ -f "$dir/meshcentral.db.json" ] && jq -e '.settings.postgres' "$cfg" >/dev/null; then
      sudo install -d -m 0700 -o root -g root /var/backups/ulrmm-mesh
      sudo mv "$dir/meshcentral.db.json" "/var/backups/ulrmm-mesh/meshcentral.db.json.$(date "+%Y%m%dT%H%M%S")" &&
        lib_warn "Moved the stale ${dir}/meshcentral.db.json to /var/backups/ulrmm-mesh/ (root only). Rotate the mesh keys, then delete it."
    fi
  fi
  chmod 700 "$dir"
  chmod 600 "$cfg"
  find "$dir" -maxdepth 1 -type f -name '*.key' -exec chmod 600 {} +
}

# ws access log is off, the log format leaves URL secrets out. client IPs stay.
logrotate_text() {
  cat <<EOF
/rmm/api/ulrmm/ulrmm/private/log/access.log /rmm/api/ulrmm/ulrmm/private/log/error.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ${USER} ${USER}
    postrotate
        kill -USR1 \$(cat /var/run/nginx.pid)
    endscript
}

# task errors can name hosts and paths
/var/log/celery/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    # celery keeps its files open; the copies keep the 0640 of harden_logs
    copytruncate
}
EOF
}

harden_logs() {
  local d=/rmm/api/ulrmm/ulrmm/private/log
  sudo mkdir -p "$d"
  sudo chown "${USER}:${USER}" "$d"
  sudo chmod 750 "$d"
  sudo find "$d" -maxdepth 1 -type f -exec chmod 640 {} +
  sudo mkdir -p /var/log/celery
  sudo chown "${USER}:${USER}" /var/log/celery
  sudo chmod 750 /var/log/celery
  sudo find /var/log/celery -maxdepth 1 -type f -exec chmod 640 {} +
  logrotate_text | sudo tee /etc/logrotate.d/ulrmm >/dev/null
}

# $1 db, $2 role, $3 password. SQL on stdin, so the password stays out of
# argv and the sudo journal.
pg_create_db() {
  sudo -iu postgres psql -v ON_ERROR_STOP=1 <<EOF
CREATE DATABASE ${1};
CREATE USER ${2} WITH PASSWORD '${3}';
ALTER ROLE ${2} SET client_encoding TO 'utf8';
ALTER ROLE ${2} SET default_transaction_isolation TO 'read committed';
ALTER ROLE ${2} SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE ${1} TO ${2};
ALTER DATABASE ${1} OWNER TO ${2};
GRANT USAGE, CREATE ON SCHEMA PUBLIC TO ${2};
EOF
}

# $1 url, $2 sha256, $3 file. A file that does not match is removed.
fetch_pinned() {
  if ! wget -O "$3" "$1"; then
    rm -f "$3"
    lib_warn "ERROR: download of $1 failed."
    return 1
  fi
  if ! echo "$2  $3" | sha256sum -c --status -; then
    rm -f "$3"
    lib_warn "ERROR: $1 does not match the sha256 pinned in install_lib.sh."
    return 1
  fi
}

# CPython $PYTHON_VER from source, checked before it is built. Ends in ~.
install_python() {
  local src="Python-${PYTHON_VER}"
  # liblzma-dev: without it the build has no lzma module (SDIO indexes need it)
  sudo apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev
  cd ~ || return 1
  fetch_pinned "https://www.python.org/ftp/python/${PYTHON_VER}/${src}.tgz" "$PYTHON_SHA256" "${src}.tgz" ||
    lib_die "Python ${PYTHON_VER} was not installed."
  tar -xf "${src}.tgz"
  cd "$src" || return 1
  ./configure --enable-optimizations
  make -j "$(nproc)"
  sudo make altinstall
  cd ~ || return 1
  sudo rm -rf "$src" "${src}.tgz"
}

# $1 = NATS_SERVER_VER from settings.py
install_nats_server() {
  local arch=amd64 sha=$NATS_SHA256_amd64 name tmp
  if [ "$(uname -m)" != x86_64 ]; then
    arch=arm64 sha=$NATS_SHA256_arm64
  fi
  [ "$1" = "$NATS_PINNED_VER" ] ||
    lib_die "settings.py wants nats-server ${1}, install_lib.sh has sha256 pins for ${NATS_PINNED_VER} only."
  name="nats-server-v${1}-linux-${arch}"
  tmp=$(mktemp -d -t nats-XXXXXXXXXX)
  if ! fetch_pinned "https://github.com/nats-io/nats-server/releases/download/v${1}/${name}.tar.gz" "$sha" "${tmp}/${name}.tar.gz" ||
    ! tar -xzf "${tmp}/${name}.tar.gz" -C "$tmp" ||
    ! sudo install -m 0755 -o "$USER" -g "$USER" "${tmp}/${name}/nats-server" /usr/local/bin/nats-server; then
    rm -rf "$tmp"
    lib_die "nats-server ${1} was not installed."
  fi
  rm -rf "$tmp"
}

# Go and the nats-api modules, before this host changes.
# install_natsapi builds offline afterwards.
# $1 = checkout. repo_preflight already compared go.mod, go.sum and go_toolchain.sh.
natsapi_prefetch() {
  local mods
  sudo mkdir -p "$AGENT_ROOT"
  sudo chown "${USER}:${USER}" "$AGENT_ROOT"
  mods=$(mktemp -d)
  if ! cp "$1/go.mod" "$1/go.sum" "$mods/" || ! (
    export ULRMM_AGENT_ROOT="$AGENT_ROOT"
    # shellcheck source=riddix/scripts/go_toolchain.sh
    . "$1/riddix/scripts/go_toolchain.sh"
    go_toolchain && cd "$mods" && go mod download all
  ); then
    rm -rf "$mods"
    lib_die "could not fetch Go or the nats-api modules. Nothing is installed yet, check the network and start again."
  fi
  rm -rf "$mods"
}

# nats-api from /rmm, Go under $AGENT_ROOT/go. Also when the agent build is skipped.
install_natsapi() {
  local out
  sudo mkdir -p "$AGENT_ROOT"
  sudo chown "${USER}:${USER}" "$AGENT_ROOT"
  out=$(mktemp -d)
  if ! ULRMM_AGENT_ROOT="$AGENT_ROOT" bash /rmm/riddix/scripts/build_natsapi.sh /rmm "$out/nats-api" ||
    ! sudo install -m 0755 -o "$USER" -g "$USER" "$out/nats-api" /usr/local/bin/nats-api; then
    rm -rf "$out"
    lib_die "building or installing nats-api failed, see above."
  fi
  rm -rf "$out"
}

# apt usually starts redis. policy-rc.d or a disabled unit can leave it down.
# The API, celery and write_brand.py need it. NOAUTH: requirepass of an
# earlier run, ensure_redis_password sets it again.
start_redis() {
  sudo systemctl enable --now redis-server || lib_die "could not start redis-server."
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    case "$(redis-cli ping 2>&1)" in
    PONG | *NOAUTH*) return 0 ;;
    esac
    sleep 1
  done
  lib_die "redis-server does not answer redis-cli ping."
}

# $1 password: requirepass in REDIS_CONF, redis-server restarted when it
# changes. The password goes through stdin and REDISCLI_AUTH, not argv.
redis_require_pass() {
  local cur
  if ! sudo test -f "$REDIS_CONF"; then
    lib_warn "ERROR: ${REDIS_CONF} is missing."
    return 1
  fi
  cur=$(sudo awk '$1 == "requirepass" {p = $2} END {print p}' "$REDIS_CONF")
  if [ "$cur" != "$1" ]; then
    sudo sed -i -E '/^[[:space:]]*requirepass[[:space:]]/d' "$REDIS_CONF" &&
      printf 'requirepass %s\n' "$1" | sudo tee -a "$REDIS_CONF" >/dev/null &&
      sudo systemctl restart redis-server || return 1
  fi
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(REDISCLI_AUTH=$1 redis-cli ping 2>/dev/null)" = PONG ] && return 0
    sleep 1
  done
  lib_warn "ERROR: redis-server does not answer redis-cli ping with REDIS_PASSWORD."
  return 1
}

# REDIS_PASSWORD in local_settings.py (settings.py puts it into REDIS_URL)
# and requirepass in redis.conf. Callers run it while every service that
# uses redis is stopped, or restart them right after.
ensure_redis_password() {
  local pw
  pw=$(ls_get REDIS_PASSWORD)
  if [ -z "$pw" ]; then
    pw=$(openssl rand -hex 32)
    ls_set REDIS_PASSWORD "$pw"
  fi
  redis_require_pass "$pw"
}

# firewall.sh apply, kept only when nginx and sshd still answer with the
# table loaded. FIREWALL=off in /etc/ulrmm/firewall.conf skips it.
firewall_step() {
  local fw=/rmm/riddix/scripts/firewall.sh out token
  if ! out=$(sudo bash "$fw" apply); then
    lib_warn "WARNING: the firewall was not loaded, see above."
    return 1
  fi
  printf '%s\n' "$out"
  token=$(sed -n 's/^confirm token: //p' <<<"$out")
  # FIREWALL=off: nothing loaded on purpose
  [ -n "$token" ] || return 2
  if sudo bash "$fw" check && sudo bash "$fw" confirm "$token"; then
    return 0
  fi
  sudo bash "$fw" revert
  lib_warn "WARNING: the firewall was removed again, see above. Fix it, then: sudo bash ${fw} apply"
  return 1
}

# the units install.sh and restore.sh leave running; prints those that are not
services_down() {
  local u down=''
  for u in redis-server postgresql nginx meshcentral nats nats-api rmm daphne celery celerybeat; do
    systemctl is-active --quiet "$u" || down+=" $u"
  done
  printf '%s' "${down# }"
}

natsapi_summary() {
  local v s
  v=$(/usr/local/bin/nats-api -version 2>/dev/null)
  s=$(sha256sum /usr/local/bin/nats-api 2>/dev/null)
  printf 'nats-api: %s, built from source, sha256 %s\n' "${v%%$'\n'*}" "${s%% *}"
}

# Windows installer: Inno Setup under Wine, x86_64 only.
# Without it, build_agents.sh still builds Linux and macOS.
build_agents_step() {
  sudo mkdir -p "$AGENT_ROOT"
  sudo chown "${USER}:${USER}" "$AGENT_ROOT"
  if ! command -v iscc >/dev/null && [ "$(uname -m)" = x86_64 ]; then
    lib_info "Installing Inno Setup under Wine for the Windows installer..."
    bash /rmm/riddix/agents/install-innosetup.sh ||
      lib_warn "WARNING: Inno Setup could not be installed, no Windows agents are built."
  fi
  lib_info "Building agents (this can take a few minutes)..."
  if ! bash /rmm/riddix/agents/build_agents.sh; then
    lib_warn "WARNING: agent build failed. Agent installs and updates fail until it succeeds:"
    lib_warn "fix the cause, then run bash /rmm/riddix/agents/build_agents.sh"
    return 1
  fi
}

# $1 = RustDesk ID server host. Clients go in the agent dist dir,
# created here even if the agent build was skipped.
rustdesk_step() {
  local script=/rmm/riddix/rustdesk/install-rustdesk-server.sh
  sudo mkdir -p "${AGENT_ROOT}/dist"
  sudo chown "${USER}:${USER}" "$AGENT_ROOT" "${AGENT_ROOT}/dist"
  if [ ! -f "$script" ]; then
    lib_warn "RustDesk: riddix/rustdesk/install-rustdesk-server.sh is not on ${GIT_BRANCH} yet, skipped."
    lib_warn "Once it is there: bash ${script} --host ${1}, then add RUSTDESK_SERVER = True and RUSTDESK_HOST = \"${1}\" to ${local_settings}"
    return 1
  fi
  lib_info "Installing the RustDesk server for ${1}"
  if ! bash "$script" --host "$1"; then
    lib_warn "WARNING: the RustDesk server install failed, RUSTDESK_SERVER stays off. Retry: bash ${script} --host ${1}"
    return 1
  fi
  sed -i -E '/^RUSTDESK_SERVER[[:space:]]*=/d' "$local_settings"
  echo "RUSTDESK_SERVER = True" >>"$local_settings"
  # without this, update.sh points hbbs at the API host
  ls_set RUSTDESK_HOST "$1"
}

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Update of a UniversalLocal RMM server in place, as the install user.
#
#   /rmm/update.sh [options]       (--help lists them)
#
# The dashboard runs it as "bash /rmm/update.sh --yes" through
# riddix/scripts/maint_runner.sh. Everything that can fail runs before a
# service is stopped; once they are stopped, any exit starts them again.
#
# All code sits in functions and main runs from the last line: the checkout
# replaces this file while it runs.

SCRIPT_VERSION="190"

# cron and some sudo setups leave USER unset
USER=${USER:-$(id -un)}

GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' NC='\033[0m'

local_settings='/rmm/api/ulrmm/ulrmm/local_settings.py'
SCRIPTS_DIR='/opt/ulrmm-community-scripts'
SETTINGS_PY='/rmm/api/ulrmm/ulrmm/settings.py'
WEB_DIR='/opt/ulrmm-web'
WEB_SRC='/opt/ulrmm-web/src'
DEFAULT_GIT_URL='https://github.com/RiDDiX/ulrmm.git'
DEFAULT_WEB_GIT_URL='https://github.com/RiDDiX/ulrmm-web.git'
MAINT_DIR=${MAINT_DIR:-/var/lib/ulrmm-maint}
UPDATE_LOCK="${MAINT_DIR}/update.lock"
PROGRESS_FILE="${MAINT_DIR}/update.progress.json"
# lib reads these when it is sourced
non_interactive=true
skip_agent_build=false

info() { printf '%b%s%b\n' "$GREEN" "$*" "$NC"; }
warn() { printf '%b%s%b\n' "$YELLOW" "$*" "$NC"; }
die() {
  printf '%bERROR: %s%b\n' "$RED" "$*" "$NC" >&2
  DIE_MSG=$*
  exit 1
}

usage() {
  cat <<'EOF'
usage: /rmm/update.sh [options]

  --git-url URL            server repository (saved in local_settings.py)
  --branch NAME            server branch (saved)
  --git-user NAME          user name for the token (saved)
  --token TOKEN            read token for private repositories (saved)
  --token-file PATH        the same from a file (/dev/stdin works)
  --web-git-url URL        dashboard repository (saved)
  --web-branch NAME        dashboard branch (saved)
  --scripts-git-url URL    script library (saved)
  --force                  run even when already on the latest commit, rebuild
                           the dashboard, MeshCentral and the Python environment;
                           also allows going back to an older version
  --no-backup              skip the backup before the update (not recommended)
  --skip-db-check          continue when the database check cannot run
  --skip-agent-build       keep the agents in /opt/ulrmm-agents/dist
  --no-firewall            leave the nftables firewall as it is (riddix/scripts/firewall.sh;
                           FIREWALL=off in /etc/ulrmm/firewall.conf does the same for every run)
  --release [VERSION]      install a signed release (latest, or VERSION) instead of the git branch
  --yes, -y                do not ask before a repository or branch switch
  -h, --help               this list

Every --option value also works as --option=value.
EOF
}

# same rules as lib's ls_get/ls_set, needed before lib is loaded
ls_get() {
  local f=${2:-$local_settings}
  [ -f "$f" ] || return 0
  grep -E "^${1}[[:space:]]*=[[:space:]]*[\"']" "$f" 2>/dev/null | tail -1 | sed -E "s/^[^=]*=[[:space:]]*[\"']([^\"']*)[\"'].*/\\1/"
}
ls_set() {
  local key="$1" val="$2"
  case "$val" in
  *\"* | *\\* | *$'\n'*) die "$key must not contain quotes, backslashes or newlines." ;;
  esac
  touch "$local_settings"
  chmod 600 "$local_settings"
  sed -i -E "/^${key}[[:space:]]*=/d" "$local_settings"
  printf '\n%s = "%s"\n' "$key" "$val" >>"$local_settings"
}

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

settings_ver() { # NAME file
  grep "^${1}" "$2" | awk -F'[= "]' '{print $5}'
}

# X.DD.MM.YYYY -> sortable key, nothing for anything else
ver_key() {
  [[ $1 =~ ^([0-9]+)\.([0-9]{2})\.([0-9]{2})\.([0-9]{4})$ ]] || return 0
  printf '%s%s%s%08d' "${BASH_REMATCH[4]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "$((10#${BASH_REMATCH[1]}))"
}

TMP_PATHS=()
tmp_file() { # var [mktemp args]
  local t
  t=$(mktemp "${@:2}") || die "mktemp failed."
  TMP_PATHS+=("$t")
  printf -v "$1" '%s' "$t"
}

ASKPASS=''
drop_token() {
  unset ULRMM_ASKPASS_TOKEN ULRMM_ASKPASS_USER GIT_ASKPASS
  GIT_TOKEN=''
  if [ -n "$ASKPASS" ]; then
    rm -f "$ASKPASS"
  fi
  ASKPASS=''
}

# git with the token, only towards the server repository's host
git_auth() {
  local url=$1
  shift
  if [ -n "$GIT_TOKEN" ] && [ -n "$ASKPASS" ] && [ "$(url_host "$url")" = "$(url_host "$GIT_URL")" ]; then
    GIT_ASKPASS=$ASKPASS ULRMM_ASKPASS_USER=$GIT_USER ULRMM_ASKPASS_TOKEN=$GIT_TOKEN git -c credential.helper= "$@"
  else
    git -c credential.helper= "$@"
  fi
}

SERVICES_STOPPED=false
MESH_STOPPED=false
BACKUP_PATH=''
SELF=''
RELEASE=false
RELEASE_DIR=''
RELEASE_TREE=''
ROLLBACK_DIR=''
PREV_COMMIT=''
TREE_REPLACED=false
ROLLING_BACK=false
DIE_MSG=''
PROG_VERSION=''
PROG_SOURCE=git
PROG_FINAL=false
DEPLOYED_WEB_COMMIT=''
# what moves between a release tree and /rmm; what .gitignore names and the
# runtime data under private/ (ISOs, deploy files, logs) stay in /rmm
TREE_SYNC=(--checksum --exclude=/.git --exclude=/api/env --exclude=/api/env.old --exclude=/api/ulrmm/ulrmm/private/ --exclude=/api/ulrmm/ulrmm/local_settings.py --exclude=/api/ulrmm/static --exclude=node_modules --exclude='*.sock' --filter=':- .gitignore')

# MAINT_DIR/update.progress.json for the dashboard. The download numbers in
# it come from fetch_release and are kept.
progress() { # phase message
  local tmp="${PROGRESS_FILE}.tmp" prev
  [ -d "$MAINT_DIR" ] || return 0
  prev=$(jq -c 'select(type == "object")' "$PROGRESS_FILE" 2>/dev/null)
  [ -n "$prev" ] || prev='{}'
  if jq -n --argjson prev "$prev" --arg phase "$1" --arg msg "$2" --arg ver "$PROG_VERSION" \
    --arg src "$PROG_SOURCE" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{phase: $phase, percent: (if $phase == "done" then 100 else ($prev.percent // null) end),
      bytes: ($prev.bytes // 0), total: ($prev.total // 0), rate_bps: ($prev.rate_bps // 0),
      source: (if $src == "" then null else $src end), version: (if $ver == "" then null else $ver end),
      message: $msg, updated_at: $now}' >"$tmp" 2>/dev/null; then
    chmod 644 "$tmp" && mv -f "$tmp" "$PROGRESS_FILE"
  fi
  case "$1" in done | failed) PROG_FINAL=true ;; esac
}

# core/health/ through the local nginx (the rmm site answers for the api
# name), daphne's socket when nginx is not up yet
health_ok() { # api-host version
  local i body
  for ((i = 0; i < 24; i++)); do
    body=$(curl -sk --max-time 5 -H "Host: $1" https://127.0.0.1/core/health/ 2>/dev/null) ||
      body=$(curl -s --max-time 5 --unix-socket /rmm/daphne.sock -H "Host: $1" http://127.0.0.1/core/health/ 2>/dev/null)
    [ "$(printf '%s' "$body" | jq -r '(.status // "") + " " + (.version // "")' 2>/dev/null)" = "ok $2" ] && return 0
    sleep 5
  done
  return 1
}

start_services() {
  local s
  for s in nats nats-api rmm daphne celery celerybeat nginx; do
    printf 'Starting %s service\n' "$s"
    sudo systemctl start "$s"
  done
  SERVICES_STOPPED=false
}

on_exit() {
  local rc=$?
  drop_token
  if [ ${#TMP_PATHS[@]} -gt 0 ]; then
    rm -rf "${TMP_PATHS[@]}"
  fi
  # the new tree is in /rmm but the update did not finish: previous tree back
  if [ "$rc" -ne 0 ] && [ "$TREE_REPLACED" = true ] && [ "$ROLLING_BACK" != true ] &&
    { { [ "$RELEASE" = true ] && [ -n "$ROLLBACK_DIR" ]; } || { [ "$RELEASE" != true ] && [ -n "$PREV_COMMIT" ]; }; }; then
    rollback "${DIE_MSG:-the update stopped, see the log}"
  fi
  if [ "$rc" -ne 0 ] && [ "$PROG_FINAL" != true ]; then
    progress failed "${DIE_MSG:-the update stopped, see the log}"
  fi
  if [ "$MESH_STOPPED" = true ]; then
    sudo systemctl start meshcentral
  fi
  if [ "$SERVICES_STOPPED" = true ]; then
    start_services
    printf '%b\n' "$RED"
    echo "THE UPDATE DID NOT FINISH. The services run again on the code now in /rmm ($(git -C /rmm rev-parse --short=8 HEAD 2>/dev/null))."
    echo "Fix the cause shown above, then run: ${SELF} --force"
    echo "A plain rerun can stop at 'Already on latest commit' and skip the rest."
    if [ -n "$BACKUP_PATH" ]; then
      echo "The backup taken before this update: ${BACKUP_PATH}"
      echo "To go back to it, restore it on a clean server: bash restore.sh ${BACKUP_PATH##*/}"
    fi
    printf '%b\n' "$NC"
  fi
  exit "$rc"
}


# NodeJS 24 from the signed NodeSource repository, as install.sh sets it up
setup_node() {
  sudo mkdir -p /etc/apt/keyrings
  fetch_apt_key https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key "$NODESOURCE_KEY_FPR" /etc/apt/keyrings/nodesource.gpg || return 1
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" |
    sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
  sudo apt update && sudo apt install -y nodejs
}

node_major() { node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/'; }
node_ok() {
  local m
  m=$(node_major)
  command -v npm >/dev/null && [[ $m =~ ^[0-9]+$ ]] && [ "$m" -ge 24 ]
}

manage() { (cd /rmm/api/ulrmm && /rmm/api/env/bin/python manage.py "$@"); }

# The new code does not answer: previous tree, dashboard and nats-api back,
# the database stays as migrated. Starts the services itself.
rollback() { # reason
  local s
  ROLLING_BACK=true
  printf '%bERROR: %s%b\n' "$RED" "$1" "$NC" >&2
  progress rollback "going back to ${CURRENT_ULRMM_VER}"
  SERVICES_STOPPED=false
  for s in celerybeat celery nginx nats-api nats rmm daphne; do
    sudo systemctl stop "$s"
  done
  if [ "$RELEASE" = true ]; then
    rsync -a --delete "${TREE_SYNC[@]}" "${ROLLBACK_DIR}/" /rmm/ || warn "WARNING: could not copy ${ROLLBACK_DIR} back."
  elif [ -n "$PREV_COMMIT" ]; then
    git -C /rmm checkout --quiet -f -B "$GIT_BRANCH" "$PREV_COMMIT" && git -C /rmm reset --quiet --hard "$PREV_COMMIT" &&
      git -C /rmm clean -df -e /api/ulrmm/ulrmm/private || warn "WARNING: git checkout of ${PREV_COMMIT:0:8} failed."
  fi
  if [ -d /var/www/rmm/dist.old ]; then
    sudo rm -rf /var/www/rmm/dist && sudo mv /var/www/rmm/dist.old /var/www/rmm/dist
    echo "${DEPLOYED_WEB_COMMIT}" | sudo tee /var/www/rmm/.ulrmm-web-commit >/dev/null
  fi
  if [ -f "${MAINT_DIR}/rollback/nats-api" ]; then
    sudo install -m 0755 -o "$USER" -g "$USER" "${MAINT_DIR}/rollback/nats-api" /usr/local/bin/nats-api
  fi
  /rmm/api/env/bin/pip install --no-cache-dir -r /rmm/api/ulrmm/requirements.txt >/dev/null ||
    warn "WARNING: pip install for the previous code failed."
  manage collectstatic --no-input >/dev/null || warn "WARNING: collectstatic for the previous code failed."
  start_services
  printf '%b\n' "$RED"
  echo "ROLLED BACK to ${CURRENT_ULRMM_VER}: code, dashboard and nats-api are the previous ones."
  echo "The database keeps the migrations of ${LATEST_ULRMM_VER}; the next update must ship them."
  if [ -n "$BACKUP_PATH" ]; then
    echo "To get the database of before this update back, restore the backup on a clean server:"
    echo "  bash restore.sh ${BACKUP_PATH##*/}"
  fi
  printf '%b\n' "$NC"
  progress failed "$1"
  exit 1
}

# release mode: signed tarballs instead of the git branch. Sets RELEASE_DIR,
# RELEASE_TREE, LATEST_ULRMM_VER, TARGET_COMMIT and WEB_COMMIT, then the
# self-update like the git path.
release_fetch() {
  local out rc new_script NEW_VER dest pin=()
  [ -z "$release_version" ] || pin=(--version "$release_version")
  progress download "downloading ${release_version:-the latest release}"
  tmp_file out -t ulrmm-fetch-XXXXXXXXXX
  manage fetch_release --dest "${MAINT_DIR}/release" "${pin[@]}" --progress "$PROGRESS_FILE" >"$out"
  rc=$?
  case "$rc" in
  0) ;;
  2) die "the release did not verify (signature, version or checksum). Nothing was changed." ;;
  3) die "no release source answered (see the lines above). Nothing was changed." ;;
  *) die "fetch_release failed with ${rc}. Nothing was changed." ;;
  esac
  RELEASE_DIR=$(tail -n 1 "$out")
  [ -f "${RELEASE_DIR}/manifest.json" ] || die "fetch_release printed no release directory."
  LATEST_ULRMM_VER=$(jq -r '.version // empty' "${RELEASE_DIR}/manifest.json")
  TARGET_COMMIT=$(jq -r '.commit // empty' "${RELEASE_DIR}/manifest.json")
  WEB_COMMIT=$(jq -r '.web_commit // empty' "${RELEASE_DIR}/manifest.json")
  [ -n "$(ver_key "$LATEST_ULRMM_VER")" ] || die "the manifest has no usable version."
  PROG_VERSION=$LATEST_ULRMM_VER
  PROG_SOURCE=$(jq -r '.source // empty' "$PROGRESS_FILE" 2>/dev/null)
  progress verify "unpacking ulrmm-server-${LATEST_ULRMM_VER}.tar.gz"
  tmp_file RELEASE_TREE -d -t ulrmm-release-XXXXXXXXXX
  tar -xzf "${RELEASE_DIR}/ulrmm-server-${LATEST_ULRMM_VER}.tar.gz" -C "$RELEASE_TREE" ||
    die "could not unpack ulrmm-server-${LATEST_ULRMM_VER}.tar.gz."
  RELEASE_TREE="${RELEASE_TREE}/ulrmm-server-${LATEST_ULRMM_VER}"
  [ -f "${RELEASE_TREE}/VERSION" ] && [ -f "${RELEASE_TREE}/api/ulrmm/ulrmm/settings.py" ] ||
    die "the server tarball does not hold ulrmm-server-${LATEST_ULRMM_VER}/."

  new_script="${RELEASE_TREE}/update.sh"
  NEW_VER=$(grep "^SCRIPT_VERSION" "$new_script" 2>/dev/null | awk -F'[="]' '{print $3}')
  if [[ $NEW_VER =~ ^[0-9]+$ ]] && [ "$NEW_VER" -gt "$SCRIPT_VERSION" ]; then
    case "$SELF" in
    /rmm/*) dest="${HOME}/update.sh" ;;
    *) dest=$SELF ;;
    esac
    bash -n "$new_script" || die "the update.sh in ${LATEST_ULRMM_VER} does not parse."
    install -m 755 "$new_script" "$dest" || die "cannot write ${dest}."
    info "update.sh ${SCRIPT_VERSION} -> ${NEW_VER}, continuing with ${dest}"
    trap - EXIT
    drop_token
    rm -rf "${TMP_PATHS[@]}"
    exec 7>&-
    exec "$dest" "${forward[@]}"
  fi
}

add_hosts() {
  local line name missing=()
  line=$(grep -m1 -E '^127\.0\.1\.1[[:space:]]' /etc/hosts)
  for name in "$@"; do
    [[ $name =~ ^[A-Za-z0-9.-]+$ ]] || continue
    if ! printf '%s\n' "$line" | tr -s ' \t' '\n\n' | grep -qxF "$name"; then
      missing+=("$name")
    fi
  done
  [ ${#missing[@]} -gt 0 ] || return 0
  if [ -n "$line" ]; then
    sudo sed -i -E "0,/^127\.0\.1\.1[[:space:]]/ s/^(127\.0\.1\.1[[:space:]].*)\$/\\1 ${missing[*]}/" /etc/hosts
  else
    echo "127.0.1.1 ${missing[*]}" | sudo tee -a /etc/hosts >/dev/null
  fi
}

# jq filter over the MeshCentral config: the three compression switches off
# whatever case they are spelled in, geolocation off in every domain
MESH_FILTER='.settings |= (reduce ("compression", "wsCompression", "agentWsCompression") as $n (.;
    [keys[] | select(ascii_downcase == ($n | ascii_downcase))] as $m
    | if ($m | length) == 0 then .[$n] = false else reduce $m[] as $k (.; .[$k] = false) end))
  | if (.domains | type) == "object" then .domains |= with_entries(.value.geoLocation = false) else . end'

# $1 jq filter, $2 backup name. Writes the config only when it changes.
mesh_cfg_apply() {
  local cfg=/meshcentral/meshcentral-data/config.json tmp
  tmp=$(mktemp) || return 1
  if jq "$1" "$cfg" >"$tmp" && [ -s "$tmp" ] && ! jq -e --slurpfile n "$tmp" '. == $n[0]' "$cfg" >/dev/null; then
    cp "$cfg" ~/"$2"
    cat "$tmp" >"$cfg" && MESH_CHANGED=1
  fi
  rm -f "$tmp"
}

mesh_package_json() {
  printf '{"dependencies": {"archiver": "7.0.1", "meshcentral": "%s", "otplib": "13.4.1", "pg": "8.16.3"}}\n' "$1"
}

# fresh node_modules for MeshCentral; the old ones come back when npm fails
mesh_reinstall() {
  local f
  for f in node_modules package.json package-lock.json; do
    rm -rf "/meshcentral/${f}.old"
    [ -e "/meshcentral/${f}" ] && mv "/meshcentral/${f}" "/meshcentral/${f}.old"
  done
  mesh_package_json "$1" >/meshcentral/package.json
  if (cd /meshcentral && npm install); then
    rm -rf /meshcentral/node_modules.old /meshcentral/package.json.old /meshcentral/package-lock.json.old
    return 0
  fi
  for f in node_modules package.json package-lock.json; do
    rm -rf "/meshcentral/${f}"
    [ -e "/meshcentral/${f}.old" ] && mv "/meshcentral/${f}.old" "/meshcentral/${f}"
  done
  printf '%b%s%b\n' "$RED" "WARNING: npm install of MeshCentral $1 failed. The previous MeshCentral was put back." "$NC"
  return 1
}

main() {
  if [ "$EUID" -eq 0 ]; then
    echo "Do NOT run this script as root. Exiting."
    exit 1
  fi

  local arg_git_url='' arg_branch='' arg_git_user='' arg_token='' arg_token_file=''
  local arg_web_git_url='' arg_web_branch='' arg_scripts_git_url=''
  local force=false no_backup=false skip_db_check=false yes=false no_firewall=false
  local release_version='' forward=() split=() a
  for a in "$@"; do
    case "$a" in
    --*=*) split+=("${a%%=*}" "${a#*=}") ;;
    *) split+=("$a") ;;
    esac
  done
  set -- "${split[@]}"
  while [ $# -gt 0 ]; do
    case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --force) force=true forward+=("$1") ;;
    --no-backup) no_backup=true forward+=("$1") ;;
    --skip-db-check) skip_db_check=true forward+=("$1") ;;
    --skip-agent-build) skip_agent_build=true forward+=("$1") ;;
    --no-firewall) no_firewall=true forward+=("$1") ;;
    --yes | -y) yes=true forward+=("$1") ;;
    --release)
      RELEASE=true
      if [ $# -gt 1 ] && [ -n "$(ver_key "$2")" ]; then
        release_version=$2
        shift
      fi
      ;;
    --git-url | --branch | --git-user | --token | --token-file | --web-git-url | --web-branch | --scripts-git-url)
      if [ $# -lt 2 ]; then
        usage >&2
        printf '%bERROR: %s needs a value.%b\n' "$RED" "$1" "$NC" >&2
        exit 2
      fi
      case "$1" in
      --git-url) arg_git_url=$2 ;;
      --branch) arg_branch=$2 ;;
      --git-user) arg_git_user=$2 ;;
      --token) arg_token=$2 ;;
      --token-file) arg_token_file=$2 ;;
      --web-git-url) arg_web_git_url=$2 ;;
      --web-branch) arg_web_branch=$2 ;;
      --scripts-git-url) arg_scripts_git_url=$2 ;;
      esac
      shift
      ;;
    *)
      usage >&2
      printf '%bERROR: unknown option %s%b\n' "$RED" "$1" "$NC" >&2
      exit 2
      ;;
    esac
    shift
  done

  local unit_user
  unit_user=$(grep -m1 '^User=' /etc/systemd/system/rmm.service 2>/dev/null | cut -d= -f2)
  if [ "$unit_user" != "$USER" ]; then
    die "You must run this update script from the same user account used during install: ${unit_user}"
  fi

  SELF=$(realpath -- "${BASH_SOURCE[0]}")

  # repository settings: option > local_settings.py > default
  if [ -n "$arg_token_file" ]; then
    [ -r "$arg_token_file" ] || die "cannot read the token file ${arg_token_file}."
    arg_token=$(tr -d '[:space:]' <"$arg_token_file")
  fi
  GIT_URL=${arg_git_url:-$(ls_get ULRMM_GIT_URL)}
  GIT_URL=${GIT_URL:-$DEFAULT_GIT_URL}
  GIT_BRANCH=${arg_branch:-$(ls_get ULRMM_GIT_BRANCH)}
  GIT_BRANCH=${GIT_BRANCH:-main}
  GIT_USER=${arg_git_user:-$(ls_get ULRMM_GIT_USER)}
  GIT_USER=${GIT_USER:-git}
  GIT_TOKEN=${arg_token:-$(ls_get ULRMM_GIT_TOKEN)}
  WEB_GIT_URL=${arg_web_git_url:-$(ls_get ULRMM_WEB_GIT_URL)}
  WEB_GIT_URL=${WEB_GIT_URL:-$DEFAULT_WEB_GIT_URL}
  WEB_GIT_BRANCH=${arg_web_branch:-$(ls_get ULRMM_WEB_GIT_BRANCH)}
  WEB_GIT_BRANCH=${WEB_GIT_BRANCH:-main}
  SCRIPTS_GIT_URL=${arg_scripts_git_url:-$(ls_get ULRMM_SCRIPTS_GIT_URL)}
  SCRIPTS_GIT_URL=${SCRIPTS_GIT_URL:-${GIT_URL%/*}/ulrmm-scripts.git}

  local v
  for v in "$GIT_URL" "$WEB_GIT_URL" "$SCRIPTS_GIT_URL"; do
    if [[ $v =~ ^https?://[^/]*@ ]]; then
      die "${v}: no credentials in urls (--git-url, --web-git-url, --scripts-git-url or ULRMM_GIT_URL, ULRMM_WEB_GIT_URL, ULRMM_SCRIPTS_GIT_URL in local_settings.py). The token goes in with --token or --token-file."
    fi
    [[ $v =~ ^https?://[^/]+ ]] || die "'${v}' is not an http(s) url."
    ! unsafe_value "$v" || die "'${v}' contains spaces, quotes or backslashes."
  done
  for v in "$GIT_BRANCH" "$WEB_GIT_BRANCH"; do
    [[ $v =~ ^[A-Za-z0-9._/-]+$ ]] || die "'${v}' is not a branch name."
  done
  ! unsafe_value "$GIT_USER" || die "the git user contains spaces, quotes or backslashes."
  ! unsafe_value "$GIT_TOKEN" || die "the token contains spaces, quotes or backslashes."

  [ -z "$arg_git_url" ] || ls_set ULRMM_GIT_URL "$GIT_URL"
  [ -z "$arg_branch" ] || ls_set ULRMM_GIT_BRANCH "$GIT_BRANCH"
  [ -z "$arg_git_user" ] || ls_set ULRMM_GIT_USER "$GIT_USER"
  [ -z "$arg_token" ] || ls_set ULRMM_GIT_TOKEN "$GIT_TOKEN"
  [ -z "$arg_web_git_url" ] || ls_set ULRMM_WEB_GIT_URL "$WEB_GIT_URL"
  [ -z "$arg_web_branch" ] || ls_set ULRMM_WEB_GIT_BRANCH "$WEB_GIT_BRANCH"
  [ -z "$arg_scripts_git_url" ] || ls_set ULRMM_SCRIPTS_GIT_URL "$SCRIPTS_GIT_URL"
  arg_token=''

  # the dashboard asks for a release through release.json, consumed here even
  # when another update holds the lock; a request older than an hour is stale
  if [ -f "${MAINT_DIR}/release.json" ]; then
    command -v jq >/dev/null || sudo apt install -y jq
    local req_at req_s
    req_at=$(jq -r '.requested_at // empty' "${MAINT_DIR}/release.json" 2>/dev/null)
    [ -n "$req_at" ] && req_s=$(date -d "$req_at" +%s 2>/dev/null) || req_s=0
    if [ $(($(date +%s) - req_s)) -gt 3600 ]; then
      warn "WARNING: ignoring release.json requested at ${req_at:-an unknown time}; request the release from the dashboard again."
      mv -f "${MAINT_DIR}/release.json" "${MAINT_DIR}/release.json.stale"
    else
      RELEASE=true
      release_version=$(jq -r '.version // empty' "${MAINT_DIR}/release.json" 2>/dev/null)
      mv -f "${MAINT_DIR}/release.json" "${MAINT_DIR}/release.json.done"
    fi
  fi

  # one update at a time (CLI and dashboard); outside /rmm, git clean would remove it
  if [ ! -d "$MAINT_DIR" ]; then
    sudo install -d -o "$USER" -g "$(id -gn)" -m 700 "$MAINT_DIR" || die "cannot create ${MAINT_DIR}."
  fi
  exec 7>"$UPDATE_LOCK" || die "cannot open ${UPDATE_LOCK}."
  if ! flock -n 7; then
    [ "$RELEASE" = true ] && mv -f "${MAINT_DIR}/release.json.done" "${MAINT_DIR}/release.json" 2>/dev/null
    die "another update is running."
  fi
  trap on_exit EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  command -v jq >/dev/null || sudo apt install -y jq

  if [ "$RELEASE" = true ]; then
    [ -z "$release_version" ] || [ -n "$(ver_key "$release_version")" ] || die "'${release_version}' is not a release version."
    forward+=("--release${release_version:+=$release_version}")
    PROG_SOURCE=''
    PROG_VERSION=$release_version
  fi
  progress preflight "checking the installation"

  export GIT_TERMINAL_PROMPT=0
  if [ -n "$GIT_TOKEN" ]; then
    tmp_file ASKPASS -t rmmaskpass_XXXXXXXXXX
    chmod 700 "$ASKPASS"
    cat >"$ASKPASS" <<'EOF'
#!/bin/sh
case "$1" in
*[Uu]sername*) printf '%s\n' "${ULRMM_ASKPASS_USER:-git}" ;;
*) printf '%s\n' "${ULRMM_ASKPASS_TOKEN}" ;;
esac
EOF
  fi

  # fetch and self-update
  local TARGET_REF="refs/remotes/ulrmm/${GIT_BRANCH}"
  local new_script NEW_VER dest
  local target_settings LATEST_ULRMM_VER CURRENT_ULRMM_VER TARGET_COMMIT WEB_COMMIT
  if [ "$RELEASE" = true ]; then
    release_fetch
  else
    progress download "fetching ${GIT_BRANCH} from ${GIT_URL}"
    if ! git_auth "$GIT_URL" -C /rmm fetch --quiet "$GIT_URL" "+refs/heads/${GIT_BRANCH}:${TARGET_REF}"; then
      die "git fetch from ${GIT_URL} failed. Check --git-url, --branch and, for a private repository, the token (--token-file)."
    fi

    tmp_file new_script -t ulrmm-update-XXXXXXXXXX
    git -C /rmm show "${TARGET_REF}:update.sh" >"$new_script" 2>/dev/null || die "${GIT_BRANCH} has no update.sh."
    NEW_VER=$(grep "^SCRIPT_VERSION" "$new_script" | awk -F'[="]' '{print $3}')
    [ -n "$NEW_VER" ] || die "the update.sh on ${GIT_BRANCH} has no SCRIPT_VERSION."
    if [ "$NEW_VER" != "$SCRIPT_VERSION" ]; then
      case "$SELF" in
      /rmm/*) dest="${HOME}/update.sh" ;;
      *) dest=$SELF ;;
      esac
      bash -n "$new_script" || die "the update.sh on ${GIT_BRANCH} does not parse."
      install -m 755 "$new_script" "$dest" || die "cannot write ${dest}."
      info "update.sh ${SCRIPT_VERSION} -> ${NEW_VER}, continuing with ${dest}"
      trap - EXIT
      drop_token
      rm -rf "${TMP_PATHS[@]}"
      exec 7>&-
      exec "$dest" "${forward[@]}"
    fi
  fi

  sudo apt update

  tmp_file target_settings -t ulrmm-settings-XXXXXXXXXX
  if [ "$RELEASE" = true ]; then
    cp "${RELEASE_TREE}/api/ulrmm/ulrmm/settings.py" "$target_settings"
  else
    git -C /rmm show "${TARGET_REF}:api/ulrmm/ulrmm/settings.py" >"$target_settings" 2>/dev/null ||
      die "could not read api/ulrmm/ulrmm/settings.py from ${GIT_BRANCH}."
  fi
  local LATEST_MESH_VER LATEST_PIP_VER NATS_SERVER_VER CURRENT_PIP_VER name
  LATEST_MESH_VER=$(settings_ver MESH_VER "$target_settings")
  LATEST_PIP_VER=$(settings_ver PIP_VER "$target_settings")
  NATS_SERVER_VER=$(settings_ver NATS_SERVER_VER "$target_settings")
  for name in MESH_VER PIP_VER NATS_SERVER_VER; do
    v=$(settings_ver "$name" "$target_settings")
    [[ $v =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || die "could not read ${name} from the target settings.py."
  done
  CURRENT_PIP_VER=$(settings_ver PIP_VER "$SETTINGS_PY")

  CURRENT_ULRMM_VER=$(tr -d '[:space:]' </rmm/VERSION 2>/dev/null)
  PREV_COMMIT=$(git -C /rmm rev-parse HEAD 2>/dev/null)
  local cur_branch cur_origin SWITCH=false up_to_date=false
  if [ "$RELEASE" = true ]; then
    [ "$CURRENT_ULRMM_VER" != "$LATEST_ULRMM_VER" ] || up_to_date=true
  else
    LATEST_ULRMM_VER=$(git -C /rmm show "${TARGET_REF}:VERSION" 2>/dev/null | tr -d '[:space:]')
    [ -n "$LATEST_ULRMM_VER" ] || die "${GIT_BRANCH} has no VERSION file."
    TARGET_COMMIT=$(git -C /rmm rev-parse "$TARGET_REF")
    PROG_VERSION=$LATEST_ULRMM_VER
    cur_branch=$(git -C /rmm rev-parse --abbrev-ref HEAD)
    cur_origin=$(git -C /rmm remote get-url origin 2>/dev/null)
    if [ "$cur_branch" != "$GIT_BRANCH" ] || [ "$cur_origin" != "$GIT_URL" ]; then
      SWITCH=true
    fi
    [ "$PREV_COMMIT" != "$TARGET_COMMIT" ] || [ "$SWITCH" = true ] || up_to_date=true
  fi

  if [ "$up_to_date" = true ] && [ "$force" != true ]; then
    progress 'done' "already on ${CURRENT_ULRMM_VER}"
    echo "Already on latest commit (${CURRENT_ULRMM_VER}). Use --force to run anyway."
    exit 0
  fi

  local k_new k_cur
  k_new=$(ver_key "$LATEST_ULRMM_VER")
  k_cur=$(ver_key "$CURRENT_ULRMM_VER")
  if [ -n "$k_new" ] && [ -n "$k_cur" ] && [[ $k_new < $k_cur ]] && [ "$force" != true ]; then
    die "${GIT_BRANCH} has ${LATEST_ULRMM_VER}, older than the installed ${CURRENT_ULRMM_VER}. Use --force to go back anyway."
  fi

  info "Updating ${CURRENT_ULRMM_VER} -> ${LATEST_ULRMM_VER}"

  if [ "$SWITCH" = true ]; then
    warn "This is a switch:"
    warn "  from ${cur_origin:-?} ${cur_branch} (${CURRENT_ULRMM_VER}, $(git -C /rmm rev-parse --short=8 HEAD))"
    warn "  to   ${GIT_URL} ${GIT_BRANCH} (${LATEST_ULRMM_VER}, ${TARGET_COMMIT:0:8})"
  fi

  # database check: the target must ship every migration the database has
  local mig_list mig_tree check_py rc db_check_ready=false
  tmp_file mig_list -t ulrmm-migrations-XXXXXXXXXX
  tmp_file mig_tree -d -t ulrmm-migtree-XXXXXXXXXX
  check_py="${mig_tree}/db_ahead_check.py"
  if [ "$RELEASE" = true ]; then
    (cd "$RELEASE_TREE" && find api/ulrmm -path '*/migrations/*.py' | grep -E '/migrations/[0-9]{4}[^/]*\.py$') >"$mig_list"
    if [ -s "$mig_list" ] && [ -x /rmm/api/env/bin/python ] && cp "${RELEASE_TREE}/riddix/scripts/db_ahead_check.py" "$check_py"; then
      mig_tree=$RELEASE_TREE
      db_check_ready=true
    fi
  else
    git -C /rmm ls-tree -r --name-only "$TARGET_COMMIT" -- api/ulrmm | grep -E '/migrations/[0-9]{4}[^/]*\.py$' >"$mig_list"
    if [ -s "$mig_list" ] && [ -x /rmm/api/env/bin/python ] &&
      git -C /rmm show "${TARGET_COMMIT}:riddix/scripts/db_ahead_check.py" >"$check_py" 2>/dev/null &&
      xargs -a "$mig_list" -d '\n' git -C /rmm archive "$TARGET_COMMIT" -- | tar -xi -C "$mig_tree"; then
      db_check_ready=true
    fi
  fi
  if [ "$db_check_ready" = true ]; then
    (cd /rmm/api/ulrmm && /rmm/api/env/bin/python "$check_py" "$mig_list" "$mig_tree")
    rc=$?
    if [ "$rc" -ne 0 ]; then
      die "the database has migrations the target code does not ship (or the check failed, see above). Not updating."
    fi
  elif [ "$skip_db_check" = true ]; then
    warn "The database check could not run, continuing because of --skip-db-check."
  else
    die "the database check could not run. Rerun with --skip-db-check to update without it."
  fi

  if [ "$SWITCH" = true ] && [ "$yes" != true ]; then
    read -rn 1 -p "Press any key to continue with the switch, ctrl+c to abort..."
    echo
  fi

  # a hook (compose: image pull and recreate) applies the update instead of this script
  local hook
  hook=$(ls_get ULRMM_UPDATER_HOOK)
  hook=${ULRMM_UPDATER_HOOK:-$hook}
  if [ -n "$hook" ]; then
    [ -x "$hook" ] || die "ULRMM_UPDATER_HOOK ${hook} is not executable."
    progress apply "running ${hook}"
    ULRMM_TARGET_VERSION=$LATEST_ULRMM_VER ULRMM_SOURCE=$PROG_SOURCE ULRMM_RELEASE_DIR=$RELEASE_DIR "$hook"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      progress 'done' "${hook} installed ${LATEST_ULRMM_VER}"
      info "Update finished by ${hook}"
    else
      progress failed "${hook} exited with ${rc}"
    fi
    exit "$rc"
  fi

  # backup
  progress backup "backup before the update"
  if [ "$no_backup" = true ]; then
    warn "backup skipped on request (--no-backup)"
  elif [ -f /rmm/backup.sh ]; then
    /rmm/backup.sh --pre-update || die "backup failed. Aborting. Use --no-backup to skip (not recommended)."
    BACKUP_PATH=$(ls -1t /rmmbackups/pre-update/rmm-backup-*.tar /rmmbackups/pre-update/rmm-backup-*.tar.age 2>/dev/null | head -1)
  else
    warn "WARNING: /rmm/backup.sh is missing, no backup before this update."
  fi

  # frontend source and script library, still with the token
  sudo mkdir -p /etc/apt/keyrings "$WEB_DIR"
  sudo chown "${USER}:$(id -gn)" "$WEB_DIR"
  local pkg_ver web_tmp spa
  if [ "$RELEASE" = true ]; then
    progress verify "unpacking ulrmm-web-${LATEST_ULRMM_VER}.tar.gz"
    tmp_file web_tmp -d -t ulrmm-webdist-XXXXXXXXXX
    tar -xzf "${RELEASE_DIR}/ulrmm-web-${LATEST_ULRMM_VER}.tar.gz" -C "$web_tmp" ||
      die "could not unpack ulrmm-web-${LATEST_ULRMM_VER}.tar.gz."
    spa="${web_tmp}/ulrmm-web-${LATEST_ULRMM_VER}/dist/spa"
    [ -f "${spa}/index.html" ] || spa="${web_tmp}/ulrmm-web-${LATEST_ULRMM_VER}/dist"
    [ -f "${spa}/index.html" ] || die "the web tarball has no dist/spa/index.html."
    mkdir -p "$WEB_SRC" && rm -rf "${WEB_SRC}/dist" && cp -r "$spa" "${WEB_SRC}/dist" ||
      die "could not place the dashboard in ${WEB_SRC}/dist."
  else
    if [ ! -d "${WEB_SRC}/.git" ]; then
      git_auth "$WEB_GIT_URL" clone --quiet --branch "$WEB_GIT_BRANCH" "$WEB_GIT_URL" "$WEB_SRC" ||
        die "cloning ${WEB_GIT_URL} failed."
    fi
    git_auth "$WEB_GIT_URL" -C "$WEB_SRC" fetch --quiet "$WEB_GIT_URL" "+refs/heads/${WEB_GIT_BRANCH}:refs/remotes/ulrmm/${WEB_GIT_BRANCH}" ||
      die "git fetch from ${WEB_GIT_URL} failed."
    git -C "$WEB_SRC" checkout --quiet -f -B "$WEB_GIT_BRANCH" "refs/remotes/ulrmm/${WEB_GIT_BRANCH}" &&
      git -C "$WEB_SRC" reset --quiet --hard "refs/remotes/ulrmm/${WEB_GIT_BRANCH}" &&
      git -C "$WEB_SRC" clean -qdf || die "could not check out ${WEB_GIT_BRANCH} in ${WEB_SRC}."
    WEB_COMMIT=$(git -C "$WEB_SRC" rev-parse HEAD)
    pkg_ver=$(grep -m1 '"version"' "${WEB_SRC}/package.json" | awk -F'"' '{print $4}')
    if [ "$pkg_ver" != "$LATEST_ULRMM_VER" ]; then
      warn "WARNING: frontend version '${pkg_ver:-unknown}' does not match server version '${LATEST_ULRMM_VER}'. Continuing."
    fi
  fi
  DEPLOYED_WEB_COMMIT=$(cat /var/www/rmm/.ulrmm-web-commit 2>/dev/null)

  local scripts_commit=''
  sudo mkdir -p "$SCRIPTS_DIR"
  sudo chown -R "${USER}:$(id -gn)" "$SCRIPTS_DIR"
  if [ "$(url_host "$SCRIPTS_GIT_URL")" != "$(url_host "$GIT_URL")" ]; then
    echo "NOTE: the script library ${SCRIPTS_GIT_URL} is on another host than the server repository, it is fetched without the token."
  fi
  if [ ! -d "${SCRIPTS_DIR}/.git" ] && [ -n "$(ls -A "$SCRIPTS_DIR" 2>/dev/null)" ]; then
    # checkout -f and clean -df would wipe whatever lives there
    printf '%b%s%b\n' "$RED" "WARNING: ${SCRIPTS_DIR} is not empty and not a git checkout of the library, not touching it." "$NC"
  elif { [ -d "${SCRIPTS_DIR}/.git" ] || git -C "$SCRIPTS_DIR" init --quiet -b main; } &&
    { git -C "$SCRIPTS_DIR" remote set-url origin "$SCRIPTS_GIT_URL" 2>/dev/null ||
      git -C "$SCRIPTS_DIR" remote add origin "$SCRIPTS_GIT_URL"; } &&
    git_auth "$SCRIPTS_GIT_URL" -C "$SCRIPTS_DIR" fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main; then
    scripts_commit=$(git -C "$SCRIPTS_DIR" rev-parse refs/remotes/origin/main)
  else
    printf '%b%s%b\n' "$RED" "WARNING: could not fetch the script library from ${SCRIPTS_GIT_URL}." "$NC"
    printf '%b%s%b\n' "$RED" "WARNING: the community scripts on disk stay as they are." "$NC"
  fi

  drop_token

  # lib from the target, then the builds
  local lib_copy
  tmp_file lib_copy -t ulrmm-lib-XXXXXXXXXX
  if [ "$RELEASE" = true ]; then
    cp "${RELEASE_TREE}/riddix/scripts/install_lib.sh" "$lib_copy" 2>/dev/null
  else
    git -C /rmm show "${TARGET_COMMIT}:riddix/scripts/install_lib.sh" >"$lib_copy" 2>/dev/null
  fi
  [ -s "$lib_copy" ] && bash -n "$lib_copy" || die "could not read riddix/scripts/install_lib.sh from ${TARGET_COMMIT:0:8}."
  # shellcheck source=riddix/scripts/install_lib.sh
  . "$lib_copy" || die "could not load install_lib.sh."
  TARGET_VERSION=$LATEST_ULRMM_VER

  if [ "$RELEASE" = true ]; then
    info "Dashboard ${WEB_COMMIT:0:8} comes built with the release"
  elif [ "$WEB_COMMIT" != "$DEPLOYED_WEB_COMMIT" ] || [ "$force" = true ] || [ ! -f "${WEB_SRC}/dist/index.html" ]; then
    if ! node_ok; then
      info "Installing NodeJS 24"
      setup_node
      node_ok || die "need node 24 or newer to build the dashboard, got '$(node_major)'."
    fi
    info "Building the frontend (${WEB_COMMIT:0:8}), this takes a few minutes..."
    rm -rf "${WEB_SRC}/dist"
    (cd "$WEB_SRC" && npm ci && npm run build) || die "the frontend build failed. Nothing was changed."
    [ -f "${WEB_SRC}/dist/index.html" ] || die "the frontend build produced no dist/index.html. Nothing was changed."
  else
    info "Frontend is already at ${WEB_COMMIT:0:8}, skipping the build"
  fi

  local natsapi_dir
  tmp_file natsapi_dir -d -t ulrmm-natsapi-XXXXXXXXXX
  sudo mkdir -p "$AGENT_ROOT"
  sudo chown "${USER}:$(id -gn)" "$AGENT_ROOT"
  if [ "$RELEASE" = true ]; then
    tar -C "$RELEASE_TREE" -cf "${natsapi_dir}/src.tar" main.go go.mod go.sum natsapi VERSION \
      riddix/scripts/go_toolchain.sh riddix/scripts/build_natsapi.sh
  else
    git -C /rmm archive -o "${natsapi_dir}/src.tar" "$TARGET_COMMIT" main.go go.mod go.sum natsapi VERSION \
      riddix/scripts/go_toolchain.sh riddix/scripts/build_natsapi.sh
  fi &&
    tar -xf "${natsapi_dir}/src.tar" -C "$natsapi_dir" &&
    ULRMM_AGENT_ROOT="$AGENT_ROOT" bash "${natsapi_dir}/riddix/scripts/build_natsapi.sh" "$natsapi_dir" "${natsapi_dir}/nats-api" ||
    die "building nats-api from ${TARGET_COMMIT:0:8} failed. Nothing was changed."

  # what the rollback puts back; dist.old may only be this run's copy
  rm -rf "${MAINT_DIR}/rollback"
  sudo rm -rf /var/www/rmm/dist.old
  mkdir -p "${MAINT_DIR}/rollback"
  cp /usr/local/bin/nats-api "${MAINT_DIR}/rollback/nats-api" 2>/dev/null || true
  if [ "$RELEASE" = true ]; then
    command -v rsync >/dev/null || sudo apt install -y rsync || die "rsync is needed for a release update."
    ROLLBACK_DIR="${MAINT_DIR}/rollback/${CURRENT_ULRMM_VER:-unknown}"
    mkdir -p "$ROLLBACK_DIR"
    rsync -a --delete "${TREE_SYNC[@]}" /rmm/ "${ROLLBACK_DIR}/" || die "could not copy /rmm to ${ROLLBACK_DIR} for the rollback."
  fi

  # packages, CPython, nats-server, npm and MeshCentral while the services still serve
  local s ME
  ME="${USER}:$(id -gn)"

  local os_id codename libs
  os_id=$(. /etc/os-release && echo "${ID:-}")
  codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
  libs=(libpango-1.0-0 libpangoft2-1.0-0)
  [ "$os_id" = ubuntu ] && libs+=(libharfbuzz0b)
  if [ "$(dpkg -l "${libs[@]}" 2>/dev/null | grep -c '^ii')" -lt ${#libs[@]} ]; then
    sudo apt install -y "${libs[@]}"
  fi

  local nginx_key=/etc/apt/keyrings/nginx-archive-keyring.gpg expired
  expired=$(gpg --show-keys --with-colons "$nginx_key" 2>/dev/null |
    awk -F: -v now="$(date +%s)" '$1=="pub" {ex=$7} $1=="fpr" && $10=="573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62" {print (ex != "" && ex < now) ? "yes" : "no"; exit}')
  if [ ! -f "$nginx_key" ] || [ "$expired" = yes ]; then
    fetch_apt_key https://nginx.org/keys/nginx_signing.key "$NGINX_KEY_FPRS" "$nginx_key" ||
      warn "WARNING: could not refresh the nginx signing key."
  fi
  if [ ! -f /etc/apt/sources.list.d/nginx.list ]; then
    echo "deb [signed-by=${nginx_key}] https://nginx.org/packages/${os_id} ${codename} nginx" |
      sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null
  else
    # earlier installs used http
    sudo sed -i 's#http://nginx\.org/#https://nginx.org/#g' /etc/apt/sources.list.d/nginx.list
  fi
  local nconf=/etc/nginx/nginx.conf
  if ! sudo grep -q 'include /etc/nginx/sites-enabled' "$nconf"; then
    nginx_conf_text | sudo tee "$nconf" >/dev/null
  else
    sudo sed -i -E 's/worker_connections[[:space:]]+[0-9]+;/worker_connections 4096;/' "$nconf"
    sudo grep -q '^worker_rlimit_nofile' "$nconf" || sudo sed -i '1i worker_rlimit_nofile 1000000;' "$nconf"
    if sudo grep -q 'server_names_hash_bucket_size' "$nconf"; then
      sudo sed -i -E 's/server_names_hash_bucket_size[[:space:]]+[0-9]+;/server_names_hash_bucket_size 256;/' "$nconf"
    else
      sudo sed -i -E '0,/^http[[:space:]]*\{/ s//&\n        server_names_hash_bucket_size 256;/' "$nconf"
    fi
  fi
  if ! sudo nginx -t; then
    die "nginx -t fails on ${nconf}, see above."
  fi

  # earlier builds lacked liblzma-dev and so the lzma module
  if ! python3.12 --version 2>/dev/null | grep -qF "$PYTHON_VER" ||
    ! python3.12 -c 'import lzma' 2>/dev/null; then
    install_python
  fi
  if ! nats-server -version 2>/dev/null | grep -qF "$NATS_SERVER_VER"; then
    install_nats_server "$NATS_SERVER_VER"
  fi

  sudo rm -rf ~/.npm ~/.cache
  [ -d ~/.config ] && sudo chown -R "$ME" ~/.config
  if ! command -v npm >/dev/null; then
    sudo apt install -y npm
  fi
  if ! command -v npm >/dev/null; then
    warn "npm is still missing, reinstalling NodeJS and MeshCentral's modules"
    sudo systemctl stop meshcentral
    MESH_STOPPED=true
    setup_node || die "could not install NodeJS."
    local mesh_cur
    mesh_cur=$(cd /meshcentral/node_modules/meshcentral 2>/dev/null && node -p "require('./package.json').version" 2>/dev/null)
    mesh_reinstall "${mesh_cur:-$LATEST_MESH_VER}" || true
    sudo systemctl start nginx
    sudo systemctl start meshcentral
    MESH_STOPPED=false
  fi

  MESH_CHANGED=0
  if ! command -v jq >/dev/null; then
    sudo apt install -y jq
  fi
  ensure_age || warn "WARNING: could not install age, backups cannot be encrypted."
  local ts
  ts=$(date "+%Y%m%dT%H%M%S")
  if [ -f /meshcentral/meshcentral-data/config.json ]; then
    mesh_cfg_apply "$MESH_FILTER" "meshcfg-${ts}.bak"
    cp /meshcentral/meshcentral-data/config.json ~/"meshcfg${CURRENT_ULRMM_VER}-${ts}.bak"
    mesh_cfg_apply '.settings.autoBackup = false' "meshcfg-${ts}-autobackup.bak"
    harden_mesh
  fi

  local mesh_installed
  mesh_installed=$(cd /meshcentral/node_modules/meshcentral 2>/dev/null && node -p "require('./package.json').version" 2>/dev/null)
  if [ "$mesh_installed" != "$LATEST_MESH_VER" ] || [ "$force" = true ]; then
    info "MeshCentral ${mesh_installed:-none} -> ${LATEST_MESH_VER}"
    sudo systemctl stop meshcentral
    MESH_STOPPED=true
    sudo chown -R "$ME" /meshcentral
    mesh_reinstall "$LATEST_MESH_VER" && MESH_CHANGED=1
    sudo systemctl start nginx
    sleep 1
    sudo systemctl start meshcentral
    MESH_STOPPED=false
  fi

  # stop
  progress apply "stopping the services"
  SERVICES_STOPPED=true
  for s in celerybeat celery nginx nats-api nats rmm daphne; do
    printf 'Stopping %s service\n' "$s"
    sudo systemctl stop "$s"
  done

  # code
  progress apply "installing ${LATEST_ULRMM_VER} into /rmm"
  if [ "$RELEASE" = true ]; then
    rsync -a --delete "${TREE_SYNC[@]}" "${RELEASE_TREE}/" /rmm/ || die "could not copy ulrmm-server-${LATEST_ULRMM_VER} into /rmm."
    TREE_REPLACED=true
  else
    git -C /rmm config user.email "admin@example.com"
    git -C /rmm config user.name "Bob"
    git -C /rmm remote set-url origin "$GIT_URL" 2>/dev/null || git -C /rmm remote add origin "$GIT_URL"
    git -C /rmm checkout --quiet -f -B "$GIT_BRANCH" "$TARGET_COMMIT" || die "git checkout of ${TARGET_COMMIT:0:8} failed."
    TREE_REPLACED=true
    git -C /rmm reset --quiet --hard "$TARGET_COMMIT"
    git -C /rmm clean -df
    if [ -d /rmm/api/ulrmm/ee ] && [ -z "$(git -C /rmm ls-files -- api/ulrmm/ee)" ]; then
      rm -rf /rmm/api/ulrmm/ee
    fi
  fi

  write_units || die "could not write the systemd units."
  write_mesh_unit
  harden_logs

  if [ -n "$scripts_commit" ]; then
    git -C "$SCRIPTS_DIR" checkout --quiet -f -B main "$scripts_commit" &&
      git -C "$SCRIPTS_DIR" reset --quiet --hard "$scripts_commit" &&
      git -C "$SCRIPTS_DIR" clean -qdf ||
      warn "WARNING: could not check out the script library, the community scripts on disk stay as they are."
  fi

  sudo chown -R "$ME" /rmm "$SCRIPTS_DIR" /var/log/celery /etc/conf.d
  # earlier builds gave the whole tree, renewal hooks included, to the user
  letsencrypt_perms /etc/letsencrypt "$(id -gn)" "$(ls_get KEY_FILE)" || warn "WARNING: could not set the permissions of /etc/letsencrypt."
  [ -d /rmmbackups ] && sudo chown -R "$ME" /rmmbackups

  if ! grep -q '^ADMIN_ENABLED' "$local_settings"; then
    echo "ADMIN_ENABLED = False" >>"$local_settings"
  fi

  sudo install -m 0755 -o "$USER" -g "$USER" "${natsapi_dir}/nats-api" /usr/local/bin/nats-api ||
    die "could not install nats-api."

  # python environment
  local env=/rmm/api/env
  venv_pip() { "${env}/bin/pip" install --no-cache-dir "$@"; }
  if [ "$CURRENT_PIP_VER" != "$LATEST_PIP_VER" ] || [ "$force" = true ]; then
    info "Recreating the Python environment"
    rm -rf "${env}.old"
    [ -d "$env" ] && mv "$env" "${env}.old"
    if python3.12 -m venv "$env" && venv_pip pip==25.1 &&
      venv_pip "setuptools==$(settings_ver SETUPTOOLS_VER "$SETTINGS_PY")" "wheel==$(settings_ver WHEEL_VER "$SETTINGS_PY")" &&
      venv_pip -r /rmm/api/ulrmm/requirements.txt; then
      rm -rf "${env}.old"
    else
      rm -rf "$env"
      [ -d "${env}.old" ] && mv "${env}.old" "$env"
      die "pip install into a new ${env} failed, the old environment is back."
    fi
  else
    venv_pip -r /rmm/api/ulrmm/requirements.txt || die "pip install -r requirements.txt failed."
  fi

  sudo mkdir -p /opt/ulrmm-reporting/assets
  sed -i '/^REDIS_HOST/d' "$local_settings"
  ensure_nats_password
  # every service that uses redis is stopped until start_services
  ensure_redis_password || die "could not set the redis password, see above."
  ensure_enroll_key
  ensure_field_keys
  ensure_token_pepper
  sudo chown -R "$ME" /opt/ulrmm-reporting

  progress migrate "migrating the database"
  manage pre_update_tasks
  (cd /rmm/api/ulrmm && /rmm/api/env/bin/celery -A ulrmm purge -f)
  manage migrate || die "manage.py migrate failed."
  manage generate_json_schemas
  manage delete_tokens
  manage collectstatic --no-input || die "manage.py collectstatic failed."
  manage reload_nats
  manage load_chocos
  manage create_installer_user
  manage create_natsapi_conf || die "manage.py create_natsapi_conf failed."
  manage create_uwsgi_conf || die "manage.py create_uwsgi_conf failed."
  # before refresh_site: the new rmm site reads ca.pem, nginx -t puts the old one back without it.
  # A CA made again revokes the certificates of the lost one (mode optional), or required locks agents out.
  ensure_agent_ca --reset-certs-if-new || warn "WARNING: manage.py ensure_agent_ca failed, see above. nginx keeps its current rmm site."
  manage clear_redis_celery_locks
  manage post_update_tasks
  local API FRONTEND MESHDOMAIN
  API=$(manage get_config api)
  FRONTEND=$(manage get_config webdomain)
  MESHDOMAIN=$(manage get_config meshdomain)

  if grep -q manage_etc_hosts /etc/hosts 2>/dev/null; then
    sudo sed -i '/manage_etc_hosts: true/d' /etc/cloud/cloud.cfg
    if ! grep -q 'manage_etc_hosts: false' /etc/cloud/cloud.cfg; then
      echo 'manage_etc_hosts: false' | sudo tee -a /etc/cloud/cloud.cfg >/dev/null
    fi
    sudo systemctl restart cloud-init
  fi
  add_hosts "$API" "$FRONTEND" "$MESHDOMAIN"

  deploy_web "$API" || die "could not copy the frontend (disk full?). Keeping the running dashboard."

  if sudo grep -q checktoken /etc/nginx/sites-available/rmm.conf 2>/dev/null; then
    warn "WARNING: /etc/nginx/sites-available/rmm.conf still has a checktoken block."
  fi
  NGINX_REFRESHED=()
  refresh_site rmm rmm_nginx_conf "$API" "$FRONTEND"
  refresh_site meshcentral mesh_nginx_conf "$MESHDOMAIN"
  refresh_site frontend frontend_nginx_conf "$FRONTEND" "$API" "$MESHDOMAIN"
  if [ ${#NGINX_REFRESHED[@]} -gt 0 ] && ! sudo nginx -t; then
    local f
    for f in "${NGINX_REFRESHED[@]}"; do
      sudo mv -f "${f}.prev" "$f"
    done
    warn "WARNING: the new nginx sites did not pass nginx -t, the previous ones are back."
  fi

  local agents_missing=false
  if [ "$skip_agent_build" != true ] && ! build_agents_step; then
    local art ver
    art=$(settings_ver AGENT_ARTIFACT_NAME "$SETTINGS_PY")
    ver=$(settings_ver LATEST_AGENT_VER "$SETTINGS_PY")
    if compgen -G "${AGENT_ROOT}/dist/${art:-ulrmm-agent}-v${ver}-*" >/dev/null; then
      warn "WARNING: the agent build failed, the agents already in ${AGENT_ROOT}/dist stay."
    else
      agents_missing=true
    fi
  fi

  progress restart "starting the services"
  start_services
  if [ "$MESH_CHANGED" = 1 ]; then
    sudo systemctl restart meshcentral
  fi
  if [ "$RELEASE" = true ] || grep -q 'health/' /rmm/api/ulrmm/core/urls.py; then
    progress health "waiting for ${LATEST_ULRMM_VER} to answer"
    if ! health_ok "$API" "$LATEST_ULRMM_VER"; then
      rollback "core/health/ did not answer ok with version ${LATEST_ULRMM_VER} within 120 s"
    fi
  else
    info "no health endpoint in this version, skipping the health check"
  fi

  if grep -qE '^RUSTDESK_SERVER[[:space:]]*=[[:space:]]*True([[:space:]#]|$)' "$local_settings"; then
    local rd_host
    rd_host=$(ls_get RUSTDESK_HOST)
    sudo bash /rmm/riddix/rustdesk/install-rustdesk-server.sh --host "${rd_host:-$API}" ||
      warn "WARNING: the RustDesk server update failed, see above."
  fi

  sudo systemctl reload nginx
  if [ "$no_firewall" != true ]; then
    firewall_step
  fi
  natsapi_summary
  progress 'done' "updated to ${LATEST_ULRMM_VER}"
  info "Update finished!"
  if [ "$agents_missing" = true ]; then
    printf '%b\n' "$RED"
    echo "NO AGENT BINARIES for ${ver} in ${AGENT_ROOT}/dist: agent installs and updates fail."
    echo "Fix the cause above, then run: bash /rmm/riddix/agents/build_agents.sh"
    printf '%b\n' "$NC"
  fi
  exit 0
}

main "$@"; exit

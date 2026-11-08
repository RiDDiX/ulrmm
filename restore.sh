#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Restore of a backup made by backup.sh onto a clean server.
# Run from a clone of the server repository as a normal user with sudo:
#
#   bash ulrmm/restore.sh [options] rmm-backup-xxxx.tar[.age]     (--help lists the options)

SCRIPT_VERSION="79"

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ ! -f "${SELF_DIR}/riddix/scripts/install_lib.sh" ]; then
  printf '%b%s%b\n' "$RED" "restore.sh has to run from a clone of the server repository:" "$NC"
  printf '%b%s%b\n' "$RED" "  git clone https://github.com/RiDDiX/ulrmm.git && bash ulrmm/restore.sh rmm-backup-xxxx.tar" "$NC"
  exit 1
fi

local_settings='/rmm/api/ulrmm/ulrmm/local_settings.py'
SCRIPTS_DIR='/opt/ulrmm-community-scripts'
SETTINGS_PY='/rmm/api/ulrmm/ulrmm/settings.py'
non_interactive=false
skip_agent_build=false
resume=false
arg_source='' arg_git_base='' arg_server_repo='' arg_web_repo='' arg_agent_repo=''
arg_branch='' arg_web_branch='' arg_agent_branch='' arg_git_user='' arg_token=''
arg_token_file='' arg_scripts_git_url='' age_identity=''
rustdesk_host='' backup_file=''

# shellcheck source=riddix/scripts/install_lib.sh
. "${SELF_DIR}/riddix/scripts/install_lib.sh"

export DEBIAN_FRONTEND=noninteractive

usage() {
  cat <<'EOF'
usage: bash restore.sh [options] rmm-backup-xxxx.tar[.age]

Restores a backup made by /rmm/backup.sh on a clean server. The repository
settings and the token come from the backup; these options override them:

  --source github|gitea         git base (default github)
  --git-base URL                any other git base, replaces --source
  --server-repo NAME            server repository
  --web-repo NAME               dashboard repository
  --agent-repo NAME             agent repository
  --branch NAME                 branch of all three
  --web-branch NAME             dashboard branch
  --agent-branch NAME           agent branch or tag
  --git-user NAME               user name for the token
  --token TOKEN                 read token for private repositories
  --token-file PATH             the same from a file (/dev/stdin works)
  --scripts-git-url URL         script library
  --skip-agent-build            do not build the agents now
  --rustdesk HOST               also install the RustDesk server for HOST
  --age-identity FILE           age key file of an encrypted backup (.tar.age)
  --non-interactive             never ask
  --resume                      run again on the server of a restore that
                                failed; databases already loaded are kept
  -h, --help                    this list

Every --option value also works as --option=value.
EOF
}

split_args=()
for a in "$@"; do
  case "$a" in
  --*=*) split_args+=("${a%%=*}" "${a#*=}") ;;
  *) split_args+=("$a") ;;
  esac
done
set -- "${split_args[@]}"

while [ $# -gt 0 ]; do
  case "$1" in
  -h | --help)
    usage
    exit 0
    ;;
  --non-interactive) non_interactive=true ;;
  --skip-agent-build) skip_agent_build=true ;;
  --resume) resume=true ;;
  --source | --git-base | --server-repo | --web-repo | --agent-repo | --branch | --web-branch | \
    --agent-branch | --git-user | --token | --token-file | --scripts-git-url | --rustdesk | --age-identity)
    [ $# -ge 2 ] || lib_die "$1 needs a value."
    case "$1" in
    --source) arg_source=$2 ;;
    --git-base) arg_git_base=$2 ;;
    --server-repo) arg_server_repo=$2 ;;
    --web-repo) arg_web_repo=$2 ;;
    --agent-repo) arg_agent_repo=$2 ;;
    --branch) arg_branch=$2 ;;
    --web-branch) arg_web_branch=$2 ;;
    --agent-branch) arg_agent_branch=$2 ;;
    --git-user) arg_git_user=$2 ;;
    --token) arg_token=$2 ;;
    --token-file) arg_token_file=$2 ;;
    --scripts-git-url) arg_scripts_git_url=$2 ;;
    --rustdesk) rustdesk_host=$2 ;;
    --age-identity) age_identity=$2 ;;
    esac
    shift
    ;;
  -*)
    usage >&2
    lib_die "unknown option $1"
    ;;
  *) backup_file=$1 ;;
  esac
  shift
done

valid_name() { [[ $1 =~ ^[A-Za-z0-9.-]+$ ]]; }
if [ -n "$rustdesk_host" ] && ! valid_name "$rustdesk_host"; then
  lib_die "--rustdesk must be a host name or IP address, not '${rustdesk_host}'."
fi

lib_info "Installing the base packages"
sudo apt update
sudo apt install -y curl wget jq dirmngr gnupg lsb-release ca-certificates git openssl ||
  lib_die "apt install of the base packages failed."
ensure_age || lib_die "apt install age failed."
if apt-cache show software-properties-common >/dev/null 2>&1; then
  sudo apt install -y software-properties-common
fi

# host checks

[ "$(systemd-detect-virt 2>/dev/null)" != lxc ] || lib_die "LXC is not supported, use a VM instead."
[ "$resume" = true ] || [ ! -d /rmm/api ] ||
  lib_die "Existing UniversalLocal RMM installation found. The restore script must be run on a clean server, or with --resume after a restore that failed."
arch=$(uname -m)
case "$arch" in
x86_64 | aarch64) ;;
*) lib_die "only x86_64 and aarch64 are supported, this is ${arch}." ;;
esac
mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[ "${mem_kb:-0}" -ge 3627528 ] || lib_die "A minimum of 4GB of RAM is required."
os_id=$(. /etc/os-release && echo "${ID:-}")
os_ver=$(. /etc/os-release && echo "${VERSION_ID:-}")
codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
case "${os_id} ${os_ver}" in
"debian 12" | "debian 13" | "ubuntu 22.04" | "ubuntu 24.04") ;;
*) lib_die "this is ${os_id} ${os_ver}. Supported are Debian 12, Debian 13, Ubuntu 22.04 and Ubuntu 24.04." ;;
esac
[ -n "$codename" ] || lib_die "/etc/os-release has no VERSION_CODENAME."
if dpkg -l 2>/dev/null | grep -qi turnkey; then
  lib_die "Turnkey images are not supported."
fi
if pgrep -f webmin >/dev/null; then
  lib_die "Webmin is running on this host, it is not supported."
fi
[ "$EUID" -ne 0 ] || lib_die "Do NOT run this script as root."
case "${LANG:-}" in
*.UTF-8) ;;
*) lib_die "the locale is '${LANG:-}', not UTF-8. Run sudo dpkg-reconfigure locales, choose an .UTF-8 one, log in again." ;;
esac
if [ ! -f "$backup_file" ]; then
  echo "usage: bash restore.sh [options] rmm-backup-xxxx.tar[.age] (--help lists the options)"
  exit 1
fi

ME="${USER}:$(id -gn)"

# the archive, checked before anything on the host changes

lib_info "Unpacking backup"
STAGING=$(mktemp -d -t ulrmm-XXXXXXXXXXXXXXXXXXXXX) || lib_die "cannot create a staging directory."
# dumps, TLS key and local_settings.py with the token
lib_cleanup() {
  if [ -n "$STAGING" ]; then
    rm -rf "$STAGING"
  fi
  STAGING=''
}
# $1 archive, $2 directory. backup.sh encrypts with age when it has recipients.
unpack_backup() {
  if [ "$(head -c 21 "$1")" = age-encryption.org/v1 ]; then
    [ -n "$age_identity" ] || lib_die "${1} is encrypted, pass its age key file with --age-identity FILE."
    [ -r "$age_identity" ] || lib_die "cannot read the age key file ${age_identity}."
    (set -o pipefail && age -d -i "$age_identity" "$1" | tar -xf - -C "$2" --no-same-owner) ||
      lib_die "${1} could not be decrypted with ${age_identity} and unpacked."
  else
    tar -xf "$1" -C "$2" --no-same-owner || lib_die "${1} could not be unpacked."
  fi
  # certs, CA and RustDesk keys are installed from here with sudo
  [ -z "$(find "$2" ! -type f ! -type d -print -quit)" ] || lib_die "${1} has links or special files."
}
unpack_backup "$backup_file" "$STAGING"
B=$STAGING
backup_settings="${B}/rmm/local_settings.py"

if [ -f "${B}/SHA256SUMS" ]; then
  (cd "$B" && sha256sum -c --quiet --strict SHA256SUMS) ||
    lib_die "${backup_file} is damaged: its SHA256SUMS do not match."
  lib_info "Checksums match ($(grep -vE '^(LARGE_PACKAGE|ISO_IMAGE)=' "${B}/MANIFEST" 2>/dev/null | tr '\n' ' '))"
  [ "$(head -c 21 "$backup_file")" = age-encryption.org/v1 ] ||
    lib_info "The checksums catch damage only, not changes: anyone who can write an unencrypted backup can rewrite it and its SHA256SUMS."
fi

if ! grep -qE "['\"]NAME['\"][[:space:]]*:[[:space:]]*['\"]ulrmm['\"]" "$backup_settings" 2>/dev/null; then
  lib_die "${backup_file} is not a backup of this version (no database ulrmm in its local_settings.py). See bash restore.sh --help."
fi

shopt -s nullglob
db_dumps=("$B"/postgres/db-*.psql.gz)
mesh_dumps=("$B"/postgres/mesh-db-*.psql.gz)
shopt -u nullglob
[ ${#db_dumps[@]} -eq 1 ] || lib_die "the backup needs exactly one postgres/db-*.psql.gz, it has ${#db_dumps[@]}."
[ ${#mesh_dumps[@]} -eq 1 ] || lib_die "the backup needs exactly one postgres/mesh-db-*.psql.gz, it has ${#mesh_dumps[@]}."
db_dump=${db_dumps[0]}
mesh_dump=${mesh_dumps[0]}
for f in "$db_dump" "$mesh_dump"; do
  gzip -t "$f" || lib_die "${f#"$B"/} is damaged."
done
[ -f "${B}/meshcentral/mesh.tar.gz" ] || lib_die "the backup has no meshcentral/mesh.tar.gz."

# Members of the inner tarballs: no absolute names, no "..", optionally all
# below one top directory, links only to targets inside the directory the
# tarball is extracted to, optionally links only below one directory.
# $1 tarball, $2 directory it is extracted to, $3 required top directory or '',
# $4 the only directory links may be in, or ''
check_tarball() {
  local names long out i n rel t abs
  out=$(tar -tf "$1") || lib_die "cannot read ${1#"$B"/}."
  mapfile -t names <<<"$out"
  out=$(tar -tvf "$1") || lib_die "cannot read ${1#"$B"/}."
  mapfile -t long <<<"$out"
  [ ${#names[@]} -eq ${#long[@]} ] || lib_die "cannot list ${1#"$B"/}."
  for i in "${!names[@]}"; do
    n=${names[$i]#./}
    case "${names[$i]}" in
    /*) lib_die "${1#"$B"/} has an unsafe member '${names[$i]}'." ;;
    esac
    case "/${n}/" in
    */../*) lib_die "${1#"$B"/} has an unsafe member '${names[$i]}'." ;;
    esac
    [ -n "$n" ] || continue
    # the top directory is stripped on extraction, links resolve without it
    rel=$n
    if [ -n "$3" ]; then
      if [ "${n%/}" = "$3" ]; then
        rel=''
      elif [ "${n#"$3"/}" = "$n" ]; then
        lib_die "${1#"$B"/} has a member outside $3/: '${names[$i]}'."
      else
        rel=${n#"$3"/}
      fi
    fi
    case "${long[$i]:0:1}" in
    l)
      t=${long[$i]##* -> }
      abs=$(realpath -ms -- "$2/$rel")
      if [ -n "${4:-}" ] && [ "${abs#"$2/$4"/}" = "$abs" ]; then
        lib_die "${1#"$B"/} has a link '${names[$i]}' outside $4/."
      fi
      ;;
    h)
      t=${long[$i]##* link to }
      case "/${t#./}/" in //* | */../*) lib_die "${1#"$B"/} has an unsafe hard link '${names[$i]}'." ;; esac
      continue
      ;;
    b | c | p) lib_die "${1#"$B"/} has a special file '${names[$i]}'." ;;
    *) continue ;;
    esac
    if [ "${t:0:1}" = / ]; then
      abs=$(realpath -m -- "$t")
    else
      abs=$(realpath -m -- "$2/$(dirname -- "./$rel")/$t")
    fi
    if [ "$abs" != "$2" ] && [ "${abs#"$2"/}" = "$abs" ]; then
      lib_die "${1#"$B"/} has a link '${names[$i]}' that points outside $2."
    fi
  done
}
check_tarball "${B}/meshcentral/mesh.tar.gz" /meshcentral meshcentral
[ ! -f "${B}/certs/etc-letsencrypt.tar.gz" ] || check_tarball "${B}/certs/etc-letsencrypt.tar.gz" /etc/letsencrypt '' live
[ ! -f "${B}/opt/opt-ulrmm-reporting.tar.gz" ] || check_tarball "${B}/opt/opt-ulrmm-reporting.tar.gz" /opt/ulrmm-reporting ''
[ ! -f "${B}/rmm/packages.tar" ] || check_tarball "${B}/rmm/packages.tar" /rmm/api/ulrmm/ulrmm/private/packages ''
[ ! -f "${B}/rmm/iso.tar" ] || check_tarball "${B}/rmm/iso.tar" /rmm/api/ulrmm/ulrmm/private/iso ''

# the MeshCentral database login goes into SQL run as postgres
mkdir -p "${B}/meshcheck"
tar -xzf "${B}/meshcentral/mesh.tar.gz" -C "${B}/meshcheck" meshcentral/meshcentral-data/config.json ||
  lib_die "the backup's mesh.tar.gz has no meshcentral-data/config.json."
mesh_db_user=$(jq -r '.settings.postgres.user // empty' "${B}/meshcheck/meshcentral/meshcentral-data/config.json")
mesh_db_pw=$(jq -r '.settings.postgres.password // empty' "${B}/meshcheck/meshcentral/meshcentral-data/config.json")
rm -rf "${B}/meshcheck"

# $1 role, $2 password, $3 where they come from
check_db_login() {
  [[ $1 =~ ^[a-z_][a-z0-9_]{0,62}$ ]] ||
    lib_die "the database user '$1' in $3 is not a plain lower-case name. Fix it in the backup by hand."
  case "$2" in
  '' | *\'* | *\\* | *$'\n'*) lib_die "the database password in $3 is empty or contains quotes, backslashes or newlines. Fix it in the backup by hand." ;;
  esac
}
check_db_login "$mesh_db_user" "$mesh_db_pw" "meshcentral-data/config.json"

# custom certificate paths come from the archive and are written as root
cert_file=$(ls_get CERT_FILE "$backup_settings")
key_file=$(ls_get KEY_FILE "$backup_settings")
check_cert_path() {
  local p=$1
  case "$p" in
  /*) ;;
  *) lib_die "custom certificate path '${p}' from the backup is not absolute." ;;
  esac
  [[ $p =~ ^/[A-Za-z0-9._/@+-]+$ ]] || lib_die "custom certificate path '${p}' from the backup has unusual characters."
  case "/${p}/" in */../* | */./*) lib_die "custom certificate path '${p}' from the backup is not normalised." ;; esac
  [ "$(realpath -m -- "$p")" = "$p" ] && [ "${p%/}" = "$p" ] ||
    lib_die "custom certificate path '${p}' from the backup is not a normalised file name."
  # restore runs on a clean server: an existing file is a system file, unless an
  # earlier run of this restore wrote it for the install user
  if sudo test -e "$p" || sudo test -L "$p"; then
    [ "$(sudo stat -c %U -- "$p")" = "$USER" ] ||
      lib_die "custom certificate path ${p} from the backup already exists on this host; move that file away first."
  fi
  case "$p" in
  /etc/ssl/ulrmm/?* | /etc/ssl/private/?* | /etc/letsencrypt/live/?* | /etc/letsencrypt/archive/?*) return 0 ;;
  esac
  local where="/etc/ssl/ulrmm, /etc/ssl/private, /etc/letsencrypt/live and /etc/letsencrypt/archive"
  if [ "$non_interactive" = true ]; then
    lib_die "custom certificate path ${p} from the backup is outside ${where}; restore it by hand"
  fi
  local answer
  read -rp "The backup puts a certificate file at ${p}, outside ${where}. Write it there? [y/N] " answer
  [[ $answer =~ ^[yY]$ ]] || lib_die "custom certificate path ${p} refused; restore it by hand."
}
if [ -f "${B}/certs/custom/cert" ] && [ -f "${B}/certs/custom/key" ]; then
  [ -n "$cert_file" ] && [ -n "$key_file" ] || lib_die "the backup has a custom certificate but no CERT_FILE/KEY_FILE."
  check_cert_path "$cert_file"
  check_cert_path "$key_file"
fi

# repository settings from the backup unless given

bset() { ls_get "$1" "$backup_settings"; }
repo_name() { local n=${1##*/}; printf '%s' "${n%.git}"; }
if [ -z "$arg_source" ] && [ -z "$arg_git_base" ]; then
  arg_git_base=$(bset ULRMM_GIT_BASE)
  if [ -z "$arg_git_base" ] && [ -n "$(bset ULRMM_GIT_URL)" ]; then
    arg_git_base=$(bset ULRMM_GIT_URL)
    arg_git_base=${arg_git_base%/*}
  fi
fi
for pair in "arg_server_repo ULRMM_GIT_SERVER_REPO ULRMM_GIT_URL" \
  "arg_web_repo ULRMM_GIT_WEB_REPO ULRMM_WEB_GIT_URL" \
  "arg_agent_repo ULRMM_GIT_AGENT_REPO ULRMM_AGENT_GIT_URL"; do
  read -r var key url_key <<<"$pair"
  if [ -z "${!var}" ]; then
    val=$(bset "$key")
    if [ -z "$val" ] && [ -n "$(bset "$url_key")" ]; then
      val=$(repo_name "$(bset "$url_key")")
    fi
    printf -v "$var" '%s' "$val"
  fi
done
arg_branch=${arg_branch:-$(bset ULRMM_GIT_BRANCH)}
arg_web_branch=${arg_web_branch:-$(bset ULRMM_WEB_GIT_BRANCH)}
arg_agent_branch=${arg_agent_branch:-$(bset ULRMM_AGENT_GIT_REF)}
arg_git_user=${arg_git_user:-$(bset ULRMM_GIT_USER)}
arg_scripts_git_url=${arg_scripts_git_url:-$(bset ULRMM_SCRIPTS_GIT_URL)}
if [ -z "$arg_token" ] && [ -z "$arg_token_file" ]; then
  arg_token=$(bset ULRMM_GIT_TOKEN)
fi

lib_info "UniversalLocal RMM restore (restore.sh ${SCRIPT_VERSION})"
resolve_repos
repo_preflight restore.sh riddix/scripts/install_lib.sh riddix/scripts/go_toolchain.sh go.mod go.sum
natsapi_prefetch "$SELF_DIR"

# host

sudo systemctl restart systemd-journald
sudo mkdir -p /etc/apt/keyrings

lib_info "Installing NodeJS"
fetch_apt_key https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key "$NODESOURCE_KEY_FPR" /etc/apt/keyrings/nodesource.gpg ||
  lib_die "could not fetch the NodeSource signing key."
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" |
  sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
sudo apt update
sudo apt install -y gcc g++ make || lib_die "apt install gcc g++ make failed."
sudo apt install -y nodejs || lib_die "apt install nodejs failed."


lib_info "Installing nginx"
fetch_apt_key https://nginx.org/keys/nginx_signing.key "$NGINX_KEY_FPRS" /etc/apt/keyrings/nginx-archive-keyring.gpg ||
  lib_die "could not fetch the nginx signing key."
echo "deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/${os_id} ${codename} nginx" |
  sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null
sudo apt update
sudo apt install -y nginx || lib_die "apt install nginx failed."
sudo systemctl stop nginx
nginx_conf_text | sudo tee /etc/nginx/nginx.conf >/dev/null
sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
sudo apt install -y certbot openssl || lib_die "apt install certbot failed."

lib_info "Restoring certificates"
if [ -f "${B}/certs/etc-letsencrypt.tar.gz" ]; then
  if [ -n "$(sudo ls -A /etc/letsencrypt 2>/dev/null)" ]; then
    le_old="/etc/letsencrypt.pre-restore-$(date +%s)"
    sudo mv /etc/letsencrypt "$le_old" || lib_die "could not move /etc/letsencrypt away."
    lib_info "The certificates that were in /etc/letsencrypt are in ${le_old} now."
  fi
  sudo rm -rf /etc/letsencrypt
  sudo mkdir -p /etc/letsencrypt
  sudo tar -xzf "${B}/certs/etc-letsencrypt.tar.gz" -C /etc/letsencrypt ||
    lib_die "could not restore /etc/letsencrypt."
  # hooks run as root on renewal and are not taken from an archive, whatever
  # the member names; links exist only below live/ (check_tarball)
  sudo rm -rf /etc/letsencrypt/renewal-hooks /etc/letsencrypt/cli.ini &&
    sudo install -d -m 755 -o root -g root /etc/letsencrypt/renewal-hooks/pre \
      /etc/letsencrypt/renewal-hooks/post /etc/letsencrypt/renewal-hooks/deploy &&
    sudo find /etc/letsencrypt -type f -name '*.conf' \
      -exec sed -i -E '/^[[:space:]]*["\x27]?[a-z_-]*hook["\x27]?[[:space:]]*=/Id' {} + ||
    lib_die "could not remove the renewal hooks from /etc/letsencrypt."
  letsencrypt_perms /etc/letsencrypt "$(id -gn)" "$key_file" || lib_die "could not set the permissions of /etc/letsencrypt."
  lib_info "Renewal hooks and cli.ini are not restored, set them up again if you used them."
fi

# missing directories are created for the user, existing ones stay as they are
ensure_dir() {
  local d=$1 todo=()
  while [ ! -d "$d" ]; do
    todo=("$d" "${todo[@]}")
    d=$(dirname -- "$d")
  done
  for d in "${todo[@]}"; do
    sudo mkdir "$d" && sudo chown "$ME" "$d" || return 1
  done
}
if [ -f "${B}/certs/custom/cert" ] && [ -f "${B}/certs/custom/key" ]; then
  for pair in "cert $cert_file 0644" "key $key_file 0600"; do
    read -r src dest mode <<<"$pair"
    ensure_dir "$(dirname -- "$dest")" || lib_die "could not create the directory of ${dest}."
    sudo install -m "$mode" -o "$USER" -g "$(id -gn)" "${B}/certs/custom/${src}" "$dest" ||
      lib_die "could not restore ${dest}."
  done
fi

# CA of the agent client certificates. Without it ensure_agent_ca makes a new one.
agent_ca_restored=false
if [ -f "${B}/agent-ca/ca.key" ] && [ -f "${B}/agent-ca/ca.pem" ]; then
  sudo install -d -m 0755 -o "$USER" -g "$(id -gn)" "$AGENT_CA_DIR" || lib_die "could not create ${AGENT_CA_DIR}."
  for pair in "ca.key 0600" "ca.pem 0644"; do
    read -r name mode <<<"$pair"
    sudo install -m "$mode" -o "$USER" -g "$(id -gn)" "${B}/agent-ca/${name}" "${AGENT_CA_DIR}/${name}" ||
      lib_die "could not restore ${AGENT_CA_DIR}/${name}."
  done
  agent_ca_restored=true
fi

if [ -f "${B}/opt/opt-ulrmm-reporting.tar.gz" ]; then
  sudo mkdir -p /opt/ulrmm-reporting/assets
  sudo tar -xzf "${B}/opt/opt-ulrmm-reporting.tar.gz" -C /opt/ulrmm-reporting || lib_die "could not restore /opt/ulrmm-reporting."
  sudo chown -R "$ME" /opt/ulrmm-reporting
fi

rustdesk_keys=false
if [ -f "${B}/rustdesk/id_ed25519" ] && [ -f "${B}/rustdesk/id_ed25519.pub" ]; then
  sudo install -d -m 0755 /opt/rustdesk
  sudo install -m 0600 "${B}/rustdesk/id_ed25519" /opt/rustdesk/id_ed25519
  sudo install -m 0644 "${B}/rustdesk/id_ed25519.pub" /opt/rustdesk/id_ed25519.pub
  rustdesk_keys=true
fi

write_units || lib_die "could not write the systemd units."
unit_text meshcentral | sudo tee /etc/systemd/system/meshcentral.service >/dev/null
sudo chown -R "$ME" /etc/conf.d
sudo systemctl daemon-reload

install_python
sudo apt install -y redis || lib_die "apt install redis failed."
start_redis

lib_info "Installing PostgreSQL 18"
fetch_apt_key https://www.postgresql.org/media/keys/ACCC4CF8.asc "$PGDG_KEY_FPR" /etc/apt/keyrings/postgresql-archive-keyring.gpg ||
  lib_die "could not fetch the PostgreSQL signing key."
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/postgresql-archive-keyring.gpg] https://apt.postgresql.org/pub/repos/apt/ ${codename}-pgdg main" |
  sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
sudo apt update
sudo apt install -y postgresql-18 || lib_die "apt install postgresql-18 failed."
sudo systemctl enable --now postgresql
for _ in $(seq 1 60); do
  pg_isready -q && break
  sleep 1
done
pg_isready -q || lib_die "PostgreSQL does not answer."

# DATABASES of the backup's local_settings.py, read as a Python literal
db_login=$(python3.12 -I - "$backup_settings" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
for node in tree.body:
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DATABASES" for t in node.targets):
        db = ast.literal_eval(node.value)["default"]
        if db.get("NAME") != "ulrmm" or not db.get("USER") or not db.get("PASSWORD"):
            sys.exit(1)
        print(db["USER"])
        print(db["PASSWORD"])
        sys.exit(0)
sys.exit(1)
EOF
) || lib_die "DATABASES in the backup's local_settings.py has no database ulrmm with USER and PASSWORD."
{
  read -r db_user
  read -r db_pw
} <<<"$db_login"
check_db_login "$db_user" "$db_pw" "local_settings.py"

sudo mkdir -p /var/log/celery
sudo chown "$ME" /var/log/celery
clone_repos

settings_ver() { grep "^${1}" "$SETTINGS_PY" | awk -F'[= "]' '{print $5}'; }
install_nats_server "$(settings_ver NATS_SERVER_VER)"

# $1 dump, $2 database, $3 role, $4 password. A database with tables is a
# dump loaded by an earlier run, kept only with --resume.
load_dump() (
  set -o pipefail
  local has
  has=$(PGPASSWORD=$4 psql -tA -h localhost -U "$3" -d "$2" -c "SELECT 1 FROM pg_tables WHERE schemaname = 'public' LIMIT 1") || exit 1
  if [ -n "$has" ]; then
    [ "$resume" = true ] || lib_die "the database ${2} already has tables, restore.sh needs a clean server."
    lib_info "The database ${2} was loaded by an earlier run, kept (--resume)."
    exit 0
  fi
  gzip -dc "$1" | PGPASSWORD=$4 psql -q -v ON_ERROR_STOP=1 --single-transaction -h localhost -U "$3" -d "$2" >/dev/null
)

lib_info "Restoring MeshCentral"
sudo mkdir -p /meshcentral
sudo chown "$ME" /meshcentral
tar -xzf "${B}/meshcentral/mesh.tar.gz" -C /meshcentral --strip-components=1 --no-same-owner ||
  lib_die "could not restore /meshcentral."
sudo chown -R "$ME" /meshcentral
rm -f /meshcentral/package.json /meshcentral/package-lock.json
pg_create_db meshcentral "$mesh_db_user" "$mesh_db_pw" || lib_die "could not create the meshcentral database."
load_dump "$mesh_dump" meshcentral "$mesh_db_user" "$mesh_db_pw" || lib_die "loading the MeshCentral database failed."
printf '{"dependencies": {"archiver": "7.0.1", "meshcentral": "%s", "otplib": "13.4.1", "pg": "8.16.3"}}\n' \
  "$(settings_ver MESH_VER)" >/meshcentral/package.json
(cd /meshcentral && npm install) || lib_die "npm install of MeshCentral failed."

lib_info "Restoring the backend"
# --resume keeps the file of the earlier run: its generated keys may be in use
if [ "$resume" != true ] || [ ! -f "$local_settings" ]; then
  install -m 600 "$backup_settings" "$local_settings" || lib_die "could not restore ${local_settings}."
fi
if [ -f "${B}/rmm/packages.tar" ]; then
  mkdir -p /rmm/api/ulrmm/ulrmm/private/packages
  chmod 755 /rmm/api/ulrmm/ulrmm/private/packages
  tar -xpf "${B}/rmm/packages.tar" -C /rmm/api/ulrmm/ulrmm/private/packages --no-same-owner ||
    lib_die "could not restore the software packages."
fi
if [ -f "${B}/rmm/iso.tar" ]; then
  mkdir -p /rmm/api/ulrmm/ulrmm/private/iso
  chmod 755 /rmm/api/ulrmm/ulrmm/private/iso
  tar -xpf "${B}/rmm/iso.tar" -C /rmm/api/ulrmm/ulrmm/private/iso --no-same-owner ||
    lib_die "could not restore the ISO images."
fi
# backup.sh leaves package files above 1 GiB out unless --with-large-packages.
# $1 MANIFEST, $2 packages dir: its LARGE_PACKAGE=<sha256> <size> <name> lines
# whose file is missing
missing_packages() {
  local sha size name
  while read -r sha size name; do
    [[ $sha =~ ^[0-9a-f]{64}$ ]] || continue
    [ -f "${2}/${sha}" ] || printf '%s (%s bytes, sha256 %s)\n' "$name" "$size" "$sha"
  done < <(sed -n 's/^LARGE_PACKAGE=//p' "$1" 2>/dev/null)
}
mapfile -t missing_pkgs < <(missing_packages "${B}/MANIFEST" /rmm/api/ulrmm/ulrmm/private/packages)
# the same for the ISO_IMAGE=<sha256 or -> <size> <file name> lines; backup.sh
# takes the images only with --with-large-packages
missing_isos() {
  local sha size name
  while read -r sha size name; do
    [ -n "$name" ] || continue
    [ -f "${2}/${name}" ] || printf '%s (%s bytes, sha256 %s)\n' "$name" "$size" "$sha"
  done < <(sed -n 's/^ISO_IMAGE=//p' "$1" 2>/dev/null)
}
mapfile -t missing_imgs < <(missing_isos "${B}/MANIFEST" /rmm/api/ulrmm/ulrmm/private/iso)
write_repo_settings
ensure_nats_password
# the backup's REDIS_PASSWORD, or a new one
ensure_redis_password || lib_die "could not set the redis password."
ensure_enroll_key
ensure_field_keys
ensure_token_pepper
GIT_TOKEN=''
install_natsapi

lib_info "Restoring the database"
pg_create_db ulrmm "$db_user" "$db_pw" || lib_die "could not create the ulrmm database."
load_dump "$db_dump" ulrmm "$db_user" "$db_pw" || lib_die "loading the ulrmm database failed."

libs=(libpango-1.0-0 libpangoft2-1.0-0)
[ "$os_id" = ubuntu ] && libs+=(libharfbuzz0b)
if [ "$(dpkg -l "${libs[@]}" 2>/dev/null | grep -c '^ii')" -lt ${#libs[@]} ]; then
  sudo apt install -y "${libs[@]}"
fi

lib_info "Creating the Python environment"
python3.12 -m venv /rmm/api/env || lib_die "python3.12 -m venv failed."
venv_pip() { /rmm/api/env/bin/pip install --no-cache-dir "$@"; }
venv_pip pip==25.1 &&
  venv_pip "setuptools==$(settings_ver SETUPTOOLS_VER)" "wheel==$(settings_ver WHEEL_VER)" &&
  venv_pip -r /rmm/api/ulrmm/requirements.txt ||
  lib_die "pip install into /rmm/api/env failed."

manage() { (cd /rmm/api/ulrmm && /rmm/api/env/bin/python manage.py "$@"); }
manage migrate || lib_die "manage.py migrate failed."
manage generate_json_schemas
manage collectstatic --no-input || lib_die "manage.py collectstatic failed."
manage create_natsapi_conf || lib_die "manage.py create_natsapi_conf failed."
manage create_uwsgi_conf || lib_die "manage.py create_uwsgi_conf failed."
ensure_agent_ca --reset-certs-if-new || lib_die "manage.py ensure_agent_ca failed, nginx needs ${AGENT_CA_DIR}/ca.pem."
if [ "$agent_ca_restored" != true ]; then
  lib_warn "The backup has no agent CA: a new one was made, every agent certificate is revoked and the mTLS mode is optional. Agents keep working with their tokens."
fi
manage reload_nats
manage post_update_tasks
# agents may hold a pin set newer than the backup and accept only a higher seq
manage pinset_bump || lib_warn "manage.py pinset_bump failed: agents that stored a pin set newer than this backup ignore pin updates until it runs. Run it again once the server certificate chain is readable."
# agents hold tokens newer than the backup; each may fetch one new token family with its identity key within 24 h
manage open_release_window --all-active || lib_warn "manage.py open_release_window failed: agents whose tokens are newer than this backup cannot log in to REST. Run manage.py open_release_window --all-active."
API=$(manage get_config api)
FRONTEND=$(manage get_config webdomain)
MESHDOMAIN=$(manage get_config meshdomain)
CERT_PUB_KEY=$(manage get_config certfile)
CERT_PRIV_KEY=$(manage get_config keyfile)
for v in API FRONTEND MESHDOMAIN; do
  if [ -z "${!v}" ]; then
    lib_warn "WARNING: manage.py get_config returned no ${v} (no core settings in the restored database?), the nginx sites will not load."
  elif ! valid_name "${!v}"; then
    lib_die "${v} '${!v}' from the restored settings is not a host name."
  fi
done

# the certificate the old server's nginx used, when it came back with the backup
nginx_path() {
  [ -f "${B}/nginx/rmm.conf" ] || return 0
  awk -v k="$1" '$1==k {sub(/;$/, "", $2); print $2; exit}' "${B}/nginx/rmm.conf"
}
old_cert=$(nginx_path ssl_certificate)
old_key=$(nginx_path ssl_certificate_key)
if [[ $old_cert =~ ^/[A-Za-z0-9._/@+-]+$ && $old_key =~ ^/[A-Za-z0-9._/@+-]+$ ]] &&
  sudo test -f "$old_cert" && sudo test -f "$old_key"; then
  CERT_PUB_KEY=$old_cert
  CERT_PRIV_KEY=$old_key
fi

if grep -q manage_etc_hosts /etc/hosts 2>/dev/null; then
  sudo sed -i '/manage_etc_hosts: true/d' /etc/cloud/cloud.cfg
  if ! grep -q 'manage_etc_hosts: false' /etc/cloud/cloud.cfg; then
    echo 'manage_etc_hosts: false' | sudo tee -a /etc/cloud/cloud.cfg >/dev/null
  fi
  sudo systemctl restart cloud-init
fi

mesh_nginx_conf "$MESHDOMAIN" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" | sudo tee /etc/nginx/sites-available/meshcentral.conf >/dev/null
frontend_nginx_conf "$FRONTEND" "$API" "$MESHDOMAIN" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" |
  sudo tee /etc/nginx/sites-available/frontend.conf >/dev/null
sudo ln -sf /etc/nginx/sites-available/meshcentral.conf /etc/nginx/sites-enabled/meshcentral.conf
sudo ln -sf /etc/nginx/sites-available/frontend.conf /etc/nginx/sites-enabled/frontend.conf

backup_conf=false
if [ -f "${B}/rmm/backup.conf" ]; then
  sudo install -d -m 0700 -o "$USER" -g "$(id -gn)" /rmmbackups
  install -m 600 "${B}/rmm/backup.conf" /rmmbackups/backup.conf && backup_conf=true
fi
restored_rustdesk=false
if grep -qE '^RUSTDESK_SERVER[[:space:]]*=[[:space:]]*True([[:space:]#]|$)' "$local_settings"; then
  restored_rustdesk=true
fi
rustdesk_id_host=$(ls_get RUSTDESK_HOST)
lib_cleanup

rmm_nginx_conf "$API" "$FRONTEND" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" | sudo tee /etc/nginx/sites-available/rmm.conf >/dev/null
sudo ln -sf /etc/nginx/sites-available/rmm.conf /etc/nginx/sites-enabled/rmm.conf

line=$(grep -m1 -E '^127\.0\.1\.1[[:space:]]' /etc/hosts)
missing=()
for name in "$API" "$FRONTEND" "$MESHDOMAIN"; do
  valid_name "$name" || continue
  printf '%s\n' "$line" | tr -s ' \t' '\n\n' | grep -qxF "$name" || missing+=("$name")
done
if [ ${#missing[@]} -gt 0 ]; then
  if [ -n "$line" ]; then
    sudo sed -i -E "0,/^127\.0\.1\.1[[:space:]]/ s/^(127\.0\.1\.1[[:space:]].*)\$/\\1 ${missing[*]}/" /etc/hosts
  else
    echo "127.0.1.1 ${missing[*]}" | sudo tee -a /etc/hosts >/dev/null
  fi
fi

sudo systemctl enable nats.service
sudo systemctl start nats.service

lib_info "Building the dashboard"
web_ok=false
if build_web && deploy_web "$API"; then
  web_ok=true
fi

sudo chown -R "$ME" /rmm /var/log/celery /etc/conf.d
for d in "${HOME}/.npm" "${HOME}/.config" "${HOME}/.cache"; do
  [ -d "$d" ] && sudo chown -R "$ME" "$d"
done

if [ "$skip_agent_build" = true ]; then
  agents_state='skipped (--skip-agent-build)'
elif build_agents_step; then
  agents_state="built into ${AGENT_ROOT}/dist"
else
  agents_state='FAILED, see above'
fi

if [ -n "$rustdesk_host" ]; then
  rustdesk_step "$rustdesk_host"
elif [ "$restored_rustdesk" = true ]; then
  if [ "$rustdesk_keys" = true ]; then
    lib_warn "The backup had a RustDesk server; its key pair is back in /opt/rustdesk, the server itself is not installed yet."
  else
    lib_warn "The backup had a RustDesk server but no key pair: a new server gets new keys and every client has to be pinned again."
  fi
  lib_warn "Install it with: bash /rmm/riddix/rustdesk/install-rustdesk-server.sh --host ${rustdesk_id_host:-$API}"
fi

lib_info "Starting the services"
for s in celery.service celerybeat.service rmm.service daphne.service nats-api.service nginx; do
  sudo systemctl enable "$s"
  sudo systemctl stop "$s"
  sudo systemctl start "$s"
done
sleep 5

mesh_cfg=/meshcentral/meshcentral-data/config.json
tmp=$(mktemp)
if jq '.settings |= (reduce ("compression", "wsCompression", "agentWsCompression") as $n (.;
      [keys[] | select(ascii_downcase == ($n | ascii_downcase))] as $m
      | if ($m | length) == 0 then .[$n] = false else reduce $m[] as $k (.; .[$k] = false) end))' \
  "$mesh_cfg" >"$tmp" && [ -s "$tmp" ] && ! jq -e --slurpfile n "$tmp" '. == $n[0]' "$mesh_cfg" >/dev/null; then
  cp "$mesh_cfg" ~/"meshcfg-$(date "+%Y%m%dT%H%M%S").bak"
  cat "$tmp" >"$mesh_cfg"
fi
rm -f "$tmp"
harden_mesh
harden_logs
sudo systemctl enable meshcentral
sudo systemctl start meshcentral

if [ "$backup_conf" = true ]; then
  lib_info "Backup settings restored to /rmmbackups/backup.conf"
fi
firewall_state='not loaded, see above'
firewall_step
case $? in
0) firewall_state='nftables table inet ulrmm (riddix/scripts/firewall.sh)' ;;
2) firewall_state='off (FIREWALL=off in /etc/ulrmm/firewall.conf)' ;;
esac

if /rmm/backup.sh --schedule; then
  backups_state='scheduled from /rmmbackups/backup.conf, see crontab -l'
else
  backups_state='NOT scheduled, run: /rmm/backup.sh --schedule'
fi

down=$(services_down)
echo
if [ -n "$down" ] || [ "$web_ok" != true ] || [ "$agents_state" = 'FAILED, see above' ]; then
  printf '%b%s%b\n' "$RED" "UniversalLocal RMM ${TARGET_VERSION} restore finished with errors, see below." "$NC"
else
  printf '%b%s%b\n' "$GREEN" "UniversalLocal RMM ${TARGET_VERSION} restore complete!" "$NC"
fi
echo
echo "Access your rmm at: https://${FRONTEND}"
echo "Code: ${GIT_URL} ${GIT_BRANCH} ($(git -C /rmm rev-parse --short=8 HEAD))"
echo "Frontend: ${WEB_GIT_URL} ${WEB_GIT_BRANCH} (${WEB_COMMIT:0:8})"
echo "Agents: ${agents_state}"
echo "Backups: ${backups_state}"
echo "Firewall: ${firewall_state}"
natsapi_summary
if [ -z "$down" ]; then
  echo "Services: all running"
else
  printf '%b%s%b\n' "$RED" "Services: ${down} not running, see sudo journalctl -u <name>" "$NC"
fi
if [ "$web_ok" != true ]; then
  printf '%b%s%b\n' "$RED" "The dashboard was not built. Fix the cause above, then run: bash /rmm/update.sh --force" "$NC"
fi
if [ ${#missing_pkgs[@]} -gt 0 ]; then
  lib_warn "Software packages above 1 GiB are not in this backup (backup.sh --with-large-packages takes them along)."
  lib_warn "The software catalog marks them as missing, upload them again there:"
  for p in "${missing_pkgs[@]}"; do
    lib_warn "  ${p}"
  done
fi
if [ ${#missing_imgs[@]} -gt 0 ]; then
  lib_warn "ISO images are not in this backup (backup.sh --with-large-packages takes them along)."
  lib_warn "Copy them into /rmm/api/ulrmm/ulrmm/private/iso again under the same name:"
  for p in "${missing_imgs[@]}"; do
    lib_warn "  ${p}"
  done
fi
exit 0

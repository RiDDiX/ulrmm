#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Fresh install of a UniversalLocal RMM server.
# Run from a clone of the server repository as a normal user with sudo:
#
#   bash ulrmm/install.sh [options]        (--help lists them)

SCRIPT_VERSION="104"

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ ! -f "${SELF_DIR}/riddix/scripts/install_lib.sh" ]; then
  printf '%b%s%b\n' "$RED" "install.sh has to run from a clone of the server repository:" "$NC"
  printf '%b%s%b\n' "$RED" "  git clone https://github.com/RiDDiX/ulrmm.git && bash ulrmm/install.sh" "$NC"
  exit 1
fi

local_settings='/rmm/api/ulrmm/ulrmm/local_settings.py'
SCRIPTS_DIR='/opt/ulrmm-community-scripts'
SETTINGS_PY='/rmm/api/ulrmm/ulrmm/settings.py'
non_interactive=false
skip_agent_build=false
arg_source='' arg_git_base='' arg_server_repo='' arg_web_repo='' arg_agent_repo=''
arg_branch='' arg_web_branch='' arg_agent_branch='' arg_git_user='' arg_token=''
arg_token_file='' arg_scripts_git_url=''
backenddomain='' frontenddomain='' meshdomain='' rootdomain='' letsemail=''
insecure=false use_own_cert=false own_cert='' own_key=''
djangousername='' admin_password_file='' rustdesk_host=''

# shellcheck source=riddix/scripts/install_lib.sh
. "${SELF_DIR}/riddix/scripts/install_lib.sh"

export DEBIAN_FRONTEND=noninteractive

usage() {
  cat <<'EOF'
usage: bash install.sh [options]

  --source github|gitea         git base (default github)
  --git-base URL                any other git base, replaces --source
  --server-repo NAME            server repository (default ulrmm)
  --web-repo NAME               dashboard repository (default <server-repo>-web)
  --agent-repo NAME             agent repository (default ulrmm-agent)
  --branch NAME                 branch of all three (default main)
  --web-branch NAME             dashboard branch
  --agent-branch NAME           agent branch or tag
  --git-user NAME               user name for the token (default git)
  --token TOKEN                 read token for private repositories
  --token-file PATH             the same from a file (/dev/stdin works)
  --scripts-git-url URL         script library (default <git base>/ulrmm-scripts.git)
  --backend-domain NAME         API name, e.g. api.example.com
  --frontend-domain NAME        dashboard name, e.g. rmm.example.com
  --mesh-domain NAME            MeshCentral name, e.g. mesh.example.com
  --root-domain NAME            e.g. example.com
  --email ADDRESS               for Django, MeshCentral and Let's Encrypt
  --insecure                    self-signed certificate
  --use-own-cert                your own certificate (with --cert and --key)
  --cert PATH, --key PATH       fullchain and private key
  --admin-user NAME             first dashboard user
  --admin-password-file PATH    its password, read from a file
  --skip-agent-build            do not build the agents now
  --rustdesk HOST               also install the RustDesk server for HOST
  --non-interactive             never ask
  -h, --help                    this list

Every --option value also works as --option=value.
EOF
}

# --opt=value -> --opt value
split_args=()
for a in "$@"; do
  case "$a" in
  --*=*) split_args+=("${a%%=*}" "${a#*=}") ;;
  *) split_args+=("$a") ;;
  esac
done
set -- "${split_args[@]}"

need_value() {
  [ "$2" -ge 2 ] || lib_die "$1 needs a value."
}

while [ $# -gt 0 ]; do
  case "$1" in
  -h | --help)
    usage
    exit 0
    ;;
  --insecure) insecure=true ;;
  --use-own-cert) use_own_cert=true ;;
  --skip-agent-build) skip_agent_build=true ;;
  --non-interactive) non_interactive=true ;;
  --source | --git-base | --server-repo | --web-repo | --agent-repo | --branch | --web-branch | \
    --agent-branch | --git-user | --token | --token-file | --scripts-git-url | --backend-domain | \
    --frontend-domain | --mesh-domain | --root-domain | --email | --cert | --key | --admin-user | \
    --admin-password-file | --rustdesk)
    need_value "$1" $#
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
    --backend-domain) backenddomain=$2 ;;
    --frontend-domain) frontenddomain=$2 ;;
    --mesh-domain) meshdomain=$2 ;;
    --root-domain) rootdomain=$2 ;;
    --email) letsemail=$2 ;;
    --cert) own_cert=$2 use_own_cert=true ;;
    --key) own_key=$2 use_own_cert=true ;;
    --admin-user) djangousername=$2 ;;
    --admin-password-file) admin_password_file=$2 ;;
    --rustdesk) rustdesk_host=$2 ;;
    esac
    shift
    ;;
  *)
    usage >&2
    lib_die "unknown option $1"
    ;;
  esac
  shift
done

# names end up in nginx configs, /etc/hosts and local_settings.py
valid_name() { [[ $1 =~ ^[A-Za-z0-9.-]+$ ]]; }
sub_domain_ok() { valid_name "$1" && [[ $1 == *.*.* ]]; }
root_domain_ok() { valid_name "$1" && [[ $1 == *.* ]]; }
email_ok() { [[ $1 == *@*.* ]] && ! unsafe_value "$1"; }
admin_user_ok() { [[ $1 =~ ^[A-Za-z0-9@.+_-]{1,150}$ ]]; }

if [ -n "$rustdesk_host" ] && ! valid_name "$rustdesk_host"; then
  lib_die "--rustdesk must be a host name or IP address, not '${rustdesk_host}'."
fi
if [ -n "$djangousername" ] && ! admin_user_ok "$djangousername"; then
  lib_die "--admin-user may only contain letters, digits and @ . + - _ (at most 150)."
fi
for v in backenddomain frontenddomain meshdomain; do
  if [ -n "${!v}" ] && ! sub_domain_ok "${!v}"; then
    lib_die "'${!v}' is not a subdomain like api.example.com."
  fi
done
if [ -n "$rootdomain" ] && ! root_domain_ok "$rootdomain"; then
  lib_die "'${rootdomain}' is not a domain like example.com."
fi
if [ -n "$letsemail" ] && ! email_ok "$letsemail"; then
  lib_die "'${letsemail}' is not an e-mail address."
fi

if [ "$non_interactive" = true ]; then
  missing=()
  sub_domain_ok "$backenddomain" || missing+=(--backend-domain)
  sub_domain_ok "$frontenddomain" || missing+=(--frontend-domain)
  sub_domain_ok "$meshdomain" || missing+=(--mesh-domain)
  root_domain_ok "$rootdomain" || missing+=(--root-domain)
  email_ok "$letsemail" || missing+=(--email)
  admin_user_ok "$djangousername" || missing+=(--admin-user)
  [ -n "$admin_password_file" ] && [ -r "$admin_password_file" ] || missing+=(--admin-password-file)
  if [ "$insecure" != true ]; then
    if [ "$use_own_cert" != true ]; then
      missing+=("--insecure or --use-own-cert")
    else
      [ -f "$own_cert" ] || missing+=(--cert)
      [ -f "$own_key" ] || missing+=(--key)
    fi
  fi
  if [ ${#missing[@]} -gt 0 ]; then
    lib_die "--non-interactive needs valid: ${missing[*]}"
  fi
fi

lib_info "Installing the base packages"
sudo apt update
sudo apt install -y curl wget jq dirmngr gnupg lsb-release ca-certificates git openssl ||
  lib_die "apt install of the base packages failed."
ensure_age || lib_die "apt install age failed."
# gone from Debian 13, nothing here needs it
if apt-cache show software-properties-common >/dev/null 2>&1; then
  sudo apt install -y software-properties-common
fi

# host checks

[ "$(systemd-detect-virt 2>/dev/null)" != lxc ] || lib_die "LXC is not supported, use a VM instead."
[ ! -d /rmm/api ] || lib_die "Existing UniversalLocal RMM installation found. install.sh runs on a fresh server only."
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

deb_arch=$(dpkg --print-architecture)
pgdg_line="deb [arch=${deb_arch} signed-by=/etc/apt/keyrings/postgresql-archive-keyring.gpg] https://apt.postgresql.org/pub/repos/apt/ ${codename}-pgdg main"
sudo systemctl restart systemd-journald

# secrets

rand() { # length, tr set
  local out=''
  while [ ${#out} -lt "$1" ]; do
    out+=$(head -c 512 /dev/urandom | LC_ALL=C tr -dc "$2")
  done
  printf '%s' "${out:0:$1}"
}
SECRET_KEY=$(rand 80 'a-zA-Z0-9')
ADMIN_URL=$(rand 70 'a-zA-Z0-9')
MESHPASSWD=$(rand 25 'a-zA-Z0-9')
pgusername=$(rand 8 'a-z')
pgpw=$(rand 20 'a-zA-Z0-9')
meshusername=$(rand 8 'a-z')
MESHPGUSER=$(rand 8 'a-z')
MESHPGPWD=$(rand 20 'a-zA-Z0-9')

# repositories, before anything on the host changes

lib_info "UniversalLocal RMM install (install.sh ${SCRIPT_VERSION})"
resolve_repos
repo_preflight install.sh riddix/scripts/install_lib.sh riddix/scripts/go_toolchain.sh go.mod go.sum
natsapi_prefetch "$SELF_DIR"

# questions

prompt_until() { # variable, prompt, check function
  local v
  while ! "$3" "${!1}"; do
    printf >&2 '%b%s%b: ' "$YELLOW" "$2" "$NC"
    read -r v
    printf -v "$1" '%s' "$v"
  done
}
prompt_until backenddomain "Backend subdomain (e.g. api.example.com)" sub_domain_ok
prompt_until frontenddomain "Frontend subdomain (e.g. rmm.example.com)" sub_domain_ok
prompt_until meshdomain "MeshCentral subdomain (e.g. mesh.example.com)" sub_domain_ok
prompt_until rootdomain "Root domain (e.g. example.com)" root_domain_ok
prompt_until letsemail "E-mail address" email_ok

if [ "$non_interactive" != true ] && [ -z "$rustdesk_host" ]; then
  while :; do
    rustdesk_host=$(ask "RustDesk server host (blank: no RustDesk server)" "")
    [ -z "$rustdesk_host" ] || valid_name "$rustdesk_host" && break
    lib_warn "'${rustdesk_host}' is not a host name or IP address."
  done
fi

if [ "$use_own_cert" = true ]; then
  while [ ! -f "$own_cert" ]; do
    [ "$non_interactive" != true ] || lib_die "--cert ${own_cert} does not exist."
    read -rp "Path to the certificate (fullchain.pem): " own_cert
  done
  while [ ! -f "$own_key" ]; do
    [ "$non_interactive" != true ] || lib_die "--key ${own_key} does not exist."
    read -rp "Path to the private key (privkey.pem): " own_key
  done
  openssl x509 -noout -in "$own_cert" 2>/dev/null || lib_die "${own_cert} is not a PEM certificate."
fi

# host

fix_cloud_init() {
  if grep -q manage_etc_hosts /etc/hosts 2>/dev/null; then
    sudo sed -i '/manage_etc_hosts: true/d' /etc/cloud/cloud.cfg
    if ! grep -q 'manage_etc_hosts: false' /etc/cloud/cloud.cfg; then
      echo 'manage_etc_hosts: false' | sudo tee -a /etc/cloud/cloud.cfg >/dev/null
    fi
    sudo systemctl restart cloud-init
  fi
}

# the three names on the 127.0.1.1 line, each once
add_hosts() {
  local line name missing=()
  line=$(grep -m1 -E '^127\.0\.1\.1[[:space:]]' /etc/hosts)
  for name in "$@"; do
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

fix_cloud_init
add_hosts "$backenddomain" "$frontenddomain" "$meshdomain"

BEHIND_NAT=false
first_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}')
if [[ $first_ip =~ ^10\. || $first_ip =~ ^172\.(1[6-9]|2[0-9]|3[01])\. || $first_ip =~ ^192\.168\. ]]; then
  BEHIND_NAT=true
fi

ME="${USER}:$(id -gn)"

if [ "$insecure" = true ]; then
  CERT_PRIV_KEY=/etc/ssl/ulrmm/key.pem
  CERT_PUB_KEY=/etc/ssl/ulrmm/cert.pem
  sudo mkdir -p /etc/ssl/ulrmm
  sudo chown "$ME" /etc/ssl/ulrmm
  sudo chmod 770 /etc/ssl/ulrmm
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CERT_PRIV_KEY" -out "$CERT_PUB_KEY" -subj "/CN=${rootdomain}" \
    -addext "subjectAltName=DNS:${rootdomain},DNS:*.${rootdomain}" ||
    lib_die "could not create the self-signed certificate."
elif [ "$use_own_cert" = true ]; then
  CERT_PRIV_KEY=$own_key
  CERT_PUB_KEY=$own_cert
  sudo chown "$ME" "$CERT_PUB_KEY" "$CERT_PRIV_KEY"
else
  sudo apt install -y certbot || lib_die "apt install certbot failed."
  lib_info "Let's Encrypt asks for a DNS TXT record for *.${rootdomain} now."
  until sudo certbot certonly --manual -d "*.${rootdomain}" --agree-tos --no-bootstrap \
    --preferred-challenges dns -m "$letsemail" --no-eff-email; do
    lib_warn "certbot failed, trying again."
  done
  CERT_PRIV_KEY="/etc/letsencrypt/live/${rootdomain}/privkey.pem"
  CERT_PUB_KEY="/etc/letsencrypt/live/${rootdomain}/fullchain.pem"
fi
if [ -d /etc/letsencrypt ]; then
  sudo chown -R "$ME" /etc/letsencrypt
fi

sudo mkdir -p /etc/apt/keyrings


lib_info "Installing nginx"
curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/nginx-archive-keyring.gpg ||
  lib_die "could not fetch the nginx signing key."
echo "deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${os_id} ${codename} nginx" |
  sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null
sudo apt update
sudo apt install -y nginx || lib_die "apt install nginx failed."
sudo systemctl stop nginx
nginx_conf_text | sudo tee /etc/nginx/nginx.conf >/dev/null
sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

lib_info "Installing NodeJS"
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg ||
  lib_die "could not fetch the NodeSource signing key."
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" |
  sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
sudo apt update
sudo apt install -y gcc g++ make || lib_die "apt install gcc g++ make failed."
sudo apt install -y nodejs || lib_die "apt install nodejs failed."
sudo npm install -g npm

install_python
sudo apt install -y redis git || lib_die "apt install redis failed."
start_redis

lib_info "Installing PostgreSQL 18"
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo gpg --dearmor --yes -o /etc/apt/keyrings/postgresql-archive-keyring.gpg ||
  lib_die "could not fetch the PostgreSQL signing key."
echo "$pgdg_line" | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
sudo apt update
sudo apt install -y postgresql-18 || lib_die "apt install postgresql-18 failed."
sudo systemctl enable --now postgresql
for _ in $(seq 1 60); do
  pg_isready -q && break
  sleep 1
done
pg_isready -q || lib_die "PostgreSQL does not answer."
pg_create_db ulrmm "$pgusername" "$pgpw" || lib_die "could not create the ulrmm database."
pg_create_db meshcentral "$MESHPGUSER" "$MESHPGPWD" || lib_die "could not create the meshcentral database."

sudo mkdir -p /var/log/celery
sudo chown "$ME" /var/log/celery
clone_repos

settings_ver() { # NAME [settings.py]
  grep "^${1}" "${2:-$SETTINGS_PY}" | awk -F'[= "]' '{print $5}'
}

install_nats_server "$(settings_ver NATS_SERVER_VER)"

lib_info "Installing MeshCentral"
MESH_VER=$(settings_ver MESH_VER)
sudo mkdir -p /meshcentral/meshcentral-data
sudo chown -R "$ME" /meshcentral
mesh_package_json() {
  printf '{"dependencies": {"archiver": "7.0.1", "meshcentral": "%s", "otplib": "13.4.1", "pg": "8.16.3"}}\n' "$1"
}
mesh_package_json "$MESH_VER" >/meshcentral/package.json
jq -n --arg mesh "$meshdomain" --arg user "$MESHPGUSER" --arg pw "$MESHPGPWD" '{
  settings: {
    cert: $mesh, WANonly: true, minify: 1, port: 4430, portBind: "127.0.0.1", aliasPort: 443,
    redirPort: 800, redirPortBind: "127.0.0.1", mpsPort: 0, allowLoginToken: true, allowFraming: true,
    agentPing: 35, allowHighQualityDesktop: true, tlsOffload: "127.0.0.1", agentCoreDump: false,
    compression: false, wsCompression: false, agentWsCompression: false,
    maxInvalidLogin: {time: 5, count: 5, coolofftime: 30}, autoBackup: false,
    postgres: {user: $user, password: $pw, port: "5432", host: "localhost"}
  },
  domains: {
    "": {
      title: "UniversalLocal RMM", title2: "UniversalLocal RMM", newAccounts: false,
      certUrl: ("https://" + $mesh + ":443/"), geoLocation: false, cookieIpCheck: false, mstsc: true
    }
  }
}' >/meshcentral/meshcentral-data/config.json || lib_die "could not write the MeshCentral config."
harden_mesh
(cd /meshcentral && npm install) || lib_die "npm install of MeshCentral failed."

# backend

lib_info "Writing ${local_settings}"
install -m 600 /dev/null "$local_settings" || lib_die "cannot create ${local_settings}."
cat >>"$local_settings" <<EOF
SECRET_KEY = "${SECRET_KEY}"
DEBUG = False
ALLOWED_HOSTS = ['${backenddomain}']
ADMIN_URL = "${ADMIN_URL}/"
CORS_ORIGIN_WHITELIST = ["https://${frontenddomain}"]

DATABASES = {
    "default": dict(
        ENGINE="django.db.backends.postgresql",
        HOST="localhost",
        PORT="5432",
        NAME="ulrmm",
        USER="${pgusername}",
        PASSWORD="${pgpw}",
    )
}

MESH_USERNAME = "${meshusername}"
MESH_SITE = "https://${meshdomain}"
ADMIN_ENABLED = False
EOF
if [ "$insecure" = true ]; then
  echo "ULRMM_INSECURE = True" >>"$local_settings"
fi
if [ "$insecure" = true ] || [ "$use_own_cert" = true ]; then
  ls_set CERT_FILE "$CERT_PUB_KEY"
  ls_set KEY_FILE "$CERT_PRIV_KEY"
fi
write_repo_settings
ls_set ULRMM_AGENT_PUBIP_URL "https://${backenddomain}/pubip"
ensure_nats_password
ensure_redis_password || lib_die "could not set the redis password."
ensure_enroll_key
ensure_field_keys
ensure_token_pepper
# from here on only build_agents.sh needs the token, it reads local_settings.py
GIT_TOKEN=''

install_natsapi

weasyprint_libs() {
  local libs=(libpango-1.0-0 libpangoft2-1.0-0)
  [ "$os_id" = ubuntu ] && libs+=(libharfbuzz0b)
  if [ "$(dpkg -l "${libs[@]}" 2>/dev/null | grep -c '^ii')" -lt ${#libs[@]} ]; then
    sudo apt install -y "${libs[@]}"
  fi
}
weasyprint_libs

sudo mkdir -p /opt/ulrmm-reporting/assets
sudo chown -R "$ME" /opt/ulrmm-reporting

lib_info "Creating the Python environment"
python3.12 -m venv /rmm/api/env || lib_die "python3.12 -m venv failed."
venv_pip() { /rmm/api/env/bin/pip install --no-cache-dir "$@"; }
venv_pip pip==25.1 &&
  venv_pip "setuptools==$(settings_ver SETUPTOOLS_VER)" "wheel==$(settings_ver WHEEL_VER)" &&
  venv_pip -r /rmm/api/ulrmm/requirements.txt ||
  lib_die "pip install into /rmm/api/env failed."

manage() { (cd /rmm/api/ulrmm && /rmm/api/env/bin/python manage.py "$@"); }

# the admin app's tables and static files exist on every install; the admin
# itself is off, and no service runs while this is True
set_admin() { sed -i -E "s/^ADMIN_ENABLED = (True|False)\$/ADMIN_ENABLED = $1/" "$local_settings"; }
trap 'askpass_cleanup; set_admin False' EXIT
set_admin True
manage migrate || lib_die "manage.py migrate failed."
manage generate_json_schemas
manage collectstatic --no-input || lib_die "manage.py collectstatic failed."
set_admin False
manage create_natsapi_conf || lib_die "manage.py create_natsapi_conf failed."
manage create_uwsgi_conf || lib_die "manage.py create_uwsgi_conf failed."
# shellcheck disable=SC2119 # a fresh install has no certificates to revoke
ensure_agent_ca || lib_die "manage.py ensure_agent_ca failed, nginx needs ${AGENT_CA_DIR}/ca.pem."
manage load_chocos
manage load_community_scripts

cred_file="${HOME}/ulrmm-install-credentials.txt"
(umask 077 && : >"$cred_file")

if [ -n "$admin_password_file" ]; then
  DJANGO_SUPERUSER_PASSWORD=$(<"$admin_password_file") manage createsuperuser --noinput \
    --username "$djangousername" --email "$letsemail" ||
    lib_die "manage.py createsuperuser failed."
else
  prompt_until djangousername "Username for the first dashboard user" admin_user_ok
  manage createsuperuser --username "$djangousername" --email "$letsemail" ||
    lib_die "manage.py createsuperuser failed."
fi
manage create_installer_user
RANDBASE=$(manage generate_totp)
if [ "$non_interactive" = true ]; then
  {
    echo "Two-factor setup for ${djangousername}:"
    manage generate_barcode "$RANDBASE" "$djangousername" "$frontenddomain"
  } >>"$cred_file"
else
  clear
  manage generate_barcode "$RANDBASE" "$djangousername" "$frontenddomain"
  echo
  lib_warn "Scan the QR code with your authenticator app now, it is not shown again."
  read -rn 1 -p "Press any key to continue..."
  echo
fi

write_units || lib_die "could not write the systemd units."
rmm_nginx_conf "$backenddomain" "$frontenddomain" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" |
  sudo tee /etc/nginx/sites-available/rmm.conf >/dev/null
mesh_nginx_conf "$meshdomain" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" |
  sudo tee /etc/nginx/sites-available/meshcentral.conf >/dev/null
sudo ln -sf /etc/nginx/sites-available/rmm.conf /etc/nginx/sites-enabled/rmm.conf
sudo ln -sf /etc/nginx/sites-available/meshcentral.conf /etc/nginx/sites-enabled/meshcentral.conf
sudo chown -R "$ME" /etc/conf.d/
unit_text meshcentral | sudo tee /etc/systemd/system/meshcentral.service >/dev/null
harden_logs
sudo systemctl daemon-reload
for d in "${HOME}/.npm" "${HOME}/.config"; do
  [ -d "$d" ] && sudo chown -R "$ME" "$d"
done

lib_info "Building the dashboard"
web_ok=false
if build_web && deploy_web "$backenddomain"; then
  web_ok=true
fi
frontend_nginx_conf "$frontenddomain" "$backenddomain" "$meshdomain" "$CERT_PUB_KEY" "$CERT_PRIV_KEY" |
  sudo tee /etc/nginx/sites-available/frontend.conf >/dev/null
sudo ln -sf /etc/nginx/sites-available/frontend.conf /etc/nginx/sites-enabled/frontend.conf

lib_info "Starting the services"
for s in rmm.service daphne.service celery.service celerybeat.service nginx; do
  sudo systemctl enable "$s"
  sudo systemctl stop "$s"
  sudo systemctl start "$s"
done
sleep 5

# only the log of the current start counts, an earlier start already wrote the line
wait_for_mesh() {
  local i inv
  inv=$(sudo systemctl show -p InvocationID --value meshcentral.service)
  for i in $(seq 1 120); do
    if sudo journalctl _SYSTEMD_INVOCATION_ID="$inv" --no-pager 2>/dev/null | grep -q 'MeshCentral HTTP server running on port'; then
      return 0
    fi
    [ "$i" -eq 1 ] && lib_info "Waiting for MeshCentral to start..."
    sleep 5
  done
  lib_die "MeshCentral did not start within 10 minutes, see sudo journalctl -u meshcentral."
}
sudo systemctl enable meshcentral
sudo systemctl restart meshcentral.service
wait_for_mesh

mesh_token_key=$(cd /meshcentral && node node_modules/meshcentral --logintokenkey)
ls_set MESH_TOKEN_KEY "$mesh_token_key"

sudo systemctl stop meshcentral
(cd /meshcentral && node node_modules/meshcentral --createaccount "$meshusername" --pass "$MESHPASSWD" --email "$letsemail")
(cd /meshcentral && node node_modules/meshcentral --adminaccount "$meshusername")
sudo systemctl start meshcentral
wait_for_mesh
(cd /meshcentral && node node_modules/meshcentral/meshctrl.js --url "wss://${meshdomain}:443" \
  --loginuser "$meshusername" --loginpass "$MESHPASSWD" AddDeviceGroup --name UniversalLocalRMM)

sudo systemctl enable nats.service
manage initial_db_setup
manage reload_nats
manage sync_mesh_with_rmm
sudo systemctl start nats.service
sleep 1
sudo systemctl enable nats-api.service
sudo systemctl start nats-api.service

set_admin False

if [ "$skip_agent_build" = true ]; then
  agents_state='skipped (--skip-agent-build)'
elif build_agents_step; then
  agents_state="built into ${AGENT_ROOT}/dist"
else
  agents_state='FAILED, see above'
fi

if [ -n "$rustdesk_host" ]; then
  rustdesk_step "$rustdesk_host"
fi

for s in rmm daphne celery celerybeat; do
  sudo systemctl stop "$s"
  sudo systemctl start "$s"
done

{
  echo "MeshCentral username: ${meshusername}"
  echo "MeshCentral password: ${MESHPASSWD}"
} >>"$cred_file"

firewall_state='not loaded, see above'
firewall_step
case $? in
0) firewall_state='nftables table inet ulrmm (riddix/scripts/firewall.sh)' ;;
2) firewall_state='off (FIREWALL=off in /etc/ulrmm/firewall.conf)' ;;
esac

if /rmm/backup.sh --schedule; then
  backups_state='nightly at 00:00 into /rmmbackups'
else
  backups_state='NOT scheduled, run: /rmm/backup.sh --schedule'
fi

# summary

down=$(services_down)
echo
if [ -n "$down" ] || [ "$web_ok" != true ] || [ "$agents_state" = 'FAILED, see above' ]; then
  printf '%b%s%b\n' "$RED" "UniversalLocal RMM ${TARGET_VERSION} installation finished with errors, see below." "$NC"
else
  printf '%b%s%b\n' "$GREEN" "UniversalLocal RMM ${TARGET_VERSION} installation complete!" "$NC"
fi
echo
echo "Access your rmm at: https://${frontenddomain}"
echo "MeshCentral username: ${meshusername}"
echo "MeshCentral password: in ${cred_file} (only ${USER} can read it)"
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
if [ "$BEHIND_NAT" = true ]; then
  echo
  lib_warn "This server has a private address (${first_ip}). If your router does not do hairpin NAT,"
  lib_warn "${backenddomain}, ${frontenddomain} and ${meshdomain} have to resolve to ${first_ip} on your LAN"
  lib_warn "(local DNS or hosts entries), or the dashboard and the agents cannot reach this server from inside."
fi
exit 0

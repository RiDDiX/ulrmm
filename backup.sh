#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Backup of this UniversalLocal RMM server into /rmmbackups.
#
#   /rmm/backup.sh               one backup in /rmmbackups
#   /rmm/backup.sh --pre-update  one backup in /rmmbackups/pre-update (update.sh)
#   /rmm/backup.sh --auto        nightly run from cron, rotated
#   /rmm/backup.sh --schedule    write or remove the cron line (backup.conf)
#   --with-large-packages        also take software package files above 1 GiB
#                                and the images of the ISO builder
#
# With BACKUP_AGE_RECIPIENTS in backup.conf (age1... recipients separated by
# spaces, or the path of a recipients file) the archive is encrypted with age
# to .tar.age; restore.sh --age-identity <key file> reads it.
#
# Run as the install user. restore.sh reads the archive layout written here.

SCRIPT_VERSION="40"

# cron and some sudo setups leave USER unset
USER=${USER:-$(id -un)}
umask 077
set -o pipefail
export DEBIAN_FRONTEND=noninteractive

GREEN='\033[0;32m' YELLOW='\033[1;33m' RED='\033[0;31m' NC='\033[0m'

BACKUP_DIR=/rmmbackups
SUBDIRS=(daily weekly monthly pre-update)
LOCAL_SETTINGS=/rmm/api/ulrmm/ulrmm/local_settings.py
PACKAGES_DIR=/rmm/api/ulrmm/ulrmm/private/packages
LARGE_PACKAGE=$((1024 * 1024 * 1024))
ISO_DIR=/rmm/api/ulrmm/ulrmm/private/iso
# AGENT_CA_DIR of install_lib.sh
AGENT_CA_DIR=/etc/ulrmm/agent-ca
PY=/rmm/api/env/bin/python
MANAGE=/rmm/api/ulrmm/manage.py
CRON_CMD='/rmm/backup.sh --auto'

say() { printf '%b%s%b\n' "$1" "$2" "$NC"; }

if [ "$EUID" -eq 0 ]; then
  say "$RED" "Do NOT run this script as root. Exiting."
  exit 1
fi

mode=manual
want_schedule=false want_auto=false want_pre=false with_large=false
for arg in "$@"; do
  case "$arg" in
  --schedule) want_schedule=true ;;
  --auto) want_auto=true ;;
  --pre-update) want_pre=true ;;
  --with-large-packages) with_large=true ;;
  *) say "$YELLOW" "Ignoring unknown option ${arg}" ;;
  esac
done
if [ "$want_schedule" = true ]; then
  mode=schedule
elif [ "$want_auto" = true ]; then
  mode=auto
elif [ "$want_pre" = true ]; then
  mode=pre-update
fi

# backup.conf is written by the dashboard. Read line by line, never sourced;
# anything unknown or out of range keeps the default.
DAILY_KEEP_DAYS=14
WEEKLY_KEEP_DAYS=60
MONTHLY_KEEP_DAYS=380
PRE_UPDATE_KEEP=5
SCHEDULE_ENABLED=1
SCHEDULE_TIME=00:00
AGE_RECIPIENTS=''
if [ -r "${BACKUP_DIR}/backup.conf" ]; then
  while IFS='=' read -r key value || [ -n "$key" ]; do
    value=${value%$'\r'}
    case "$key" in
    DAILY_KEEP_DAYS | WEEKLY_KEEP_DAYS | MONTHLY_KEEP_DAYS | PRE_UPDATE_KEEP)
      if [[ $value =~ ^[0-9]{1,4}$ ]]; then
        printf -v "$key" '%d' "$((10#$value))"
      fi
      ;;
    SCHEDULE_ENABLED)
      [[ $value =~ ^[01]$ ]] && SCHEDULE_ENABLED=$value
      ;;
    SCHEDULE_TIME)
      [[ $value =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && SCHEDULE_TIME=$value
      ;;
    BACKUP_AGE_RECIPIENTS)
      AGE_RECIPIENTS=$value
      ;;
    esac
  done <"${BACKUP_DIR}/backup.conf"
fi

make_backup_dirs() {
  local d dirs=("$BACKUP_DIR")
  for d in "${SUBDIRS[@]}"; do
    dirs+=("${BACKUP_DIR}/${d}")
  done
  for d in "${dirs[@]}"; do
    [ -d "$d" ] || sudo mkdir -p "$d"
  done
  sudo chown "${USER}:$(id -gn)" "${dirs[@]}"
  sudo chmod 700 "$BACKUP_DIR"
}

schedule() {
  local hour minute current
  if ! sudo -n true 2>/dev/null; then
    echo "Error: Passwordless sudo is required for scheduling."
    exit 1
  fi
  make_backup_dirs
  hour=$((10#${SCHEDULE_TIME%:*}))
  minute=$((10#${SCHEDULE_TIME#*:}))
  current=$(crontab -l 2>/dev/null | grep -vF "$CRON_CMD")
  if [ "$SCHEDULE_ENABLED" = 1 ]; then
    current+="${current:+$'\n'}${minute} ${hour} * * * ${CRON_CMD} > /dev/null 2>&1"
  fi
  printf '%s\n' "$current" | sed '/^$/d' | crontab - || {
    echo "Error: could not write the crontab."
    exit 1
  }
  if [ "$SCHEDULE_ENABLED" = 1 ]; then
    echo "Backups run daily at ${SCHEDULE_TIME} and rotate."
  else
    echo "Scheduled backups are off."
  fi
  exit 0
}

STAGING=''
PART=''
cleanup() {
  [ -n "$STAGING" ] && rm -rf "$STAGING"
  [ -n "$PART" ] && rm -f "$PART"
}
trap cleanup EXIT

fail() {
  say "$RED" "ERROR: $* Backup aborted."
  exit 1
}

# GNU tar exits 1 when a file changed while it was read (live MeshCentral
# data); that is a warning, 2 and up is a failure.
tar_ok() {
  local rc=$1 what=$2
  [ "$rc" -eq 0 ] && return 0
  if [ "$rc" -eq 1 ]; then
    say "$YELLOW" "WARNING: files in ${what} changed while they were read."
    return 0
  fi
  fail "could not archive ${what}."
}

[ "$mode" = schedule ] && schedule

if ! sudo -n true 2>/dev/null; then
  # by hand sudo may ask; cron, update.sh and the dashboard runner cannot
  if ! { [ -t 0 ] && sudo -v; }; then
    say "$RED" "Error: Passwordless sudo is required for backups."
    exit 1
  fi
fi

make_backup_dirs

exec 8>"${BACKUP_DIR}/.backup.lock" || fail "cannot open ${BACKUP_DIR}/.backup.lock."
if ! flock -n 8; then
  say "$RED" "ERROR: another backup is running."
  exit 1
fi

# leftovers of runs that were killed; a running one is newer than a day
for d in "$BACKUP_DIR" "${SUBDIRS[@]/#/${BACKUP_DIR}/}"; do
  find "$d" -maxdepth 1 -type f -name 'rmm-backup-*.part' -mmin +1440 -delete 2>/dev/null
done

# age_args from BACKUP_AGE_RECIPIENTS: a recipients file or age1... keys;
# anything else stops the backup
age_args=()
age_recipients() {
  local r
  [ -n "$AGE_RECIPIENTS" ] || return 0
  if [[ $AGE_RECIPIENTS == /* ]]; then
    [ -r "$AGE_RECIPIENTS" ] || fail "cannot read the age recipients file ${AGE_RECIPIENTS} (BACKUP_AGE_RECIPIENTS)."
    age_args=(-R "$AGE_RECIPIENTS")
    return 0
  fi
  for r in $AGE_RECIPIENTS; do
    [[ $r =~ ^age1[0-9a-z]+$ ]] || fail "BACKUP_AGE_RECIPIENTS: '${r}' is not an age1... recipient or a file path."
    age_args+=(-r "$r")
  done
}
# $1 staging directory, $2 archive; encrypted when age_args is set
write_archive() {
  if [ ${#age_args[@]} -gt 0 ]; then
    tar -cf - -C "$1" . | age -e "${age_args[@]}" -o "$2"
  else
    tar -cf "$2" -C "$1" .
  fi
}
age_recipients
if [ ${#age_args[@]} -gt 0 ] && ! command -v age >/dev/null; then
  sudo apt install -y age || fail "age is missing and could not be installed."
fi

case "$mode" in
auto)
  if [ "$(date +%d)" = 10 ]; then
    out_dir="${BACKUP_DIR}/monthly"
  elif [ "$(date +%u)" = 5 ]; then
    out_dir="${BACKUP_DIR}/weekly"
  else
    out_dir="${BACKUP_DIR}/daily"
  fi
  ;;
pre-update) out_dir="${BACKUP_DIR}/pre-update" ;;
*) out_dir=$BACKUP_DIR ;;
esac

rm -rf /meshcentral/meshcentral-backup/* /meshcentral/meshcentral-backups/* /meshcentral/meshcentral-coredumps/* 2>/dev/null

dt_now=$(date '+%Y_%m_%d__%H_%M_%S')
target="${out_dir}/rmm-backup-${dt_now}.tar"
[ ${#age_args[@]} -eq 0 ] || target+=.age
[ -e "$target" ] && fail "${target} already exists."

STAGING=$(mktemp -d -t ulrmm-XXXXXXXXXXXXXXXXXXXXX) || fail "cannot create a staging directory."
mkdir -p "$STAGING"/{meshcentral,postgres,certs,nginx,systemd,rmm,confd,opt,rustdesk,agent-ca} || fail "cannot create the staging directories."

say "$GREEN" "Backing up the databases"
dbname=$("$PY" "$MANAGE" get_config dbname)
dbuser=$("$PY" "$MANAGE" get_config dbuser)
dbpw=$("$PY" "$MANAGE" get_config dbpw)
if [ -z "$dbname" ] || [ -z "$dbuser" ] || [ -z "$dbpw" ]; then
  fail "manage.py get_config dbname/dbuser/dbpw returned nothing."
fi
PGPASSWORD=$dbpw pg_dump --no-privileges --no-owner -h localhost -p 5432 -U "$dbuser" -d "$dbname" |
  gzip -9 >"${STAGING}/postgres/db-${dt_now}.psql.gz" || fail "pg_dump of ${dbname} failed."

if ! command -v jq >/dev/null; then
  sudo apt install -y jq || fail "jq is missing and could not be installed."
fi
mesh_cfg=/meshcentral/meshcentral-data/config.json
mesh_user=$(jq -r '.settings.postgres.user // empty' "$mesh_cfg")
mesh_pw=$(jq -r '.settings.postgres.password // empty' "$mesh_cfg")
[ -n "$mesh_user" ] && [ -n "$mesh_pw" ] || fail "no MeshCentral database login in ${mesh_cfg}."
PGPASSWORD=$mesh_pw pg_dump --no-privileges --no-owner -h localhost -p 5432 -U "$mesh_user" -d meshcentral |
  gzip -9 >"${STAGING}/postgres/mesh-db-${dt_now}.psql.gz" || fail "pg_dump of meshcentral failed."

say "$GREEN" "Backing up files"
tar -czvf "${STAGING}/meshcentral/mesh.tar.gz" --exclude=/meshcentral/node_modules --exclude=/meshcentral/meshcentral-recordings /meshcentral
tar_ok $? /meshcentral

if [ -d /etc/letsencrypt ]; then
  sudo tar -czvf "${STAGING}/certs/etc-letsencrypt.tar.gz" -C /etc/letsencrypt .
  tar_ok $? /etc/letsencrypt
fi
if [ -d /opt/ulrmm-reporting ]; then
  sudo tar -czvf "${STAGING}/opt/opt-ulrmm-reporting.tar.gz" -C /opt/ulrmm-reporting .
  tar_ok $? /opt/ulrmm-reporting
fi
for f in /opt/rustdesk/id_ed25519 /opt/rustdesk/id_ed25519.pub; do
  if sudo test -f "$f"; then
    sudo cp -p "$f" "${STAGING}/rustdesk/" || fail "could not copy ${f}."
  fi
done
for f in "${AGENT_CA_DIR}/ca.key" "${AGENT_CA_DIR}/ca.pem"; do
  if sudo test -f "$f"; then
    sudo cp -p "$f" "${STAGING}/agent-ca/" || fail "could not copy ${f}."
  fi
done

ls_value() {
  sed -nE "s/^${1}[[:space:]]*=[[:space:]]*[\"']([^\"']*)[\"'].*/\\1/p" "$LOCAL_SETTINGS" | tail -1
}
if grep -q '^CERT_FILE' "$LOCAL_SETTINGS"; then
  cert_file=$(ls_value CERT_FILE)
  key_file=$(ls_value KEY_FILE)
  mkdir -p "${STAGING}/certs/custom"
  sudo cp -p "$cert_file" "${STAGING}/certs/custom/cert" || fail "could not copy the certificate ${cert_file}."
  sudo cp -p "$key_file" "${STAGING}/certs/custom/key" || fail "could not copy the key ${key_file}."
fi

for f in rmm frontend meshcentral; do
  if [ -f "/etc/nginx/sites-enabled/${f}.conf" ]; then
    sudo cp "/etc/nginx/sites-enabled/${f}.conf" "${STAGING}/nginx/" || fail "could not copy the nginx site ${f}.conf."
  fi
done
if [ -d /etc/conf.d ]; then
  sudo tar -czvf "${STAGING}/confd/etc-confd.tar.gz" -C /etc/conf.d .
  tar_ok $? /etc/conf.d
fi
for u in rmm celery celerybeat meshcentral nats daphne nats-api; do
  if [ -f "/etc/systemd/system/${u}.service" ]; then
    sudo cp "/etc/systemd/system/${u}.service" "${STAGING}/systemd/" || fail "could not copy ${u}.service."
  fi
done
cp "$LOCAL_SETTINGS" "${STAGING}/rmm/" || fail "could not copy ${LOCAL_SETTINGS}."
if [ -f "${BACKUP_DIR}/backup.conf" ]; then
  cp "${BACKUP_DIR}/backup.conf" "${STAGING}/rmm/" || fail "could not copy backup.conf."
fi
# unfinished uploads stay out, files above 1 GiB unless --with-large-packages;
# the MANIFEST lists those with sha256, size and package name
pkg_files() {
  (cd "$PACKAGES_DIR" && find . -mindepth 1 \( -name .uploads -o -name '.incoming-*' \) -prune -o -type f "$@" -print0)
}
large=()
# $1 tarball. Fills large with the files left out.
pack_packages() {
  local keep=()
  if [ "$with_large" != true ]; then
    keep=(-size "-$((LARGE_PACKAGE + 1))c")
    mapfile -d '' large < <(pkg_files -size "+${LARGE_PACKAGE}c")
  fi
  pkg_files "${keep[@]}" | (cd "$PACKAGES_DIR" && tar --null --no-recursion -T - -cvf "$1")
}
# LARGE_PACKAGE=<sha256> <size> <package name> for each file in large
large_lines() {
  local f names name
  [ ${#large[@]} -gt 0 ] || return 0
  names=$(PGPASSWORD=$dbpw psql -AtX -F ' ' -h localhost -p 5432 -U "$dbuser" -d "$dbname" \
    -c "SELECT sha256, translate(name, E'\n\r\t', '   ') FROM packages_softwarepackage WHERE size > ${LARGE_PACKAGE}")
  for f in "${large[@]}"; do
    f=${f#./}
    name=$(awk -v s="$f" '$1 == s {sub(/^[^ ]+ /, ""); print; exit}' <<<"$names")
    echo "LARGE_PACKAGE=${f} $(stat -c %s "${PACKAGES_DIR}/${f}") ${name:--}"
  done
}
if [ -d "$PACKAGES_DIR" ]; then
  pack_packages "${STAGING}/rmm/packages.tar" || fail "could not archive ${PACKAGES_DIR}."
  [ ${#large[@]} -eq 0 ] ||
    say "$YELLOW" "${#large[@]} package file(s) above 1 GiB left out, see MANIFEST (--with-large-packages takes them along)."
fi
# the ISO builder's images only with --with-large-packages; unfinished
# downloads (*.part), jobs/ and .uploads/ stay out. The MANIFEST lists them all.
isos=()
# $1 tarball. Fills isos with the images.
pack_isos() {
  mapfile -d '' isos < <(cd "$ISO_DIR" && find . -mindepth 1 -maxdepth 1 -type f ! -name '*.part' -print0)
  [ "$with_large" = true ] || return 0
  [ ${#isos[@]} -gt 0 ] || return 0
  (cd "$ISO_DIR" && tar --no-recursion -cvf "$1" -- "${isos[@]}")
}
# ISO_IMAGE=<sha256 or -> <size> <file name> for each file in isos
iso_lines() {
  local f sums sha
  [ ${#isos[@]} -gt 0 ] || return 0
  sums=$(PGPASSWORD=$dbpw psql -AtX -F ' ' -h localhost -p 5432 -U "$dbuser" -d "$dbname" \
    -c "SELECT sha256, filename FROM deploy_baseiso WHERE sha256 <> ''")
  for f in "${isos[@]}"; do
    f=${f#./}
    sha=$(awk -v s="$f" '{h = $1; sub(/^[^ ]+ /, "")} $0 == s {print h; exit}' <<<"$sums")
    echo "ISO_IMAGE=${sha:--} $(stat -c %s "${ISO_DIR}/${f}") ${f}"
  done
}
if [ -d "$ISO_DIR" ]; then
  pack_isos "${STAGING}/rmm/iso.tar" || fail "could not archive ${ISO_DIR}."
  [ "$with_large" = true ] || [ ${#isos[@]} -eq 0 ] ||
    say "$YELLOW" "${#isos[@]} ISO image(s) left out, see MANIFEST (--with-large-packages takes them along)."
fi

sudo chown -R "${USER}:$(id -gn)" "$STAGING" || fail "could not take ownership of ${STAGING}."

{
  echo "FORMAT=1"
  echo "VERSION=$(tr -d '[:space:]' </rmm/VERSION 2>/dev/null)"
  echo "COMMIT=$(git -C /rmm rev-parse HEAD 2>/dev/null)"
  echo "BACKUP_SH=${SCRIPT_VERSION}"
  echo "CREATED=$(date -Iseconds)"
  iso_lines
  large_lines
} >"${STAGING}/MANIFEST" || fail "could not write the manifest."
(cd "$STAGING" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS) ||
  fail "could not write SHA256SUMS."

PART="${target}.part"
write_archive "$STAGING" "$PART" || fail "could not write ${target}."
mv -n "$PART" "$target" && [ ! -e "$PART" ] || fail "could not move the backup to ${target}."
PART=''
if [ ${#age_args[@]} -eq 0 ]; then
  say "$YELLOW" "WARNING: ${target} is not encrypted. It holds local_settings.py, the agent CA key and the database with the agent tokens. Set BACKUP_AGE_RECIPIENTS in ${BACKUP_DIR}/backup.conf."
  "$PY" "$MANAGE" security_event backup_unencrypted warning --detail "no BACKUP_AGE_RECIPIENTS in backup.conf" >/dev/null 2>&1 ||
    say "$YELLOW" "WARNING: could not record the security event."
fi

case "$mode" in
auto)
  find "${BACKUP_DIR}/daily" -type f -mtime "+${DAILY_KEEP_DAYS}" \( -name '*.tar' -o -name '*.tar.age' \) -execdir rm -- {} \;
  find "${BACKUP_DIR}/weekly" -type f -mtime "+${WEEKLY_KEEP_DAYS}" \( -name '*.tar' -o -name '*.tar.age' \) -execdir rm -- {} \;
  find "${BACKUP_DIR}/monthly" -type f -mtime "+${MONTHLY_KEEP_DAYS}" \( -name '*.tar' -o -name '*.tar.age' \) -execdir rm -- {} \;
  say "$GREEN" "Backup Completed"
  ;;
pre-update)
  if [ "$PRE_UPDATE_KEEP" -gt 0 ]; then
    find "${BACKUP_DIR}/pre-update" -maxdepth 1 -type f \( -name 'rmm-backup-*.tar' -o -name 'rmm-backup-*.tar.age' \) -printf '%T@ %p\n' |
      sort -rn | tail -n "+$((PRE_UPDATE_KEEP + 1))" | cut -d' ' -f2- |
      while read -r old; do rm -f -- "$old"; done
  fi
  say "$GREEN" "Backup saved to ${target}"
  ;;
*)
  say "$GREEN" "Backup saved to ${target}"
  ;;
esac
exit 0

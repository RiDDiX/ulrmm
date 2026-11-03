#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Rotates server secrets, run by hand as the install user:
#
#   bash /rmm/riddix/scripts/rotate-secrets.sh mesh    MeshCentral login token key,
#                                                     MESH_TOKEN_KEY and the mesh token in the database
#   bash /rmm/riddix/scripts/rotate-secrets.sh db      Postgres passwords of the ulrmm role (nats-api
#                                                     uses it too) and of the MeshCentral role
#   bash /rmm/riddix/scripts/rotate-secrets.sh redis   REDIS_PASSWORD and requirepass
#
# New secrets go through files (umask 077), stdin and the environment, never
# argv. It prints what it changed, never a secret, and restarts the services
# that use it. Backups made before keep the old values.

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
USER=${USER:-$(id -un)}
local_settings=${local_settings:-/rmm/api/ulrmm/ulrmm/local_settings.py}
MESH_DIR=${MESH_DIR:-/meshcentral}
DJANGO_UNITS=(rmm daphne celery celerybeat)

# shellcheck source=riddix/scripts/install_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/install_lib.sh" || exit 1

manage() { (cd /rmm/api/ulrmm && /rmm/api/env/bin/python manage.py "$@"); }

STOPPED=()
start_stopped() {
  [ ${#STOPPED[@]} -gt 0 ] || return 0
  sudo systemctl start "${STOPPED[@]}"
  STOPPED=()
}
stop_units() {
  sudo systemctl stop "$@" && STOPPED+=("$@")
}

# $1 extra MeshCentral option. The key is the last line of 160+ hex digits.
mesh_key() {
  (cd "$MESH_DIR" && node node_modules/meshcentral --logintokenkey "$@") | grep -xE '[0-9a-f]{160,}' | tail -1
}

rotate_mesh() {
  local old new
  old=$(mesh_key)
  [ -n "$old" ] || lib_die "node node_modules/meshcentral --logintokenkey printed no key."
  stop_units meshcentral || lib_die "could not stop meshcentral."
  new=$(mesh_key --logintokengen)
  if [ -z "$new" ] || [ "$new" = "$old" ]; then
    lib_die "MeshCentral made no new login token key, nothing changed."
  fi
  ls_set MESH_TOKEN_KEY "$new"
  ULRMM_NEW_MESH_KEY=$new manage shell -c 'import os
from core.models import CoreSettings
core = CoreSettings.objects.first()
core.mesh_token = os.environ["ULRMM_NEW_MESH_KEY"]
core.save(update_fields=["mesh_token"])' ||
    lib_die "MeshCentral and MESH_TOKEN_KEY have the new key, the database not: enter MESH_TOKEN_KEY of ${local_settings} under Global Settings > MeshCentral."
  start_stopped
  sudo systemctl restart "${DJANGO_UNITS[@]}"
  echo "mesh: new LoginCookieEncryptionKey in MeshCentral, MESH_TOKEN_KEY in ${local_settings}, mesh token in Global Settings; restarted meshcentral ${DJANGO_UNITS[*]}"
  local out
  for _ in $(seq 1 24); do
    out=$(manage check_mesh 2>&1)
    if grep -q 'Mesh device id ok' <<<"$out"; then
      echo "mesh: manage.py check_mesh works with the new key"
      return 0
    fi
    sleep 5
  done
  lib_warn "WARNING: manage.py check_mesh still fails after 2 minutes, its last answer:"
  printf '%s\n' "$out" | tail -5 >&2
  return 1
}

# $1 role, $2 password. SQL on stdin, like pg_create_db.
pg_set_password() {
  sudo -iu postgres psql -q -v ON_ERROR_STOP=1 <<EOF
ALTER ROLE "${1}" WITH PASSWORD '${2}';
EOF
}

# $1 settings|mesh, $2 file, $3 new file. Password from ULRMM_NEW_PW, prints
# the role name.
new_db_file() {
  python3.12 -I - "$@" <<'EOF'
import ast, json, os, sys

mode, src, dst = sys.argv[1:4]
new = os.environ["ULRMM_NEW_PW"]
if mode == "mesh":
    cfg = json.load(open(src))
    pg = cfg["settings"]["postgres"]
    pg["password"] = new
    out = (json.dumps(cfg, indent=2) + "\n").encode()
    user = pg["user"]
else:
    data = open(src, "rb").read()
    hit = None
    for node in ast.parse(data).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DATABASES" for t in node.targets):
            db = dict(zip((getattr(k, "value", None) for k in node.value.keys), node.value.values))["default"]
            hit = dict(zip((getattr(k, "value", None) for k in db.keys), db.values))
    if hit is None or ast.literal_eval(hit["NAME"]) != "ulrmm" or not isinstance(hit["PASSWORD"], ast.Constant):
        sys.exit("DATABASES has no default database ulrmm with a PASSWORD string")
    pw, user = hit["PASSWORD"], ast.literal_eval(hit["USER"])
    starts = [0]
    for line in data.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    a = starts[pw.lineno - 1] + pw.col_offset
    b = starts[pw.end_lineno - 1] + pw.end_col_offset
    out = data[:a] + repr(new).encode() + data[b:]
open(dst, "wb").write(out)
print(user)
EOF
}

rotate_db() {
  local cfg="${MESH_DIR}/meshcentral-data/config.json" app_pw mesh_pw app_role mesh_role tmp_ls tmp_cfg r
  app_pw=$(openssl rand -hex 24)
  mesh_pw=$(openssl rand -hex 24)
  tmp_ls=$(mktemp -p "$(dirname "$local_settings")" .local_settings.XXXXXX) || lib_die "mktemp failed."
  tmp_cfg=$(mktemp -p "$(dirname "$cfg")" .config.XXXXXX) || lib_die "mktemp failed."
  # shellcheck disable=SC2064 # the paths are fixed now
  trap "rm -f '$tmp_ls' '$tmp_cfg'; start_stopped" EXIT
  app_role=$(ULRMM_NEW_PW=$app_pw new_db_file settings "$local_settings" "$tmp_ls") ||
    lib_die "could not read DATABASES from ${local_settings}, nothing changed."
  mesh_role=$(ULRMM_NEW_PW=$mesh_pw new_db_file mesh "$cfg" "$tmp_cfg") ||
    lib_die "could not read settings.postgres from ${cfg}, nothing changed."
  for r in "$app_role" "$mesh_role"; do
    [[ $r =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || lib_die "'${r}' is not a role name this script handles, nothing changed."
  done

  stop_units celerybeat celery rmm daphne nats-api || lib_die "could not stop the services."
  pg_set_password "$app_role" "$app_pw" || lib_die "ALTER ROLE ${app_role} failed, nothing changed."
  mv -f "$tmp_ls" "$local_settings" ||
    lib_die "role ${app_role} has the new password but ${local_settings} could not be replaced."
  manage create_natsapi_conf >/dev/null || lib_die "manage.py create_natsapi_conf failed, nats-api has the old password."
  start_stopped
  echo "db: new password for role ${app_role} in Postgres, ${local_settings} and nats-api.conf; restarted ${DJANGO_UNITS[*]} nats-api"

  stop_units meshcentral || lib_die "could not stop meshcentral, its role keeps the old password."
  pg_set_password "$mesh_role" "$mesh_pw" || lib_die "ALTER ROLE ${mesh_role} failed, MeshCentral keeps the old password."
  mv -f "$tmp_cfg" "$cfg" ||
    lib_die "role ${mesh_role} has the new password but ${cfg} could not be replaced."
  start_stopped
  echo "db: new password for role ${mesh_role} in Postgres and ${cfg}; restarted meshcentral"
}

rotate_redis() {
  local pw
  pw=$(openssl rand -hex 32)
  ls_set REDIS_PASSWORD "$pw"
  redis_require_pass "$pw" ||
    lib_die "REDIS_PASSWORD is new but redis-server did not come back with it. Fix redis (sudo journalctl -u redis-server), then run this again."
  sudo systemctl restart "${DJANGO_UNITS[@]}"
  echo "redis: new REDIS_PASSWORD in ${local_settings} and requirepass in ${REDIS_CONF}; restarted redis-server ${DJANGO_UNITS[*]}"
}

main() {
  [ "$EUID" -ne 0 ] || lib_die "run it as the install user, not as root."
  local unit_user
  unit_user=$(grep -m1 '^User=' /etc/systemd/system/rmm.service 2>/dev/null | cut -d= -f2)
  [ "$unit_user" = "$USER" ] || lib_die "run it as ${unit_user:-the install user}, the user of rmm.service."
  umask 077
  trap start_stopped EXIT
  case "$1" in
  mesh) rotate_mesh ;;
  db) rotate_db ;;
  redis) rotate_redis ;;
  *)
    sed -n '2,13p' "$0" >&2
    exit 2
    ;;
  esac
}

[ "${BASH_SOURCE[0]}" != "$0" ] || main "$@"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# One-shot init of the compose stack, same order as install.sh. Every step
# is idempotent; the api, ws, celery and celerybeat services wait for it.
set -euo pipefail
cd /rmm/api/ulrmm

LS=/settings/local_settings.py
SCRIPTS_DIR=/opt/ulrmm-community-scripts

log() { printf '[init] %s\n' "$*"; }
die() {
  printf '[init] ERROR: %s\n' "$*" >&2
  exit 1
}
manage() { python manage.py "$@"; }
# install.sh: the admin app's tables and static files exist, the admin is off
set_admin() { sed -i -E "s/^ADMIN_ENABLED = (True|False)\$/ADMIN_ENABLED = $1/" "$LS"; }

wait_for() { # name, tries, command...
  local name=$1 tries=$2 i
  shift 2
  for ((i = 1; i <= tries; i++)); do
    "$@" && return 0
    [ "$i" -eq 1 ] && log "waiting for ${name}"
    sleep 2
  done
  die "${name} not ready after $((tries * 2))s"
}

redis_ok() {
  python - <<'EOF'
import os, sys, redis
try:
    redis.Redis(host="redis", password=os.environ["REDIS_PASSWORD"], socket_connect_timeout=2).ping()
except Exception:
    sys.exit(1)
EOF
}

wait_for db 60 pg_isready -q -h db -U ulrmm
wait_for redis 60 redis_ok
wait_for "MeshCentral login token key" 300 test -s /mesh-data/ulrmm-logintokenkey
# written by the mesh entrypoint after the UniversalLocalRMM device group exists
wait_for "MeshCentral first start" 300 test -f /mesh-data/ulrmm-initialized

log "rendering ${LS}"
python /rmm/docker/api/render_settings.py

trap 'set_admin False' EXIT
set_admin True
log "migrate"
manage migrate --no-input
log "ensure_agent_ca"
manage ensure_agent_ca
log "create_natsapi_conf"
manage create_natsapi_conf
# writes /conf/nats-rmm.conf; the reload itself is the nats service's
# reload-watch.sh, the binary call fails here
log "reload_nats"
manage reload_nats
# the query schema and the plotly.js copy that collectstatic publishes
log "generate_json_schemas"
manage generate_json_schemas
log "collectstatic"
manage collectstatic --no-input
set_admin False
trap - EXIT
log "initial_db_setup"
manage initial_db_setup

if manage shell -c 'import sys; from accounts.models import User; sys.exit(0 if User.objects.filter(is_superuser=True).exists() else 1)'; then
  log "superuser exists"
else
  log "createsuperuser ${ADMIN_USER}"
  [ -n "${ADMIN_PASSWORD:-}" ] || die "ADMIN_PASSWORD is empty and no superuser exists"
  DJANGO_SUPERUSER_USERNAME=$ADMIN_USER DJANGO_SUPERUSER_EMAIL=$ADMIN_EMAIL \
    DJANGO_SUPERUSER_PASSWORD=$ADMIN_PASSWORD manage createsuperuser --no-input
fi

# deployments and install links authenticate as this account
log "create_installer_user"
manage create_installer_user
log "sync_mesh_with_rmm"
manage sync_mesh_with_rmm

# the default repo needs access; an optional token goes in through GIT_ASKPASS
# like ulrmm/utils.py git_auth_env, never into the URL. A failed clone is
# not fatal, the dashboard syncs the library from ULRMM_SCRIPTS_GIT_URL later.
if [ ! -d "$SCRIPTS_DIR/.git" ]; then
  log "cloning ${ULRMM_SCRIPTS_REPO}"
  askpass=$(mktemp)
  printf '#!/bin/sh\ncase "$1" in *[Uu]sername*) echo git ;; *) echo "$ULRMM_SCRIPTS_TOKEN" ;; esac\n' >"$askpass"
  chmod 700 "$askpass"
  if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=$askpass git clone --quiet --branch main "$ULRMM_SCRIPTS_REPO" "$SCRIPTS_DIR"; then
    log "WARNING: script library clone failed, ${SCRIPTS_DIR} stays empty"
  fi
  rm -f "$askpass"
else
  log "script library present"
fi
log "load_chocos"
manage load_chocos
# warns and changes nothing when the clone above failed
log "load_community_scripts"
manage load_community_scripts
log "done"

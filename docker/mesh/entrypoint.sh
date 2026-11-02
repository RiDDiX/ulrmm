#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Renders config.json like install.sh does for the native install, seeds the
# login token key, admin account and device group on the first start, then
# runs MeshCentral in the foreground. Checked against meshcentral 1.2.4:
# --createaccount works on an empty database before the first server start,
# and meshctrl reaches the tlsOffload instance over ws://127.0.0.1:4430.
set -euo pipefail
cd /meshcentral

: "${MESH_DOMAIN:?}" "${MESH_DB_PASSWORD:?}"
data=/meshcentral/meshcentral-data
marker=$data/ulrmm-initialized
keyfile=$data/ulrmm-logintokenkey

wait_tcp() { # host port
  local i
  for i in $(seq 1 120); do
    if (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; then
      return 0
    fi
    [ "$i" -eq 1 ] && echo "waiting for $1:$2"
    sleep 2
  done
  echo "$1:$2 did not answer within 4 minutes" >&2
  return 1
}

wait_tcp db 5432

jq -n --arg mesh "$MESH_DOMAIN" --arg pw "$MESH_DB_PASSWORD" '{
  settings: {
    cert: $mesh, WANonly: true, minify: 1, port: 4430, portBind: "0.0.0.0", aliasPort: 443,
    redirPort: 800, redirPortBind: "127.0.0.1", mpsPort: 0, allowLoginToken: true, allowFraming: true,
    agentPing: 35, allowHighQualityDesktop: true, tlsOffload: true, agentCoreDump: false,
    compression: false, wsCompression: false, agentWsCompression: false,
    maxInvalidLogin: {time: 5, count: 5, coolofftime: 30}, autoBackup: false,
    postgres: {user: "meshcentral", password: $pw, port: "5432", host: "db", database: "meshcentral"}
  },
  domains: {
    "": {
      title: "UniversalLocal RMM", title2: "UniversalLocal RMM", newAccounts: false,
      certUrl: ("https://" + $mesh + ":443/"), geoLocation: false, cookieIpCheck: false, mstsc: true
    }
  }
}' >"$data/config.json.new"
mv -f "$data/config.json.new" "$data/config.json"
chmod 600 "$data/config.json"

first=false
if [ ! -f "$marker" ]; then
  first=true
  : "${MESH_USERNAME:?}" "${MESH_PASSWORD:?}" "${ADMIN_EMAIL:?}"
  echo "first start: login token key and admin account"
  if [ ! -f "$keyfile" ]; then
    (umask 077 && node node_modules/meshcentral --logintokenkey >"$keyfile.new")
    [ -s "$keyfile.new" ] || { echo "no login token key" >&2; exit 1; }
    mv -f "$keyfile.new" "$keyfile"
  fi
  node node_modules/meshcentral --createaccount "$MESH_USERNAME" --pass "$MESH_PASSWORD" --email "$ADMIN_EMAIL"
  node node_modules/meshcentral --adminaccount "$MESH_USERNAME"
fi

node node_modules/meshcentral &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

if [ "$first" = true ]; then
  wait_tcp 127.0.0.1 4430
  meshctrl() {
    node node_modules/meshcentral/meshctrl.js --url ws://127.0.0.1:4430 \
      --loginuser "$MESH_USERNAME" --loginpass "$MESH_PASSWORD" "$@"
  }
  # MeshCentral allows duplicate group names; a start that died before the
  # marker was written must not add a second one
  if meshctrl ListDeviceGroups --json | jq -e 'any(.[]; .name == "UniversalLocalRMM")' >/dev/null; then
    echo "device group UniversalLocalRMM exists"
  else
    meshctrl AddDeviceGroup --name UniversalLocalRMM
  fi
  touch "$marker"
  echo "first start done"
fi

wait "$pid"

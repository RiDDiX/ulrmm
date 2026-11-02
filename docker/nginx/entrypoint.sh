#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Renders nginx.conf and the three site files with the generators of
# install_lib.sh, points them at the compose services, then runs $@.
set -euo pipefail

: "${API_DOMAIN:?}" "${APP_DOMAIN:?}" "${MESH_DOMAIN:?}" "${ROOT_DOMAIN:?}"
ULRMM_TLS=${ULRMM_TLS:-own}
cert=/certs/fullchain.pem
key=/certs/privkey.pem

# lib_info and lib_warn read the colors
export GREEN='' YELLOW='' RED='' NC=''
sudo() { "$@"; }
# shellcheck source=/dev/null
. /opt/ulrmm/install_lib.sh

if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
  if [ "$ULRMM_TLS" != selfsigned ]; then
    lib_die "ULRMM_TLS=${ULRMM_TLS} but ${cert} or ${key} is missing. Mount them or set ULRMM_TLS=selfsigned."
  fi
  lib_info "Creating a self-signed certificate for ${ROOT_DOMAIN} and *.${ROOT_DOMAIN}"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$key" -out "$cert" -subj "/CN=${ROOT_DOMAIN}" \
    -addext "subjectAltName=DNS:${ROOT_DOMAIN},DNS:*.${ROOT_DOMAIN}" ||
    lib_die "could not create the self-signed certificate."
fi

# sockets and loopback ports of the native install become service names
render() {
  "$@" | sed \
    -e 's#unix:////rmm/api/ulrmm/ulrmm.sock#api:8000#' \
    -e 's#http://unix:/rmm/daphne.sock#http://ws:8001#' \
    -e 's#127\.0\.0\.1:9235#nats:9235#' \
    -e 's#127\.0\.0\.1:4430#mesh:4430#' \
    -e 's#/rmm/api/ulrmm/ulrmm/private/log/#/var/log/nginx/#'
}

render nginx_conf_text >/etc/nginx/nginx.conf
render rmm_nginx_conf "$API_DOMAIN" "$APP_DOMAIN" "$cert" "$key" >/etc/nginx/sites-enabled/rmm.conf
render mesh_nginx_conf "$MESH_DOMAIN" "$cert" "$key" >/etc/nginx/sites-enabled/meshcentral.conf
render frontend_nginx_conf "$APP_DOMAIN" "$API_DOMAIN" "$MESH_DOMAIN" "$cert" "$key" >/etc/nginx/sites-enabled/frontend.conf
echo "window._env_ = {PROD_URL: \"https://${API_DOMAIN}\"}" >/var/www/rmm/dist/env-config.js

nginx -t
exec "$@"

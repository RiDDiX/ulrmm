#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# postgres initdb hook: the MeshCentral role and database, like pg_create_db
# in install.sh. Runs once, when the data directory is created.
set -euo pipefail
: "${MESH_DB_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 -v pw="$MESH_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE ROLE meshcentral LOGIN PASSWORD :'pw';
CREATE DATABASE meshcentral OWNER meshcentral;
EOSQL

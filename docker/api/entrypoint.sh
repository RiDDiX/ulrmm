#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# activates the venv at the path the scripts and settings assume
set -euo pipefail
# shellcheck disable=SC1091
. /rmm/api/env/bin/activate
exec "$@"

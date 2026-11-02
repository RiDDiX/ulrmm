#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# nats-api for this host, pinned Go. Install user, no sudo.
# Does not copy the binary to /usr/local/bin.
# <src-tree>: checkout or git archive with main.go, go.mod, go.sum, natsapi/, VERSION.
#
#   build_natsapi.sh <src-tree> <out-file>
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[ $# -eq 2 ] || die "usage: $0 <src-tree> <out-file>"
src=$1
out=$(realpath -m -- "$2")
[ -f "$src/go.mod" ] || die "$src has no go.mod"
[ -f "$src/VERSION" ] || die "$src has no VERSION file"
ver=$(tr -d '[:space:]' <"$src/VERSION")
if ! [[ $ver =~ ^[1-9][0-9]*\.([0-9]{2})\.([0-9]{2})\.([0-9]{4})$ ]] ||
  ! date -d "${BASH_REMATCH[3]}-${BASH_REMATCH[2]}-${BASH_REMATCH[1]}" >/dev/null 2>&1; then
  die "VERSION '$ver' is not X.DD.MM.YYYY with a real date"
fi

# shellcheck source=riddix/scripts/go_toolchain.sh
. "$(dirname "${BASH_SOURCE[0]}")/go_toolchain.sh"
echo "=== Go $GO_VER ==="
go_toolchain

echo "=== nats-api $ver ==="
rm -f -- "$out"
# no .git in an archive; -buildvcs=false makes a checkout build the same
(cd "$src" && CGO_ENABLED=0 GOFLAGS='-mod=readonly -buildvcs=false' \
  go build -trimpath -ldflags "-s -w -X main.version=$ver" -o "$out" .) ||
  die "go build failed"

got=$("$out" -version) || got=''
if [ "${got%%$'\n'*}" != "$ver" ]; then
  rm -f -- "$out"
  die "$out -version does not report $ver"
fi
sum=$(sha256sum -- "$out")
echo "  version: $ver"
echo "  go:      $(go version)"
echo "  sha256:  ${sum%% *}"
echo "  file:    $out"

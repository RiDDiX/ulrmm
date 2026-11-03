# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# shellcheck shell=bash
# sourced by build_agents.sh and build_natsapi.sh.
# go_toolchain installs Go $GO_VER under $ULRMM_AGENT_ROOT/go (sha256 checked)
# on first use or a version change. Sets GO_HOST, GODIR, GO. Exports
# GOTOOLCHAIN, GOPATH, GOCACHE, PATH. Caller sets GOFLAGS and CGO_ENABLED.
# No sudo if the root is writable.
#
# .go-install.lock covers the check and the install. The caller holds
# .go.lock shared until exit, so a replace waits for builds still using it.

GO_VER=1.27.3

_go_ok() {
  [ -x "$GO" ] && [[ $("$GO" version) == *"go$GO_VER "* ]]
}

# go_toolchain error path: close both lock fds so the caller does not keep them
_go_fail() {
  echo "ERROR: $1" >&2
  [ -z "${lock:-}" ] || exec {lock}>&-
  [ -z "${GO_LOCK_FD:-}" ] || exec {GO_LOCK_FD}>&-
  GO_LOCK_FD=''
}

go_toolchain() {
  local root=${ULRMM_AGENT_ROOT:-/opt/ulrmm-agents} sha tgz tmp q traps lock='' err=''
  case "$(uname -m)" in
  x86_64 | amd64) GO_HOST=amd64 sha=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
  aarch64 | arm64) GO_HOST=arm64 sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
  *)
    echo "ERROR: no pinned Go checksum for $(uname -m)" >&2
    return 1
    ;;
  esac
  GODIR=$root/go
  GO=$GODIR/go/bin/go

  if ! mkdir -p "$root" 2>/dev/null || ! exec {lock}>>"$root/.go-install.lock" {GO_LOCK_FD}>>"$root/.go.lock"; then
    _go_fail "$root is not writable"
    return 1
  fi
  if ! flock -w 1800 -x "$lock"; then
    _go_fail "timed out waiting for $root/.go-install.lock"
    return 1
  fi

  if _go_ok; then
    flock -s "$GO_LOCK_FD"
    echo "  present: $("$GO" version)"
  else
    if ! flock -w 1800 -x "$GO_LOCK_FD"; then
      _go_fail "timed out waiting for builds using $GODIR"
      return 1
    fi
    tgz=go${GO_VER}.linux-${GO_HOST}.tar.gz
    if ! tmp=$(mktemp -d "$root/.go-new.XXXXXX"); then
      _go_fail "cannot create a temp dir in $root"
      return 1
    fi
    # the caller's traps come back once the download dir is gone
    traps=$(trap -p EXIT INT TERM)
    q=$(printf '%q' "$tmp")
    # shellcheck disable=SC2064  # the path is fixed now
    trap "rm -rf -- $q" EXIT
    # shellcheck disable=SC2064
    trap "rm -rf -- $q; exit 130" INT
    # shellcheck disable=SC2064
    trap "rm -rf -- $q; exit 143" TERM
    echo "  downloading $tgz"
    if ! curl -fsSL --max-time 900 -o "$tmp/$tgz" "https://go.dev/dl/$tgz"; then
      err="download of $tgz failed"
    elif ! echo "$sha  $tmp/$tgz" | sha256sum -c -; then
      err="checksum of $tgz does not match"
    elif ! tar -C "$tmp" -xzf "$tmp/$tgz"; then
      err="unpacking $tgz failed"
    elif ! { rm -rf "$GODIR" && mkdir -p "$GODIR" && mv "$tmp/go" "$GODIR/go"; }; then
      err="cannot replace $GODIR"
    fi
    rm -rf "$tmp"
    trap - EXIT INT TERM
    eval "$traps"
    if [ -n "$err" ]; then
      _go_fail "$err"
      return 1
    fi
    flock -s "$GO_LOCK_FD"
    echo "  installed: $("$GO" version)"
  fi
  exec {lock}>&-

  export GOTOOLCHAIN=local GOPATH="$root/gopath" GOCACHE="$root/gocache"
  export PATH="$GODIR/go/bin:$GOPATH/bin:$PATH"
}

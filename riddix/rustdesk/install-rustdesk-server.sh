#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# hbbs + hbbr (AGPL-3.0) as systemd services, user rustdesk, plus a mirror
# of the pinned clients under <dist>/rustdesk/. The endpoints fetch the files
# from /agentdist/rustdesk/. No RustDesk Server Pro.
#
#   bash install-rustdesk-server.sh --host <address> [--dist <directory>]
#     [--server-version <v> --server-zip <file>]
#   bash install-rustdesk-server.sh --selftest
#
# --host: name or IP (without port) under which the clients reach this
#   server; hbbs hands it to them as relay (<host>:21117).
# --dist: agent directory behind /agentdist/, default /opt/ulrmm-agents/dist.
#   Must exist (build_agents.sh creates it).
# --server-version/--server-zip: only together. hbbs/hbbr <v> from the already
#   downloaded zip (the RMM fetches it from github.com) instead of the pinned
#   version. Only checked that both binaries report <v>. If they do not
#   start, the previous ones come back. The client mirror stays.
#   Without the options a newer installed version is left in place.
# If <dist>/rustdesk/manifest.json exists, the mirror belongs to the RMM and
#   is left alone.
# Ports: TCP 21115-21117, UDP 21116. The web client ports 21118/21119 stay closed.
# Key: /opt/rustdesk/id_ed25519 (0600, service user), the .pub is readable by
# all - the RMM reads it for the client configuration string.
# A second run downloads nothing and only restarts what changed.
# Root, otherwise it re-runs itself via sudo.
set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

SERVER_VER=1.1.16
# https://github.com/rustdesk/rustdesk-server/releases/download/$SERVER_VER/<file>
declare -A SERVER_ZIP=(
  [amd64]="rustdesk-server-linux-amd64.zip 0565c41affe6c3f409b0bddfaf5a24ccbf3f64f5f8e3fec250b69a0d5f6bdbcf"
  [arm64]="rustdesk-server-linux-arm64v8.zip 6a4ae3c5ca257a4278ded72fd17eb2ca4eeb0356a5425e63a3e7fcb0ec6c155c"
)
CLIENT_VER=1.4.9
# https://github.com/rustdesk/rustdesk/releases/download/$CLIENT_VER/<file>
# Same files and sums as the start value in remote/migrations/0002.
# After that the RMM pins on its own (manifest.json in mirror_clients).
CLIENT_FILES=(
  "rustdesk-1.4.9-x86_64.msi c87d2f4cef2a5acd6003b6507dcfbf5d5168a256db082cd90b54d35193224aaa"
  "rustdesk-1.4.9-x86_64.deb 7244ba47c40e804172044bfbe659467c54ce46554c98e78c8c0406f1d612fda3"
  "rustdesk-1.4.9-0.x86_64.rpm eb1b053ac5b2f774f2271f7fbbfd2ea475899f7a55135c5e172bc54b9388f108"
  "rustdesk-1.4.9-x86_64.dmg fa1129a0635019f9c5841937942cc2b08be028a192f47c009edde7e53812904e"
  "rustdesk-1.4.9-aarch64.dmg f7935597b247d42c8f2a2ed71176a9f5868018cd9e1a33b8096418a668c8caf0"
)

RD_DIR=/opt/rustdesk
RD_USER=rustdesk
UNIT_DIR=/etc/systemd/system

die() { echo "ERROR: $*" >&2; exit 1; }

valid_host() {
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]
}

valid_version() { [[ $1 =~ ^[0-9]{1,5}(\.[0-9]{1,5}){1,3}$ ]]; }

# newer <a> <b>: a sorts above b with sort -V
newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]; }

verify() { echo "$2  $1" | sha256sum -c --status -; }

# fetch <url> <target> <sha256>: the target appears only after the check passes
fetch() {
  echo "  downloading $1"
  curl -fsSL --retry 3 --max-time 900 -o "$2.part" "$1" || { rm -f "$2.part"; die "download failed: $1"; }
  verify "$2.part" "$3" || { rm -f "$2.part"; die "sha256 mismatch: $1"; }
  mv -f "$2.part" "$2"
}

render_unit() { sed "s|@HOST@|$2|g" "$SELF_DIR/rustdesk-$1.service"; }

# restore <dir>: previous hbbs/hbbr back if the update aborts
restore() {
  [ -d "$1" ] || return 0
  echo "  update aborted, previous binaries restored" >&2
  install -m 0755 -o root -g root "$1/hbbs" "$1/hbbr" "$RD_DIR/bin/" &&
    systemctl restart rustdesk-hbbs rustdesk-hbbr || true
}

install_server() {
  local arch zip sha inner b tmp have src changed=false
  case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
  amd64 | x86_64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "no pinned RustDesk server for $(uname -m)" ;;
  esac
  read -r zip sha <<<"${SERVER_ZIP[$arch]}"
  inner=${zip#rustdesk-server-linux-}
  inner=${inner%.zip}
  have=$(cat "$RD_DIR/version" 2>/dev/null || true)
  if [ -n "$ZIP_FILE" ]; then
    # pin version: the sum above also applies to this zip
    [ "$WANT_VER" != "$SERVER_VER" ] || verify "$ZIP_FILE" "$sha" || die "sha256 mismatch: $ZIP_FILE"
    SERVER_VER=$WANT_VER
  elif valid_version "$have" && newer "$have" "$SERVER_VER" &&
    [ -x "$RD_DIR/bin/hbbs" ] && [ -x "$RD_DIR/bin/hbbr" ]; then
    # updated by the RMM, do not reset to the pin
    SERVER_VER=$have
  fi

  echo "=== RustDesk server $SERVER_VER ($arch) ==="
  id -u "$RD_USER" >/dev/null 2>&1 ||
    useradd --system --home-dir "$RD_DIR" --no-create-home --shell /usr/sbin/nologin "$RD_USER"
  install -d -m 0755 -o "$RD_USER" -g "$RD_USER" "$RD_DIR"
  install -d -m 0755 -o root -g root "$RD_DIR/bin"

  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # tmp is meant to expand now
  trap "restore '$tmp/old'; rm -rf '$tmp'" EXIT
  if [ "$(cat "$RD_DIR/version" 2>/dev/null)" != "$SERVER_VER" ] ||
    [ ! -x "$RD_DIR/bin/hbbs" ] || [ ! -x "$RD_DIR/bin/hbbr" ]; then
    if [ -n "$ZIP_FILE" ]; then
      src=$ZIP_FILE
    else
      fetch "https://github.com/rustdesk/rustdesk-server/releases/download/$SERVER_VER/$zip" "$tmp/$zip" "$sha"
      src=$tmp/$zip
    fi
    python3 -m zipfile -e "$src" "$tmp/x"
    for b in hbbs hbbr; do
      install -m 0755 -o root -g root "$tmp/x/$inner/$b" "$RD_DIR/bin/$b.new"
      # not as root: the zip from the RMM has no pinned sum
      [ "$(runuser -u "$RD_USER" -- "$RD_DIR/bin/$b.new" --version 2>/dev/null)" = "$b $SERVER_VER" ] ||
        die "$b does not report version $SERVER_VER"
    done
    if [ -x "$RD_DIR/bin/hbbs" ] && [ -x "$RD_DIR/bin/hbbr" ]; then
      install -d -m 0700 "$tmp/old"
      cp -p "$RD_DIR/bin/hbbs" "$RD_DIR/bin/hbbr" "$tmp/old/"
    fi
    for b in hbbs hbbr; do mv -f "$RD_DIR/bin/$b.new" "$RD_DIR/bin/$b"; done
    changed=true
  else
    echo "  binaries present"
  fi

  for b in hbbs hbbr; do
    render_unit "$b" "$HOST" >"$tmp/rustdesk-$b.service"
    if ! cmp -s "$tmp/rustdesk-$b.service" "$UNIT_DIR/rustdesk-$b.service"; then
      install -m 0644 "$tmp/rustdesk-$b.service" "$UNIT_DIR/rustdesk-$b.service"
      changed=true
    fi
  done
  systemctl daemon-reload

  # the pair from the backup belongs to root. without chown hbbs creates a new
  # one, and the clients do not know the key
  for k in id_ed25519 id_ed25519.pub; do
    [ ! -f "$RD_DIR/$k" ] || chown "$RD_USER:$RD_USER" "$RD_DIR/$k"
  done

  # hbbs first: it creates the key pair, hbbr only reads it
  if $changed; then systemctl restart rustdesk-hbbs; fi
  systemctl enable --now rustdesk-hbbs
  for _ in $(seq 30); do
    [ -s "$RD_DIR/id_ed25519.pub" ] && [ -s "$RD_DIR/id_ed25519" ] && break
    sleep 1
  done
  [ -s "$RD_DIR/id_ed25519.pub" ] || die "hbbs created no key pair (journalctl -u rustdesk-hbbs)"
  chown "$RD_USER:$RD_USER" "$RD_DIR/id_ed25519" "$RD_DIR/id_ed25519.pub"
  chmod 0600 "$RD_DIR/id_ed25519"
  chmod 0644 "$RD_DIR/id_ed25519.pub"
  grep -qxE '[A-Za-z0-9+/]{43}=' "$RD_DIR/id_ed25519.pub" || die "$RD_DIR/id_ed25519.pub is not an ed25519 key"

  if $changed; then systemctl restart rustdesk-hbbr; fi
  systemctl enable --now rustdesk-hbbr
  sleep 2
  systemctl is-active --quiet rustdesk-hbbs || die "rustdesk-hbbs is not running (journalctl -u rustdesk-hbbs)"
  systemctl is-active --quiet rustdesk-hbbr || die "rustdesk-hbbr is not running (journalctl -u rustdesk-hbbr)"
  rm -rf "$tmp/old"
  # the RMM shows the version (remote/utils.py server_version)
  echo "$SERVER_VER" >"$RD_DIR/version"
  chmod 0644 "$RD_DIR/version"

  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 21115:21117/tcp >/dev/null
    ufw allow 21116/udp >/dev/null
    echo "  ufw: 21115-21117/tcp and 21116/udp opened"
  fi
  echo "  running, relay $HOST:21117, key $(cat "$RD_DIR/id_ed25519.pub")"
}

source_txt() {
  printf '%s\n' "RustDesk client $1" "License: AGPL-3.0" \
    "Source: https://github.com/rustdesk/rustdesk/tree/$1" \
    "License text: https://github.com/rustdesk/rustdesk/blob/$1/LICENCE"
}

mirror_clients() {
  local out="$DIST/rustdesk" entry name sha f keep=" "
  if [ -f "$out/manifest.json" ]; then
    echo "=== RustDesk client: $out is managed by the RMM (manifest.json), left as is ==="
    return
  fi
  echo "=== RustDesk client $CLIENT_VER to $out ==="
  [ -d "$DIST" ] || die "$DIST missing - run riddix/agents/build_agents.sh first"
  install -d -m 0755 "$out"
  for entry in "${CLIENT_FILES[@]}"; do
    read -r name sha <<<"$entry"
    keep+="$name "
    if [ -f "$out/$name" ] && verify "$out/$name" "$sha"; then
      echo "  present: $name"
      continue
    fi
    fetch "https://github.com/rustdesk/rustdesk/releases/download/$CLIENT_VER/$name" "$out/$name" "$sha"
    chmod 0644 "$out/$name"
  done
  # files of old versions and aborted downloads
  for f in "$out"/rustdesk-*; do
    [ -e "$f" ] || continue
    case "$keep" in *" ${f##*/} "*) ;; *) rm -f "$f" && echo "  removed: ${f##*/}" ;; esac
  done
  # the client is AGPL-3.0, same text as SOURCE_TXT in remote/tasks.py
  source_txt "$CLIENT_VER" >"$out/SOURCE.txt.part"
  chmod 0644 "$out/SOURCE.txt.part"
  mv -f "$out/SOURCE.txt.part" "$out/SOURCE.txt"
  chown -R --reference="$DIST" "$out"
}

selftest() {
  local entry name sha h tmp
  for entry in "${SERVER_ZIP[@]}" "${CLIENT_FILES[@]}"; do
    read -r name sha <<<"$entry"
    [[ $sha =~ ^[0-9a-f]{64}$ ]] || die "selftest: sha256 for $name"
  done
  for entry in "${CLIENT_FILES[@]}"; do
    [[ $entry == "rustdesk-$CLIENT_VER"[-.]* ]] || die "selftest: $entry does not match $CLIENT_VER"
  done
  for h in 1.1.16 1.4.10 10.0.0.1; do valid_version "$h" || die "selftest: version $h rejected"; done
  for h in "" v1.1.16 1 "1.1;id" 1.1.16-1 "1.1 2"; do
    ! valid_version "$h" || die "selftest: version '$h' accepted"
  done
  newer 1.1.17 1.1.16 && newer 1.4.10 1.4.9 || die "selftest: newer"
  ! newer 1.1.16 1.1.16 && ! newer 1.1.9 1.1.16 || die "selftest: newer"
  for h in rmm.example.com 192.168.178.3 a; do
    valid_host "$h" || die "selftest: $h rejected"
  done
  # shellcheck disable=SC2016  # '$(id)' must arrive literally
  for h in "" "a b" "x;y" "-bad" "bad-" "host:21116" "a'b" '$(id)'; do
    ! valid_host "$h" || die "selftest: '$h' accepted"
  done
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  render_unit hbbs rd.example.com >"$tmp/hbbs"
  render_unit hbbr rd.example.com >"$tmp/hbbr"
  grep -qx 'ExecStart=/opt/rustdesk/bin/hbbs -k _ -r rd.example.com:21117' "$tmp/hbbs" || die "selftest: hbbs unit"
  grep -qx 'ExecStart=/opt/rustdesk/bin/hbbr -k _' "$tmp/hbbr" || die "selftest: hbbr unit"
  ! grep -q '@' "$tmp/hbbs" "$tmp/hbbr" || die "selftest: placeholder left over"
  echo "selftest ok"
}

ARGS=("$@")
HOST=''
WANT_VER=''
ZIP_FILE=''
DIST=${AGENTS_DIST_DIR:-/opt/ulrmm-agents/dist}
while [ $# -gt 0 ]; do
  case "$1" in
  --selftest)
    selftest
    exit 0
    ;;
  --host | --dist | --server-version | --server-zip)
    [ $# -gt 1 ] || die "$1 needs a value"
    case "$1" in
    --host) HOST=$2 ;;
    --dist) DIST=$2 ;;
    --server-version) WANT_VER=$2 ;;
    --server-zip) ZIP_FILE=$2 ;;
    esac
    shift
    ;;
  --host=*) HOST=${1#*=} ;;
  --dist=*) DIST=${1#*=} ;;
  --server-version=*) WANT_VER=${1#*=} ;;
  --server-zip=*) ZIP_FILE=${1#*=} ;;
  *) die "unknown option: $1 (allowed: --host, --dist, --server-version, --server-zip, --selftest)" ;;
  esac
  shift
done

valid_host "$HOST" || die "--host needs a name or an IP without port, got '$HOST'"
if [ -n "$WANT_VER$ZIP_FILE" ]; then
  [ -n "$WANT_VER" ] && [ -n "$ZIP_FILE" ] || die "--server-version and --server-zip only together"
  valid_version "$WANT_VER" || die "--server-version: '$WANT_VER' is not a version number"
  [ -f "$ZIP_FILE" ] || die "--server-zip: $ZIP_FILE missing"
fi
[ "$(id -u)" -eq 0 ] || exec sudo -- bash "$0" "${ARGS[@]}"

install_server
# --server-zip: server only. The RMM mirrors the clients.
[ -n "$ZIP_FILE" ] || mirror_clients
echo "=== done ==="
echo "  forward these ports on the router (later): TCP 21115-21117, UDP 21116"
echo "  Global Settings > RustDesk: ID server $HOST, the client config string is shown there too"

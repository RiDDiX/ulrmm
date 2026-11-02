# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# shellcheck shell=bash
# Signatures for the self-built agents. Sourced by build_agents.sh and can
# be sourced and tested on its own.
#
# Off as long as nothing is configured. Configured via env or
# local_settings.py (py_setting from build_agents.sh):
#   ULRMM_SIGN_WIN_PFX          PKCS#12 with Authenticode certificate and key
#   ULRMM_SIGN_WIN_PASS_FILE    file holding only the PFX password
#   ULRMM_SIGN_MAC_P12          PKCS#12 with Developer ID Application or own certificate
#   ULRMM_SIGN_MAC_PASS_FILE    file holding only the P12 password
#   ULRMM_NOTARY_API_KEY_FILE   JSON from "rcodesign encode-app-store-connect-api-key"
#   ULRMM_SIGN_TIMESTAMP_URL    RFC 3161 timestamp service (optional, outbound connection)
#
# Passwords only as files: on the command line they would be readable by
# anyone in the process list.

RCODESIGN_VER=0.29.0

sign_setup() {
  SIGN_WIN_PFX=${ULRMM_SIGN_WIN_PFX:-$(py_setting ULRMM_SIGN_WIN_PFX)}
  SIGN_WIN_PASS_FILE=${ULRMM_SIGN_WIN_PASS_FILE:-$(py_setting ULRMM_SIGN_WIN_PASS_FILE)}
  SIGN_MAC_P12=${ULRMM_SIGN_MAC_P12:-$(py_setting ULRMM_SIGN_MAC_P12)}
  SIGN_MAC_PASS_FILE=${ULRMM_SIGN_MAC_PASS_FILE:-$(py_setting ULRMM_SIGN_MAC_PASS_FILE)}
  NOTARY_API_KEY_FILE=${ULRMM_NOTARY_API_KEY_FILE:-$(py_setting ULRMM_NOTARY_API_KEY_FILE)}
  SIGN_TIMESTAMP_URL=${ULRMM_SIGN_TIMESTAMP_URL:-$(py_setting ULRMM_SIGN_TIMESTAMP_URL)}

  # fail before building, not after a ten minute build
  if [ -n "$SIGN_WIN_PFX" ]; then
    [ -r "$SIGN_WIN_PFX" ] || die "ULRMM_SIGN_WIN_PFX not readable: $SIGN_WIN_PFX"
    [ -r "$SIGN_WIN_PASS_FILE" ] || die "ULRMM_SIGN_WIN_PASS_FILE not readable"
    command -v osslsigncode >/dev/null 2>&1 ||
      die "osslsigncode missing (Debian/Ubuntu: apt install osslsigncode)"
  fi

  RCODESIGN=""
  if [ -n "$SIGN_MAC_P12" ]; then
    [ -r "$SIGN_MAC_P12" ] || die "ULRMM_SIGN_MAC_P12 not readable: $SIGN_MAC_P12"
    [ -r "$SIGN_MAC_PASS_FILE" ] || die "ULRMM_SIGN_MAC_PASS_FILE not readable"
    if [ -n "$NOTARY_API_KEY_FILE" ]; then
      [ -r "$NOTARY_API_KEY_FILE" ] || die "ULRMM_NOTARY_API_KEY_FILE not readable"
    fi
    [ -n "${ARTIFACT:-}" ] || die "ARTIFACT missing: the macOS signature needs the identifier"
    rcodesign_install
  fi
}

# pinned version with checksum, like the Go toolchain
rcodesign_install() {
  local arch sha dir tgz tmp
  case "$(uname -m)" in
  x86_64 | amd64)
    arch=x86_64
    sha=dbe85cedd8ee4217b64e9a0e4c2aef92ab8bcaaa41f20bde99781ff02e600002
    ;;
  aarch64 | arm64)
    arch=aarch64
    sha=4af92c87ddf52f5f2d1258a3b4e56c7dcb8f1b2468df744976c5f139e031961f
    ;;
  *) die "no pinned rcodesign sha256 for $(uname -m)" ;;
  esac
  dir="$ROOT/tools/apple-codesign-$RCODESIGN_VER-$arch-unknown-linux-musl"
  RCODESIGN="$dir/rcodesign"
  [ -x "$RCODESIGN" ] && return 0

  tgz="apple-codesign-$RCODESIGN_VER-$arch-unknown-linux-musl.tar.gz"
  tmp=$(mktemp -d)
  curl -fsSL --max-time 300 -o "$tmp/$tgz" \
    "https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign/$RCODESIGN_VER/$tgz" ||
    { rm -rf "$tmp"; die "rcodesign download failed"; }
  echo "$sha  $tmp/$tgz" | sha256sum -c - >/dev/null ||
    { rm -rf "$tmp"; die "rcodesign sha256 mismatch"; }
  mkdir -p "$ROOT/tools"
  tar -C "$ROOT/tools" -xzf "$tmp/$tgz"
  rm -rf "$tmp"
  [ -x "$RCODESIGN" ] || die "rcodesign not found after unpacking"
}

# Authenticode; replaces the file only once the signature is verifiably in it
sign_win() {
  [ -n "${SIGN_WIN_PFX:-}" ] || return 0
  local f=$1 out="$1.signed"
  local ts=()
  if [ -n "$SIGN_TIMESTAMP_URL" ]; then
    ts=(-ts "$SIGN_TIMESTAMP_URL")
  fi
  rm -f "$out"
  osslsigncode sign -pkcs12 "$SIGN_WIN_PFX" -readpass "$SIGN_WIN_PASS_FILE" \
    -h sha256 "${ts[@]}" -in "$f" -out "$out" >/dev/null ||
    { rm -f "$out"; die "Authenticode signature for $(basename "$f") failed"; }
  osslsigncode extract-signature -in "$out" -out "$out.p7" >/dev/null 2>&1 ||
    { rm -f "$out" "$out.p7"; die "$(basename "$f") carries no signature after signing"; }
  rm -f "$out.p7"
  mv -f "$out" "$f"
  echo "  signed (Authenticode): $(basename "$f")"
}

# Signature with hardened runtime. TCC grants (e.g. Full Disk Access) are
# tied to identifier and certificate and survive updates. Ad-hoc is tied to
# the cdhash and is gone after every build. Go otherwise carries "a.out".
sign_mac() {
  [ -n "${SIGN_MAC_P12:-}" ] || return 0
  local f=$1 ts=()
  if [ -n "$SIGN_TIMESTAMP_URL" ]; then
    ts=(--timestamp-url "$SIGN_TIMESTAMP_URL")
  fi
  "$RCODESIGN" sign --p12-file "$SIGN_MAC_P12" --p12-password-file "$SIGN_MAC_PASS_FILE" \
    --binary-identifier "$ARTIFACT" --code-signature-flags runtime "${ts[@]}" "$f" >/dev/null 2>&1 ||
    die "macOS signature for $(basename "$f") failed (P12 from OpenSSL 3? rcodesign reads only the legacy format: openssl pkcs12 -export -legacy)"
  "$RCODESIGN" verify "$f" >/dev/null 2>&1 ||
    die "macOS signature of $(basename "$f") does not verify"
  echo "  signed (macOS, $ARTIFACT): $(basename "$f")"

  if [ -n "$NOTARY_API_KEY_FILE" ]; then
    # Apple accepts single binaries only as a zip. Stapling does not work on
    # a bare binary; Gatekeeper asks for the ticket online.
    local zip="$f.zip"
    "$PY" -c 'import sys, zipfile, os
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.write(sys.argv[2], os.path.basename(sys.argv[2]))' "$zip" "$f" ||
      die "zip for notarization of $(basename "$f") failed"
    "$RCODESIGN" notary-submit --api-key-path "$NOTARY_API_KEY_FILE" --wait "$zip" >/dev/null 2>&1 ||
      { rm -f "$zip"; die "notarization of $(basename "$f") rejected or failed"; }
    rm -f "$zip"
    echo "  notarized: $(basename "$f")"
  fi
}

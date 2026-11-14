#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Builds the UniversalLocal RMM agents and puts them where nginx serves
# /agentdist/. Runs as the install user, without sudo. The Go toolchain lives
# under $ROOT/go (riddix/scripts/go_toolchain.sh), /usr/local/go is left alone.
set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Configuration
ULRMM_API_DIR=${ULRMM_API_DIR:-/rmm/api/ulrmm}
SETTINGS="$ULRMM_API_DIR/ulrmm/settings.py"
LOCAL_SETTINGS="$ULRMM_API_DIR/ulrmm/local_settings.py"

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "  WARNING: $*" >&2; }

# NAME = "value" from local_settings.py, else settings.py.
# Must always return 0: "VAR=${VAR:-$(py_setting X)}" would otherwise end the
# script under "set -e" as soon as the key is missing.
py_setting() {
  local f v
  for f in "$LOCAL_SETTINGS" "$SETTINGS"; do
    [ -r "$f" ] || continue
    v=$(sed -n "s/^$1[[:space:]]*=[[:space:]]*[\"']\([^\"']*\)[\"'].*/\1/p" "$f" | tail -1)
    [ -n "$v" ] && { printf '%s' "$v"; return 0; }
  done
  return 0
}

AGENT_VER=${AGENT_VER:-$(py_setting LATEST_AGENT_VER)}
# Artifact name = identity. The server builds the download URL from it
# (agent_ident.agent_artifact), the agent recognizes itself by it.
# If it differs, update and self-healing go nowhere.
ARTIFACT=$(py_setting AGENT_ARTIFACT_NAME)
ARTIFACT=${ARTIFACT:-ulrmm-agent}
ROOT=${ULRMM_AGENT_ROOT:-/opt/ulrmm-agents}
DIST=${DIST:-$ROOT/dist}
SRC=${SRC:-$ROOT/src}
# The agent source is its own repo. Without ULRMM_AGENT_GIT_URL it sits next to
# the server repo (ULRMM_GIT_URL with ulrmm-agent.git as the last path part).
AGENT_GIT_URL=${ULRMM_AGENT_GIT_URL:-$(py_setting ULRMM_AGENT_GIT_URL)}
if [ -z "$AGENT_GIT_URL" ]; then
  srv_url=$(py_setting ULRMM_GIT_URL)
  if [ -n "$srv_url" ]; then
    AGENT_GIT_URL="${srv_url%/*}/ulrmm-agent.git"
  fi
fi
AGENT_GIT_REF=${ULRMM_AGENT_GIT_REF:-$(py_setting ULRMM_AGENT_GIT_REF)}
AGENT_GIT_REF=${AGENT_GIT_REF:-main}
# The Python zips of the Windows agents: release "python" of the agent repo
PY_ZIP_URL=${ULRMM_PY_ZIP_URL:-$(py_setting ULRMM_PY_ZIP_URL)}
PY_ZIP_URL=${PY_ZIP_URL:-${AGENT_GIT_URL%.git}/releases/download/python}
# Choco install script for Windows agents, pinned to this SHA256
CHOCO_URL=${ULRMM_CHOCO_URL:-https://community.chocolatey.org/install.ps1}
CHOCO_SHA256=${ULRMM_CHOCO_SHA256:-44e045ed5350758616d664c5af631e7f2cd10165f5bf2bd82cbf3a0bb8f63462}
PY=${ULRMM_PY:-}
[ -n "$PY" ] || { PY=$(dirname "$ULRMM_API_DIR")/env/bin/python; [ -x "$PY" ] || PY=python3; }

# Only one run at a time: $SRC, $GODIR and $DIST are shared, parallel runs
# (update.sh + cron) would reset each other's source tree and serve
# half-written binaries.
mkdir -p "$ROOT"
exec 9>"$ROOT/.build.lock"
flock -n 9 || die "an agent build is already running"

[ -n "$AGENT_GIT_URL" ] || die "neither ULRMM_AGENT_GIT_URL nor ULRMM_GIT_URL is set"
[[ $AGENT_GIT_URL != *@* ]] || die "ULRMM_AGENT_GIT_URL must not carry credentials, the token comes from ULRMM_GIT_TOKEN"
[[ $AGENT_GIT_REF =~ ^[A-Za-z0-9._/-]+$ ]] || die "ULRMM_AGENT_GIT_REF '$AGENT_GIT_REF' is not a branch or tag name"
[ -n "$AGENT_VER" ] || die "AGENT_VER is empty and LATEST_AGENT_VER cannot be read from $SETTINGS"
# X.DD.MM.YYYY, X is the release number of the day. Windows takes at most
# four numbers up to 65535, hence YYYY.M.D.X (1.23.09.2026 -> 2026.9.23.1).
if ! [[ $AGENT_VER =~ ^([1-9][0-9]*)\.([0-9]{2})\.([0-9]{2})\.([0-9]{4})$ ]] ||
  ! date -d "${BASH_REMATCH[4]}-${BASH_REMATCH[3]}-${BASH_REMATCH[2]}" >/dev/null 2>&1; then
  die "AGENT_VER '$AGENT_VER' is not X.DD.MM.YYYY with a valid date"
fi
AGENT_NUMVER="${BASH_REMATCH[4]}.$((10#${BASH_REMATCH[3]})).$((10#${BASH_REMATCH[2]})).${BASH_REMATCH[1]}"
[[ $ARTIFACT =~ ^[A-Za-z0-9._-]+$ ]] || die "AGENT_ARTIFACT_NAME '$ARTIFACT' is not a file name"

POSIX_TARGETS="linux/amd64 linux/386 linux/arm64 linux/arm darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64"
WIN_ARCHS="amd64 386"
# Windows setup: makensis with build/setup.nsi, or iscc with build/setup.iss
# (Inno Setup under Wine, kept as the way back)
WIN_PACKER=${ULRMM_WIN_PACKER:-$(py_setting ULRMM_WIN_PACKER)}
WIN_PACKER=${WIN_PACKER:-nsis}
case $WIN_PACKER in
nsis) WIN_PACKER_BIN=makensis ;;
inno) WIN_PACKER_BIN=iscc ;;
*) die "ULRMM_WIN_PACKER '$WIN_PACKER' is neither nsis nor inno" ;;
esac

echo "=== Configuration ==="
printf '  %-18s %s\n' AGENT_VER "$AGENT_VER ($AGENT_NUMVER)" ARTIFACT "$ARTIFACT" AGENT_SRC "$AGENT_GIT_URL@$AGENT_GIT_REF" SRC "$SRC" DIST "$DIST" GO "$ROOT/go" PYTHON "$PY" WIN_PACKER "$WIN_PACKER"

# shellcheck source=riddix/agents/sign.sh
. "$SELF_DIR/sign.sh"
sign_setup
printf '  %-18s %s\n' SIGN_WINDOWS "${SIGN_WIN_PFX:+yes}" SIGN_MACOS "${SIGN_MAC_P12:+yes}" NOTARIZE "${NOTARY_API_KEY_FILE:+yes}"

# Go toolchain
# shellcheck source=riddix/scripts/go_toolchain.sh
. "$SELF_DIR/../scripts/go_toolchain.sh"
echo "=== Go $GO_VER ==="
go_toolchain || die "Go toolchain not available"
export GOFLAGS=-mod=mod CGO_ENABLED=0

# Source code
echo "=== Source ==="
# Token via GIT_ASKPASS as in update.sh, never in argv, URL or .git/config.
# Only git and the Python mirror see it, the Go build and write_brand.py do not.
AGENT_GIT_TOKEN=$(py_setting ULRMM_GIT_TOKEN)
AGENT_GIT_USER=$(py_setting ULRMM_GIT_USER)
url_host() { local h=${1#*://}; h=${h%%/*}; printf '%s' "${h,,}"; }
# The token belongs to the host of ULRMM_GIT_URL; if the agent repo lives
# elsewhere, it does not get it.
tok_url=$(py_setting ULRMM_GIT_URL)
[ "$(url_host "$AGENT_GIT_URL")" = "$(url_host "${tok_url:-$AGENT_GIT_URL}")" ] || AGENT_GIT_TOKEN=''
ASKPASS=''
if [ -n "$AGENT_GIT_TOKEN" ]; then
  ASKPASS=$(mktemp)
  chmod 700 "$ASKPASS"
  cat >"$ASKPASS" <<'EOF_ASKPASS'
#!/bin/sh
case "$1" in
*[Uu]sername*) printf '%s\n' "${ULRMM_ASKPASS_USER:-git}" ;;
*) printf '%s\n' "${ULRMM_ASKPASS_TOKEN}" ;;
esac
EOF_ASKPASS
fi
agit() {
  if [ -n "$ASKPASS" ]; then
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" ULRMM_ASKPASS_USER="$AGENT_GIT_USER" \
      ULRMM_ASKPASS_TOKEN="$AGENT_GIT_TOKEN" git -c credential.helper= "$@"
  else
    GIT_TERMINAL_PROMPT=0 git -c credential.helper= "$@"
  fi
}
fetch_ok=yes
if [ -d "$SRC/.git" ]; then
  git -C "$SRC" remote set-url origin "$AGENT_GIT_URL"
  agit -C "$SRC" fetch -q --tags --prune --force origin \
    "+refs/heads/*:refs/remotes/origin/*" || fetch_ok=no
else
  mkdir -p "$(dirname "$SRC")"
  agit clone -q "$AGENT_GIT_URL" "$SRC" || fetch_ok=no
fi
[ -z "$ASKPASS" ] || rm -f "$ASKPASS"
[ "$fetch_ok" = yes ] || die "cannot fetch agent repo $AGENT_GIT_URL (check ULRMM_GIT_TOKEN)"

if git -C "$SRC" rev-parse -q --verify "refs/remotes/origin/$AGENT_GIT_REF^{commit}" >/dev/null; then
  REF="refs/remotes/origin/$AGENT_GIT_REF"
elif git -C "$SRC" rev-parse -q --verify "refs/tags/$AGENT_GIT_REF^{commit}" >/dev/null; then
  REF="refs/tags/$AGENT_GIT_REF"
else
  die "no branch or tag '$AGENT_GIT_REF' in the agent repo"
fi
# The version is in main.go. If it differs from LATEST_AGENT_VER, the agent
# reports the old version after the update and gets updated again every hour.
src_ver=$(git -C "$SRC" show "$REF:main.go" | sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9.]*\)".*/\1/p' | head -1) || src_ver=''
[ "$src_ver" = "$AGENT_VER" ] ||
  die "agent repo $AGENT_GIT_REF has version '${src_ver:-?}', LATEST_AGENT_VER is $AGENT_VER"
# Leftovers of an earlier run (generated files, formerly the brand patch)
# would block the checkout
git -C "$SRC" reset -q --hard
git -C "$SRC" clean -qfdx
git -C "$SRC" checkout -q --detach "$REF"
git -C "$SRC" reset -q --hard "$REF"
git -C "$SRC" clean -qfdx
echo "  $REF -> $(git -C "$SRC" rev-parse --short HEAD)"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Python mirror
# Windows agents fetch their Python from <agentdist>/python and check it
# against agent/pyzip.go. The same table says which zips belong in
# $DIST/python. Errors here are warnings: without a zip only the Python
# install on the Windows agent fails.
mirror_python() {
  local dir="$DIST/python" auth=() cfg='' name sha part want=0 have=0
  mkdir -p "$dir"
  # the token only via https to the host of the agent repo, and never in argv
  if [ -n "$AGENT_GIT_TOKEN" ] && [[ $PY_ZIP_URL == https://* ]] &&
    [ "$(url_host "$PY_ZIP_URL")" = "$(url_host "$AGENT_GIT_URL")" ]; then
    cfg="$TMP/py-curl.cfg"
    (
      umask 077
      t=${AGENT_GIT_TOKEN//\\/\\\\}
      printf 'user = "%s:%s"\n' "${AGENT_GIT_USER:-git}" "$t" >"$cfg"
    )
    auth=(-K "$cfg")
  fi
  while read -r name sha; do
    want=$((want + 1))
    if [ -f "$dir/$name" ] && echo "$sha  $dir/$name" | sha256sum -c --status -; then
      have=$((have + 1))
      continue
    fi
    part="$dir/.$name.$$.part"
    if curl -fsSL --max-time 900 "${auth[@]}" -o "$part" "$PY_ZIP_URL/$name" &&
      echo "$sha  $part" | sha256sum -c --status -; then
      chmod 0644 "$part"
      mv -f "$part" "$dir/$name"
      have=$((have + 1))
      echo "  downloaded: $name"
    else
      rm -f "$part"
      warn "$name not downloadable or sha256 mismatch ($PY_ZIP_URL/$name)"
    fi
  done < <(sed -n 's/^[[:space:]]*"\(py[0-9.]*_[a-z0-9]*\.zip\)":[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1 \2/p' "$SRC/agent/pyzip.go")
  [ -z "$cfg" ] || rm -f "$cfg"
  echo "  $have of $want Python zips in $dir"
  if [ "$have" -eq 0 ]; then
    warn "================================================================"
    warn "NO Python zip in $dir - Windows agents cannot install Python"
    warn "until the zips are there ($PY_ZIP_URL, ULRMM_PY_ZIP_URL)"
    warn "================================================================"
  fi
}
echo "=== Python mirror ==="
mirror_python

# Choco mirror
# The script runs on Windows agents as SYSTEM. The server tells them URL and
# SHA256 of $DIST/chocolatey-install.ps1 (apiv3 config); without the file they
# load it unchecked from chocolatey.org as before. If Chocolatey changes the
# script, the check fails and the old file stays: bump ULRMM_CHOCO_SHA256
# after reviewing the new version.
mirror_choco() {
  local f="$DIST/chocolatey-install.ps1" part
  mkdir -p "$DIST"
  if [ -f "$f" ] && echo "$CHOCO_SHA256  $f" | sha256sum -c --status -; then
    echo "  chocolatey-install.ps1 up to date"
    return 0
  fi
  part="$DIST/.chocolatey-install.ps1.$$.part"
  if curl -fsSL --max-time 120 -o "$part" "$CHOCO_URL" &&
    echo "$CHOCO_SHA256  $part" | sha256sum -c --status -; then
    chmod 0644 "$part"
    mv -f "$part" "$f"
    echo "  downloaded: chocolatey-install.ps1"
  else
    rm -f "$part"
    warn "Chocolatey install script not downloadable or sha256 mismatch ($CHOCO_URL)"
  fi
}
echo "=== Chocolatey mirror ==="
mirror_choco
unset AGENT_GIT_TOKEN

# Branding
echo "=== Branding ==="
"$PY" "$SELF_DIR/write_brand.py" "$SRC" || die "write_brand.py failed"
# brand.go is the identity. If IdentArtifact differs from $ARTIFACT, the agent
# gets a foreign binary on update.
grep -qE "^[[:space:]]*IdentArtifact[[:space:]]*=[[:space:]]*\"$ARTIFACT\"$" "$SRC/agent/brand.go" ||
  die "brand.go does not carry the identity '$ARTIFACT' (AGENT_ARTIFACT_NAME)"
# Key of the enrollment tokens, as it is in the build (empty without ENROLL_SIGNING_KEY)
ENROLL_PUBKEY=$(sed -n 's|^[[:space:]]*BrandEnrollPubKey[[:space:]]*=[[:space:]]*"\([A-Za-z0-9+/=]*\)"$|\1|p' "$SRC/agent/brand.go")

# Build
echo "=== Linux/macOS/FreeBSD ==="
for t in $POSIX_TARGETS; do
  goos=${t%/*}; goarch=${t#*/}
  out="$TMP/$ARTIFACT-v$AGENT_VER-$goos-$goarch"
  ( cd "$SRC" && env GOOS="$goos" GOARCH="$goarch" "$GO" build -trimpath -buildvcs=false -ldflags "-s -w" -o "$out" . ) \
    || die "build $goos/$goarch failed"
  printf '  %-46s %s\n' "$(basename "$out")" "$(du -h "$out" | cut -f1)"
  if [ "$goos" = darwin ]; then
    sign_mac "$out"
  fi
done

# The file name says v$AGENT_VER - the binary must report the same. Otherwise
# the server updates the agent again every hour because the reported version
# never reaches the target.
selfcheck="$TMP/$ARTIFACT-v$AGENT_VER-linux-$GO_HOST"
if [ "$(uname -s)" = Linux ] && [ -x "$selfcheck" ]; then
  # -version prints the whole module graph from line 2 on, with dependency
  # versions. Only the first line ("<Name> Agent: 1.23.09.2026") counts.
  # Read the output completely: "| head -1" closes the pipe, the binary gets
  # SIGPIPE, and pipefail passes the 141 on to set -e.
  verout=$("$selfcheck" -version 2>/dev/null) || verout=''
  reported=${verout%%$'\n'*}
  reported=${reported##*: }
  [ "$reported" = "$AGENT_VER" ] ||
    die "built binary reports version '${reported:-?}', would ship as v$AGENT_VER"
  echo "  version check: $reported"
fi

# Windows
# The installer is built with makensis (package nsis, any architecture), or
# with iscc for ULRMM_WIN_PACKER=inno (install-innosetup.sh, x86_64 only).
# Without the packer there is only Linux/macOS/FreeBSD.
echo "=== Windows ==="
if ! command -v "$WIN_PACKER_BIN" >/dev/null 2>&1; then
  WIN_ARCHS=''
  hint="apt-get install nsis"
  [ "$WIN_PACKER" = nsis ] || hint="riddix/agents/install-innosetup.sh, x86_64 only"
  warn "================================================================"
  warn "no $WIN_PACKER_BIN found - Windows agents are NOT built. Windows"
  warn "endpoints get no update from this server until a build with"
  warn "$WIN_PACKER_BIN succeeds ($hint)."
  warn "================================================================"
elif [ "$WIN_PACKER" = nsis ]; then
  # Setup stubs before NSIS 3.09 lack the fix for CVE-2023-37378 (the
  # uninstaller's temporary directory); Debian 12 carries it in
  # 3.08-3+deb12u1. Older runtimes (Ubuntu 22.04: 3.08-2) still build,
  # and no newer package exists for them, so the warning only states it.
  nsis_ver=$(makensis -VERSION 2>/dev/null) || nsis_ver=''
  nsis_ver=${nsis_ver#v}
  if ! printf '%s\n' 3.09 "$nsis_ver" | sort -VC; then
    nsis_pkg=$(dpkg-query -W -f='${Version}' nsis-common 2>/dev/null) || nsis_pkg=''
    if [ -z "$nsis_pkg" ] || ! dpkg --compare-versions "$nsis_pkg" ge 3.08-3+deb12u1; then
      warn "NSIS ${nsis_ver:-?} (package ${nsis_pkg:-none}) lacks the fix for CVE-2023-37378 (the uninstaller's temporary directory) that NSIS 3.09 and Debian's 3.08-3+deb12u1 carry; the Windows setups built here have that flaw"
    fi
  fi
fi
# shellcheck disable=SC1091
. "$SRC/build/brand.env"
# setup.nsi builds one path element below Program Files from the first two
# and refuses \ / :, makensis stops on * ? < > | in the file name. A backtick
# ends a string in setup.nsi, and makensis reads "$$\r" as "$" plus a carriage
# return. The value is kept: another one would give installed agents another
# identity.
if [ -n "$WIN_ARCHS" ] && [ "$WIN_PACKER" = nsis ]; then
  for s in "AGENT_WIN_PROG_DIR=$ISCC_PROG_DIR" "AGENT_WIN_EXE=$ISCC_EXE_NAME" \
    "AGENT_SVC_NAME=$ISCC_SVC_NAME" "AGENT_WIN_REG_KEY=$ISCC_REG_KEY"; do
    case $s in
    *\`* | *\$\\*) why='holds a ` or a \ after a $' ;;
    AGENT_WIN_PROG_DIR=*[\\/:*?\<\>\|]* | AGENT_WIN_EXE=*[\\/:*?\<\>\|]*)
      why='holds one of \ / : * ? < > |' ;;
    *) continue ;;
    esac
    WIN_ARCHS=''
    warn "================================================================"
    warn "${s%%=*} '${s#*=}' $why - Windows agents"
    warn "are NOT built with makensis. Windows endpoints get no update from"
    warn "this server until a build with ULRMM_WIN_PACKER=inno succeeds; that"
    warn "keeps the identity of installed agents. Changing the setting gives"
    warn "new installs another identity and is only for servers without"
    warn "Windows agents under that name."
    warn "================================================================"
    break
  done
fi
# The .syso holds version strings and the manifest with requireAdministrator
# (versioninfo.json -> build/rmm.exe.manifest). Without the manifest the agent
# does not request elevation. Do not ship the installer then.
if [ -n "$WIN_ARCHS" ] &&
  ! "$GO" install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1 >/dev/null 2>&1; then
  die "goversioninfo cannot be installed - no Windows agent is built without the manifest"
fi
# makensis reads "$" in a define as a variable, "$$" is a literal one
nsis_defs=()
for d in "MyAppName=$ISCC_APP_NAME" "MyAppPublisher=$ISCC_PUBLISHER" "MyAppURL=$ISCC_URL" \
  "MyAppVersion=$AGENT_VER" "MyAppNumVersion=$AGENT_NUMVER" "MyAppId=$ISCC_APP_ID" "MyAppExeName=$ISCC_EXE_NAME" \
  "MyAppSvcName=$ISCC_SVC_NAME" "MyAppProgDir=$ISCC_PROG_DIR" "MyAppRegKey=$ISCC_REG_KEY"; do
  nsis_defs+=("-D${d//\$/\$\$}")
done
for a in $WIN_ARCHS; do
  f="$ARTIFACT-v$AGENT_VER-windows-$a.exe"
  rm -f "$SRC/resource_windows.syso"
  "$PY" - "$SRC" "$AGENT_VER" "$AGENT_NUMVER" "$ISCC_APP_NAME" "$ISCC_PUBLISHER" "$ISCC_EXE_NAME" <<'PYVI'
import json, os, sys
src, ver, numver, name, publisher, exe = sys.argv[1:7]
p = os.path.join(src, "versioninfo.json")
vi = json.load(open(p, encoding="utf-8"))
sfi = vi["StringFileInfo"]
sfi.update(CompanyName=publisher, FileDescription=name, ProductName=name,
           InternalName=exe, OriginalFilename=exe,
           LegalCopyright=f"Copyright (c) {publisher}",
           FileVersion=f"v{ver}", ProductVersion=f"v{ver}")
major, minor, patch, build = (int(x) for x in numver.split("."))
for key in ("FileVersion", "ProductVersion"):
    vi["FixedFileInfo"][key].update(Major=major, Minor=minor, Patch=patch, Build=build)
ico = os.path.join(src, "build", "brand.ico")
if os.path.exists(ico):
    vi["IconPath"] = "build/brand.ico"
else:
    vi.pop("IconPath", None)
json.dump(vi, open(p, "w", encoding="utf-8"), indent=2)
PYVI
  bits=-64
  if [ "$a" = 386 ]; then bits=""; fi
  # shellcheck disable=SC2086
  ( cd "$SRC" && goversioninfo $bits -o resource_windows.syso ) || warn "goversioninfo $a failed"
  ( cd "$SRC" && env GOOS=windows GOARCH="$a" "$GO" build -trimpath -buildvcs=false -ldflags "-s -w" -o agent.exe . ) \
    || die "Windows build $a failed"
  # the program inside the installer gets the same signature as the installer
  sign_win "$SRC/agent.exe"
  # sha256 of the program inside the installer; installed agents check
  # themselves against it (deploy/integrity.py); published with the installer
  sha256sum "$SRC/agent.exe" | cut -d' ' -f1 >"$TMP/$f.agent.sha256"

  if [ "$WIN_PACKER" = nsis ]; then
    # -WX: a warning (an unknown "$" variable, a missing file) fails the build;
    # the UTF-8 locale lets makensis read non-ASCII brand values from argv
    out="$TMP/$f"
    ( cd "$SRC" && LC_ALL=C.UTF-8 makensis -V2 -WX -INPUTCHARSET UTF8 "-DOutFile=${out//\$/\$\$}" \
      "${nsis_defs[@]}" build/setup.nsi ) || die "makensis ($a) failed"
  else
    ( cd "$SRC" && iscc build/setup.iss "/Fwin-$a" \
      "/DMyAppName=$ISCC_APP_NAME" "/DMyAppPublisher=$ISCC_PUBLISHER" "/DMyAppURL=$ISCC_URL" \
      "/DMyAppVersion=$AGENT_VER" "/DMyAppNumVersion=$AGENT_NUMVER" "/DMyAppId=$ISCC_APP_ID" "/DMyAppExeName=$ISCC_EXE_NAME" \
      "/DMyAppSvcName=$ISCC_SVC_NAME" "/DMyAppProgDir=$ISCC_PROG_DIR" "/DMyAppRegKey=$ISCC_REG_KEY" >/dev/null ) || die "ISCC ($a) failed"
    mv "$SRC/build/Output/win-$a.exe" "$TMP/$f"
  fi
  printf '  %-46s %s (self-built)\n' "$f" "$(du -h "$TMP/$f" | cut -f1)"
done
rm -f "$SRC/agent.exe" "$SRC/resource_windows.syso"

for a in $WIN_ARCHS; do
  f="$TMP/$ARTIFACT-v$AGENT_VER-windows-$a.exe"
  if [ -s "$f" ]; then
    sign_win "$f"
  fi
done

# Publish
# Move into $DIST only after a successful build, and there via mv, so a half
# file is never served while an agent is pulling.
# Check what THIS run built first. Looking at $DIST would let an old file
# from an earlier run pass as success.
echo "=== Result ==="
expected=$POSIX_TARGETS
for a in $WIN_ARCHS; do expected+=" windows/$a.exe windows/$a.exe.agent.sha256"; done
missing=0
for t in $expected; do
  f="$ARTIFACT-v$AGENT_VER-${t%/*}-${t#*/}"
  if [ -s "$TMP/$f" ]; then
    printf '  OK      %-46s %s\n' "$f" "$(du -h "$TMP/$f" | cut -f1)"
  else
    printf '  MISSING %s\n' "$f"
    missing=$((missing + 1))
  fi
done
[ "$missing" -eq 0 ] || die "$missing artifact(s) missing - $DIST stays unchanged"

# A version is published once. Rebuilding it with other code would give the
# installed agents a manifest entry they do not match (integrity_mismatch);
# only a branding or key change (brand.go, brand.env) may replace it, or
# ULRMM_AGENT_REPLACE=1. The Windows setups themselves are not compared,
# their bytes depend on the packer and its version (Inno Setup also stamps
# the build time); their agent exes are, through the .agent.sha256.
inputs=$(cat "$SRC/agent/brand.go" "$SRC/build/brand.env" | sha256sum | cut -d' ' -f1)
stamp="$DIST/.inputs-v$AGENT_VER"
if [ "${ULRMM_AGENT_REPLACE:-}" != 1 ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs" ]; then
  differ=()
  for f in "$TMP/$ARTIFACT"-*; do
    b=$(basename "$f")
    case "$b" in *-windows-*.exe) continue ;; esac
    if [ -f "$DIST/$b" ] && ! cmp -s "$f" "$DIST/$b"; then
      differ+=("$b")
    fi
  done
  if [ ${#differ[@]} -gt 0 ]; then
    warn "================================================================"
    warn "v$AGENT_VER is already published and this build differs:"
    for b in "${differ[@]}"; do warn "  $b"; done
    warn "The agent source changed without a new version. The published"
    warn "builds stay. Raise the agent version, or run again with"
    warn "ULRMM_AGENT_REPLACE=1 to replace them on purpose."
    warn "================================================================"
    exit 0
  fi
fi

echo "=== Publish to $DIST ==="
mkdir -p "$DIST"
for f in "$TMP/$ARTIFACT"-*; do
  b=$(basename "$f")
  # unique staging name: two parallel runs must not slip each other a
  # half-written file
  stage="$DIST/.$b.$$.new"
  install -m 0644 "$f" "$stage"
  mv -f "$stage" "$DIST/$b"
done
echo "  all $(wc -w <<<"$expected") artifacts present"
printf '%s\n' "$inputs" >"$stamp"
# The server hands out installers only if this file matches ENROLL_SIGNING_KEY
# (deploy/signing.py dist_pubkey_ok), otherwise the agents carry another key
printf '%s\n' "$ENROLL_PUBKEY" >"$TMP/enroll-pubkey.txt"
install -m 0644 "$TMP/enroll-pubkey.txt" "$DIST/.enroll-pubkey.txt.$$.new"
mv -f "$DIST/.enroll-pubkey.txt.$$.new" "$DIST/enroll-pubkey.txt"
echo "  enroll-pubkey.txt: ${ENROLL_PUBKEY:-empty}"

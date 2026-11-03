#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# UniversalLocal RMM agent installer for Linux (systemd hosts, TrueNAS SCALE).
# The server fills in the values below when the installer is downloaded.
#
#   sudo bash ./<name>.sh [debug] [nomesh]
#   sudo bash ./<name>.sh uninstall
#
# Deployment installers carry a signed enrollment token instead of the client,
# site and installer token values; packages ship the agent binary and the
# token (enroll.jws) next to this script.

agentDL='agentDLChange'
agentSha256='agentSha256Change'
meshDL='meshDLChange'
meshSha256='meshSha256Change'
apiURL='apiURLChange'
token='tokenChange'
clientID='clientIDChange'
siteID='siteIDChange'
agentType='agentTypeChange'
agentBrand='agentBrandChange'
proxy=''
# certificate of a self-signed server, the agent trusts it with -cert
serverCert=''
enrollJWS='enrollChange'
# one line per build, picked by uname -m:
# <goarch> <agent url> <sha256> <mesh url> [<mesh sha256>]
agentBuilds='agentBuildsChange'
localBinary='localBinaryChange'

agentBin='/usr/local/bin/identNixBin'
agentConf='identNixConf'
agentDir='identNixDir'
agentSvcName='identNixSvc'
agentSvcFile="/etc/systemd/system/${agentSvcName}"
serverCertFile="${agentConf}.server.pem"
healBase="/etc/systemd/system/${agentSvcName%.service}-selfheal"

# fixed paths the agent itself looks for, do not rename
meshDir='/opt/ulrmm-mesh'
meshBin="${meshDir}/meshagent"
meshSvcName='meshagent.service'
meshSvcFile="/lib/systemd/system/${meshSvcName}"
meshTmpDir='/root/meshtemp'
meshTmp="${meshTmpDir}/meshagent"
agentNew="${agentBin}.new"
meshLocale='en_US.UTF-8'

# the same markers as the agent
is_truenas() {
  [ -e /data/manifest.json ] && [ -e /usr/bin/midclt ]
}

# TrueNAS SCALE: /usr, /opt and /lib are read-only and replaced by every
# update, /root survives it, /etc/systemd/system is writable
truenas=false
if is_truenas; then
  truenas=true
  agentHome='/root/identNixBin'
  agentBin="${agentHome}/identNixBin"
  agentConf="${agentHome}/identNixBin.conf"
  serverCertFile="${agentConf}.server.pem"
  agentDir="$agentHome"
  agentNew='/root/identNixBin.new'
  meshDir='/root/ulrmm-mesh'
  meshBin="${meshDir}/meshagent"
  meshSvcFile="/etc/systemd/system/${meshSvcName}"
  # TrueNAS ships no other UTF-8 locale and cannot generate one
  meshLocale='C.UTF-8'
  # restores the units after an update, the agent adds it again when it is missing
  healCmd="${agentHome}/selfheal/identNixBin -m selfheal"
fi

die() {
  echo "ERROR: $*" >&2
  exit 1
}

if [ "$EUID" -ne 0 ]; then
  die "Must be run as root"
fi
if [ "$(ps -p 1 -o comm= 2>/dev/null)" != systemd ]; then
  die "this installer needs systemd as the init system (PID 1)."
fi
if [ -n "${DISPLAY:-}" ]; then
  die "run this from a text console or ssh session, not inside a desktop session (DISPLAY=${DISPLAY}). Use 'sudo systemctl isolate multi-user.target', or 'unset DISPLAY' first."
fi

# ids of the init tasks running healCmd, with $1 only those of that "when";
# python3 is part of TrueNAS and builds the JSON
postinit_ids() {
  local filter
  filter=$(python3 -c 'import json, sys; print(json.dumps([["command", "=", sys.argv[1]]] + [["when", "=", w] for w in sys.argv[2:]]))' "$healCmd" "$@") || return 1
  midclt call initshutdownscript.query "$filter" |
    python3 -c 'import json, sys; print(" ".join(str(r["id"]) for r in json.load(sys.stdin)))'
}

# like the agent: registered means a POSTINIT entry with the same command
register_postinit() {
  local ids task
  ids=$(postinit_ids POSTINIT) || return 1
  [ -n "$ids" ] && return 0
  task=$(python3 -c 'import json, sys; print(json.dumps({"type": "COMMAND", "command": sys.argv[1], "when": "POSTINIT", "enabled": True, "timeout": 120, "comment": sys.argv[2]}))' "$healCmd" "$agentBrand") || return 1
  midclt call initshutdownscript.create "$task" >/dev/null
}

remove_postinit() {
  local id
  for id in $(postinit_ids); do
    midclt call initshutdownscript.delete "$id" >/dev/null
  done
}

remove_mesh() {
  if [ -x "$meshBin" ]; then
    XAUTHORITY=foo DISPLAY=bar "$meshBin" -uninstall
  fi
  if [ -f "$meshSvcFile" ]; then
    systemctl stop "$meshSvcName"
    systemctl disable "$meshSvcName"
    rm -f "$meshSvcFile"
  fi
  rm -rf "$meshDir"
  systemctl daemon-reload
}

remove_agent() {
  if [ "$truenas" = true ]; then
    remove_postinit
    # the agent's script directory there
    rm -rf '/var/tmp/identNixBin'
  fi
  if [ -f "${healBase}.timer" ]; then
    systemctl disable --now "${healBase##*/}.timer"
    rm -f "${healBase}.timer" "${healBase}.service"
    systemctl daemon-reload
  fi
  if [ -f "$agentSvcFile" ]; then
    systemctl disable "$agentSvcName"
    systemctl stop "$agentSvcName"
    rm -f "$agentSvcFile"
    systemctl daemon-reload
  fi
  rm -f "$agentConf" "$serverCertFile" "$agentBin"
  rm -rf "$agentDir"
}

self_delete() {
  local self=${BASH_SOURCE[0]:-}
  if [ -n "$self" ] && [ -f "$self" ]; then
    rm -f -- "$self"
  fi
}

case "${1:-}" in
uninstall | -uninstall | --uninstall)
  remove_mesh
  remove_agent
  self_delete
  exit 0
  ;;
esac

debug=false
nomesh=false
for arg in "$@"; do
  case "$arg" in
  debug | -debug | --debug) debug=true ;;
  insecure | -insecure | --insecure) die "insecure mode was removed. Download the installer again, it carries the certificate of a self-signed server." ;;
  nomesh | -nomesh | --nomesh) nomesh=true ;;
  *) die "Unknown parameter: ${arg}" ;;
  esac
done

if [ -n "$agentBuilds" ]; then
  case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  i?86) arch=386 ;;
  aarch64 | arm64) arch=arm64 ;;
  armv7* | armv8l | armhf) arch=arm ;;
  *) die "there is no agent build for this machine ($(uname -m))" ;;
  esac
  while read -r buildArch buildURL buildSha buildMesh buildMeshSha; do
    if [ "$buildArch" = "$arch" ]; then
      agentDL=$buildURL
      agentSha256=$buildSha
      meshDL=$buildMesh
      meshSha256=$buildMeshSha
    fi
  done <<<"$agentBuilds"
  [ -n "$agentDL" ] || die "this server has no agent build for ${arch}"
fi

here=''
if [ "$localBinary" = true ]; then
  here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || die "cannot find the directory of this script"
fi

# a self-signed server is verified against its own certificate
caFile=''
curlCA=() wgetCA=()
if [ -n "$serverCert" ]; then
  caFile=$(mktemp) || die "cannot create a temporary file"
  printf '%s\n' "$serverCert" >"$caFile"
  curlCA=(--cacert "$caFile")
  wgetCA=("--ca-certificate=${caFile}")
fi

# $1 what, $2 url, $3 destination, $4 sha256 or empty
fetch_binary() {
  local what=$1 url=$2 dest=$3 sha=$4 limit=()
  case "$url" in https://*) ;; *) die "the ${what} download is not an https url: ${url}" ;; esac
  if command -v timeout >/dev/null; then
    limit=(timeout 900)
  fi
  rm -f "$dest"
  # curl follows https redirects only; wget cannot tell, so it follows none
  if command -v curl >/dev/null; then
    "${limit[@]}" curl -fsSL --proto "=https" --proto-redir "=https" "${curlCA[@]}" --retry 2 --connect-timeout 30 --max-time 900 -o "$dest" "$url"
  else
    "${limit[@]}" wget -q --max-redirect=0 "${wgetCA[@]}" --tries=3 --timeout=30 -O "$dest" "$url"
  fi || {
    rm -f "$dest"
    die "Unable to download the ${what} from ${url}"
  }
  check_binary "$what" "$url" "$dest" "$sha"
}

# $1 what, $2 where it came from, $3 file, $4 sha256 or empty
check_binary() {
  local what=$1 url=$2 dest=$3 sha=$4 head
  if [ "$(head -c 4 "$dest" | tail -c 3)" != ELF ]; then
    head=$(head -c 120 "$dest" | tr -d '\r' | tr '\n' ' ')
    rm -f "$dest"
    die "the ${what} from ${url} is not a Linux program, it starts with: ${head}
Usually DNS, a proxy or a firewall on this machine answers instead of the server."
  fi
  if [ -n "$sha" ] && ! echo "${sha}  ${dest}" | sha256sum -c --status -; then
    rm -f "$dest"
    die "the ${what} from ${url} does not match its sha256 ${sha}"
  fi
}

mkdir -p "${agentNew%/*}"
if [ "$localBinary" = true ]; then
  install -m 0755 "${here}/identNixBin" "$agentNew" || die "the agent binary next to this script is missing"
  check_binary "agent" "${here}/identNixBin" "$agentNew" "$agentSha256"
else
  echo "Downloading the UniversalLocal RMM agent..."
  fetch_binary "agent" "$agentDL" "$agentNew" "$agentSha256"
fi
if [ "$nomesh" != true ]; then
  echo "Downloading the mesh agent..."
  mkdir -p "$meshTmpDir"
  fetch_binary "mesh agent" "$meshDL" "$meshTmp" "$meshSha256"
fi

remove_agent
mkdir -p "${agentBin%/*}"
mv -f "$agentNew" "$agentBin"
chmod +x "$agentBin"

in_list() {
  local w
  for w in "${@:2}"; do
    [ "$w" = "$1" ] && return 0
  done
  return 1
}

set_locale() {
  local deb=(ubuntu debian raspbian kali linuxmint) ids w
  [ -f /etc/os-release ] || return 0
  # shellcheck disable=SC1091
  ids=$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")
  for w in $ids; do
    if in_list "$w" "${deb[@]}"; then
      locale-gen en_US.UTF-8
      localectl set-locale LANG=en_US.UTF-8
      # shellcheck disable=SC1091
      . /etc/default/locale
      return 0
    fi
  done
  localedef -c -i en_US -f UTF-8 en_US.UTF-8
  localectl set-locale LANG=en_US.UTF-8
  # shellcheck disable=SC1091
  . /etc/locale.conf
}

# the mesh installer copies itself, then fails to write its unit below the
# read-only /lib and still exits 0; the unit text is the one the agent restores
truenas_mesh_unit() {
  [ -x "$meshBin" ] || install -m 0755 "$meshTmp" "$meshBin"
  cat >"$meshSvcFile" <<UNIT
[Unit]
Description=Mesh Agent

[Service]
WorkingDirectory=${meshDir}
ExecStart=${meshBin}
StandardOutput=null
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$meshSvcName"
}

if [ "$nomesh" = true ]; then
  echo "Skipping mesh install"
else
  if [ -f "$meshBin" ]; then
    remove_mesh
  fi
  echo "Installing mesh agent..."
  if [ "$truenas" != true ]; then
    set_locale
  fi
  chmod +x "$meshTmp"
  mkdir -p "$meshDir"
  env LC_ALL="$meshLocale" LANGUAGE=en_US XAUTHORITY=foo DISPLAY=bar "$meshTmp" -install --installPath="$meshDir"
  sleep 1
  if [ "$truenas" = true ]; then
    truenas_mesh_unit
  fi
  rm -rf "$meshTmpDir"
fi

enrollFile=''
if [ "$localBinary" = true ]; then
  enrollFile="${here}/enroll.jws"
  [ -s "$enrollFile" ] || die "${enrollFile} is missing, it is removed after the first install; download the installer again"
elif [ -n "$enrollJWS" ]; then
  # mktemp creates the file with mode 0600
  enrollFile=$(mktemp) || die "cannot create a temporary file"
  printf '%s\n' "$enrollJWS" >"$enrollFile"
fi
authFile=''
if [ -n "$enrollFile" ]; then
  installArgs=(-m install -enroll "$enrollFile")
else
  # a file instead of -auth keeps the token out of the process list;
  # the agent deletes it after reading
  authFile=$(mktemp) || die "cannot create a temporary file"
  printf '%s' "$token" >"$authFile"
  installArgs=(-m install -api "$apiURL" -client-id "$clientID" -site-id "$siteID" -agent-type "$agentType" -auth-file "$authFile")
fi
if [ -n "$serverCert" ]; then
  (umask 022 && printf '%s\n' "$serverCert" >"$serverCertFile") || die "cannot write ${serverCertFile}"
  installArgs+=(-cert "$serverCertFile")
fi
if [ "$debug" = true ]; then
  installArgs+=(--log debug)
fi
if [ -n "$proxy" ]; then
  installArgs+=(--proxy "$proxy")
fi
installRC=0
"$agentBin" "${installArgs[@]}" || installRC=$?
rm -f "$authFile" "$caFile"
if [ -n "$enrollJWS" ]; then
  rm -f "$enrollFile"
fi
if [ "$installRC" -ne 0 ]; then
  rm -f "$agentBin"
  die "the agent install failed (see above)"
fi

cat >"$agentSvcFile" <<UNIT
[Unit]
Description=UniversalLocal RMM Linux Agent
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=${agentBin} -m svc
User=root
Group=root
Restart=always
RestartSec=5s
LimitNOFILE=1000000
KillMode=process
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$agentSvcName"
if [ "$truenas" = true ] && ! register_postinit; then
  echo "WARNING: the POSTINIT script that survives TrueNAS updates was not registered, the agent adds it when it starts" >&2
fi
if [ "$localBinary" = true ]; then
  rm -f "$enrollFile"
else
  # the script holds the installer token
  self_delete
fi
systemctl start "$agentSvcName"

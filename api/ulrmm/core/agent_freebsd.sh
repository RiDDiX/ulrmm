#!/bin/sh
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# UniversalLocal RMM agent installer for FreeBSD.
# The server fills in the values below when the installer is downloaded.
#
#   sh ./<name>.sh [debug] [nomesh]    (as root)
#   sh ./<name>.sh uninstall

agentDL='agentDLChange'
agentSha256='agentSha256Change'
apiURL='apiURLChange'
token='tokenChange'
clientID='clientIDChange'
siteID='siteIDChange'
agentType='agentTypeChange'
proxy=''
# certificate of a self-signed server, the agent trusts it with -cert
serverCert=''

agentBin='/usr/local/bin/identNixBin'
agentConf='identNixConf'
agentDir='identNixDir'
agentSvcName='identNixSvc'
healName='identNixHeal'
rcName=$(echo "${agentSvcName%.service}" | tr - _)
rcScript="/usr/local/etc/rc.d/${rcName}"
agentLog="/var/log/${agentBin##*/}.log"
serverCertFile="${agentConf}.server.pem"

# fixed paths the agent itself looks for, do not rename
meshDir='/opt/ulrmm-mesh'
meshBin="${meshDir}/meshagent"
meshRc='/usr/local/etc/rc.d/meshagent'

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

die() {
  echo "ERROR: $*" >&2
  exit 1
}

if [ "$(id -u)" -ne 0 ]; then
  die "Must be run as root"
fi
if [ "$(uname -s)" != FreeBSD ]; then
  die "this installer is for FreeBSD, this system is $(uname -s)."
fi
if [ -f /etc/platform ]; then
  die "pfSense is not supported yet, only plain FreeBSD."
fi
if [ -x /usr/local/sbin/opnsense-version ]; then
  die "OPNsense is not supported yet, only plain FreeBSD."
fi
if [ -x /usr/local/bin/midclt ] || grep -qs TrueNAS /etc/version; then
  die "TrueNAS CORE is not supported yet, only plain FreeBSD."
fi

remove_mesh() {
  if [ -x "$meshBin" ]; then
    "$meshBin" -uninstall
  fi
  # left behind by an uninstall that did not finish
  if grep -qs "$meshDir" "$meshRc"; then
    service meshagent onestop >/dev/null 2>&1
    sysrc -x meshagent_enable >/dev/null 2>&1
    rm -f "$meshRc"
  fi
  rm -rf "$meshDir"
}

remove_agent() {
  # the self-healing job goes first, it would bring the agent back
  rm -f "/etc/cron.d/${healName}"
  if [ -f "$rcScript" ]; then
    service "$rcName" onestop >/dev/null 2>&1
    rm -f "$rcScript"
  fi
  sysrc -x "${rcName}_enable" >/dev/null 2>&1
  rm -f "$agentConf" "$serverCertFile" "$agentBin" "/var/run/${rcName}.pid"
  rm -rf "$agentDir"
}

self_delete() {
  case $0 in *.sh) ;; *) return 0 ;; esac
  if [ -f "$0" ]; then
    rm -f -- "$0"
  fi
}

case "${1:-}" in
uninstall | -uninstall | --uninstall)
  remove_mesh
  remove_agent
  # a reinstall keeps the log
  rm -f "$agentLog" "${agentLog}.1" "${agentLog}.2"
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

# ELF e_machine of the builds
case $(uname -m) in
amd64) machine=62 ;;
arm64) machine=183 ;;
*) die "FreeBSD agents are built for amd64 and arm64 only, this system is $(uname -m)." ;;
esac

if [ "$nomesh" != true ] && [ "$(uname -m)" != amd64 ]; then
  echo "MeshCentral has no mesh agent for FreeBSD on $(uname -m), installing without it"
  nomesh=true
fi

limited() {
  if command -v timeout >/dev/null; then
    timeout 900 "$@"
  else
    "$@"
  fi
}

# a self-signed server is verified against its own certificate
caFile=''
if [ -n "$serverCert" ]; then
  caFile=$(mktemp) || die "cannot create a temporary file"
  printf '%s\n' "$serverCert" >"$caFile"
fi

# $1 what, $2 url, $3 destination, $4 sha256 or empty
fetch_binary() {
  fb_what=$1
  fb_url=$2
  fb_dest=$3
  fb_sha=$4
  case "$fb_url" in https://*) ;; *) die "the ${fb_what} download is not an https url: ${fb_url}" ;; esac
  rm -f "$fb_dest"
  # curl follows https redirects only; fetch(1) cannot tell, -A follows none
  if ! command -v curl >/dev/null; then
    limited fetch -A -q -T 30 ${caFile:+--ca-cert="$caFile"} -o "$fb_dest" "$fb_url"
  else
    limited curl -fsSL --proto =https --proto-redir =https ${caFile:+--cacert "$caFile"} --retry 2 --connect-timeout 30 --max-time 900 -o "$fb_dest" "$fb_url"
  fi || {
    rm -f "$fb_dest"
    die "Unable to download the ${fb_what} from ${fb_url}"
  }
  if [ "$(head -c 4 "$fb_dest" | tail -c 3)" != ELF ]; then
    fb_head=$(head -c 120 "$fb_dest" | tr -d '\r' | tr '\n' ' ')
    rm -f "$fb_dest"
    die "the ${fb_what} from ${fb_url} is not a program, it starts with: ${fb_head}
Usually DNS, a proxy or a firewall on this machine answers instead of the server."
  fi
  # EI_OSABI, 9 is FreeBSD
  fb_abi=$(od -An -t u1 -j 7 -N 1 "$fb_dest" | tr -d ' ')
  if [ "$fb_abi" != 9 ]; then
    rm -f "$fb_dest"
    die "the ${fb_what} from ${fb_url} is not a FreeBSD program (ELF OS ABI ${fb_abi})"
  fi
  fb_machine=$(od -An -t u1 -j 18 -N 1 "$fb_dest" | tr -d ' ')
  if [ "$fb_machine" != "$machine" ]; then
    rm -f "$fb_dest"
    case $fb_machine in 62) fb_machine=amd64 ;; 183) fb_machine=arm64 ;; *) fb_machine="ELF machine ${fb_machine}" ;; esac
    die "the ${fb_what} from ${fb_url} is built for ${fb_machine}, this system is $(uname -m)"
  fi
  if [ -n "$fb_sha" ] && [ "$(sha256 -q "$fb_dest")" != "$fb_sha" ]; then
    rm -f "$fb_dest"
    die "the ${fb_what} from ${fb_url} does not match its sha256 ${fb_sha}"
  fi
}

echo "Downloading the UniversalLocal RMM agent..."
mkdir -p "${agentBin%/*}"
fetch_binary "agent" "$agentDL" "${agentBin}.new" "$agentSha256"
rm -f "$caFile"

remove_agent
if [ "$nomesh" != true ] && [ -f "$meshBin" ]; then
  remove_mesh
fi
mv -f "${agentBin}.new" "$agentBin"
chmod 755 "$agentBin"

# a file instead of -auth keeps the token out of the process list;
# the agent deletes it after reading. mktemp creates it 0600.
authFile=$(mktemp) || die "cannot create a temporary file"
printf '%s' "$token" >"$authFile"
# the agent installs the mesh agent, its rc.d service and the self-healing job
set -- -m install -api "$apiURL" -client-id "$clientID" -site-id "$siteID" -agent-type "$agentType" -auth-file "$authFile"
if [ -n "$serverCert" ]; then
  (umask 022 && printf '%s\n' "$serverCert" >"$serverCertFile") || die "cannot write ${serverCertFile}"
  set -- "$@" -cert "$serverCertFile"
fi
if [ "$nomesh" = true ]; then
  set -- "$@" -nomesh
else
  echo "The mesh agent needs procfs: the agent adds it to /etc/fstab and mounts /proc"
fi
if [ "$debug" = true ]; then
  set -- "$@" --log debug
fi
if [ -n "$proxy" ]; then
  set -- "$@" --proxy "$proxy"
fi
if ! "$agentBin" "$@"; then
  rm -f "$agentBin" "$authFile"
  die "the agent install failed (see above)"
fi
rm -f "$authFile"
# the script holds the installer token
self_delete

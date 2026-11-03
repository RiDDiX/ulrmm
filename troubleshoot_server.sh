#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Looks at DNS, services, port 443 and certificates of this UniversalLocal RMM
# server. It only reads: no service is started or stopped, nothing installed.
# Everything shown also goes to checklog.log in the current directory.
#
#   bash /rmm/troubleshoot_server.sh

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

umask 077
LOG=checklog.log
LOG_DIR=/rmm/api/ulrmm/ulrmm/private/log

say() {
  printf '%b%s%b\n' "$1" "$2" "$NC"
  printf '%s\n' "$2" >>"$LOG"
}
good() { say "$GREEN" "$*"; }
bad() { say "$RED" "$*"; }
note() { say "$YELLOW" "$*"; }

first_ipv4() { grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1; }

# --- host ----------------------------------------------------------------------

mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
if [ "${mem_kb:-0}" -lt 3627528 ]; then
  bad "A minimum of 4GB of RAM is required."
  exit 1
fi

os_id=$(. /etc/os-release && echo "${ID:-}")
os_ver=$(. /etc/os-release && echo "${VERSION_ID:-}")
case "${os_id} ${os_ver}" in
"debian 12" | "debian 13" | "ubuntu 22.04" | "ubuntu 24.04")
  good "You are running ${os_id} ${os_ver}, which is supported."
  ;;
"debian 11" | "ubuntu 20.04")
  note "You are running ${os_id} ${os_ver}. New installs need Debian 12, Debian 13, Ubuntu 22.04 or Ubuntu 24.04."
  ;;
*)
  bad "Only Debian 12, Debian 13, Ubuntu 22.04 and Ubuntu 24.04 are supported, this is ${os_id} ${os_ver}."
  exit 1
  ;;
esac
if dpkg -l 2>/dev/null | grep -qi turnkey; then
  bad "Turnkey images are not supported."
  exit 1
fi
if pgrep -f webmin >/dev/null; then
  bad "Webmin is running on this host, it is not supported."
  exit 1
fi

echo "=== $(date) ===" >>"$LOG"

# --- local resolver, read only ---------------------------------------------------

if systemctl is-active --quiet systemd-resolved && command -v resolvectl >/dev/null; then
  local_dns=$(resolvectl dns 2>/dev/null | first_ipv4)
else
  local_dns=$(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf 2>/dev/null | first_ipv4)
fi
if [ -n "$local_dns" ]; then
  good "Local DNS server: ${local_dns}"
else
  note "No IPv4 DNS server found in resolvectl or /etc/resolv.conf."
fi

have_dig=false
if command -v dig >/dev/null; then
  have_dig=true
else
  note "dig is not installed (package dnsutils or bind9-dnsutils), the DNS comparisons are skipped."
fi

# --- names -------------------------------------------------------------------------

resolves() {
  if command -v ping >/dev/null; then
    ping -c 1 -W 3 "$1" >/dev/null 2>&1
  else
    getent hosts "$1" >/dev/null
  fi
}

ask_domain() { # prompt, dots it needs at least
  local v=''
  until [[ $v =~ ^[A-Za-z0-9.-]+$ ]] && [ "$(tr -cd . <<<"$v" | wc -c)" -ge "$2" ]; do
    read -rp "$1: " v
  done
  printf '%s' "$v"
}
rmmdomain=$(ask_domain "Backend subdomain (e.g. api.example.com)" 2)
frontenddomain=$(ask_domain "Frontend subdomain (e.g. rmm.example.com)" 2)
meshdomain=$(ask_domain "MeshCentral subdomain (e.g. mesh.example.com)" 2)
for d in "$rmmdomain" "$frontenddomain" "$meshdomain"; do
  if ! resolves "$d"; then
    bad "${d} doesnt exist please create it or check for a typo"
    exit
  fi
done
domain=$(ask_domain "Root domain of the Let's Encrypt certificate (e.g. example.com)" 1)
echo "Domains: ${rmmdomain} ${frontenddomain} ${meshdomain}, certificate for ${domain}" >>"$LOG"

public_ip() { dig +short @8.8.8.8 "$1" 2>/dev/null | first_ipv4; }

if [ "$have_dig" = true ]; then
  for d in "$rmmdomain" "$frontenddomain" "$meshdomain"; do
    local_ip=''
    [ -n "$local_dns" ] && local_ip=$(dig +short "@${local_dns}" "$d" 2>/dev/null | first_ipv4)
    pub_ip=$(public_ip "$d")
    if [ -n "$local_ip" ] && [ "$local_ip" = "$pub_ip" ]; then
      good "${d} resolves to ${pub_ip} locally and publicly."
    else
      note "${d} resolves to '${local_ip}' on the local DNS server and to '${pub_ip}' publicly. Fine with split DNS, otherwise the record is not public yet."
    fi
  done
fi

# --- services ----------------------------------------------------------------------

for s in rmm daphne celery celerybeat nginx nats nats-api meshcentral postgresql redis-server; do
  if systemctl is-active --quiet "$s"; then
    good "Service ${s} is running."
  else
    bad "Service ${s} is NOT running, see sudo journalctl -u ${s}."
  fi
done

# --- port 443 from outside ------------------------------------------------------------

port_open() { # host port
  if command -v nc >/dev/null; then
    timeout 10 nc -z -w 5 "$1" "$2" >/dev/null 2>&1
  else
    timeout 10 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" 2>/dev/null
  fi
}

wanip=''
if [ "$have_dig" = true ]; then
  wanip=$(dig +short @resolver4.opendns.com myip.opendns.com 2>/dev/null | first_ipv4)
fi
if [ -z "$wanip" ]; then
  note "Could not find out the public IP address of this network."
elif port_open "$wanip" 443; then
  good "Port 443 on ${wanip} is open."
else
  bad "Port 443 on ${wanip} is closed or filtered. Agents and browsers outside cannot reach this server."
fi

# --- is something else answering on 443 ---------------------------------------------------

cert_of() { # address, server name
  echo | timeout 10 openssl s_client -connect "$1:443" -servername "$2" 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256 2>/dev/null
}
if [ "$have_dig" = true ]; then
  remrmmip=$(public_ip "$rmmdomain")
  remfrontip=$(public_ip "$frontenddomain")
  if [ -n "$remrmmip" ]; then
    there=$(cert_of "$remrmmip" "$rmmdomain")
    here=$(cert_of 127.0.0.1 "$rmmdomain")
    if [ -n "$here" ] && [ "$there" = "$here" ]; then
      good "${rmmdomain} (${remrmmip}) serves the certificate of this server, no proxy in between."
    else
      note "${rmmdomain} (${remrmmip}) serves another certificate than this server: a proxy, a port forward to another host, or the address is wrong."
    fi
  fi
  if [ -n "$wanip" ] && [ -n "$remfrontip" ] && [ "$wanip" != "$remfrontip" ]; then
    note "This network's public IP ${wanip} differs from ${frontenddomain} (${remfrontip}): another public address or a proxy is in front."
  fi
fi

# --- certificates ---------------------------------------------------------------------------

if command -v certbot >/dev/null; then
  certs=$(sudo certbot certificates 2>&1)
  if printf '%s' "$certs" | grep -q INVALID; then
    bad "certbot lists an INVALID certificate, see ${LOG}."
  else
    good "The Let's Encrypt certificates look fine."
  fi
  printf '%s\n' "$certs" >>"$LOG"
else
  note "certbot is not installed (own or self-signed certificate)."
fi

# --- logs -----------------------------------------------------------------------------------

for f in django_debug.log ulrmm_debug.log error.log; do
  if [ -r "${LOG_DIR}/${f}" ]; then
    {
      echo "--- tail of ${LOG_DIR}/${f}"
      tail -n 50 "${LOG_DIR}/${f}"
    } >>"$LOG"
  fi
done

echo
echo "Everything above is also in $(pwd)/${LOG} (with the last log lines). Attach it when you ask for help."
exit 0

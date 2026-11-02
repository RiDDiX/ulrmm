#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# nftables table inet ulrmm: inbound only what this server serves (ssh,
# http/https, RustDesk, NATS when USE_NATS_STANDARD is set), anything else
# dropped. Output, forward and every other table (docker, libvirt) stay as
# they are. update.sh runs apply, check and confirm. As root:
#
#   firewall.sh render          print the ruleset
#   firewall.sh apply           load it and print a confirm token; without
#                               confirm the table is deleted after 5 minutes
#   firewall.sh check           nginx answers on 443 via the LAN address and
#                               something listens on an allowed ssh port
#   firewall.sh confirm TOKEN   keep it, also after a reboot
#   firewall.sh revert          delete a table that is not confirmed, now
#   firewall.sh off             delete it, also from the boot
#   firewall.sh boot            what ulrmm-firewall.service runs: render with
#                               the ssh ports of now, the saved rules if that fails
#
# /etc/ulrmm/firewall.conf, read line by line, never sourced:
#   FIREWALL=off                apply loads nothing and removes a loaded one
#                               (update.sh --no-firewall leaves it as it is)
#   TCP_PORTS=8443 9100-9101    more inbound ports
#   UDP_PORTS=51820

FW_CONF=${FW_CONF:-/etc/ulrmm/firewall.conf}
FW_RULES=${FW_RULES:-/etc/ulrmm/firewall.nft}
FW_UNIT=${FW_UNIT:-/etc/systemd/system/ulrmm-firewall.service}
FW_RUN=${FW_RUN:-/run/ulrmm-firewall}
local_settings=${local_settings:-/rmm/api/ulrmm/ulrmm/local_settings.py}
ROLLBACK=ulrmm-firewall-rollback
FW_SCRIPT=${FW_SCRIPT:-$(readlink -f "${BASH_SOURCE[0]}")}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

read_conf() {
  local line key p
  fw_off=false tcp_extra=() udp_extra=()
  [ -r "$FW_CONF" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    [[ ${line%%#*} =~ ^[[:space:]]*([A-Z_]+)=[\"\']?([^\"\']*)[\"\']?[[:space:]]*$ ]] || continue
    key=${BASH_REMATCH[1]}
    case "$key" in
    FIREWALL) [ "${BASH_REMATCH[2],,}" != off ] || fw_off=true ;;
    TCP_PORTS | UDP_PORTS)
      for p in ${BASH_REMATCH[2]}; do
        [[ $p =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || die "${FW_CONF}: ${key} '${p}' is not a port or a port range."
        if [ "$key" = TCP_PORTS ]; then
          tcp_extra+=("$p")
        else
          udp_extra+=("$p")
        fi
      done
      ;;
    esac
  done <"$FW_CONF"
}

# 22, the sshd config and whatever sshd or ssh.socket listens on; at boot
# also the ports of the saved rules
ssh_ports() {
  # sshd -T refuses to run before ssh.service created its privilege dir
  [ -d /run/sshd ] || install -d -m 0755 /run/sshd 2>/dev/null
  {
    echo 22
    sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
    [ "${fw_boot:-}" != true ] || awk '$1 == "tcp" && $2 == "dport" {print $3}' "$FW_RULES" 2>/dev/null
    systemctl show -p Listen ssh.socket sshd.socket 2>/dev/null | grep -oE ':[0-9]+ \(Stream\)' | tr -dc '0-9\n'
    ss -Hltnp 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print a[n]}'
  } | grep -xE '[0-9]{1,5}' | sort -nu
}

nats_port() {
  grep -qE '^USE_NATS_STANDARD[[:space:]]*=[[:space:]]*True([[:space:]#]|$)' "$local_settings" 2>/dev/null || return 0
  local p
  p=$(sed -nE 's/^NATS_STANDARD_PORT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' "$local_settings" | tail -1)
  echo "${p:-4222}"
}

# one atomic nft -f: create, delete, define again, so a rerun replaces it
render() {
  local p
  cat <<'EOF'
table inet ulrmm
delete table inet ulrmm
table inet ulrmm {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state established,related accept
		ct state invalid drop
		icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
		icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query } accept
		udp sport 67 udp dport 68 accept
		ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
EOF
  for p in $({ ssh_ports; printf '%s\n' 80 443 21115-21117; nats_port; printf '%s\n' "${tcp_extra[@]}"; } | awk '!seen[$0]++'); do
    printf '\t\ttcp dport %s accept\n' "$p"
  done
  for p in $(printf '%s\n' 21116 "${udp_extra[@]}" | awk '!seen[$0]++'); do
    printf '\t\tudp dport %s accept\n' "$p"
  done
  printf '\t}\n}\n'
}

unit_text() {
  cat <<EOF
[Unit]
Description=UniversalLocal RMM firewall (nftables table inet ulrmm)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
After=nftables.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v bash) ${FW_SCRIPT} boot

[Install]
WantedBy=sysinit.target
EOF
}

disarm() {
  systemctl stop "${ROLLBACK}.timer" 2>/dev/null
  systemctl reset-failed "${ROLLBACK}.timer" "${ROLLBACK}.service" 2>/dev/null
  return 0
}

apply() {
  local token
  read_conf
  if [ "$fw_off" = true ]; then
    if nft list table inet ulrmm >/dev/null 2>&1 || [ -e "$FW_UNIT" ]; then
      off >/dev/null
      echo "firewall: FIREWALL=off in ${FW_CONF}, the loaded table and its boot unit were removed"
    else
      echo "firewall: FIREWALL=off in ${FW_CONF}, nothing loaded"
    fi
    return 0
  fi
  if ! command -v nft >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >&2 || die "nftables is not installed."
  fi
  command -v systemd-run >/dev/null || die "no systemd-run, so no rollback: nothing loaded."
  (umask 077 && mkdir -p "$FW_RUN") || die "cannot create ${FW_RUN}."
  render >"${FW_RUN}/rules.nft" || die "could not render the ruleset."
  nft -c -f "${FW_RUN}/rules.nft" || die "nft rejects the ruleset, nothing loaded."
  disarm
  systemd-run --quiet --unit="$ROLLBACK" --on-active=300 --timer-property=AccuracySec=1s \
    "$(command -v nft)" delete table inet ulrmm || die "could not arm the rollback, nothing loaded."
  if ! nft -f "${FW_RUN}/rules.nft"; then
    disarm
    die "loading the ruleset failed."
  fi
  token=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  printf '%s\n' "$token" >"${FW_RUN}/token"
  echo "firewall: table inet ulrmm loaded, deleted again in 5 minutes unless confirmed"
  echo "confirm token: ${token}"
}

lan_ip() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
  [ -n "$ip" ] || ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}')
  printf '%s' "$ip"
}

check() {
  local ip code p
  nft list table inet ulrmm >/dev/null 2>&1 || {
    echo "check: table inet ulrmm is not loaded"
    return 1
  }
  ip=$(lan_ip)
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://${ip:-127.0.0.1}/")
  if [ -z "$ip" ] || [ "${code:-000}" = 000 ]; then
    echo "check: nginx does not answer on https://${ip:-<no LAN address>}/"
    return 1
  fi
  for p in $(ssh_ports); do
    if [ -n "$(ss -Hltn sport = ":${p}" 2>/dev/null)" ]; then
      echo "check: nginx answers on https://${ip}/ (${code}), ssh listens on ${p}"
      return 0
    fi
  done
  echo "check: nothing listens on an allowed ssh port ($(ssh_ports | tr '\n' ' '))"
  return 1
}

confirm() {
  if [ -z "$1" ] || [ "$1" != "$(cat "${FW_RUN}/token" 2>/dev/null)" ]; then
    die "no pending apply with this token, run firewall.sh apply."
  fi
  disarm
  nft list table inet ulrmm >/dev/null 2>&1 || die "the rollback already deleted the table, run firewall.sh apply again."
  if ! mkdir -p "$(dirname "$FW_RULES")" || ! install -m 600 "${FW_RUN}/rules.nft" "$FW_RULES" ||
    ! unit_text >"$FW_UNIT"; then
    die "could not write ${FW_RULES} or ${FW_UNIT}."
  fi
  systemctl daemon-reload
  systemctl enable ulrmm-firewall.service >/dev/null 2>&1 || die "could not enable ulrmm-firewall.service."
  rm -f "${FW_RUN}/token"
  echo "firewall: confirmed, ulrmm-firewall.service loads it at boot"
}

revert() {
  disarm
  nft delete table inet ulrmm 2>/dev/null
  rm -f "${FW_RUN}/token"
  echo "firewall: table inet ulrmm deleted"
}

off() {
  revert
  systemctl disable ulrmm-firewall.service >/dev/null 2>&1
  rm -f "$FW_UNIT" "$FW_RULES"
  systemctl daemon-reload 2>/dev/null
  echo "firewall: off, also at boot. update.sh loads it again unless ${FW_CONF} has FIREWALL=off"
}

# at boot sshd may have moved to another port since the last confirm
boot() {
  fw_boot=true
  read_conf
  [ "$fw_off" != true ] || return 0
  if (umask 077 && mkdir -p "$FW_RUN") && render >"${FW_RUN}/boot.nft" &&
    nft -c -f "${FW_RUN}/boot.nft" && nft -f "${FW_RUN}/boot.nft"; then
    return 0
  fi
  nft -f "$FW_RULES"
}

main() {
  [ "$EUID" -eq 0 ] || die "run it as root: sudo bash $0 $*"
  case "$1" in
  render)
    read_conf
    render
    ;;
  apply | check | revert | off | boot) "$1" ;;
  confirm) confirm "$2" ;;
  *)
    sed -n '2,22p' "$0" >&2
    exit 2
    ;;
  esac
}

[ "${BASH_SOURCE[0]}" != "$0" ] || main "$@"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install/update rustdesk. update: no $RD_PASSWORD, only if older. verify id/pw/key survive.
# server reads one line RUSTDESK_OK id ver / FAIL reason.
#
# Subshell with its own stdio, so a child cannot hold the agent's pipes open.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
log=/var/log/rustdesk-deploy.log
dir=$(mktemp -d /tmp/rustdesk-deploy.XXXXXX) || exit 1

(
    fail() {
        echo "failed: $*"
        echo "RUSTDESK_FAIL $*" >"$dir/result"
        exit 1
    }
    older() { [ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]; }
    # hash of the ID, key pair and password entries (key_pair spans several
    # lines); it is only compared, never logged
    fingerprint() {
        lines=$(awk '/^[A-Za-z_]+ = /{k=/^(enc_id|password|salt|key_pair) = /} /^\[[A-Za-z_]/{k=0} k' "$toml") &&
            [ -n "$lines" ] && printf '%s\n' "$lines" | sha256sum
    }
    echo "=== $(date)"
    mode='rdMode'
    [ "$mode" = update ] || [ -n "${RD_PASSWORD:-}" ] || fail "no password was handed to the script"
    rd=/usr/bin/rustdesk
    toml=/root/.config/rustdesk/RustDesk.toml

    have=
    if [ "$mode" = update ]; then
        [ -x "$rd" ] || fail "RustDesk is not installed, use Install or reconfigure"
        have=$("$rd" --version | head -n 1)
        printf '%s' "$have" | grep -Eqx '[0-9]+(\.[0-9]+){1,3}' || fail "cannot read the installed RustDesk version"
        older 'rdVersion' "$have" && fail "not downgrading: RustDesk rdVersion is older than the installed $have"
        before=$(fingerprint) || fail "the RustDesk config holds no ID or password"
    fi

    # only an update upgrades, so a reconfigure can always rotate the password
    if [ ! -x "$rd" ] || { [ -n "$have" ] && older "$have" 'rdVersion'; }; then
        # the package scripts stop RustDesk. Arguments are matched, never logged.
        # At the login screen there is no --cm, only the session's TCP
        # connection: to hbbr (21117) or the viewer. 21114-21116 belong to the
        # ID server.
        if [ -n "$have" ]; then
            pgrep -f '(^|/)rustdesk (--cm|--connect|--play|--file-transfer|--view-camera|--port-forward|--terminal|--whiteboard|--rdp|rustdesk:)' >/dev/null &&
                fail "busy: a RustDesk session is open on this device"
            conns=$(ss -Htnp state established) || fail "busy: cannot list the TCP connections"
            printf '%s\n' "$conns" | awk '/\("rustdesk",/ && $4 !~ /:2111[456]$/ {n++} END {exit !n}' &&
                fail "busy: a RustDesk session is open on this device"
        fi
        if command -v apt-get >/dev/null; then
            url='rdDebUrl' sum='rdDebSha256' pkg="$dir/rustdesk.deb"
        elif command -v dnf >/dev/null || command -v yum >/dev/null; then
            url='rdRpmUrl' sum='rdRpmSha256' pkg="$dir/rustdesk.rpm"
        else
            fail "no apt-get, dnf or yum on this system"
        fi
        if command -v curl >/dev/null; then
            curl -fsSL --max-time 120 -o "$pkg" "$url"
        else
            wget -q -T 120 -O "$pkg" "$url"
        fi || fail "download failed: $url"
        echo "$sum  $pkg" | sha256sum -c - || fail "checksum mismatch: $url"
        case $pkg in
        *.deb)
            apt-get install -y -o DPkg::Lock::Timeout=60 "$pkg" ||
                { apt-get update && apt-get install -y -o DPkg::Lock::Timeout=60 "$pkg"; }
            ;;
        *)
            if command -v dnf >/dev/null; then dnf install -y "$pkg"; else yum localinstall -y "$pkg"; fi
            ;;
        esac || fail "installing the RustDesk package failed"
    fi
    { systemctl enable --now rustdesk && systemctl is-active --quiet rustdesk; } ||
        fail "the RustDesk service does not start"

    # the service needs a moment before it answers the CLI. An update never
    # sets the password.
    for i in $(seq 30); do
        [ "$mode" = update ] && break
        "$rd" --password "$RD_PASSWORD" | grep -qx 'Done!' && break
        [ "$i" = 30 ] && fail "the RustDesk service did not take the password"
        sleep 2
    done
    "$rd" --config 'rdConfig'
    [ "$("$rd" --option custom-rendezvous-server | tail -n 1)" = 'rdHost' ] ||
        fail "the server settings did not stick"
    id=$("$rd" --get-id | tail -n 1)
    [ -n "$id" ] || fail "rustdesk --get-id printed nothing"
    ver=$("$rd" --version | head -n 1)
    if [ "$mode" = update ]; then
        [ "$id" = 'rdExpectId' ] || fail "the RustDesk ID changed to $id, use Install or reconfigure"
        [ "$ver" = 'rdVersion' ] || fail "the update left RustDesk at $ver instead of rdVersion"
        [ "$(fingerprint)" = "$before" ] ||
            fail "the RustDesk key or password changed during the update, use Install or reconfigure"
    fi
    echo "RUSTDESK_OK $id $ver" >"$dir/result"
) </dev/null >>"$log" 2>&1

cat "$dir/result" 2>/dev/null
rm -rf "$dir"

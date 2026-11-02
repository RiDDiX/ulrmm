#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install one distribution package as root, for a baseline. PKG_NAME env only.
# server reads the last line: ULRMM-PKG {json}, like the package scripts.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

name=${PKG_NAME:-}
unset PKG_NAME
result=fail code=null msg='the script stopped early' out=''

# printable ascii, capped, json-escaped
esc() {
    printf '%s' "$1" | tr '\000-\037' ' ' | tr -c ' -~' '?' | cut -c 1-400 | sed 's/[\\"]/\\&/g'
}
finish() {
    [ -n "$out" ] && rm -f "$out"
    printf 'ULRMM-PKG {"result":"%s","exit":%s,"sig":"","signer":"","msg":"%s"}\n' \
        "$result" "$code" "$(esc "$msg")"
}
refuse() {
    result=refused msg=$*
    exit 1
}
fail() {
    result=fail msg=$*
    exit 1
}
trap finish EXIT
trap 'fail "the script was stopped"' HUP INT TERM

[ "$(id -u)" = 0 ] || refuse "not running as root"
# the server checks the same rule, a leading dash would be an option
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]] || refuse "not a package name: $name"

if command -v apt-get >/dev/null; then
    set -- apt-get install -y -o DPkg::Lock::Timeout=300 \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$name"
elif command -v dnf >/dev/null; then
    set -- dnf install -y "$name"
elif command -v yum >/dev/null; then
    set -- yum install -y "$name"
elif command -v zypper >/dev/null; then
    set -- zypper --non-interactive install "$name"
elif command -v pacman >/dev/null; then
    set -- pacman -S --noconfirm --needed "$name"
else
    refuse "no apt-get, dnf, yum, zypper or pacman on this system"
fi

out=$(mktemp /tmp/ulrmm-pkg.XXXXXX) || fail "cannot create a log file"
"$@" </dev/null >"$out" 2>&1
code=$?
# unknown package: refresh the lists once and try again
if [ "$code" != 0 ] && [ "$1" = apt-get ]; then
    { apt-get update; "$@"; } </dev/null >>"$out" 2>&1
    code=$?
fi
tail -n 40 "$out"
case $1:$code in
*:0) result=ok msg="$name installed with $1" ;;
zypper:102) result=reboot msg="$name installed with zypper, it asks for a reboot" ;;
*) fail "$1 exited with $code: $(tail -n 3 "$out")" ;;
esac

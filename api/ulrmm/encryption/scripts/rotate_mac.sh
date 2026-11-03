#!/bin/bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# New FileVault personal recovery key. bash 3.2.
# FV_USER and FV_PASSWORD (an account that can unlock the disk) arrive in
# env_vars. fdesetup reads them as a plist on stdin, not from argv or a file.
# Prints ULRMM-FV <key>. ULRMM-FAIL <reason>: the old key is unchanged.
# ULRMM-LOST <reason>: the key changed and the new one was not read back.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
umask 077

user=${FV_USER:-} pw=${FV_PASSWORD:-}
unset FV_USER FV_PASSWORD

fail() {
    echo "ULRMM-FAIL $*"
    exit 1
}
trap 'fail "the script was stopped"' HUP INT TERM

# first line, printable ascii
text() { printf '%s\n' "$1" | head -n 1 | tr -cd ' -~' | cut -c 1-200; }
# xml-escaped. the value is written to the pipe
xml() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

if [ "$(uname -s)" != Darwin ]; then fail "not macOS"; fi
if [ "$(id -u)" != 0 ]; then fail "not running as root"; fi
if [ -z "$user" ] || [ -z "$pw" ]; then
    fail "no user name or password was handed to the script"
fi
case $(fdesetup status 2>/dev/null) in
*"FileVault is On"*) ;;
*) fail "FileVault is not on" ;;
esac

result=$(mktemp /tmp/ulrmm-fv.XXXXXX) || fail "cannot create a temp file"
# every exit from here on, also through fail and the signal trap
trap 'rm -f "$result"' EXIT
chmod 600 "$result" || fail "cannot protect the temp file"

plist() {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo "<key>Username</key><string>$(xml "$user")</string>"
    echo "<key>Password</key><string>$(xml "$pw")</string>"
    echo '</dict></plist>'
}

# a stop from here on may come after the key changed
trap 'echo "ULRMM-LOST the script was stopped"; exit 1' HUP INT TERM
err=$(plist | fdesetup changerecovery -personal -outputplist -inputplist 2>&1 >"$result")
rc=$?
pw=''
if [ $rc -ne 0 ]; then fail "fdesetup changerecovery failed (exit $rc): $(text "$err")"; fi

key=$(/usr/libexec/PlistBuddy -c 'Print :RecoveryKey' "$result" 2>/dev/null)
re='^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$'
if [[ ! $key =~ $re ]]; then
    echo "ULRMM-LOST fdesetup reported success but its output holds no recovery key"
    exit 1
fi
echo "ULRMM-FV $key"
exit 0

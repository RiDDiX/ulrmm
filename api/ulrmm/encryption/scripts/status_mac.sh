#!/bin/bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# FileVault state. No input. Prints
#   ULRMM-FVS <on|off|unknown>|<percent encrypted, while encrypting>|<personal key: true|false|unknown>
# then ULRMM-END. fdesetup does not print the recovery key. See rotate_mac.sh.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C

if [ "$(uname -s)" != Darwin ]; then
    echo "ULRMM-FAIL not macOS"
    exit 3
fi
if [ "$(id -u)" != 0 ]; then
    echo "ULRMM-FAIL not running as root"
    exit 3
fi

out=$(fdesetup status 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
    echo "ULRMM-FAIL fdesetup status failed (exit $rc): $(printf '%s\n' "$out" | head -n 1 | tr -cd ' -~')"
    exit 1
fi
case $out in
*"FileVault is On"* | *"Encryption in progress"*) state=on ;;
*"FileVault is Off"*) state=off ;;
*) state=unknown ;;
esac
percent=$(printf '%s\n' "$out" | sed -n 's/.*Encryption in progress: Percent completed = \([0-9][0-9.]*\).*/\1/p' | head -n 1)
personal=$(fdesetup haspersonalrecoverykey 2>/dev/null)
case $personal in
true | false) ;;
*) personal=unknown ;;
esac
echo "ULRMM-FVS $state|$percent|$personal"
echo "ULRMM-END"

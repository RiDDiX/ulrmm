#!/bin/sh
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# LUKS volumes, without keys. No input. Prints
#   ULRMM-LUKS <device>|<first mount point of it or its children, or empty>
# per crypto_LUKS device, then ULRMM-END.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

if ! command -v lsblk >/dev/null 2>&1; then
    echo "ULRMM-FAIL lsblk is not installed (util-linux)"
    exit 3
fi
if ! list=$(lsblk -rpno NAME,FSTYPE 2>&1); then
    echo "ULRMM-FAIL lsblk failed: $(printf '%s\n' "$list" | head -n 1 | tr -cd ' -~')"
    exit 1
fi
printf '%s\n' "$list" | while read -r dev fstype; do
    [ "$fstype" = crypto_LUKS ] || continue
    mnt=$(lsblk -rno MOUNTPOINT "$dev" 2>/dev/null | awk 'NF { print; exit }')
    echo "ULRMM-LUKS $dev|$mnt"
done
echo "ULRMM-END"

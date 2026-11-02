# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# BitLocker recovery passwords for the key escrow. No input.
# One line per recovery password protector:
#   ULRMM-BL <mount>|<protector id>|<password>|<protection>|<percent>
# a volume without one gets a line with both fields empty. ULRMM-END comes
# last and only when every volume was read; the server parses nothing else.
# [Console]::Out bypasses the PowerShell host, so no transcript gets the keys.
# Exit: 0 read, 1 a volume could not be read, 3 no BitLocker module (e.g. Home).
$ProgressPreference = 'SilentlyContinue'

function Get-Text([string]$Text) {
    ($Text -replace '[^ -~]', ' ').Trim()
}

if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    [Console]::Out.WriteLine('ULRMM-FAIL BitLocker is not available on this edition (no BitLocker PowerShell module)')
    exit 3
}

$failed = $null
try {
    $volumes = @(Get-BitLockerVolume -ErrorAction SilentlyContinue -ErrorVariable failed)
} catch {
    [Console]::Out.WriteLine('ULRMM-FAIL ' + (Get-Text $_.Exception.Message))
    exit 1
}
if ($volumes.Count -eq 0 -and -not $failed) {
    [Console]::Out.WriteLine('ULRMM-FAIL Get-BitLockerVolume returned no volumes')
    exit 1
}

foreach ($v in $volumes) {
    # folder mount points may hold other characters; the server takes 64
    $mount = ([string]$v.MountPoint) -replace '[^ -{}~]', '?'
    if ($mount.Length -gt 64) { $mount = $mount.Substring(0, 64) }
    $state = [string]$v.ProtectionStatus
    if ($state -notin 'On', 'Off') { $state = 'Unknown' }
    $percent = [int][math]::Floor([double]$v.EncryptionPercentage)
    $found = $false
    foreach ($p in @($v.KeyProtector)) {
        if ([string]$p.KeyProtectorType -eq 'RecoveryPassword' -and $p.RecoveryPassword) {
            [Console]::Out.WriteLine(('ULRMM-BL {0}|{1}|{2}|{3}|{4}' -f $mount, $p.KeyProtectorId, $p.RecoveryPassword, $state, $percent))
            $found = $true
        }
    }
    if (-not $found) {
        [Console]::Out.WriteLine(('ULRMM-BL {0}|||{1}|{2}' -f $mount, $state, $percent))
    }
}

# the keys printed so far are kept, but without ULRMM-END none goes stale
if ($failed) {
    [Console]::Out.WriteLine('ULRMM-FAIL ' + (Get-Text $failed[0].Exception.Message))
    exit 1
}
[Console]::Out.WriteLine('ULRMM-END')
exit 0

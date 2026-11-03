# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# remove one third-party driver package from the driver store. DRV_INF env only.
# server reads the last line: ULRMM-PKG {json}.
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

# json string. printable ascii stays, anything else is \u-escaped.
function ConvertTo-JsonText([string]$Text) {
    $b = New-Object Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        $n = [int]$c
        if ($n -eq 34 -or $n -eq 92) { [void]$b.Append('\').Append($c) }
        elseif ($n -lt 32 -or $n -gt 126) { [void]$b.AppendFormat('\u{0:x4}', $n) }
        else { [void]$b.Append($c) }
    }
    '"' + $b.ToString() + '"'
}

function Format-Marker($R) {
    $f = @{}
    foreach ($k in 'result', 'sig', 'signer', 'msg') {
        $s = [string]$R[$k]
        if ($s.Length -gt 400) { $s = $s.Substring(0, 400) }
        $f[$k] = ConvertTo-JsonText $s
    }
    $exit = if ($null -eq $R.exit) { 'null' } else { [string][long]$R.exit }
    'ULRMM-PKG {"result":' + $f.result + ',"exit":' + $exit + ',"sig":' + $f.sig +
    ',"signer":' + $f.signer + ',"msg":' + $f.msg + '}'
}

function Deny([string]$Why) {
    $r.result = 'refused'
    throw $Why
}

# the server blocks the same classes, removing one can leave Windows unbootable
$boot = 'SCSIAdapter', 'HDC', 'DiskDrive', 'Volume', 'VolumeSnapshot', 'System', 'Processor', 'Computer'
$inf = [string]$env:DRV_INF
$r = @{ result = 'fail'; exit = $null; sig = ''; signer = ''; msg = 'the script stopped early' }
try {
    # inbox drivers never have an oem name
    if ($inf -notmatch '^oem\d{1,5}\.inf\z') { Deny ('not a third-party driver package: ' + $inf) }
    $inf = $inf.ToLowerInvariant()
    if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { Deny 'not running as SYSTEM' }
    if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot ('INF\' + $inf)) -PathType Leaf)) {
        Deny ($inf + ' is not in the driver store')
    }
    $used = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter ("InfName = '" + $inf + "'") |
            Where-Object { $boot -contains [string]$_.DeviceClass })
    if ($used.Count) { Deny ($inf + ' is used by ' + $used[0].DeviceName + ', a device Windows needs to boot') }

    $sys = Join-Path $env:SystemRoot 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $sys = Join-Path $env:SystemRoot 'Sysnative' }
    # never forced, a driver a device still needs stays
    # pnputil writes in the ANSI code page, PowerShell would read it as OEM
    $enc = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
        $out = & { $ErrorActionPreference = 'Continue'; & (Join-Path $sys 'pnputil.exe') /delete-driver $inf /uninstall 2>&1 } |
            ForEach-Object { [string]$_ }
        $code = $LASTEXITCODE
    } finally { [Console]::OutputEncoding = $enc }
    $out
    $r.exit = $code
    $r.msg = 'pnputil.exe exited with ' + $code
    $r.result = if ($code -eq 0) { 'ok' } elseif ($code -eq 3010) { 'reboot' } else { 'fail' }
} catch {
    if ($r.result -cne 'refused') { $r.result = 'fail' }
    $r.msg = $_.Exception.Message
} finally {
    Write-Output (Format-Marker $r)
}

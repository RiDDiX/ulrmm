# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# baseline check: a file or an HKLM key or value. DET_* env only.
# server reads the last line: ULRMM-DET {"found":bool,"version":"..."}.
$ErrorActionPreference = 'Stop'
$kind = [string]$env:DET_TYPE
$found = $false
$ver = ''
try {
    if ($kind -ceq 'file') {
        $p = [Environment]::ExpandEnvironmentVariables([string]$env:DET_PATH)
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $found = $true
            $info = (Get-Item -LiteralPath $p -Force).VersionInfo
            $ver = [string]$info.ProductVersion
            if (-not $ver) { $ver = [string]$info.FileVersion }
        }
    } elseif ($kind -ceq 'registry') {
        $key = [string]$env:DET_KEY
        $name = [string]$env:DET_VALUE
        if (Test-Path -LiteralPath $key) {
            if ($name) {
                $item = Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
                if ($null -ne $item) {
                    $found = $true
                    $ver = [string]$item.$name
                }
            } else {
                $found = $true
            }
        }
    }
} catch {
    $found = $false
    $ver = ''
}
if ($ver.Length -gt 255) { $ver = $ver.Substring(0, 255) }
'ULRMM-DET ' + (@{ found = $found; version = $ver } | ConvertTo-Json -Compress)

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install or update rustdesk. update mode: no pw, only if older than rdVersion.
# checks id/key/pw survived. server reads one line: RUSTDESK_OK id ver or FAIL reason.
# stderr to null.
$ProgressPreference = 'SilentlyContinue'
$tls = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ([Enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
    $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
}
[Net.ServicePointManager]::SecurityProtocol = $tls
$log = Join-Path $env:ProgramData 'rustdesk-deploy.log'
$exe = Join-Path $env:ProgramFiles 'RustDesk\rustdesk.exe'
$toml = Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk.toml'
$update = 'rdMode' -eq 'update'
# hash of the ID, key pair and password entries (key_pair spans several
# lines); it is only compared, never written anywhere
function Get-Fingerprint {
    $keep = $false
    $lines = foreach ($l in @(Get-Content -LiteralPath $toml -ErrorAction Stop)) {
        if ($l -match '^([A-Za-z_]+) = ') { $keep = $Matches[1] -in 'enc_id', 'password', 'salt', 'key_pair' }
        elseif ($l -match '^\[[A-Za-z_]') { $keep = $false }
        if ($keep) { $l }
    }
    if (-not $lines) { throw 'the RustDesk config holds no ID or password' }
    $sha = [Security.Cryptography.SHA256]::Create()
    [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($lines -join "`n")))
}
# a failure up to the password step leaves the endpoint with its old password,
# see PRE_PASSWORD_FAILURES in remote/utils.py
$prefix = 'setup: '
try {
    # an agent that drops env_vars would otherwise set an empty password
    if (-not $update -and -not $env:RD_PASSWORD) { throw 'no password was handed to the script' }
    $have = $null
    $installed = Test-Path -LiteralPath $exe
    if ($update) {
        if (-not $installed) { throw 'RustDesk is not installed, use Install or reconfigure' }
        if (-not [version]::TryParse((& $exe --version 2>$null | Select-Object -First 1), [ref]$have)) {
            throw 'cannot read the installed RustDesk version'
        }
        if ($have -gt [version]'rdVersion') { throw ('not downgrading: RustDesk rdVersion is older than the installed ' + $have) }
        $before = Get-Fingerprint
    }
    # only an update upgrades, so a reconfigure can always rotate the password
    if (-not $installed -or ($update -and $have -lt [version]'rdVersion')) {
        if ($installed) {
            # a major upgrade would leave an install from the exe installer in place
            $arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RustDesk'
            if ((Get-ItemProperty -LiteralPath $arp -ErrorAction SilentlyContinue).WindowsInstaller -ne 1) {
                throw 'RustDesk was not installed from the MSI, uninstall it first'
            }
            # the MSI ends every rustdesk.exe. Arguments are matched, never logged.
            $open = '^\s*("[^"]*"|\S+)\s+"?(--cm|--connect|--play|--file-transfer|--view-camera|--port-forward|--terminal|--whiteboard|--rdp|rustdesk:)'
            $procs = @(Get-CimInstance Win32_Process -Filter "Name='rustdesk.exe'" -ErrorAction Stop)
            # at the sign-in screen there is no --cm, only the session's TCP
            # connection: to hbbr (21117) or the viewer. 21114-21116 belong to the ID server.
            $conns = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    $_.State -eq 'Established' -and $_.OwningProcess -in $procs.ProcessId -and $_.RemotePort -notin 21114..21116
                })
            if (@($procs | Where-Object { $_.CommandLine -match $open }).Count -or $conns.Count) {
                throw 'busy: a RustDesk session is open on this device'
            }
        }
        # new directory. Users can create files in C:\Windows\Temp.
        $dir = Join-Path $env:SystemRoot ('Temp\rustdesk-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
        $msi = Join-Path $dir 'rustdesk.msi'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri 'rdMsiUrl' -OutFile $msi -ErrorAction Stop
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $msi -ErrorAction Stop).Hash -ne 'rdMsiSha256') {
                throw 'checksum mismatch: rdMsiUrl'
            }
            $p = Start-Process -FilePath msiexec.exe -ArgumentList '/i', $msi, '/qn', '/norestart', '/l*v', $log -Wait -PassThru -ErrorAction Stop
            if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
                throw ('msiexec exited with ' + $p.ExitCode + ', see ' + $log)
            }
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $svc = $null
    for ($i = 0; $i -lt 30 -and -not $svc; $i++) {
        $svc = Get-Service -Name RustDesk -ErrorAction SilentlyContinue
        if (-not $svc) { Start-Sleep -Seconds 2 }
    }
    if (-not $svc) { throw 'the RustDesk service is missing' }
    if ($svc.Status -ne 'Running') { Start-Service -Name RustDesk -ErrorAction Stop }

    # the service needs a moment before it answers the CLI
    # rustdesk.exe is a gui binary. without a pipe powershell does not
    # wait for it or read its output. An update never sets the password.
    $ok = $update
    for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
        $out = @(& $exe --password $env:RD_PASSWORD 2>$null | ForEach-Object { $_ })
        $ok = $out -contains 'Done!'
        if (-not $ok) { Start-Sleep -Seconds 2 }
    }
    if (-not $ok) { throw ('the RustDesk service did not take the password: ' + ($out -join ' ')) }
    $prefix = ''
    & $exe --config 'rdConfig' 2>$null | Out-Null
    if ((& $exe --option custom-rendezvous-server 2>$null | Select-Object -Last 1) -ne 'rdHost') {
        throw 'the server settings did not stick'
    }
    $id = & $exe --get-id 2>$null | Select-Object -Last 1
    if (-not $id) { throw 'rustdesk --get-id printed nothing' }
    $ver = & $exe --version 2>$null | Select-Object -First 1
    if ($update) {
        if ($id -cne 'rdExpectId') { throw ('the RustDesk ID changed to ' + $id + ', use Install or reconfigure') }
        if ($ver -cne 'rdVersion') { throw ('the update left RustDesk at ' + $ver + ' instead of rdVersion') }
        if ((Get-Fingerprint) -cne $before) {
            throw 'the RustDesk key or password changed during the update, use Install or reconfigure'
        }
    }
    Write-Output ('RUSTDESK_OK ' + $id + ' ' + $ver)
} catch {
    # one ascii line, whatever language windows speaks
    Write-Output ('RUSTDESK_FAIL ' + $prefix + ($_.Exception.Message -replace '[^ -~]', '?'))
}

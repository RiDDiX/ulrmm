# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install an uploaded package. PKG_* env only.
# server reads the last line: ULRMM-PKG {json}.
# run_as_user with nobody logged in comes back as SYSTEM, so check the
# token against PKG_MODE before the download.
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# json string. printable ascii stays, anything else is \u-escaped.
# status text comes back in the system language.
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

# marker line. $Hide (the download link and its token) is left out.
function Format-Marker($R, [string[]]$Hide) {
    $f = @{}
    foreach ($k in 'result', 'sig', 'signer', 'msg') {
        $s = [string]$R[$k]
        foreach ($h in $Hide) { if ($h.Length -ge 16) { $s = $s.Replace($h, '<hidden>') } }
        if ($s.Length -gt 400) { $s = $s.Substring(0, 400) }
        $f[$k] = ConvertTo-JsonText $s
    }
    $exit = if ($null -eq $R.exit) { 'null' } else { [string][long]$R.exit }
    'ULRMM-PKG {"result":' + $f.result + ',"exit":' + $exit + ',"sig":' + $f.sig +
    ',"signer":' + $f.signer + ',"msg":' + $f.msg + '}'
}

function Get-ExitResult([long]$Code) {
    if ($Code -eq 0) { 'ok' } elseif ($Code -eq 3010 -or $Code -eq 1641) { 'reboot' } else { 'fail' }
}

# pnputil: 259 means the driver went into the store but no device took it
function Get-PnpResult([long]$Code) {
    if ($Code -eq 259) { 'ok' } else { Get-ExitResult $Code }
}

# signature to store, or $null when the file must not run.
# msix/appx files this cmdlet cannot read go to Add-Appx*, which rejects
# untrusted packages.
function Get-SigVerdict([string]$Status, [string]$Kind, [bool]$AllowUnsigned) {
    if ($Status -ceq 'Valid') { return 'Valid' }
    if ($Status -ceq 'NotSigned' -and $AllowUnsigned) { return 'NotSigned' }
    if ($Kind -in 'msix', 'appx' -and $Status -in 'NotSupportedFileFormat', 'UnknownError') { return 'AppxEnforced' }
    $null
}

function Deny([string]$Why) {
    $r.result = 'refused'
    throw $Why
}

# waits for the started process until PKG_TIMEOUT, then stops it and throws
function Wait-Installer($P) {
    if ($waitSecs) {
        $ms = [int][Math]::Max(1000, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $P.WaitForExit($ms)) {
            # a failed taskkill does not replace the timeout error.
            # Continue: with Stop, PowerShell 5.1 throws on taskkill's first stderr line.
            try {
                & { $ErrorActionPreference = 'Continue'; & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /T /F /PID $P.Id 2>&1 | Out-Null }
            } catch {
                'taskkill failed: ' + $_.Exception.Message
            }
            throw ('the installer did not finish within ' + $waitSecs + ' seconds and was stopped')
        }
    }
    $P.WaitForExit()
}

$maxEntries = 20000
$maxBytes = 4GB

# zip into $To. every entry has to land under $To, the sizes are counted
# while writing, the sizes in the zip header can lie.
function Expand-DriverZip([string]$Zip, [string]$To) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $base = [IO.Path]::GetFullPath($To).TrimEnd('\') + '\'
    $a = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        if ($a.Entries.Count -gt $maxEntries) { Deny ('the zip has more than ' + $maxEntries + ' entries') }
        $targets = New-Object 'Collections.Generic.List[object]'
        foreach ($e in $a.Entries) {
            if ($e.FullName.Contains(':')) { Deny ('zip entry with a drive or stream name: ' + $e.FullName) }
            $t = [IO.Path]::GetFullPath([IO.Path]::Combine($base, $e.FullName))
            if (-not $t.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
                Deny ('zip entry outside the package folder: ' + $e.FullName)
            }
            $targets.Add(@($e, $t))
        }
        $total = 0L
        $buf = New-Object byte[] 65536
        foreach ($pair in $targets) {
            $e, $t = $pair
            if ($e.FullName.EndsWith('/') -or $e.FullName.EndsWith('\')) {
                [void][IO.Directory]::CreateDirectory($t)
                continue
            }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($t))
            $src = $e.Open()
            try {
                $out = New-Object IO.FileStream($t, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
                try {
                    while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
                        $total += $n
                        if ($total -gt $maxBytes) { Deny 'the zip unpacks to more than 4 GiB' }
                        $out.Write($buf, 0, $n)
                    }
                } finally { $out.Dispose() }
            } finally { $src.Dispose() }
        }
    } finally { $a.Dispose() }
}

# cab into $To with expand.exe, after its file list passed the same name rules
function Expand-DriverCab([string]$Cab, [string]$To) {
    $expand = Join-Path $sys 'expand.exe'
    $list = @(& { $ErrorActionPreference = 'Continue'; & $expand -D $Cab 2>&1 } | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE) { throw ('expand.exe could not list the cab, exit code ' + $LASTEXITCODE) }
    $prefix = $Cab + ': '
    $names = @($list | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { $_.Substring($prefix.Length) })
    if (-not $names) { throw 'the cab lists no files' }
    if ($names.Count -gt $maxEntries) { Deny ('the cab has more than ' + $maxEntries + ' files') }
    foreach ($n in $names) {
        if ($n.Contains(':') -or [IO.Path]::IsPathRooted($n) -or $n.StartsWith('/') -or
            ($n -split '[\\/]') -contains '..') {
            Deny ('cab entry outside the package folder: ' + $n)
        }
    }
    & { $ErrorActionPreference = 'Continue'; & $expand ('-F:*') $Cab $To 2>&1 | Out-Null }
    if ($LASTEXITCODE) { throw ('expand.exe failed with exit code ' + $LASTEXITCODE) }
}

# Valid or NotSigned (with allow_unsigned) for the .cat files, else Deny.
# no catalog at all counts as NotSigned.
function Test-DriverCatalogs([string]$Dir) {
    $cats = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -Filter '*.cat')
    if (-not $cats) {
        if (-not $allowUnsigned) { Deny 'the driver package has no signed catalog (.cat) and unsigned packages are not allowed' }
        $r.sig = 'NotSigned'
        return
    }
    $r.sig = 'Valid'
    foreach ($c in $cats) {
        $s = Get-AuthenticodeSignature -LiteralPath $c.FullName
        $st = [string]$s.Status
        if ($st -ceq 'Valid') {
            if (-not $r.signer) { $r.signer = $s.SignerCertificate.Subject }
        } elseif ($st -ceq 'NotSigned' -and $allowUnsigned) {
            $r.sig = 'NotSigned'
        } elseif ($st -ceq 'NotSigned') {
            Deny ($c.Name + ' is not signed and unsigned packages are not allowed')
        } else {
            Deny ($c.Name + ': signature ' + $st + ': ' + $s.StatusMessage)
        }
    }
}

$url = [string]$env:PKG_URL
$sum = [string]$env:PKG_SHA256
$name = [string]$env:PKG_NAME
$kind = [string]$env:PKG_KIND
$pkgArgs = [string]$env:PKG_ARGS
$allowUnsigned = $env:PKG_ALLOW_UNSIGNED -eq '1'
$mode = [string]$env:PKG_MODE
# a file the agent downloaded and checked itself (agent jobs), instead of a download
$localFile = [string]$env:PKG_FILE
# a driver folder the agent unpacked itself (SDIO packs), instead of a download.
# agent jobs set PKG_DIR to their work folder, so PKG_FILE wins.
$localDir = if ($localFile) { '' } else { [string]$env:PKG_DIR }
if ($localDir) { $allowUnsigned = $false }
# the agent kills this script at its timeout, and finally does not run.
# stop the installer on PKG_TIMEOUT instead.
$waitSecs = 0
if (-not [int]::TryParse([string]$env:PKG_TIMEOUT, [ref]$waitSecs) -or $waitSecs -lt 1) { $waitSecs = 0 }
$deadline = [DateTime]::UtcNow.AddSeconds($waitSecs)
# installers do not get to see the download link
Remove-Item -Path Env:PKG_* -ErrorAction SilentlyContinue
$tok = $url.TrimEnd('/') -replace '^.*/', ''
$r = @{ result = 'fail'; exit = $null; sig = ''; signer = ''; msg = 'the script stopped early' }
$dir = $null
# 64-bit tools from a 32-bit PowerShell are under Sysnative
$sys = Join-Path $env:SystemRoot 'System32'
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $sys = Join-Path $env:SystemRoot 'Sysnative' }
try {
    $exts = @{ exe = @('.exe'); msi = @('.msi'); msix = @('.msix', '.msixbundle'); appx = @('.appx', '.appxbundle'); driver = @('.zip', '.cab') }
    if ($kind -cnotin 'exe', 'msi', 'msix', 'appx', 'driver') { Deny ('not a Windows package kind: ' + $kind) }
    if ($mode -cnotin 'system', 'user') { Deny ('unknown install mode: ' + $mode) }
    if ($kind -ceq 'driver' -and $mode -cne 'system') { Deny 'drivers install as system' }
    # pnputil /subdirs needs Windows 10 1607
    if ($kind -ceq 'driver' -and [Environment]::OSVersion.Version.Build -lt 14393) {
        Deny 'driver packages need Windows 10 1607 (build 14393) or later'
    }
    if ($localDir) {
        if ($kind -cne 'driver') { Deny 'a local folder can only hold a driver' }
        $pd = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
        $localDir = [IO.Path]::GetFullPath($localDir)
        if (-not $localDir.StartsWith($pd, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $localDir -PathType Container) -or
            (Get-Item -LiteralPath $localDir -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            Deny 'the driver folder is not a folder below ProgramData'
        }
    } else {
        if ($sum -notmatch '^[0-9a-fA-F]{64}\z') { Deny 'no valid sha256 was handed to the script' }
        $u = $null
        if ($localFile) {
            if ($mode -cne 'system') { Deny 'a file from the agent installs as system only' }
            $pd = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
            $localFile = [IO.Path]::GetFullPath($localFile)
            if (-not $localFile.StartsWith($pd, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $localFile -PathType Leaf) -or
                (Get-Item -LiteralPath $localFile -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
                [IO.Path]::GetExtension($localFile) -notin $exts[$kind]) {
                Deny 'the package file is not a file below ProgramData'
            }
        } elseif (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -cne 'https') {
            Deny 'the download link is not https'
        }
        if ($name -notmatch '^[A-Za-z0-9._()+ -]{1,120}\z' -or $name -match '^(CON|PRN|AUX|NUL|COM\d|LPT\d)\.' -or
            [IO.Path]::GetExtension($name) -notin $exts[$kind]) {
            Deny 'the file name is not safe to use'
        }
    }

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($mode -ceq 'system' -and -not $id.IsSystem) { Deny 'not running as SYSTEM' }
    if ($mode -ceq 'user' -and $id.IsSystem) { Deny 'nobody is logged in' }
    # elevated: integrity High or System. includes Backup Operators and
    # other non-admins with a linked token, not just Administrators.
    # the label SID is the same in every language. no label from whoami: fail.
    $label = @(& {
            $ErrorActionPreference = 'Continue'
            & (Join-Path $env:SystemRoot 'System32\whoami.exe') /groups 2>$null
        } | Select-String -Pattern '\bS-1-16-(\d+)\b')
    if (-not $label) { throw 'cannot read the integrity level of this token' }
    $elevated = [int]$label[0].Matches[0].Groups[1].Value -ge 12288
    # SetOwner to Administrators needs that group in the token. without it
    # the dir below locks this user out.
    if ($elevated -and -not $id.IsSystem -and
        -not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Deny 'the user is elevated but not an administrator, install this package as system'
    }

    # ACL is SYSTEM, Administrators, and the user only when not elevated,
    # so nothing else can swap the file between the hash check and the run.
    # elevated: %SystemRoot%\Temp, owner Administrators. the user's %TEMP%,
    # or a dir the user owns (owner has WRITE_DAC), can be renamed or
    # re-ACLed by an unelevated process. SYSTEM keeps the default owner;
    # for that case the check wants SYSTEM or Administrators.
    $sids = @('S-1-5-18', 'S-1-5-32-544')
    if (-not $elevated) { $sids += $id.User.Value }
    $root = if ($elevated) { Join-Path $env:SystemRoot 'Temp' } else { $env:TEMP }
    $path = Join-Path $root ('ulrmm-pkg-' + [guid]::NewGuid())
    if (Test-Path -LiteralPath $path) { Deny 'the work directory already exists' }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($s in $sids) {
        $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                    (New-Object Security.Principal.SecurityIdentifier $s), 'FullControl',
                    'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    if ($elevated -and -not $id.IsSystem) { $sec.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544') }
    [void][IO.Directory]::CreateDirectory($path, $sec)
    # CreateDirectory keeps a directory that already exists, ACL and all
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $foreign = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -notin $sids })
    if (-not $acl.AreAccessRulesProtected -or $foreign.Count -or $owner -notin $sids -or
        (Get-Item -LiteralPath $path -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        Deny 'the work directory is not the one this script created'
    }
    $dir = $path

    if ($localFile) {
        $file = $localFile
    } elseif (-not $localDir) {
        $file = Join-Path $dir $name
        # nginx does not log a ulrmm/* user agent. the link has the token.
        Invoke-WebRequest -UseBasicParsing -UserAgent 'ulrmm/pkg' -Uri $u -OutFile $file
    }
    if (-not $localDir) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash -ne $sum) {
            Deny 'sha256 mismatch, the download is not the uploaded package'
        }
    }

    if ($kind -cne 'driver') {
        $s = Get-AuthenticodeSignature -LiteralPath $file
        $r.sig = [string]$s.Status
        $verdict = Get-SigVerdict $r.sig $kind $allowUnsigned
        if (-not $verdict) {
            if ($r.sig -ceq 'NotSigned') { Deny 'the package is not signed and unsigned packages are not allowed' }
            Deny ('signature ' + $r.sig + ': ' + $s.StatusMessage)
        }
        $r.sig = $verdict
        if ($verdict -ceq 'Valid') { $r.signer = $s.SignerCertificate.Subject }
    }

    if ($kind -ceq 'driver') {
        # a zip archive has no Authenticode signature, its .cat catalogs do
        if ($localDir) {
            $x = $localDir
        } else {
            $x = Join-Path $dir 'x'
            [void][IO.Directory]::CreateDirectory($x)
            $head = New-Object byte[] 4
            $fs = [IO.File]::OpenRead($file)
            try { [void]$fs.Read($head, 0, 4) } finally { $fs.Dispose() }
            if ($head[0] -eq 0x50 -and $head[1] -eq 0x4B -and $head[2] -eq 3 -and $head[3] -eq 4) {
                Expand-DriverZip $file $x
            } elseif ([Text.Encoding]::ASCII.GetString($head) -ceq 'MSCF') {
                Expand-DriverCab $file $x
            } else {
                Deny 'the driver package is neither a zip nor a cab'
            }
        }
        $items = @(Get-ChildItem -LiteralPath $x -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) }).Count) {
            Deny 'the driver package contains links'
        }
        $size = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
        if ($size -gt $maxBytes) { Deny 'the driver package unpacks to more than 4 GiB' }
        if (-not @($items | Where-Object { -not $_.PSIsContainer -and $_.Extension -eq '.inf' }).Count) {
            throw 'no INF file in the package'
        }
        Test-DriverCatalogs $x

        $pnp = Join-Path $sys 'pnputil.exe'
        $log = Join-Path $dir 'pnputil.log'
        $sp = @{ FilePath = $pnp; PassThru = $true; NoNewWindow = $true; WorkingDirectory = $dir
            ArgumentList = '/add-driver "{0}\*.inf" /subdirs /install' -f $x
            RedirectStandardOutput = $log
        }
        $p = Start-Process @sp
        $null = $p.Handle
        try { Wait-Installer $p } finally {
            Get-Content -LiteralPath $log -ErrorAction SilentlyContinue
        }
        $r.exit = $p.ExitCode
        $r.result = Get-PnpResult $p.ExitCode
        $r.msg = 'pnputil.exe exited with ' + $p.ExitCode
        if ($p.ExitCode -eq 259) { $r.msg = 'added to the driver store, no device took it' }
    } elseif ($kind -in 'msix', 'appx') {
        if ($mode -ceq 'system') {
            $res = Add-AppxProvisionedPackage -Online -PackagePath $file -SkipLicense
            $r.msg = 'provisioned for all users'
            $r.result = if ($res.RestartNeeded) { 'reboot' } else { 'ok' }
        } else {
            Add-AppxPackage -Path $file
            $r.msg = 'installed for the logged in user'
            $r.result = 'ok'
        }
    } else {
        $log = Join-Path $dir 'install.log'
        $sp = @{ FilePath = $file; PassThru = $true; WindowStyle = 'Hidden'; WorkingDirectory = $dir }
        if ($kind -ceq 'msi') {
            $sp.FilePath = Join-Path $env:SystemRoot 'System32\msiexec.exe'
            $sp.ArgumentList = '/i "{0}" /qn /norestart /l*v "{1}" {2}' -f $file, $log, $pkgArgs
        } elseif ($pkgArgs) {
            $sp.ArgumentList = $pkgArgs
        }
        # not elevated: no UAC prompt. an installer that asks for elevation
        # runs unelevated and fails.
        if (-not $elevated) { $env:__COMPAT_LAYER = 'RunAsInvoker' }
        # no -Wait: that also waits on processes the installer left running.
        # reading Handle keeps ExitCode valid after the process exits.
        $p = Start-Process @sp
        $null = $p.Handle
        Wait-Installer $p
        $r.exit = $p.ExitCode
        $r.msg = [IO.Path]::GetFileName($sp.FilePath) + ' exited with ' + $p.ExitCode
        $res = Get-ExitResult $p.ExitCode
        if ($res -ceq 'fail' -and $kind -ceq 'msi') {
            $tail = @(Get-Content -LiteralPath $log -Tail 20 -ErrorAction SilentlyContinue)
            $tail
            $r.msg += ': ' + ($tail -join ' | ')
        }
        $r.result = $res
    }
} catch {
    if ($r.result -cne 'refused') { $r.result = 'fail' }
    $r.msg = $_.Exception.Message
} finally {
    # the installer can still have the log open
    for ($i = 0; $dir -and $i -lt 5 -and (Test-Path -LiteralPath $dir); $i++) {
        if ($i) { Start-Sleep -Seconds 2 }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output (Format-Marker $r @($url, $tok))
}

# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

$innosetup = 'innosetupchange'
$api = '"apichange"'
$clientid = 'clientchange'
$siteid = 'sitechange'
$agenttype = '"atypechange"'
$power = powerchange
$rdp = rdpchange
$ping = pingchange
$auth = 'tokenchange'
$downloadlink = 'downloadchange'
$sha256 = 'sha256change'
# signed enrollment token of a deployment, used instead of the values above
$enroll = 'enrollchange'
$enrollFile = $null
$authFile = $null
# certificate of a self-signed server, the agent trusts it with -cert
$cert = ''
$apilink = $downloadlink.split('/')

$tls = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ([Enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
    $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
}
[Net.ServicePointManager]::SecurityProtocol = $tls
if ($cert) {
    # a self-signed server: its own certificate is the only one accepted
    $pinned = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Text.Encoding]::ASCII.GetBytes($cert)).GetCertHashString()
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $certificate, $chain, $errors)
        $certificate.GetCertHashString() -eq $pinned
    }.GetNewClosure()
}

# a file only SYSTEM and the administrators can read
function Write-Secret($path, $text) {
    [IO.File]::WriteAllText($path, $text)
    icacls $path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
        throw "could not restrict access to $path"
    }
}

$serviceName = 'identSvcName'
If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('UniversalLocal RMM is already installed')
} Else {
    $OutPath = $env:TMP
    $output = $innosetup

    $installArgs = @('-m install --api ', "$api", '--client-id', $clientid, '--site-id', $siteid, '--agent-type', "$agenttype")

    if ($power) {
        $installArgs += "--power"
    }

    if ($rdp) {
        $installArgs += "--rdp"
    }

    if ($ping) {
        $installArgs += "--ping"
    }

    Try
    {
        $DefenderStatus = Get-MpComputerStatus | select  AntivirusEnabled
        if ($DefenderStatus -match "True") {
            Add-MpPreference -ExclusionPath 'identWinProgPath\*'
            Add-MpPreference -ExclusionPath 'C:\Program Files\Mesh Agent\*'
            Add-MpPreference -ExclusionPath 'identWinProgData\*'
        }
    }
    Catch {
        # pass
    }
    
    $X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1      
    } until(($connectresult = Test-NetConnection $apilink[2] -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)
    
    if ($connectresult.TcpTestSucceeded -eq $true){
        Try
        {  
            Invoke-WebRequest -UseBasicParsing -Uri $downloadlink -OutFile $OutPath\$output
            if ($sha256 -and (Get-FileHash -Algorithm SHA256 -LiteralPath $OutPath\$output).Hash -ne $sha256) {
                throw "the download does not match its sha256 $sha256"
            }
            Start-Process -FilePath $OutPath\$output -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES') -Wait
            write-host ('Extracting...')
            Start-Sleep -s 7
            if ($enroll) {
                $enrollFile = Join-Path $OutPath ('enroll-' + [guid]::NewGuid().ToString('N') + '.jws')
                Write-Secret $enrollFile $enroll
                $agent = Start-Process -FilePath "identWinProgPath\identWinExe" -ArgumentList @('-m', 'install', '-enroll', "`"$enrollFile`"", '-silent') -Wait -PassThru
                exit $agent.ExitCode
            }
            # a file instead of -auth keeps the token out of the process list;
            # the agent deletes it after reading
            $authFile = Join-Path $OutPath ('auth-' + [guid]::NewGuid().ToString('N') + '.txt')
            Write-Secret $authFile $auth
            $installArgs += @('-auth-file', "`"$authFile`"")
            if ($cert) {
                $certFile = 'identWinProgPath\server.pem'
                [IO.File]::WriteAllText($certFile, $cert)
                $installArgs += @('-cert', "`"$certFile`"")
            }
            $agent = Start-Process -FilePath "identWinProgPath\identWinExe" -ArgumentList $installArgs -Wait -PassThru
            exit $agent.ExitCode
        }
        Catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Error -Message "$ErrorMessage $FailedItem"
            exit 1
        }
        Finally
        {
            Remove-Item -Path $OutPath\$output
            foreach ($f in @($enrollFile, $authFile)) {
                if ($f) {
                    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
                }
            }
        }
    } else {
        Write-Output "Unable to connect to server"
        exit 1
    }
}

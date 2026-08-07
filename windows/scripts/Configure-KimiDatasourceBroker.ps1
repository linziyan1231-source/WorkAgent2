[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CredentialSource,
    [string]$PortalConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$InstallRoot = 'C:\Program Files\AionUiPortal',
    [string]$ListenAddress = '127.0.0.1:3211'
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AionKimiDatasourceBroker'
$programData = 'C:\ProgramData\AionUiPortal'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
if (-not [IO.Path]::IsPathFullyQualified($CredentialSource) -or -not (Test-Path -LiteralPath $CredentialSource -PathType Leaf)) {
    throw 'CredentialSource must be an absolute path to an existing Kimi Code credential JSON file.'
}
if ($ListenAddress -cnotmatch '^127\.0\.0\.1:[0-9]{1,5}$') { throw 'ListenAddress must be an exact 127.0.0.1 TCP endpoint.' }
$sourceItem = Get-Item -LiteralPath $CredentialSource -Force
if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'CredentialSource must not be a reparse point.' }
$credential = Get-Content -LiteralPath $sourceItem.FullName -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace([string]$credential.access_token) -or [string]::IsNullOrWhiteSpace([string]$credential.refresh_token)) {
    throw 'CredentialSource must contain access_token and refresh_token.'
}
$portalConfig = Get-Content -LiteralPath $PortalConfigPath -Raw | ConvertFrom-Json
$brokerExe = Join-Path $InstallRoot 'AionKimiDatasourceBroker.exe'
if (-not (Test-Path -LiteralPath $brokerExe -PathType Leaf)) { throw "Kimi datasource broker binary is missing: $brokerExe" }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$wasRunning = $existing -and $existing.Status -ne 'Stopped'
if ($wasRunning) {
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
$credentialPath = Join-Path $programData 'kimi-datasource-credential.json'
$brokerConfigPath = Join-Path $programData 'kimi-datasource-broker.json'
$brokerLogPath = Join-Path $programData 'logs\kimi-datasource-broker.log'
$temporaryCredential = Join-Path $programData ('.kimi-datasource-credential-' + [Guid]::NewGuid().ToString('N') + '.tmp')
$temporaryConfig = Join-Path $programData ('.kimi-datasource-broker-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    Copy-Item -LiteralPath $sourceItem.FullName -Destination $temporaryCredential
    Move-Item -LiteralPath $temporaryCredential -Destination $credentialPath -Force
    & icacls.exe $credentialPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Apply protected Kimi credential ACL failed.' }
    $configuration = [ordered]@{
        listen_address = $ListenAddress
        database_path = [IO.Path]::GetFullPath([string]$portalConfig.database_path)
        audit_log_path = [IO.Path]::GetFullPath([string]$portalConfig.audit_log_path)
        credential_path = $credentialPath
        log_path = $brokerLogPath
        oauth_host = 'https://auth.kimi.com'
        api_url = 'https://api.kimi.com/coding/v1/tools'
        outbound_proxy_url = if ($portalConfig.outbound_proxy_url) { [string]$portalConfig.outbound_proxy_url } else { '' }
    }
    [IO.File]::WriteAllText($temporaryConfig, (($configuration | ConvertTo-Json -Depth 4) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryConfig -Destination $brokerConfigPath -Force
    & icacls.exe $brokerConfigPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Apply protected Kimi broker configuration ACL failed.' }
} finally {
    if (Test-Path -LiteralPath $temporaryCredential) { Remove-Item -LiteralPath $temporaryCredential -Force }
    if (Test-Path -LiteralPath $temporaryConfig) { Remove-Item -LiteralPath $temporaryConfig -Force }
}

$imagePath = '"' + $brokerExe + '" --service --config "' + $brokerConfigPath + '"'
if (-not $existing) {
    & sc.exe create $serviceName binPath= $imagePath start= delayed-auto obj= LocalSystem DisplayName= 'AionUi Kimi Datasource Broker' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Create Kimi datasource broker service failed.' }
} else {
    & sc.exe config $serviceName binPath= $imagePath start= delayed-auto obj= LocalSystem | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Update Kimi datasource broker service failed.' }
}
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/none/0 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Configure Kimi datasource broker recovery failed.' }
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$healthURL = 'http://' + $ListenAddress + '/health'
$response = Invoke-RestMethod -Uri $healthURL -TimeoutSec 15 -Proxy $null
if ([string]$response.status -cne 'ok') { throw 'Kimi datasource broker health check failed.' }
Write-Host 'Kimi datasource broker configured and healthy. The source credential file was preserved.'

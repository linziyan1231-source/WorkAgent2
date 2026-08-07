[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$portalConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$publicUri = [Uri][string]$portalConfig.public_base_url
if (-not $publicUri.IsAbsoluteUri -or $publicUri.Scheme -notin @('http', 'https')) { throw 'Portal public_base_url has an unsupported scheme.' }
$healthUri = ('{0}://127.0.0.1:25808/healthz' -f $publicUri.Scheme)
Stop-Service -Name AionUiPortal -Force -ErrorAction Stop
& (Join-Path $PSScriptRoot 'Stop-AllInstances.ps1') -PortalCli $PortalCli -ConfigPath $ConfigPath
& $PortalCli --config $ConfigPath release rollback
if ($LASTEXITCODE -ne 0) { throw 'Release rollback failed; Portal remains stopped.' }
& $PortalCli --config $ConfigPath acl apply
if ($LASTEXITCODE -ne 0) { throw 'Post-rollback ACL application failed; Portal remains stopped.' }
& $PortalCli --config $ConfigPath acl verify
if ($LASTEXITCODE -ne 0) { throw 'Post-rollback integrity/ACL verification failed; Portal remains stopped.' }
Start-Service -Name AionUiPortal
(Get-Service AionUiPortal).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$handler = New-Object Net.Http.HttpClientHandler
$handler.UseProxy = $false
if ($publicUri.Scheme -eq 'https') {
    $handler.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
}
$client = [Net.Http.HttpClient]::new($handler)
try {
    $response = $client.GetAsync($healthUri).GetAwaiter().GetResult()
    if (-not $response.IsSuccessStatusCode) { throw "Portal health check returned HTTP $([int]$response.StatusCode)." }
} finally { $client.Dispose(); $handler.Dispose() }
Write-Host 'Rollback completed without deleting or restoring over user data.'

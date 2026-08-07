[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe',
    [string]$BaseUrl = 'http://127.0.0.1:8317/v1',
    [string]$CLIProxyManagementURL = 'http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy',
    [string]$CLIProxyManagementKeyFile = 'C:\ProgramData\CLIProxyAPI\.management-key',
    [string[]]$PortalUsername,
    [switch]$ConfirmCutover
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmCutover) {
    throw 'Re-run with -ConfirmCutover only after the local CLIProxyAPI, policy state, OAuth auth-dir, and rollback snapshot have been verified.'
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
foreach ($path in @($ConfigPath, $PortalCli)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}
$base = [Uri]$BaseUrl
if (-not $base.IsAbsoluteUri -or $base.Scheme -notin @('http', 'https') -or $base.AbsolutePath -cne '/v1' -or $base.Query -or $base.Fragment -or $base.UserInfo) {
    throw 'BaseUrl must be an absolute HTTP or HTTPS URL ending exactly in /v1 without credentials, query, or fragment.'
}
$management = [Uri]$CLIProxyManagementURL
if (-not $management.IsAbsoluteUri -or $management.Scheme -ne 'http' -or $management.Host -ne '127.0.0.1' -or
    $management.AbsolutePath -ne '/v0/management/plugins/cpa-key-policy' -or $management.UserInfo -or $management.Query -or $management.Fragment) {
    throw 'CLIProxyManagementURL must be the exact local cpa-key-policy Management API URL.'
}
if (-not (Test-Path -LiteralPath $CLIProxyManagementKeyFile -PathType Leaf)) { throw 'CLIProxyAPI management key file is missing.' }
$managementKey = (Get-Content -LiteralPath $CLIProxyManagementKeyFile -Raw).Trim()
if ($managementKey -notmatch '^[A-Za-z0-9_-]{40,256}$') { throw 'CLIProxyAPI management key file has invalid content.' }

$catalogOutput = @(& $PortalCli --config $ConfigPath model-bootstrap catalog-converge --management-url $CLIProxyManagementURL --management-key-file $CLIProxyManagementKeyFile 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "CLIProxyAPI managed Kimi catalog convergence failed: $($catalogOutput -join [Environment]::NewLine)"
}

$listeners = @(Get-NetTCPConnection -State Listen -LocalPort $base.Port -ErrorAction SilentlyContinue)
if ($listeners.Count -eq 0) { throw "No local CLIProxyAPI listener exists on port $($base.Port)." }
try {
    $headers = @{ Authorization = 'Bearer ' + $managementKey }
    $policyStatus = Invoke-RestMethod -Uri ($CLIProxyManagementURL + '/status') -Headers $headers -TimeoutSec 10
    $keys = Invoke-RestMethod -Uri ($CLIProxyManagementURL + '/keys') -Headers $headers -TimeoutSec 10
    $aliases = Invoke-RestMethod -Uri ($CLIProxyManagementURL + '/aliases') -Headers $headers -TimeoutSec 10
} catch {
    throw 'Local CLIProxyAPI policy Management API is not ready.'
}
if (-not [bool]$policyStatus.enabled -or @($keys.keys).Count -lt 1 -or @($aliases.aliases).Count -lt 1) {
    throw 'Local CLIProxyAPI policy Management API did not report migrated keys and aliases.'
}

if (-not $PortalUsername) {
    $lines = @(& $PortalCli --config $ConfigPath instance list 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Portal user enumeration failed: $($lines -join [Environment]::NewLine)" }
    $PortalUsername = @($lines | ForEach-Object {
        if ([string]$_ -match '^user=(?<username>\S+).* enabled=true ') { $Matches.username }
    })
}
$PortalUsername = @($PortalUsername | Where-Object { $_ } | Select-Object -Unique)
if ($PortalUsername.Count -eq 0) { throw 'No enabled Portal users were selected for Base URL rebase.' }

$completed = @()
foreach ($username in $PortalUsername) {
    if ($username -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "Invalid Portal username: $username" }
    $output = @(& $PortalCli --config $ConfigPath model-bootstrap rebase --base-url $BaseUrl $username 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Base URL rebase failed for $username after completing [$($completed -join ', ')]: $($output -join [Environment]::NewLine)"
    }
    $completed += $username
}

Write-Host "Staged or completed the Base URL rebase for $($completed.Count) Portal users without rotating their CLIProxyAPI keys."
Write-Host 'The old CLIProxyAPI must remain active until local real-dispatch, quota, restart, and rollback checks pass.'

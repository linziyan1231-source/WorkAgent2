[CmdletBinding()]
param(
    [string]$Root = 'C:\ProgramData\CLIProxyAPI',
    [string]$ManagementURL = 'http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
if (-not $rootPath.Equals('C:\ProgramData\CLIProxyAPI', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The managed CLIProxyAPI root must be C:\ProgramData\CLIProxyAPI.'
}
$management = [Uri]$ManagementURL
if (-not $management.IsAbsoluteUri -or $management.Scheme -ne 'http' -or $management.Host -ne '127.0.0.1' -or
    $management.AbsolutePath -ne '/v0/management/plugins/cpa-key-policy' -or $management.UserInfo -or $management.Query -or $management.Fragment) {
    throw 'ManagementURL must be the exact local cpa-key-policy Management API URL.'
}

$required = @(
    (Join-Path $rootPath 'cli-proxy-api.exe'),
    (Join-Path $rootPath 'plugins\cpa-key-policy.dll'),
    (Join-Path $rootPath 'config.yaml'),
    (Join-Path $rootPath 'cpa-key-policy-state.json'),
    (Join-Path $rootPath '.management-key')
)
foreach ($path in $required) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Required CLIProxyAPI path must be a regular non-reparse file: $path"
    }
}
$key = (Get-Content -LiteralPath (Join-Path $rootPath '.management-key') -Raw).Trim()
if ($key -notmatch '^[A-Za-z0-9_-]{40,256}$') { throw 'CLIProxyAPI management key file has invalid content.' }
$headers = @{ Authorization = 'Bearer ' + $key }
try {
    $status = Invoke-RestMethod -Uri ($ManagementURL + '/status') -Headers $headers -TimeoutSec 10
    $keys = Invoke-RestMethod -Uri ($ManagementURL + '/keys') -Headers $headers -TimeoutSec 10
    $aliases = Invoke-RestMethod -Uri ($ManagementURL + '/aliases') -Headers $headers -TimeoutSec 10
} catch {
    throw 'Local Windows CLIProxyAPI Management API is not ready.'
}
if (-not [bool]$status.enabled -or @($keys.keys).Count -lt 1 -or @($aliases.aliases).Count -lt 1) {
    throw 'Local Windows cpa-key-policy did not load the migrated policy state.'
}
Write-Host "Windows CLIProxyAPI policy ready: keys=$(@($keys.keys).Count) aliases=$(@($aliases.aliases).Count)."

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$PortalUsername,
    [Parameter(Mandatory)][string]$WindowsAccount,
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe',
    [string]$CLIProxyManagementURL = 'http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy',
    [string]$CLIProxyManagementKeyFile = 'C:\ProgramData\CLIProxyAPI\.management-key',
    [string]$CLIProxyBaseUrl = 'http://127.0.0.1:8317/v1',
    [string[]]$ChatGPTModels = @('gpt-5.6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra'),
    [string[]]$KimiModels = @('kimi-for-coding', 'kimi-for-coding-highspeed', 'kimi-k3'),
    [switch]$PortalAdministrator
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
foreach ($path in @($ConfigPath, $PortalCli)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}

$resolvedAccount = $WindowsAccount
if ($resolvedAccount.StartsWith('.\')) { $resolvedAccount = $env:COMPUTERNAME + $resolvedAccount.Substring(1) }
try {
    $expectedSid = ([Security.Principal.NTAccount]::new($resolvedAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "Windows account could not be resolved: $WindowsAccount. $($_.Exception.Message)"
}
$profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $expectedSid })
if ($profiles.Count -ne 1 -or [string]::IsNullOrWhiteSpace($profiles[0].LocalPath)) {
    throw "Exactly one existing Windows profile is required for $WindowsAccount ($expectedSid). Sign in or create the profile through the approved Windows process first."
}
$profilePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$profiles[0].LocalPath)).TrimEnd('\')
if (-not ([IO.Path]::GetDirectoryName($profilePath)).Equals('C:\Users', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Windows profile $profilePath must be a direct child of C:\Users."
}
$profileItem = Get-Item -LiteralPath $profilePath -Force -ErrorAction Stop
if (-not $profileItem.PSIsContainer -or ($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Windows profile must be a normal directory, not a reparse point: $profilePath"
}
$listOutput = @(& $PortalCli --config $ConfigPath instance list 2>&1)
if ($LASTEXITCODE -ne 0) { throw "Existing Portal user inspection failed: $($listOutput -join [Environment]::NewLine)" }
$records = @()
foreach ($line in $listOutput) {
    if ([string]$line -match '^user=(?<username>\S+).* sid=(?<sid>S-[0-9-]+) enabled=(?<enabled>true|false) admin=(?<admin>true|false) sessions=') {
        $records += [pscustomobject]@{
            Username = $Matches.username
            Sid = $Matches.sid
            Enabled = [bool]::Parse($Matches.enabled)
            IsAdmin = [bool]::Parse($Matches.admin)
        }
    }
}
$sameUsername = @($records | Where-Object { $_.Username -ieq $PortalUsername })
$sameSid = @($records | Where-Object { $_.Sid -ieq $expectedSid })
if ($sameUsername.Count -gt 1 -or $sameSid.Count -gt 1) { throw 'Portal database contains duplicate identity mappings; refusing to guess.' }
$createUser = $sameUsername.Count -eq 0
$requestedAdmin = $PortalAdministrator.IsPresent
if (-not $createUser) {
    $existing = $sameUsername[0]
    if ($existing.Sid -ine $expectedSid) {
        throw "Portal user $PortalUsername is already mapped to $($existing.Sid), not $expectedSid. Use the explicit map-windows-sid command."
    }
    if (-not $existing.Enabled) {
        throw "Portal user $PortalUsername is disabled. Enable it explicitly before reinstalling the task."
    }
    if ($existing.IsAdmin -ne $requestedAdmin) {
        throw "Portal user $PortalUsername already exists with admin=$($existing.IsAdmin), but this run requested admin=$requestedAdmin. Refusing to change roles implicitly."
    }
    Write-Host "Reusing existing Portal user $PortalUsername mapped to $expectedSid."
} elseif ($sameSid.Count -ne 0) {
    throw "Windows SID $expectedSid is already mapped to Portal user $($sameSid[0].Username)."
}

$sandboxGroupScript = Join-Path $PSScriptRoot 'Remove-CodexSandboxGroupMembership.ps1'
& $sandboxGroupScript -WindowsAccount $resolvedAccount
$rightsScript = Join-Path $PSScriptRoot 'Set-UserHostRights.ps1'
& $rightsScript -WindowsAccount $resolvedAccount
if ($createUser) {
    $arguments = @('--config', $ConfigPath, 'user', 'add', '--username', $PortalUsername, '--windows-account', $resolvedAccount)
    if ($PortalAdministrator) { $arguments += '--admin' }
    & $PortalCli @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Portal user provisioning failed. The scheduled task was not attempted.' }
}

$userDataRoot = ''
$config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($config.PSObject.Properties.Name -contains 'user_data_root') { $userDataRoot = [string]$config.user_data_root }
& (Join-Path $PSScriptRoot 'Set-UserDiskQuota.ps1') -WindowsAccount $resolvedAccount -DataRootBase $userDataRoot -LimitGiB 60 -SharedLimitGiB 20

$modelArguments = @('--config', $ConfigPath, 'model-bootstrap', 'provision', '--management-url', $CLIProxyManagementURL,
    '--management-key-file', $CLIProxyManagementKeyFile, '--base-url', $CLIProxyBaseUrl, '--codex-default-model', 'gpt-5.6-sol',
    '--codex-models', ($ChatGPTModels -join ','), '--kimi-models', ($KimiModels -join ','), '--rpm', '0',
    '--codex-daily-usd', '40', '--codex-weekly-usd', '80', '--kimi-daily-usd', '10', '--kimi-weekly-usd', '20', $PortalUsername)
& $PortalCli @modelArguments
if ($LASTEXITCODE -ne 0) { throw 'Per-user CLIProxyAPI key creation/model bootstrap failed.' }

& $PortalCli --config $ConfigPath task install $PortalUsername
if ($LASTEXITCODE -ne 0) { throw 'Password-logon task registration or real identity verification failed.' }
& $PortalCli --config $ConfigPath model-bootstrap status $PortalUsername
if ($LASTEXITCODE -ne 0) { throw 'UserHost did not complete Codex/Aion model initialization.' }
& $PortalCli --config $ConfigPath acl verify
if ($LASTEXITCODE -ne 0) { throw 'Post-install ACL verification failed.' }
& (Join-Path $PSScriptRoot 'Test-WindowsProfileIsolation.ps1') -WindowsAccount $resolvedAccount -DataRootBase $userDataRoot
$installedDataRoot = if ([string]::IsNullOrWhiteSpace($userDataRoot)) { Join-Path $profilePath 'AionUiPortal' } else { Join-Path $userDataRoot $sid }
Write-Host "User $PortalUsername is installed at $installedDataRoot and its real UserHost launch verified."

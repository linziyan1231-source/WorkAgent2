[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$PortalUsername,
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$listOutput = @(& $PortalCli --config $ConfigPath instance list 2>&1)
if ($LASTEXITCODE -ne 0) { throw "Portal user inspection failed: $($listOutput -join [Environment]::NewLine)" }
$escapedUsername = [regex]::Escape($PortalUsername)
$matches = @($listOutput | Where-Object { [string]$_ -match "^user=$escapedUsername\s" })
if ($matches.Count -ne 1 -or [string]$matches[0] -notmatch '\swindows=(?<account>\S+)\s') {
    throw "Exactly one Windows account mapping is required for Portal user $PortalUsername."
}
$windowsAccount = $Matches.account
$sandboxGroupScript = Join-Path $PSScriptRoot 'Remove-CodexSandboxGroupMembership.ps1'
& $sandboxGroupScript -WindowsAccount $windowsAccount
$rightsScript = Join-Path $PSScriptRoot 'Set-UserHostRights.ps1'
Write-Host 'Change the Windows account password with your approved Windows/AD process first.'
Write-Host 'The following prompt updates only Task Scheduler/LSA; input is not a command argument or PowerShell variable.'
& $rightsScript -WindowsAccount $windowsAccount
& $PortalCli --config $ConfigPath windows-password rotate $PortalUsername
if ($LASTEXITCODE -ne 0) { throw 'Windows task credential rotation failed.' }
Write-Host 'Rotation passed a fresh TASK_LOGON_PASSWORD launch and whoami /user SID verification.'

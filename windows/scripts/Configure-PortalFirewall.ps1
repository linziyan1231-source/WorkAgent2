[CmdletBinding()]
param(
    [string]$PortalExecutable = 'C:\Program Files\AionUiPortal\AionUiPortal.exe',
    [string]$RuleName = 'AionUi Portal TCP 25808'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
if (-not [IO.Path]::IsPathRooted($PortalExecutable) -or -not (Test-Path -LiteralPath $PortalExecutable -PathType Leaf)) {
    throw "Portal executable is missing or not absolute: $PortalExecutable"
}

foreach ($existingName in @($RuleName, 'AionUi Portal HTTPS 25808') | Select-Object -Unique) {
    Get-NetFirewallRule -DisplayName $existingName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 25808 -Profile Any -Program $PortalExecutable | Out-Null
$rules = @(Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop)
if ($rules.Count -ne 1 -or $rules[0].Enabled -ne 'True' -or $rules[0].Direction -ne 'Inbound' -or $rules[0].Action -ne 'Allow') {
    throw 'The Portal firewall rule did not verify.'
}
$portFilter = $rules[0] | Get-NetFirewallPortFilter
if ($portFilter.Protocol -ne 'TCP' -or [string]$portFilter.LocalPort -ne '25808') {
    throw 'The Portal firewall rule exposes an unexpected protocol or port.'
}
$applicationFilter = $rules[0] | Get-NetFirewallApplicationFilter
if (-not ([IO.Path]::GetFullPath([string]$applicationFilter.Program)).Equals([IO.Path]::GetFullPath($PortalExecutable), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The Portal firewall rule is not restricted to the Portal executable.'
}
Write-Host 'Verified the product inbound rule: only AionUiPortal.exe is allowed on TCP 25808. Unrelated system firewall rules were not modified.'

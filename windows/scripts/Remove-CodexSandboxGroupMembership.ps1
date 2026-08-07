[CmdletBinding()]
param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$WindowsAccount)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

$group = Get-LocalGroup -Name 'CodexSandboxUsers' -ErrorAction SilentlyContinue
if ($null -eq $group) {
    Write-Host 'CodexSandboxUsers is not present; no machine-global Codex sandbox membership needs removal.'
    return
}

foreach ($requestedAccount in $WindowsAccount) {
    $resolvedAccount = $requestedAccount
    if ($resolvedAccount.StartsWith('.\')) { $resolvedAccount = $env:COMPUTERNAME + $resolvedAccount.Substring(1) }
    try {
        $expectedSid = ([Security.Principal.NTAccount]::new($resolvedAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Windows account could not be resolved: $requestedAccount. $($_.Exception.Message)"
    }

    $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
    $matches = @($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -ieq $expectedSid })
    if ($matches.Count -gt 1) { throw "CodexSandboxUsers contains duplicate SID entries for $expectedSid." }
    if ($matches.Count -eq 1) {
        Remove-LocalGroupMember -SID $group.SID -Member $matches[0] -Confirm:$false -ErrorAction Stop
    }

    $remaining = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop | Where-Object {
        $null -ne $_.SID -and $_.SID.Value -ieq $expectedSid
    })
    if ($remaining.Count -ne 0) { throw "Failed to remove $resolvedAccount ($expectedSid) from CodexSandboxUsers." }
    Write-Host "Verified $resolvedAccount ($expectedSid) is not a member of CodexSandboxUsers."
}

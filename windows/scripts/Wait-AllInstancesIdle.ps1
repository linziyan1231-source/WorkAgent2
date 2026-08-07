[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PortalCli,
    [Parameter(Mandatory)][string]$ConfigPath,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 7200,
    [ValidateRange(100, 10000)][int]$PollMilliseconds = 2000
)

$ErrorActionPreference = 'Stop'

function Get-ActivityBlockers {
    $lines = @(& $PortalCli --config $ConfigPath instance list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate instances while waiting for a safe deployment window: $($lines -join [Environment]::NewLine)"
    }
    $blockers = @()
    foreach ($line in $lines) {
        if ([string]$line -notmatch '^user=(?<username>[A-Za-z0-9][A-Za-z0-9._-]{0,63})\s') { continue }
        $username = $Matches.username
        if ([string]$line -match '\sstate=stopped(?:\s|$)') { continue }
        if ([string]$line -match '\sstate=unavailable(?:\s|$)') {
            $blockers += "$username`: UserHost state is unavailable"
            continue
        }
        $activity = @(& $PortalCli --config $ConfigPath instance activity $username 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $blockers += "$username`: activity probe failed: $($activity -join ' ')"
            continue
        }
        $summary = ($activity -join ' ').Trim()
        if ($summary -notmatch '^known=true\s+active=false(?:\s|$)') {
            $blockers += "$username`: $summary"
        }
    }
    return @($blockers)
}

$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$lastSummary = ''
do {
    $blockers = @(Get-ActivityBlockers)
    if ($blockers.Count -eq 0) {
        Write-Host 'All running UserHosts report authoritative idle activity.'
        return
    }
    $summary = $blockers -join '; '
    if ($summary -cne $lastSummary) {
        Write-Host "Waiting for active UserHosts to finish before deployment: $summary"
        $lastSummary = $summary
    }
    if ([DateTime]::UtcNow -ge $deadline) { break }
    Start-Sleep -Milliseconds $PollMilliseconds
} while ($true)

throw "Timed out without interrupting active or unknown UserHosts: $($blockers -join '; ')"

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PortalCli,
    [Parameter(Mandatory)][string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$configuration = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$lines = @(& $PortalCli --config $ConfigPath instance list 2>&1)
if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate instances: $($lines -join [Environment]::NewLine)" }
foreach ($line in $lines) {
    if ($line -match '^user=([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s') {
        $username = $Matches[1]
        if ($line -notmatch '\sstate=stopped(?:\s|$)') {
            & $PortalCli --config $ConfigPath instance stop $username
            if ($LASTEXITCODE -ne 0) { throw "Failed to stop instance for $username" }
        }
    }
}

$deadline = [DateTime]::UtcNow.AddSeconds(90)
do {
    $running = @(& $PortalCli --config $ConfigPath instance list 2>&1 | Where-Object { $_ -notmatch '\sstate=stopped(?:\s|$)' })
    if ($LASTEXITCODE -ne 0) { throw "Unable to verify stopped instances: $($running -join [Environment]::NewLine)" }
    if ($running.Count -eq 0) { break }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)
if ($running.Count -ne 0) { throw "Instances did not stop before the deadline: $($running -join '; ')" }

$schedulerType = [type]::GetTypeFromProgID('Schedule.Service')
if ($null -eq $schedulerType) { throw 'Task Scheduler COM service is unavailable.' }
$scheduler = [Activator]::CreateInstance($schedulerType)
$taskRoot = $null
try {
    $scheduler.Connect()
    $taskRoot = $scheduler.GetFolder('\')
    # UserHost closes its IPC pipe just before the scheduled process finishes. Give that
    # normal exit time to complete so Task Scheduler records success instead of a forced 1.
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $runningTasks = @()
        $snapshot = @($taskRoot.GetTasks(0))
        foreach ($task in $snapshot) {
            try {
                if ($task.Name -match '^AionUiWeb-S-1-(?:[0-9]+-)+[0-9]+$' -and [int]$task.State -eq 4) { $runningTasks += [string]$task.Name }
            } finally {
                if ($null -ne $task) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($task) }
            }
        }
        if ($runningTasks.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $taskDeadline)

    if ($runningTasks.Count -ne 0) {
        Write-Warning "Hard-stopping UserHost tasks that exceeded the graceful-exit deadline: $($runningTasks -join ', ')"
        $scheduled = @($taskRoot.GetTasks(0))
        foreach ($task in $scheduled) {
            try {
                if ($task.Name -in $runningTasks -and [int]$task.State -eq 4) { $task.Stop(0) }
            } finally {
                if ($null -ne $task) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($task) }
            }
        }
    }

    $taskDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $runningTasks = @()
        $snapshot = @($taskRoot.GetTasks(0))
        foreach ($task in $snapshot) {
            try {
                if ($task.Name -match '^AionUiWeb-S-1-(?:[0-9]+-)+[0-9]+$' -and [int]$task.State -eq 4) { $runningTasks += [string]$task.Name }
            } finally {
                if ($null -ne $task) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($task) }
            }
        }
        if ($runningTasks.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $taskDeadline)
    if ($runningTasks.Count -ne 0) { throw "UserHost scheduled tasks are still running: $($runningTasks -join ', ')" }
} finally {
    if ($null -ne $taskRoot) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($taskRoot) }
    if ($null -ne $scheduler) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($scheduler) }
}

$userHostPath = [IO.Path]::GetFullPath([string]$configuration.user_host_executable)
$releaseRoot = [IO.Path]::GetFullPath([string]$configuration.releases_root).TrimEnd('\') + '\'
$processDeadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $orphans = @(Get-CimInstance Win32_Process | Where-Object {
        $path = [string]$_.ExecutablePath
        ($_.Name -ieq 'AionUiUserHost.exe' -and $path -ieq $userHostPath) -or
        (($_.Name -ieq 'aionui-web.exe' -or $_.Name -ieq 'aioncore.exe') -and $path.StartsWith($releaseRoot, [StringComparison]::OrdinalIgnoreCase))
    })
    if ($orphans.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $processDeadline)
if ($orphans.Count -ne 0) {
    $orphanList = (($orphans | ForEach-Object { "$($_.Name):$($_.ProcessId)" }) -join ', ')
    throw "Shared-release process trees survived UserHost shutdown: $orphanList"
}
Write-Host 'All UserHost tasks and shared-release Job Object process trees are stopped.'

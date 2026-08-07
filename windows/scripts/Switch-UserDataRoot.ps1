[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [Parameter(Mandatory)][string]$TargetBase,
    [ValidateRange(1, 1024)][uint64]$LimitGiB = 60,
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe',
    [string]$EvidenceRoot
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

$targetBasePath = [IO.Path]::GetFullPath($TargetBase).TrimEnd('\')
if (-not [IO.Path]::IsPathFullyQualified($targetBasePath) -or [IO.Path]::GetPathRoot($targetBasePath).TrimEnd('\').Equals($targetBasePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "TargetBase must be an absolute non-volume-root path: $TargetBase"
}
$targetDrive = [IO.Path]::GetPathRoot($targetBasePath).TrimEnd('\').TrimEnd(':')
$volume = Get-Volume -DriveLetter $targetDrive -ErrorAction Stop
if ($volume.FileSystem -ne 'NTFS' -or $volume.HealthStatus -ne 'Healthy') { throw "Target volume must be healthy NTFS: $targetBasePath" }
$targetBaseItem = Get-Item -LiteralPath $targetBasePath -Force -ErrorAction Stop
if (-not $targetBaseItem.PSIsContainer -or ($targetBaseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "TargetBase must be a normal directory: $targetBasePath"
}
if (@(Get-Process AionUiUserHost,aionui-web,aioncore -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'All UserHost process trees must be stopped before final synchronization.'
}

$portal = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
$configFiles = @(Get-ChildItem -LiteralPath ([string]$portal['user_config_root']) -Filter userhost.json -Recurse | Sort-Object FullName)
if ($configFiles.Count -eq 0) { throw 'No managed UserHost configurations were found.' }
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path (Join-Path (Split-Path -Parent $ConfigPath) 'backups') ("storage-migration-$stamp")
}
$evidence = [IO.Path]::GetFullPath($EvidenceRoot)
if (Test-Path -LiteralPath $evidence) { throw "Refusing to overwrite migration evidence: $evidence" }
New-Item -ItemType Directory -Path (Join-Path $evidence 'configs') -Force | Out-Null
Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $evidence 'portal.json') -Force

$users = @()
foreach ($file in $configFiles) {
    $user = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable
    $sid = [string]$user['windows_sid']
    $source = [IO.Path]::GetFullPath([string]$user['data_root']).TrimEnd('\')
    $profileSource = [IO.Path]::GetFullPath((Join-Path ([string]$user['windows_profile']) 'AionUiPortal')).TrimEnd('\')
    if (-not $source.Equals($profileSource, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected legacy data root for ${sid}: $source" }
    $destination = Join-Path $targetBasePath $sid
    $destinationItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
    if (-not $destinationItem.PSIsContainer -or ($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Destination must be a normal directory: $destination" }
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path (Join-Path $evidence 'configs') ("$sid.json")) -Force
    $users += [pscustomobject]@{ SID = $sid; Account = [string]$user['windows_username']; Source = $source; Destination = $destination; ConfigPath = $file.FullName; Config = $user }
}

$copyResults = @()
foreach ($user in $users) {
    $log = Join-Path $evidence ("final-sync-$($user.SID).log")
    & robocopy.exe $user.Source $user.Destination /E /COPYALL /SECFIX /TIMFIX /DCOPY:DAT /B /XJ /R:2 /W:1 /MT:8 /NP /NFL /NDL /LOG:$log
    $copyExit = $LASTEXITCODE
    if ($copyExit -gt 7) { throw "Final synchronization failed for $($user.SID) with robocopy exit $copyExit; see $log" }
    $links = @(Get-ChildItem -LiteralPath $user.Source -Force -Recurse -Attributes ReparsePoint -ErrorAction Stop)
    foreach ($link in $links) {
        $sourceTarget = [IO.Path]::GetFullPath([string]$link.Target).TrimEnd('\')
        $sourcePrefix = $user.Source + '\'
        if ($link.LinkType -ne 'Junction' -or -not $link.PSIsContainer -or -not $sourceTarget.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsupported or escaping reparse point: $($link.FullName)"
        }
        $destinationLink = Join-Path $user.Destination $link.FullName.Substring($sourcePrefix.Length)
        $destinationTarget = Join-Path $user.Destination $sourceTarget.Substring($sourcePrefix.Length)
        $existing = Get-Item -LiteralPath $destinationLink -Force -ErrorAction SilentlyContinue
        if ($null -eq $existing) {
            New-Item -ItemType Junction -Path $destinationLink -Target $destinationTarget | Out-Null
        } elseif ($existing.LinkType -ne 'Junction' -or -not ([IO.Path]::GetFullPath([string]$existing.Target).TrimEnd('\')).Equals($destinationTarget, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Destination junction readback mismatch: $destinationLink"
        }
    }
    & robocopy.exe $user.Source $user.Destination /E /L /COPY:DAT /DCOPY:DAT /XJ /R:0 /W:0 /NP /NFL /NDL /LOG+:$log
    $verifyExit = $LASTEXITCODE
    if ($verifyExit -notin @(0, 2)) { throw "Final synchronization readback mismatch for $($user.SID): robocopy exit $verifyExit" }
    $copyResults += [pscustomobject]@{ sid = $user.SID; source = $user.Source; destination = $user.Destination; copy_exit = $copyExit; verify_exit = $verifyExit; junctions = $links.Count }
}

$configChanged = $false
$portalWasRunning = (Get-Service AionUiPortal -ErrorAction Stop).Status -ne 'Stopped'
$adminService = Get-Service AionUiPortalAdmin -ErrorAction SilentlyContinue
$adminWasRunning = $adminService -and $adminService.Status -ne 'Stopped'
try {
    if ($portalWasRunning) { Stop-Service AionUiPortal -Force; (Get-Service AionUiPortal).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
    if ($adminWasRunning) { Stop-Service AionUiPortalAdmin -Force; (Get-Service AionUiPortalAdmin).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }

    $portal['user_data_root'] = $targetBasePath
    $portalJson = ($portal | ConvertTo-Json -Depth 10).Replace("`r`n", "`n") + "`n"
    $portalTemp = "$ConfigPath.migrate-$stamp.tmp"
    [IO.File]::WriteAllText($portalTemp, $portalJson, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $portalTemp -Destination $ConfigPath -Force
    foreach ($user in $users) {
        $user.Config['config_version'] = 2
        $user.Config['data_root_base'] = $targetBasePath
        $user.Config['data_root'] = $user.Destination
        $json = ($user.Config | ConvertTo-Json -Depth 10).Replace("`r`n", "`n") + "`n"
        $temp = "$($user.ConfigPath).migrate-$stamp.tmp"
        [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temp -Destination $user.ConfigPath -Force
    }
    $configChanged = $true

    if ($portalWasRunning) { Start-Service AionUiPortal; (Get-Service AionUiPortal).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) }
    if ($adminWasRunning) { Start-Service AionUiPortalAdmin; (Get-Service AionUiPortalAdmin).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) }

    & $PortalCli --config $ConfigPath acl apply
    if ($LASTEXITCODE -ne 0) { throw 'ACL application failed after data-root switch.' }
    & $PortalCli --config $ConfigPath acl verify
    if ($LASTEXITCODE -ne 0) { throw 'ACL verification failed after data-root switch.' }
    foreach ($user in $users) {
        & (Join-Path $PSScriptRoot 'Set-UserDiskQuota.ps1') -WindowsAccount $user.Account -DataRootBase $targetBasePath -LimitGiB $LimitGiB -SharedLimitGiB 20
        if ($LASTEXITCODE -ne 0) { throw "Quota convergence failed for $($user.SID)." }
    }

    $result = [ordered]@{ format_version = 1; switched_at_utc = [DateTime]::UtcNow.ToString('o'); target_base = $targetBasePath; limit_bytes = [uint64]$LimitGiB * 1GB; users = $copyResults }
    [IO.File]::WriteAllText((Join-Path $evidence 'migration-result.json'), (($result | ConvertTo-Json -Depth 6).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Host "User data root switch completed for $($users.Count) SIDs. Evidence: $evidence"
} catch {
    if ($configChanged) {
        Stop-Service AionUiPortal -Force -ErrorAction SilentlyContinue
        Stop-Service AionUiPortalAdmin -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath (Join-Path $evidence 'portal.json') -Destination $ConfigPath -Force
        foreach ($user in $users) { Copy-Item -LiteralPath (Join-Path (Join-Path $evidence 'configs') ("$($user.SID).json")) -Destination $user.ConfigPath -Force }
        if ($portalWasRunning) { Start-Service AionUiPortal -ErrorAction SilentlyContinue }
        if ($adminWasRunning) { Start-Service AionUiPortalAdmin -ErrorAction SilentlyContinue }
    }
    throw
}

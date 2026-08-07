[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$PortalCli = 'C:\Program Files\AionUiPortal\portal.exe',
    [switch]$RemovePrograms,
    [switch]$PurgeAllData
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$service = Get-Service AionUiPortal -ErrorAction SilentlyContinue
$adminService = Get-Service AionUiPortalAdmin -ErrorAction SilentlyContinue
if ($adminService -and $adminService.Status -ne 'Stopped') {
    Stop-Service AionUiPortalAdmin -Force
    $adminService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service AionUiPortal -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
}
$userDataPaths = @()
if ($PurgeAllData) {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw 'PurgeAllData requires the protected Portal configuration so per-user paths can be verified; no data was deleted.'
    }
    $portalConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $profilesRoot = [IO.Path]::GetFullPath([string]$portalConfig.user_profiles_root).TrimEnd('\')
    if (-not $profilesRoot.Equals('C:\Users', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected user_profiles_root in Portal configuration: $profilesRoot"
    }
    $userConfigRoot = [IO.Path]::GetFullPath([string]$portalConfig.user_config_root)
    if (Test-Path -LiteralPath $userConfigRoot -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $userConfigRoot -Filter 'userhost.json' -File -Recurse)) {
            $userConfig = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            $sid = [string]$userConfig.windows_sid
            if ($sid -notmatch '^S-1-[0-9-]+$') { throw "Invalid SID in $($file.FullName)" }
            $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid })
            if ($profiles.Count -ne 1 -or [string]::IsNullOrWhiteSpace($profiles[0].LocalPath)) {
                throw "Cannot safely resolve the Windows profile for $sid; no data was deleted."
            }
            $profilePath = [IO.Path]::GetFullPath([string]$profiles[0].LocalPath).TrimEnd('\')
            if (-not ([IO.Path]::GetDirectoryName($profilePath)).Equals($profilesRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Profile $profilePath is outside $profilesRoot; no data was deleted."
            }
            $expected = [IO.Path]::GetFullPath((Join-Path $profilePath 'AionUiPortal')).TrimEnd('\')
            $actual = [IO.Path]::GetFullPath([string]$userConfig.data_root).TrimEnd('\')
            if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Configured user data root $actual does not match $expected; no data was deleted."
            }
            if (Test-Path -LiteralPath $actual) {
                $item = Get-Item -LiteralPath $actual -Force
                if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Refusing to purge a non-directory or reparse point: $actual"
                }
            }
            $userDataPaths += $actual
        }
    }
}
if ((Test-Path -LiteralPath $PortalCli -PathType Leaf) -and (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'Stop-AllInstances.ps1') -PortalCli $PortalCli -ConfigPath $ConfigPath
    $lines = @(& $PortalCli --config $ConfigPath instance list 2>&1)
    foreach ($line in $lines) {
        if ($line -match '^user=([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s') {
            & $PortalCli --config $ConfigPath task remove $Matches[1]
            if ($LASTEXITCODE -ne 0) { throw "Task removal failed for $($Matches[1])" }
        }
    }
}
if ($service) {
    & sc.exe delete AionUiPortal | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Portal service deletion failed with exit code $LASTEXITCODE" }
}
if ($adminService) {
    & sc.exe delete AionUiPortalAdmin | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Portal administration service deletion failed with exit code $LASTEXITCODE" }
}
foreach ($ruleName in @('AionUi Portal TCP 25808', 'AionUi Portal HTTPS 25808')) {
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if ($RemovePrograms -and $PSCmdlet.ShouldProcess('C:\Program Files\AionUiPortal, C:\Program Files\AionUiWebShared, and C:\Program Files\AionAgentCliShared', 'Recursively remove program files')) {
    foreach ($path in @('C:\Program Files\AionUiPortal', 'C:\Program Files\AionUiWebShared', 'C:\Program Files\AionAgentCliShared')) {
        $full = [IO.Path]::GetFullPath($path)
        $allowed = $full.StartsWith('C:\Program Files\AionUi', [StringComparison]::OrdinalIgnoreCase) -or
            $full.Equals('C:\Program Files\AionAgentCliShared', [StringComparison]::OrdinalIgnoreCase)
        if (-not $allowed) { throw "Unsafe removal path: $full" }
        if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop }
    }
    $agentBin = 'C:\Program Files\AionAgentCliShared\bin'
    $machineSegments = @([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and -not ([IO.Path]::GetFullPath($_).TrimEnd('\').Equals($agentBin, [StringComparison]::OrdinalIgnoreCase))
    })
    [Environment]::SetEnvironmentVariable('Path', ($machineSegments -join ';'), 'Machine')
}
if ($PurgeAllData -and $PSCmdlet.ShouldProcess('C:\ProgramData\AionUiPortal and each verified C:\Users\<profile>\AionUiPortal directory', 'PERMANENTLY DELETE all Portal and employee data')) {
    foreach ($path in @($userDataPaths) + @('C:\ProgramData\AionUiPortal')) {
        $full = [IO.Path]::GetFullPath($path)
        $isProgramData = $full.Equals('C:\ProgramData\AionUiPortal', [StringComparison]::OrdinalIgnoreCase)
        $isVerifiedUserData = @($userDataPaths | Where-Object { $full.Equals($_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
        if (-not $isProgramData -and -not $isVerifiedUserData) { throw "Unsafe purge path: $full" }
        if ($isVerifiedUserData -and (Get-Command Get-FsrmQuota -ErrorAction SilentlyContinue)) {
            $quota = @(Get-FsrmQuota -Path $full -ErrorAction SilentlyContinue)
            if ($quota.Count -gt 1 -or ($quota.Count -eq 1 -and $quota[0].Description -notlike 'AionUiPortal managed hard quota for S-1-*')) {
                throw "Refusing to remove an unexpected FSRM quota at $full."
            }
            if ($quota.Count -eq 1) { $quota[0] | Remove-FsrmQuota -Confirm:$false -ErrorAction Stop }
        }
        if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop }
    }
} else {
    Write-Host 'Portal database, optional TLS files, logs, and all C:\Users\<profile>\AionUiPortal data were retained.'
}
Write-Host 'Uninstall completed.'

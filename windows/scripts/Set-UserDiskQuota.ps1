[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsAccount,
    [string]$DataRootBase,
    [string]$PortalConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [ValidateRange(1, 1024)][uint64]$LimitGiB = 60,
    [ValidateRange(1, 1024)][uint64]$SharedLimitGiB = 20
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

$resolvedAccount = $WindowsAccount
if ($resolvedAccount.StartsWith('.\')) { $resolvedAccount = $env:COMPUTERNAME + $resolvedAccount.Substring(1) }
try {
    $sid = ([Security.Principal.NTAccount]::new($resolvedAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "Windows account could not be resolved: $WindowsAccount. $($_.Exception.Message)"
}

$profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid })
if ($profiles.Count -ne 1 -or [string]::IsNullOrWhiteSpace($profiles[0].LocalPath)) {
    throw "Exactly one existing Windows profile is required for $resolvedAccount ($sid)."
}
$profilePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$profiles[0].LocalPath)).TrimEnd('\')
if (-not ([IO.Path]::GetDirectoryName($profilePath)).Equals('C:\Users', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Windows profile $profilePath must be a direct child of C:\Users."
}
$configuredDataRootBase = $DataRootBase
if ([string]::IsNullOrWhiteSpace($configuredDataRootBase) -and (Test-Path -LiteralPath $PortalConfigPath -PathType Leaf)) {
	$portalConfig = Get-Content -LiteralPath $PortalConfigPath -Raw | ConvertFrom-Json
	if ($portalConfig.PSObject.Properties.Name -contains 'user_data_root') {
		$configuredDataRootBase = [string]$portalConfig.user_data_root
	}
}
$dataRoot = if ([string]::IsNullOrWhiteSpace($configuredDataRootBase)) {
    throw 'DataRootBase is required because independent shared-space quotas need one stable root alongside SID-private roots.'
} else {
	$expandedBase = [Environment]::ExpandEnvironmentVariables($configuredDataRootBase)
    $isDriveRelative = $expandedBase -match '^[A-Za-z]:(?:$|[^\\/])'
    $isRootRelative = $expandedBase -match '^[\\/](?![\\/])'
    if (-not [IO.Path]::IsPathRooted($expandedBase) -or $isDriveRelative -or $isRootRelative) {
		throw "DataRootBase must be an absolute non-volume-root path: $configuredDataRootBase"
    }
	$base = [IO.Path]::GetFullPath($expandedBase).TrimEnd('\')
    if ([IO.Path]::GetPathRoot($base).TrimEnd('\').Equals($base, [StringComparison]::OrdinalIgnoreCase)) {
		throw "DataRootBase must be an absolute non-volume-root path: $configuredDataRootBase"
    }
	$traverseRoots = @($base, [IO.Path]::GetDirectoryName($base)) | Select-Object -Unique
	foreach ($traverseRoot in $traverseRoots) {
		$traverseItem = Get-Item -LiteralPath $traverseRoot -Force -ErrorAction Stop
		if (-not $traverseItem.PSIsContainer -or ($traverseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
			throw "Data-root ancestor must be a normal directory: $traverseRoot"
		}
		& icacls.exe $traverseRoot /grant "*$sid`:(X)" | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "Failed to grant SID traverse access on $traverseRoot" }
		$acl = Get-Acl -LiteralPath $traverseRoot
		$matching = @($acl.Access | Where-Object {
			$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid -and
			($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Traverse) -eq [Security.AccessControl.FileSystemRights]::Traverse -and
			$_.InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::None -and -not $_.IsInherited
		})
		if ($matching.Count -lt 1) { throw "SID traverse ACL readback failed on $traverseRoot" }
	}
    Join-Path $base $sid
}
$dataRootItem = Get-Item -LiteralPath $dataRoot -Force -ErrorAction Stop
if (-not $dataRootItem.PSIsContainer -or ($dataRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "The fixed user data root must be a normal directory: $dataRoot"
}

$feature = Get-WindowsFeature FS-Resource-Manager
if (-not $feature.Installed) {
    throw 'The File Server Resource Manager role service is required. Run the base Install.ps1 before setting user quotas.'
}
Import-Module FileServerResourceManager -ErrorAction Stop

function Assert-NormalDirectory([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be a normal directory: $Path"
    }
}

function Ensure-HardQuota([string]$Path, [uint64]$Size, [string]$Description) {
    Assert-NormalDirectory $Path 'Quota root'
    $existing = @(Get-FsrmQuota -Path $Path -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 1) {
        throw "Expected at most one FSRM quota for $Path; found $($existing.Count)."
    }
    if ($existing.Count -eq 0) {
        New-FsrmQuota -Path $Path -Size $Size -Description $Description -ErrorAction Stop | Out-Null
    } else {
        Set-FsrmQuota -Path $Path -Size $Size -Description $Description -SoftLimit:$false -ErrorAction Stop | Out-Null
    }
    $matches = @(Get-FsrmQuota -Path $Path -ErrorAction Stop)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one FSRM quota for $Path; found $($matches.Count)."
    }
    $quota = $matches[0]
    if (-not ([IO.Path]::GetFullPath($quota.Path).TrimEnd('\')).Equals($Path, [StringComparison]::OrdinalIgnoreCase) -or
        [uint64]$quota.Size -ne $Size -or $quota.SoftLimit -or $quota.Disabled -or $quota.Description -ne $Description) {
        throw "FSRM quota readback mismatch for ${Path}: size=$($quota.Size) soft=$($quota.SoftLimit) disabled=$($quota.Disabled) description=$($quota.Description)."
    }
}

$sharedRoot = Join-Path $base 'shared'
$sharedOwnerRoot = Join-Path $sharedRoot $sid
foreach ($path in @($sharedRoot, $sharedOwnerRoot)) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
    }
    Assert-NormalDirectory $path 'Shared-space root'
}

# Shared ancestors expose traversal only. The owner's root is the FSRM accounting
# boundary and is private until individual project ACLs add accepted members.
& icacls.exe $sharedRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to protect shared root ACL: $sharedRoot" }
& icacls.exe $sharedRoot /grant "*$sid`:(X)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to grant owner traverse access on $sharedRoot" }
& icacls.exe $sharedOwnerRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$sid`:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to protect shared owner root ACL: $sharedOwnerRoot" }
& icacls.exe $sharedOwnerRoot /setowner "*$sid" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to set shared owner root owner: $sharedOwnerRoot" }

$personalLimitBytes = [uint64]$LimitGiB * 1GB
$sharedLimitBytes = [uint64]$SharedLimitGiB * 1GB
Ensure-HardQuota $dataRoot $personalLimitBytes "AionUiPortal personal hard quota for $sid"
Ensure-HardQuota $sharedOwnerRoot $sharedLimitBytes "AionUiPortal shared hard quota for $sid"

Write-Host "Independent FSRM hard quotas verified for $resolvedAccount ($sid): personal=$dataRoot/$personalLimitBytes bytes shared=$sharedOwnerRoot/$sharedLimitBytes bytes."

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsAccount,
    [string]$DataRootBase
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

$resolvedAccount = $WindowsAccount
if ($resolvedAccount.StartsWith('.\')) { $resolvedAccount = $env:COMPUTERNAME + $resolvedAccount.Substring(1) }
$account = New-Object Security.Principal.NTAccount($resolvedAccount)
$sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
$profile = @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid })
if ($profile.Count -ne 1 -or [string]::IsNullOrWhiteSpace($profile[0].LocalPath)) {
    throw "Exactly one loaded-or-created Windows profile is required for $WindowsAccount ($sid)."
}
$profilePath = [IO.Path]::GetFullPath($profile[0].LocalPath)
if (-not ([IO.Path]::GetDirectoryName($profilePath.TrimEnd('\'))).Equals('C:\Users', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Windows profile must be a direct child of C:\Users: $profilePath"
}
$hivePath = Join-Path $profilePath 'NTUSER.DAT'
$dataRoot = if ([string]::IsNullOrWhiteSpace($DataRootBase)) {
    Join-Path $profilePath 'AionUiPortal'
} else {
    Join-Path ([Environment]::ExpandEnvironmentVariables($DataRootBase)) $sid
}
$dataRootFull = [IO.Path]::GetFullPath($dataRoot).TrimEnd('\')
$dataRootPrefix = $dataRootFull + '\'

function Test-IsolatedAcl([string]$Path, [bool]$RequireProtected) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        if ([IO.Path]::GetFullPath($Path).TrimEnd('\').Equals($dataRootFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Isolation root is a reparse point: $Path"
        }
        $targets = @($item.Target)
        if ($targets.Count -ne 1) { throw "Private-tree reparse point does not have one target: $Path" }
        $target = [IO.Path]::GetFullPath([string]$targets[0]).TrimEnd('\')
        if (-not $target.Equals($dataRootFull, [StringComparison]::OrdinalIgnoreCase) -and
            -not $target.StartsWith($dataRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Private-tree reparse point escapes its protected root: $Path -> $target"
        }
        return
    }
    $acl = Get-Acl -LiteralPath $Path
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) { throw "ACL inheritance is not protected: $Path" }
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $sid)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $allowed) { throw "Unexpected owner $owner on $Path" }
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $seen = @{}
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $principal = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "Unexpected deny ACE for $principal on $Path"
        }
        if ($principal -notin $allowed) { throw "Unexpected allowed principal $principal on $Path" }
        if (($rule.FileSystemRights -band $full) -ne $full) { throw "Principal $principal lacks FullControl on $Path" }
        $seen[$principal] = $true
    }
    foreach ($principal in $allowed) {
        if (-not $seen.ContainsKey($principal)) { throw "Required principal $principal is missing from $Path" }
    }
}

Test-IsolatedAcl -Path $profilePath -RequireProtected $true
Test-IsolatedAcl -Path $hivePath -RequireProtected $false
if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
    throw "Per-user AionUi data root is missing: $dataRoot"
}
Test-IsolatedAcl -Path $dataRoot -RequireProtected $true
foreach ($item in @(Get-ChildItem -LiteralPath $dataRoot -Force -Recurse)) {
    Test-IsolatedAcl -Path $item.FullName -RequireProtected $false
}
Write-Host "Verified Windows Profile, HKCU hive, and AionUi data-tree isolation for $WindowsAccount ($sid) at $dataRoot."

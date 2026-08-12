[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$DataRoot,
    [Parameter(Mandatory, ParameterSetName = 'All')][switch]$AllPortalUsers,
    [Parameter(ParameterSetName = 'All')][string]$DataRootBase = 'E:\AionUiData\users',
    [string]$PluginRoot = (Join-Path $PSScriptRoot '..\plugins\llm-wiki'),
    [string]$BuiltinReferenceRoot = (Join-Path $PSScriptRoot '..\.tools\AionCore-src\crates\aionui-app\assets\builtin-skills'),
    [string]$PythonExe,
    [switch]$PlanOnly,
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'

function Get-PolicySha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

$bundleManifestPath = Join-Path $PSScriptRoot 'skill-policy-manifest.json'
if (Test-Path -LiteralPath $bundleManifestPath -PathType Leaf) {
    $manifestItem = Get-Item -LiteralPath $bundleManifestPath -Force
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Managed Skill policy bundle manifest must not be a reparse point: $bundleManifestPath"
    }
    $bundleManifest = Get-Content -LiteralPath $bundleManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($bundleManifest.format_version -ne 1 -or $null -eq $bundleManifest.files) {
        throw 'Managed Skill policy bundle manifest is invalid.'
    }
    $bundleRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
    $bundlePrefix = $bundleRoot + '\'
    foreach ($entry in $bundleManifest.files.PSObject.Properties) {
        $relative = [string]$entry.Name
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "Managed Skill policy bundle manifest path is unsafe: $relative"
        }
        $target = [IO.Path]::GetFullPath((Join-Path $bundleRoot $relative))
        if (-not $target.StartsWith($bundlePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Managed Skill policy bundle path escaped its root: $relative"
        }
        $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Managed Skill policy bundle entry must be a regular file: $relative"
        }
        if ((Get-PolicySha256 $target) -cne ([string]$entry.Value.sha256).ToLowerInvariant() -or
            $item.Length -ne [int64]$entry.Value.size) {
            throw "Managed Skill policy bundle integrity check failed: $relative"
        }
    }
}

$engine = Join-Path $PSScriptRoot 'user_skill_policy.py'
foreach ($path in @($engine, (Join-Path $PluginRoot '.codex-plugin\plugin.json'), (Join-Path $BuiltinReferenceRoot 'workagent-help\SKILL.md'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required Skill policy input is missing: $path" }
}

if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $sharedPython = 'C:\Program Files\AionAgentCliShared\bin\python.exe'
    if (Test-Path -LiteralPath $sharedPython -PathType Leaf) {
        $PythonExe = $sharedPython
    } else {
        $PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
    }
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "Python executable is missing: $PythonExe" }

function Assert-NormalDirectory([string]$Path, [string]$Description) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must be a normal directory: $full"
    }
    return $full
}

$roots = @()
if ($AllPortalUsers) {
    $base = Assert-NormalDirectory $DataRootBase 'Portal user data root'
    $prefix = $base + '\'
    $roots = @(Get-ChildItem -LiteralPath $base -Force -Directory | Where-Object {
        $_.Name -match '^S-[0-9-]+$' -and
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'data\aionui-backend.db') -PathType Leaf)
    } | Sort-Object Name | ForEach-Object {
        $full = [IO.Path]::GetFullPath($_.FullName).TrimEnd('\')
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Portal user data root escaped the configured base: $full"
        }
        $full
    })
    if ($roots.Count -eq 0) { throw "No initialized Portal user data roots were found below $base" }
} else {
    $root = Assert-NormalDirectory $DataRoot 'Portal SID data root'
    if ([IO.Path]::GetFileName($root) -notmatch '^S-[0-9-]+$') {
        throw "Portal SID data root must end in a Windows SID: $root"
    }
    $roots = @($root)
}

if ($PlanOnly -and $VerifyOnly) { throw 'PlanOnly and VerifyOnly are mutually exclusive.' }
$command = if ($PlanOnly) { 'plan' } elseif ($VerifyOnly) { 'verify' } else { 'apply' }
$results = @()
foreach ($root in $roots) {
    $output = @(& $PythonExe $engine $command --data-root $root --plugin-root $PluginRoot --builtin-reference-root $BuiltinReferenceRoot 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Skill policy $command failed for $root`: $($output -join [Environment]::NewLine)"
    }
    $result = ($output -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop
    $expectedStatus = if ($PlanOnly) { 'READY' } else { 'OK' }
    if ($result.status -cne $expectedStatus) { throw "Skill policy returned $($result.status) for $root`: $($result.errors -join '; ')" }
    $results += $result
    $managedCount = if ($PlanOnly) { $result.managed_available_count_after } else { $result.managed_available_count }
    Write-Host "Skill policy $command passed for $([IO.Path]::GetFileName($root)): managed_available_count=$managedCount"
}

$results | ConvertTo-Json -Depth 6

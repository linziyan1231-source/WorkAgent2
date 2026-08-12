[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DestinationDirectory,
    [string]$PluginRoot = (Join-Path $PSScriptRoot '..\plugins\llm-wiki')
)

$ErrorActionPreference = 'Stop'

function Get-PolicySha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Assert-NormalDirectory([string]$Path, [string]$Description) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must be a normal directory: $resolved"
    }
    return [IO.Path]::GetFullPath($resolved).TrimEnd('\')
}

function Assert-RegularFile([string]$Path, [string]$Description) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must be a regular file: $resolved"
    }
    return $resolved
}

function Copy-RegularTree([string]$Source, [string]$Destination) {
    $sourceRoot = Assert-NormalDirectory $Source 'Skill policy source tree'
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    $sourcePrefix = $sourceRoot + '\'
    Get-ChildItem -LiteralPath $sourceRoot -Force -Recurse | Sort-Object FullName | ForEach-Object {
        if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are forbidden in the Skill policy bundle: $($_.FullName)"
        }
        $full = [IO.Path]::GetFullPath($_.FullName)
        if (-not $full.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Skill policy source escaped its root: $full"
        }
        $relative = $full.Substring($sourcePrefix.Length)
        if ($relative -match '(^|[\\/])__pycache__([\\/]|$)' -or $relative -match '\.pyc$') { return }
        $target = Join-Path $Destination $relative
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
        } else {
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force -ErrorAction Stop | Out-Null
            Copy-Item -LiteralPath $full -Destination $target -ErrorAction Stop
        }
    }
}

$destinationRoot = Assert-NormalDirectory $DestinationDirectory 'Administration scripts directory'
$pluginSource = Assert-NormalDirectory $PluginRoot 'LLM Wiki plugin root'
$wrapper = Assert-RegularFile (Join-Path $PSScriptRoot 'Apply-UserSkillPolicy.ps1') 'Skill policy wrapper'
$engine = Assert-RegularFile (Join-Path $PSScriptRoot 'user_skill_policy.py') 'Skill policy engine'
$stage = Join-Path $destinationRoot ('.skill-policy-stage-' + [Guid]::NewGuid().ToString('N'))
$target = Join-Path $destinationRoot 'skill-policy'
$archive = Join-Path $destinationRoot ('skill-policy-archive\' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$published = $false

try {
    New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $wrapper -Destination (Join-Path $stage 'Apply-UserSkillPolicy.ps1') -ErrorAction Stop
    Copy-Item -LiteralPath $engine -Destination (Join-Path $stage 'user_skill_policy.py') -ErrorAction Stop
    $pluginStage = Join-Path $stage 'llm-wiki'
    New-Item -ItemType Directory -Path (Join-Path $pluginStage '.codex-plugin') -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath (Assert-RegularFile (Join-Path $pluginSource '.codex-plugin\plugin.json') 'LLM Wiki plugin manifest') -Destination (Join-Path $pluginStage '.codex-plugin\plugin.json') -ErrorAction Stop
    foreach ($name in @('assets', 'scripts', 'skills')) {
        Copy-RegularTree (Join-Path $pluginSource $name) (Join-Path $pluginStage $name)
    }

    $stageRoot = [IO.Path]::GetFullPath($stage).TrimEnd('\')
    $stagePrefix = $stageRoot + '\'
    $files = [ordered]@{}
    Get-ChildItem -LiteralPath $stageRoot -Force -File -Recurse | Sort-Object FullName | ForEach-Object {
        $full = [IO.Path]::GetFullPath($_.FullName)
        if (-not $full.StartsWith($stagePrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Invalid staged Skill policy file: $full"
        }
        $relative = $full.Substring($stagePrefix.Length).Replace('\', '/')
        $files[$relative] = [ordered]@{ sha256 = Get-PolicySha256 $full; size = $_.Length }
    }
    $manifest = [ordered]@{ format_version = 1; generated_at_utc = [DateTime]::UtcNow.ToString('o'); files = $files }
    [IO.File]::WriteAllText(
        (Join-Path $stageRoot 'skill-policy-manifest.json'),
        (($manifest | ConvertTo-Json -Depth 6).Replace("`r`n", "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )

    if (Test-Path -LiteralPath $target) {
        $targetItem = Get-Item -LiteralPath $target -Force
        if (-not $targetItem.PSIsContainer -or ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Existing Skill policy bundle must be a normal directory: $target"
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $archive) -Force -ErrorAction Stop | Out-Null
        Move-Item -LiteralPath $target -Destination $archive -ErrorAction Stop
    }
    try {
        Move-Item -LiteralPath $stageRoot -Destination $target -ErrorAction Stop
        $published = $true
    } catch {
        if ((Test-Path -LiteralPath $archive) -and -not (Test-Path -LiteralPath $target)) {
            Move-Item -LiteralPath $archive -Destination $target -ErrorAction SilentlyContinue
        }
        throw
    }
} finally {
    if (-not $published -and (Test-Path -LiteralPath $stage)) {
        $resolvedStage = [IO.Path]::GetFullPath($stage)
        if (-not $resolvedStage.StartsWith($destinationRoot + '\.skill-policy-stage-', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean an unexpected Skill policy staging path: $resolvedStage"
        }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}

Write-Host "Published verified Skill policy bundle to $target"

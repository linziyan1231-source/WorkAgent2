[CmdletBinding(DefaultParameterSetName = 'All', SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'All')]
    [string]$UsersRoot = 'E:\AionUiData\users',

    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$ConfigPath,

    [ValidateRange(1, 128)]
    [int]$MaxNewAgentsPerSession = 4,

    [string]$AgentCliRoot = 'C:\Program Files\AionAgentCliShared'
)

$ErrorActionPreference = 'Stop'
$sourceGuard = Join-Path $PSScriptRoot 'kimi-agent-swarm-guard.ps1'
if (-not (Test-Path -LiteralPath $sourceGuard -PathType Leaf)) {
    throw "AgentSwarm guard script is missing: $sourceGuard"
}

$beginMarker = '# BEGIN WorkAgent2 managed AgentSwarm policy'
$endMarker = '# END WorkAgent2 managed AgentSwarm policy'
$timestamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$updated = 0

$configs = if ($PSCmdlet.ParameterSetName -eq 'Single') {
    @(Get-Item -LiteralPath $ConfigPath -Force -ErrorAction Stop)
} else {
    if (-not (Test-Path -LiteralPath $UsersRoot -PathType Container)) {
        throw "Users root is missing: $UsersRoot"
    }
    @(Get-ChildItem -LiteralPath $UsersRoot -Directory -Force | ForEach-Object {
        $modern = Join-Path $_.FullName 'profile\.kimi-code\config.toml'
        $legacy = Join-Path $_.FullName 'profile\.kimi\config.toml'
        if (Test-Path -LiteralPath $modern -PathType Leaf) { Get-Item -LiteralPath $modern }
        elseif (Test-Path -LiteralPath $legacy -PathType Leaf) { Get-Item -LiteralPath $legacy }
    })
}
if ($configs.Count -eq 0) { throw 'No Kimi user configurations were found.' }
foreach ($config in $configs) {
    if ($config.PSIsContainer -or ($config.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Kimi configuration must be a regular file: $($config.FullName)"
    }
}

$currentPath = Join-Path $AgentCliRoot 'current.json'
$pointer = Get-Content -LiteralPath $currentPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$releaseID = [string]$pointer.release_id
if ($releaseID -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]{0,255}$') { throw "Agent CLI release pointer is invalid: $currentPath" }
$releasesRoot = [IO.Path]::GetFullPath((Join-Path $AgentCliRoot 'releases')).TrimEnd('\')
$releasePath = [IO.Path]::GetFullPath((Join-Path $releasesRoot $releaseID)).TrimEnd('\')
if (-not $releasePath.StartsWith($releasesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Agent CLI release escaped its protected root: $releasePath"
}
$validationPython = Join-Path $releasePath 'kimi-tool\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $validationPython -PathType Leaf)) {
    throw "Kimi configuration validator is missing: $validationPython"
}
$validationScript = @'
import sys
from pathlib import Path
from kimi_cli.config import load_config

config = load_config(Path(sys.argv[2]))
matches = [hook for hook in config.hooks if hook.event == "PreToolUse" and hook.matcher == r"^AgentSwarm$"]
if len(matches) != 1:
    raise RuntimeError("expected exactly one managed AgentSwarm hook")
'@
$encodedValidationScript = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($validationScript))

foreach ($config in $configs) {
    $kimiHome = Split-Path $config.FullName -Parent
    $hookDirectory = Join-Path $kimiHome 'hooks'
    $stateDirectory = Join-Path $hookDirectory 'agent-swarm-state'
    $guardPath = Join-Path $hookDirectory 'limit-agent-swarm.ps1'
    $backupDirectory = Join-Path $kimiHome ("backups\agent-swarm-policy-$timestamp")

    if (-not $PSCmdlet.ShouldProcess($config.FullName, "limit AgentSwarm to $MaxNewAgentsPerSession new subagents per conversation")) {
        continue
    }

    [void][IO.Directory]::CreateDirectory($backupDirectory)
    Copy-Item -LiteralPath $config.FullName -Destination (Join-Path $backupDirectory 'config.toml') -Force
    [void][IO.Directory]::CreateDirectory($hookDirectory)
    Copy-Item -LiteralPath $sourceGuard -Destination $guardPath -Force

    $text = [IO.File]::ReadAllText($config.FullName)
    $managedPattern = '(?ms)^' + [regex]::Escape($beginMarker) + '.*?^' + [regex]::Escape($endMarker) + '\s*'
    $text = [regex]::Replace($text, $managedPattern, '').TrimEnd()
    $text = [regex]::Replace($text, '(?m)^hooks\s*=\s*\[\s*\]\s*\r?\n?', '')
    if ($text -match '(?m)^hooks\s*=') {
        throw "Refusing to replace non-empty inline hooks in $($config.FullName)"
    }
    $command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $guardPath + '" -MaxNewAgentsPerSession ' + $MaxNewAgentsPerSession + ' -StateDirectory "' + $stateDirectory + '"'
    if ($command.Contains("'")) { throw "Managed hook command cannot be represented as a TOML literal string: $command" }
    $block = @"

$beginMarker
[[hooks]]
event = "PreToolUse"
command = '$command'
matcher = "^AgentSwarm$"
timeout = 5
$endMarker
"@
    [IO.File]::WriteAllText($config.FullName, $text + "`r`n" + $block.TrimStart() + "`r`n", [Text.UTF8Encoding]::new($false))
    $hadDontWriteBytecode = Test-Path Env:PYTHONDONTWRITEBYTECODE
    $previousDontWriteBytecode = $env:PYTHONDONTWRITEBYTECODE
    try {
        $env:PYTHONDONTWRITEBYTECODE = '1'
        & $validationPython -B -c 'import base64,sys;exec(base64.b64decode(sys.argv[1]))' $encodedValidationScript $config.FullName
        $validationExitCode = $LASTEXITCODE
    } finally {
        if ($hadDontWriteBytecode) {
            $env:PYTHONDONTWRITEBYTECODE = $previousDontWriteBytecode
        } else {
            Remove-Item Env:PYTHONDONTWRITEBYTECODE -ErrorAction SilentlyContinue
        }
    }
    if ($validationExitCode -ne 0) {
        Copy-Item -LiteralPath (Join-Path $backupDirectory 'config.toml') -Destination $config.FullName -Force
        throw "Kimi configuration validation failed and the original was restored: $($config.FullName)"
    }
    $updated++
}

[pscustomobject]@{
    discovered = $configs.Count
    updated = $updated
    max_new_agents_per_session = $MaxNewAgentsPerSession
    backup_tag = "agent-swarm-policy-$timestamp"
}

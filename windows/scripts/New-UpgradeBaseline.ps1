[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$InstallRoot = 'C:\Program Files\AionUiPortal',
    [string]$AgentCurrentFile = 'C:\Program Files\AionAgentCliShared\current.json'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
if (-not [IO.Path]::IsPathFullyQualified($OutputPath)) { throw 'OutputPath must be absolute.' }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$paths = [ordered]@{
    'web' = [string]$config.current_release_file
    'AionUiPortal.exe' = (Join-Path $InstallRoot 'AionUiPortal.exe')
    'AionUiUserHost.exe' = (Join-Path $InstallRoot 'AionUiUserHost.exe')
    'portal.exe' = (Join-Path $InstallRoot 'portal.exe')
    'AionKimiDatasourceBroker.exe' = (Join-Path $InstallRoot 'AionKimiDatasourceBroker.exe')
    'AionAgentCli.exe' = $AgentCurrentFile
}
$components = [ordered]@{}
foreach ($entry in $paths.GetEnumerator()) {
    if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
        if ($entry.Key -ceq 'AionKimiDatasourceBroker.exe') {
            $components[$entry.Key] = [ordered]@{ path = [IO.Path]::GetFullPath($entry.Value); sha256 = 'absent'; size = 0 }
            continue
        }
        throw "Installed component is missing: $($entry.Value)"
    }
    $item = Get-Item -LiteralPath $entry.Value -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Installed component is a reparse point: $($entry.Value)" }
    $components[$entry.Key] = [ordered]@{
        path = [IO.Path]::GetFullPath($entry.Value)
        sha256 = (Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $item.Length
    }
}
$captured = [DateTime]::UtcNow
$baseline = [ordered]@{
    format_version = 1
    baseline_id = $captured.ToString('yyyyMMddTHHmmssZ')
    captured_at_utc = $captured.ToString('o')
    components = $components
}
$destination = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Output directory is missing: $parent" }
if (Test-Path -LiteralPath $destination) { throw "Refusing to overwrite immutable baseline: $destination" }
$json = ($baseline | ConvertTo-Json -Depth 5).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($destination, $json, [Text.UTF8Encoding]::new($false))
Write-Host "Captured non-secret production component baseline: $destination"

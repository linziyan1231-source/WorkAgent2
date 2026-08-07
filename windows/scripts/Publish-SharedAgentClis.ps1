[CmdletBinding()]
param(
    [string]$CodexVersion,
    [string]$KimiVersion,
    [string]$PythonVersion,
    [string]$ReleaseSuffix,
    [string]$LauncherPath = (Join-Path $PSScriptRoot '..\artifacts\bin\AionAgentCli.exe'),
    [string]$KimiCodeExecutablePath,
    [string]$NpmCommand = 'npm.cmd',
    [string]$UvCommand = 'uv.exe',
    [switch]$PreserveStableLaunchers,
    [switch]$UpdateKimiLauncherOnly
)

$ErrorActionPreference = 'Stop'
$sharedRoot = 'C:\Program Files\AionAgentCliShared'
$releasesRoot = Join-Path $sharedRoot 'releases'
$binDirectory = Join-Path $sharedRoot 'bin'
$configPath = 'C:\ProgramData\AionUiPortal\portal.json'
$portalCli = 'C:\Program Files\AionUiPortal\portal.exe'
$script:portalUserHostsStopped = $false

function Assert-Exit([string]$operation) {
    if ($LASTEXITCODE -ne 0) { throw "$operation failed with exit code $LASTEXITCODE" }
}

function Resolve-CommandPath([string]$command, [string]$description) {
    $resolved = Get-Command $command -ErrorAction Stop | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace([string]$resolved.Source)) { throw "$description command has no executable source: $command" }
    return [IO.Path]::GetFullPath([string]$resolved.Source)
}

function Assert-Version([string]$value, [string]$name) {
    if ($value -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$') { throw "$name version contains unsupported characters: $value" }
}

function Remove-SafeTree([string]$parent, [string]$target) {
    if (-not (Test-Path -LiteralPath $target)) { return }
    $parentFull = [IO.Path]::GetFullPath($parent).TrimEnd('\') + '\'
    $targetFull = [IO.Path]::GetFullPath($target).TrimEnd('\')
    if (-not $targetFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a tree outside $parentFull`: $targetFull"
    }
    $item = Get-Item -LiteralPath $targetFull -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a non-directory or reparse point: $targetFull"
    }
    Remove-Item -LiteralPath $targetFull -Recurse -Force -ErrorAction Stop
}

function Stop-PortalUserHosts {
    if ($script:portalUserHostsStopped) { return }
    $stopScript = Join-Path $PSScriptRoot 'Stop-AllInstances.ps1'
    if ((Test-Path -LiteralPath $configPath -PathType Leaf) -and (Test-Path -LiteralPath $portalCli -PathType Leaf)) {
        & $stopScript -PortalCli $portalCli -ConfigPath $configPath
        $script:portalUserHostsStopped = $true
        return
    }
    $currentPointer = Join-Path $sharedRoot 'current.json'
    if (Test-Path -LiteralPath $currentPointer -PathType Leaf) {
        throw "Cannot stop existing Portal UserHosts before agent CLI activation because Portal configuration or CLI is missing."
    }
    $script:portalUserHostsStopped = $true
}

function Install-Launcher([string]$destination) {
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        $sourceHash = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($sourceHash -eq $destinationHash) { return $false }
    }
    $temporary = $destination + ".tmp-$PID"
    Copy-Item -LiteralPath $launcher -Destination $temporary -Force
    try {
        [IO.File]::Move($temporary, $destination, $true)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
    return $true
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
if (-not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows installation is required.' }
if ($PreserveStableLaunchers -and $UpdateKimiLauncherOnly) { throw 'PreserveStableLaunchers and UpdateKimiLauncherOnly cannot be combined.' }
$launcher = (Resolve-Path -LiteralPath $LauncherPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw "Shared agent CLI launcher is missing: $LauncherPath" }
$npm = Resolve-CommandPath $NpmCommand 'npm'
$uv = Resolve-CommandPath $UvCommand 'uv'

$npmRoot = (& $npm root -g | Out-String).Trim()
Assert-Exit 'Discover administrator npm root'
$codexPackage = Join-Path $npmRoot '@openai\codex\package.json'
if (-not (Test-Path -LiteralPath $codexPackage -PathType Leaf)) {
    throw 'Administrator Codex CLI is not installed through npm; install @openai/codex before publishing.'
}
$installedCodexVersion = [string](Get-Content -LiteralPath $codexPackage -Raw | ConvertFrom-Json).version
if ([string]::IsNullOrWhiteSpace($CodexVersion)) { $CodexVersion = $installedCodexVersion }
if ($CodexVersion -cne $installedCodexVersion) {
    throw "Requested Codex $CodexVersion does not match the administrator source $installedCodexVersion; update the administrator copy first."
}
$toolRoot = (& $uv tool dir | Out-String).Trim()
Assert-Exit 'Discover administrator uv tool root'
$kimiSource = Join-Path $toolRoot 'kimi-cli'
$pyvenv = Join-Path $kimiSource 'pyvenv.cfg'
if (-not (Test-Path -LiteralPath $pyvenv -PathType Leaf)) { throw 'Administrator Kimi uv environment is missing; install kimi-cli before publishing.' }
$pyvenvText = Get-Content -LiteralPath $pyvenv -Raw
if ($pyvenvText -notmatch '(?m)^home\s*=\s*(.+?)\s*$') { throw "Cannot read the Kimi Python home from $pyvenv" }
$pythonSource = [IO.Path]::GetFullPath($Matches[1].Trim())
if (-not (Test-Path -LiteralPath (Join-Path $pythonSource 'python.exe') -PathType Leaf)) { throw "Administrator Kimi Python runtime is missing: $pythonSource" }
if ($pyvenvText -notmatch '(?m)^version_info\s*=\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$') { throw "Cannot read the Kimi Python version from $pyvenv" }
$installedPythonVersion = $Matches[1]
if ([string]::IsNullOrWhiteSpace($PythonVersion)) { $PythonVersion = $installedPythonVersion }
if ($PythonVersion -cne $installedPythonVersion) {
    throw "Requested Python $PythonVersion does not match the administrator Kimi runtime $installedPythonVersion; update the administrator copy first."
}
$useKimiCode = -not [string]::IsNullOrWhiteSpace($KimiCodeExecutablePath)
if ($useKimiCode) {
    $kimiCodeExecutable = (Resolve-Path -LiteralPath $KimiCodeExecutablePath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $kimiCodeExecutable -PathType Leaf)) { throw "Kimi Code executable is missing: $KimiCodeExecutablePath" }
    $kimiOutput = (& $kimiCodeExecutable --version | Out-String).Trim()
    Assert-Exit 'Read official Kimi Code version'
    if ($kimiOutput -notmatch '^([0-9A-Za-z][0-9A-Za-z._-]{0,127})$') {
        throw "Official Kimi Code returned an unexpected version string: $kimiOutput"
    }
    $installedKimiVersion = $Matches[1]
} else {
    $kimiOutput = (& (Join-Path $kimiSource 'Scripts\python.exe') -m kimi_cli --version | Out-String).Trim()
    Assert-Exit 'Read administrator Kimi CLI version'
    if ($kimiOutput -notmatch '^kimi, version ([0-9A-Za-z][0-9A-Za-z._-]{0,127})$') {
        throw "Administrator Kimi CLI returned an unexpected version string: $kimiOutput"
    }
    $installedKimiVersion = $Matches[1]
}
if ([string]::IsNullOrWhiteSpace($KimiVersion)) { $KimiVersion = $installedKimiVersion }
if ($KimiVersion -cne $installedKimiVersion) {
    throw "Requested Kimi $KimiVersion does not match the administrator source $installedKimiVersion; update the administrator copy first."
}
Assert-Version $CodexVersion 'Codex'
Assert-Version $KimiVersion 'Kimi'
Assert-Version $PythonVersion 'Python'
if (-not [string]::IsNullOrWhiteSpace($ReleaseSuffix)) {
    Assert-Version $ReleaseSuffix 'Release suffix'
}

$kimiReleaseLabel = if ($useKimiCode) { 'kimi-code' } else { 'kimi' }
$releaseRevision = if ([string]::IsNullOrWhiteSpace($ReleaseSuffix)) { '' } else { '-' + $ReleaseSuffix }
$releaseID = "codex-$CodexVersion`_$kimiReleaseLabel-$KimiVersion$releaseRevision`_python-$PythonVersion"
$releasePath = Join-Path $releasesRoot $releaseID
New-Item -ItemType Directory -Force -Path $sharedRoot, $releasesRoot, $binDirectory | Out-Null
& $launcher acl apply --root $sharedRoot
Assert-Exit 'Protect initial shared agent CLI directories'

if (Test-Path -LiteralPath $releasePath) {
    $releaseItem = Get-Item -LiteralPath $releasePath -Force
    if (-not $releaseItem.PSIsContainer -or ($releaseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Existing shared agent CLI release is not a normal directory: $releasePath"
    }
    & $launcher release verify --root $sharedRoot --release-id $releaseID
    Assert-Exit 'Verify existing immutable shared agent CLI release'
} else {
    New-Item -ItemType Directory -Path $releasePath | Out-Null
    try {
        $codexSource = Split-Path $codexPackage -Parent
        $codexCandidates = @(Get-ChildItem -LiteralPath $codexSource -Filter 'codex.exe' -File -Recurse | Where-Object {
            $_.FullName -match '[\\/]@openai[\\/]codex-win32-x64[\\/]vendor[\\/]x86_64-pc-windows-msvc[\\/]bin[\\/]codex\.exe$'
        })
        if ($codexCandidates.Count -ne 1) { throw "Expected exactly one Windows x64 Codex binary, found $($codexCandidates.Count)." }
        $vendorSource = Split-Path (Split-Path $codexCandidates[0].DirectoryName -Parent) -Parent
        $codexDestination = Join-Path $releasePath 'codex'
        New-Item -ItemType Directory -Path $codexDestination | Out-Null
        Copy-Item -LiteralPath $vendorSource -Destination (Join-Path $codexDestination 'vendor') -Recurse
        Copy-Item -LiteralPath $codexPackage -Destination (Join-Path $codexDestination 'package.json')

        $codexExecutable = Join-Path $releasePath 'codex\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
        $codexOutput = (& $codexExecutable --version | Out-String).Trim()
        Assert-Exit 'Probe pinned Codex executable'
        if ($codexOutput -cne "codex-cli $CodexVersion") { throw "Shared Codex reported unexpected version: $codexOutput" }

        $pythonDestination = Join-Path $releasePath 'python'
        $kimiDestination = Join-Path $releasePath 'kimi-tool'
        Copy-Item -LiteralPath $pythonSource -Destination $pythonDestination -Recurse
        Copy-Item -LiteralPath $kimiSource -Destination $kimiDestination -Recurse
        $relocatedPyvenv = [Text.RegularExpressions.Regex]::Replace($pyvenvText, '(?m)^home\s*=\s*.+?\s*$', "home = $pythonDestination")
        [IO.File]::WriteAllText((Join-Path $kimiDestination 'pyvenv.cfg'), $relocatedPyvenv, [Text.UTF8Encoding]::new($false))
        if ($useKimiCode) {
            $kimiCodeDestination = Join-Path $releasePath 'kimi-code'
            New-Item -ItemType Directory -Path $kimiCodeDestination | Out-Null
            $kimiExecutable = Join-Path $kimiCodeDestination 'kimi.exe'
            Copy-Item -LiteralPath $kimiCodeExecutable -Destination $kimiExecutable
            $kimiOutput = (& $kimiExecutable --version | Out-String).Trim()
            Assert-Exit 'Probe pinned Kimi Code executable'
            if ($kimiOutput -cne $KimiVersion) { throw "Shared Kimi Code reported unexpected version: $kimiOutput" }
        } else {
            & (Join-Path $PSScriptRoot 'Patch-KimiAcpStaticApiKey.ps1') -KimiToolRoot $kimiDestination
            $kimiExecutable = Join-Path $kimiDestination 'Scripts\python.exe'
            $kimiOutput = (& $kimiExecutable -m kimi_cli --version | Out-String).Trim()
            Assert-Exit 'Probe pinned Kimi executable'
            if ($kimiOutput -cne "kimi, version $KimiVersion") { throw "Shared Kimi reported unexpected version: $kimiOutput" }
        }

        $reparsePoints = @(Get-ChildItem -LiteralPath $releasePath -Force -Recurse | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($reparsePoints.Count -ne 0) { throw "Shared agent CLI release contains a reparse point: $($reparsePoints[0].FullName)" }
        & $launcher release manifest --root $sharedRoot --release-id $releaseID --codex-version $CodexVersion --kimi-version $KimiVersion --python-version $PythonVersion
        Assert-Exit 'Write shared agent CLI release manifest'
        & $launcher release verify --root $sharedRoot --release-id $releaseID
        Assert-Exit 'Verify new shared agent CLI release'
    } catch {
        Remove-SafeTree $releasesRoot $releasePath
        throw
    }
}

$launcherNames = @('codex.exe', 'kimi.exe', 'python.exe', 'rg.exe')
if ($UpdateKimiLauncherOnly) {
    foreach ($name in @('codex.exe', 'python.exe', 'rg.exe')) {
        $destination = Join-Path $binDirectory $name
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            throw "Cannot preserve a missing stable launcher: $destination"
        }
        $item = Get-Item -LiteralPath $destination -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Cannot preserve a stable launcher reparse point: $destination"
        }
    }
    $kimiLauncher = Join-Path $binDirectory 'kimi.exe'
    if (-not (Test-Path -LiteralPath $kimiLauncher -PathType Leaf) -or
        (Get-FileHash -LiteralPath $kimiLauncher -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash) {
        if (Test-Path -LiteralPath $kimiLauncher -PathType Leaf) { Stop-PortalUserHosts }
        [void](Install-Launcher $kimiLauncher)
    }
} elseif ($PreserveStableLaunchers) {
    foreach ($name in $launcherNames) {
        $destination = Join-Path $binDirectory $name
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            [void](Install-Launcher $destination)
            continue
        }
        $item = Get-Item -LiteralPath $destination -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Cannot preserve a stable launcher reparse point: $destination"
        }
    }
} else {
    $launcherNeedsUpdate = $false
    foreach ($name in $launcherNames) {
        $destination = Join-Path $binDirectory $name
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash) {
            $launcherNeedsUpdate = $true
            break
        }
    }
    if ($launcherNeedsUpdate -and (Test-Path -LiteralPath (Join-Path $binDirectory 'codex.exe') -PathType Leaf)) {
        Stop-PortalUserHosts
    }
    foreach ($name in $launcherNames) {
        [void](Install-Launcher (Join-Path $binDirectory $name))
    }
}

# Agent CLI activation is a stop-the-world cutover. Build and verify the new
# immutable release first, then stop every UserHost immediately before moving
# current.json so no running workflow can straddle old and new CLI releases.
Stop-PortalUserHosts
& $launcher release activate --root $sharedRoot --release-id $releaseID
Assert-Exit 'Activate shared agent CLI release'
& $launcher acl apply --root $sharedRoot
Assert-Exit 'Apply shared agent CLI read-only ACLs'
& $launcher release verify --root $sharedRoot
Assert-Exit 'Verify active shared agent CLI release'
& $launcher acl verify --root $sharedRoot
Assert-Exit 'Verify shared agent CLI read-only ACLs'

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$pathPresent = @([string]$machinePath -split ';' | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and [IO.Path]::GetFullPath($_).TrimEnd('\').Equals($binDirectory, [StringComparison]::OrdinalIgnoreCase)
}).Count -gt 0
if (-not $pathPresent) {
    $newMachinePath = if ([string]::IsNullOrWhiteSpace($machinePath)) { $binDirectory } else { $machinePath.TrimEnd(';') + ';' + $binDirectory }
    [Environment]::SetEnvironmentVariable('Path', $newMachinePath, 'Machine')
    Stop-PortalUserHosts
}
$processPathPresent = @(($env:Path -split ';') | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and [IO.Path]::GetFullPath($_).TrimEnd('\').Equals($binDirectory, [StringComparison]::OrdinalIgnoreCase)
}).Count -gt 0
if (-not $processPathPresent) { $env:Path = $binDirectory + ';' + $env:Path }

if (-not ('AionEnvironmentBroadcast' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AionEnvironmentBroadcast {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
}
'@
}
$broadcastResult = [UIntPtr]::Zero
[void][AionEnvironmentBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 0x0002, 5000, [ref]$broadcastResult)

$codexOutput = (& (Join-Path $binDirectory 'codex.exe') --version | Out-String).Trim()
Assert-Exit 'Probe stable Codex launcher'
$kimiOutput = (& (Join-Path $binDirectory 'kimi.exe') --version | Out-String).Trim()
Assert-Exit 'Probe stable Kimi launcher'
$pythonOutput = (& (Join-Path $binDirectory 'python.exe') --version | Out-String).Trim()
Assert-Exit 'Probe stable Python launcher'
$ripgrepOutput = (& (Join-Path $binDirectory 'rg.exe') --version | Out-String).Trim()
Assert-Exit 'Probe stable ripgrep launcher'
$expectedKimiOutput = if ($useKimiCode) { $KimiVersion } else { "kimi, version $KimiVersion" }
if ($codexOutput -cne "codex-cli $CodexVersion" -or $kimiOutput -cne $expectedKimiOutput -or $pythonOutput -cne "Python $PythonVersion" -or
    ($ripgrepOutput -split "`r?`n", 2)[0] -notmatch '^ripgrep [0-9]') {
    throw "Stable launcher version verification failed: Codex=$codexOutput Kimi=$kimiOutput Python=$pythonOutput ripgrep=$ripgrepOutput"
}

Write-Host "Published immutable shared agent CLI release $releaseID."
Write-Host "Machine PATH includes $binDirectory; new and restarted users resolve codex, kimi, python, and ripgrep without administrator-profile paths."
Write-Host 'Future updates: update the administrator copies, then rerun this elevated script. Existing immutable releases are retained for rollback.'

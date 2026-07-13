[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildManifestPath,
    [Parameter(Mandatory)][string]$AionUiPackedDirectory,
    [Parameter(Mandatory)][string]$AionUiVersion,
    [Parameter(Mandatory)][string]$AionCoreVersion,
    [string]$BinariesDirectory
)

$ErrorActionPreference = 'Stop'
foreach ($path in @($BuildManifestPath, (Join-Path $AionUiPackedDirectory 'aionui-web.exe'), (Join-Path $AionUiPackedDirectory 'package.json'),
    (Join-Path $AionUiPackedDirectory 'static\index.html'), (Join-Path $AionUiPackedDirectory 'bundled-aioncore\win32-x64\aioncore.exe'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required build artifact is missing: $path" }
}
$manifest = Get-Content -LiteralPath $BuildManifestPath -Raw | ConvertFrom-Json
if ($manifest.format_version -ne 1 -or [string]$manifest.aionui_version -cne $AionUiVersion -or [string]$manifest.aioncore_version -cne $AionCoreVersion) {
    throw 'Build manifest format or AionUi/AionCore version does not match the requested deployment.'
}

if ($BinariesDirectory) {
    $binaryNames = @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionAgentCli.exe')
    $actualBinaryNames = @(Get-ChildItem -LiteralPath $BinariesDirectory -File | ForEach-Object { $_.Name })
    $unexpectedBinaryNames = @($actualBinaryNames | Where-Object { $_ -notin $binaryNames })
    if ($actualBinaryNames.Count -ne $binaryNames.Count -or $unexpectedBinaryNames.Count -ne 0) {
        throw "Binaries directory must contain exactly the four product executables; found: $($actualBinaryNames -join ', ')"
    }
    foreach ($name in $binaryNames) {
        $path = Join-Path $BinariesDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Built binary is missing: $path" }
        $entry = $manifest.binaries.PSObject.Properties[$name].Value
        if ($null -eq $entry) { throw "Build manifest is missing binary $name" }
        $item = Get-Item -LiteralPath $path -Force
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($item.Length -ne [int64]$entry.size -or $hash -cne ([string]$entry.sha256).ToLowerInvariant()) {
            throw "Built binary failed size/SHA-256 verification: $name"
        }
    }
}

$reparsePoints = @(Get-ChildItem -LiteralPath $AionUiPackedDirectory -Force -Recurse | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
})
if ($reparsePoints.Count -ne 0) { throw "Packed AionUi contains a reparse point: $($reparsePoints[0].FullName)" }
$files = @(Get-ChildItem -LiteralPath $AionUiPackedDirectory -Force -File -Recurse)
$expectedFiles = @($manifest.aionui_packed_files.PSObject.Properties)
if ($expectedFiles.Count -eq 0 -or $files.Count -ne $expectedFiles.Count) {
    throw "Packed AionUi file count $($files.Count) does not match build manifest count $($expectedFiles.Count)."
}
$root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AionUiPackedDirectory).Path).TrimEnd('\') + '\'
foreach ($file in $files) {
    $full = [IO.Path]::GetFullPath($file.FullName)
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "Packed file escaped its root: $full" }
    $relative = $full.Substring($root.Length).Replace('\', '/')
    $entry = $manifest.aionui_packed_files.PSObject.Properties[$relative].Value
    if ($null -eq $entry) { throw "Packed file is absent from build manifest: $relative" }
    $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($file.Length -ne [int64]$entry.size -or $hash -cne ([string]$entry.sha256).ToLowerInvariant()) {
        throw "Packed AionUi file failed size/SHA-256 verification: $relative"
    }
}

$webVersion = (& (Join-Path $AionUiPackedDirectory 'aionui-web.exe') version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $webVersion -cne $AionUiVersion) { throw "Packed aionui-web reports unexpected version: $webVersion" }
$coreVersionOutput = (& (Join-Path $AionUiPackedDirectory 'bundled-aioncore\win32-x64\aioncore.exe') --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $coreVersionOutput -cne ('aioncore ' + $AionCoreVersion.TrimStart('v'))) {
    throw "Packed aioncore reports unexpected version: $coreVersionOutput"
}
Write-Host "Verified build manifest, executable versions, and SHA-256 for $($files.Count) packed AionUi files."

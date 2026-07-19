[CmdletBinding()]
param(
    [string]$AionUiSource = (Join-Path $PSScriptRoot '..\..\AionUi'),
    [string]$GoExe = 'go',
    [switch]$SkipAionUiPack,
    [switch]$ReuseVerifiedPortalBinaries
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$aionRoot = (Resolve-Path $AionUiSource).Path
$package = Get-Content -Raw (Join-Path $aionRoot 'package.json') | ConvertFrom-Json
$version = [string]$package.version
$coreVersion = [string]$package.aioncoreVersion
$dist = Join-Path $aionRoot 'dist-web-cli'
$archive = Join-Path $dist "aionui-web-$version-win-x86_64.tar.gz"
$packedDirectory = Join-Path $dist 'staging\aionui-web'

if (-not $SkipAionUiPack) {
    Push-Location $aionRoot
    try {
        # pack-web-cli copies the already-built renderer from out/renderer.
        # Always rebuild it first so an immutable Web release cannot silently
        # package stale UI/help/i18n assets from an earlier source revision.
        & bun run package
        if ($LASTEXITCODE -ne 0) { throw "AionUi renderer build failed with exit code $LASTEXITCODE" }
        $env:PACK_PLATFORM = 'win32'
        $env:PACK_ARCH = 'x64'
        & node 'scripts\pack-web-cli.js'
        if ($LASTEXITCODE -ne 0) { throw "AionUi pack-web-cli.js failed with exit code $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
}

foreach ($path in @(
    $archive,
    "$archive.sha256",
    (Join-Path $packedDirectory 'aionui-web.exe'),
    (Join-Path $packedDirectory 'package.json'),
    (Join-Path $packedDirectory 'static\index.html'),
    (Join-Path $packedDirectory 'bundled-aioncore\win32-x64\aioncore.exe')
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required build output is missing: $path" }
}

$managedResourcesRoot = Join-Path $packedDirectory 'bundled-aioncore\win32-x64\managed-resources'
& (Join-Path $PSScriptRoot 'Patch-CodexAcpSessionFork.ps1') -ManagedResourcesRoot $managedResourcesRoot

# The managed bridge is part of the immutable Web/Core bundle. Rebuild the
# archive and checksum after patching so the published archive and expanded
# staging tree describe the exact same release bytes.
& tar -czf $archive -C (Join-Path $dist 'staging') 'aionui-web'
if ($LASTEXITCODE -ne 0) { throw "Repack patched AionUi archive failed with exit code $LASTEXITCODE" }
$patchedArchiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    "$archive.sha256",
    "$patchedArchiveHash  $([IO.Path]::GetFileName($archive))`n",
    [Text.UTF8Encoding]::new($false)
)

$declaredHash = ((Get-Content -LiteralPath "$archive.sha256" -Raw) -split '\s+')[0].ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($declaredHash -ne $actualHash) { throw "AionUi archive checksum mismatch" }
$webVersion = (& (Join-Path $packedDirectory 'aionui-web.exe') version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $webVersion -cne $version) { throw "Packed aionui-web reports unexpected version: $webVersion" }
$coreVersionOutput = (& (Join-Path $packedDirectory 'bundled-aioncore\win32-x64\aioncore.exe') --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $coreVersionOutput -cne ('aioncore ' + $coreVersion.TrimStart('v'))) {
    throw "Packed aioncore reports unexpected version: $coreVersionOutput"
}
$reparsePoints = @(Get-ChildItem -LiteralPath $packedDirectory -Force -Recurse | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
})
if ($reparsePoints.Count -ne 0) { throw "Packed AionUi contains a reparse point: $($reparsePoints[0].FullName)" }
$packedFiles = [ordered]@{}
$packedRoot = [IO.Path]::GetFullPath($packedDirectory).TrimEnd('\') + '\'
Get-ChildItem -LiteralPath $packedDirectory -Force -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = ([IO.Path]::GetFullPath($_.FullName).Substring($packedRoot.Length)).Replace('\', '/')
    $packedFiles[$relative] = [ordered]@{
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $_.Length
    }
}

$env:GOTOOLCHAIN = 'local'
$env:CGO_ENABLED = '0'
Push-Location $projectRoot
try {
    $bin = Join-Path $projectRoot 'artifacts\bin'
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    if (-not $ReuseVerifiedPortalBinaries) {
        & $GoExe test -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw "Go behavior tests failed" }
        & $GoExe vet -unsafeptr=false ./...
        if ($LASTEXITCODE -ne 0) { throw "Go vet failed" }
        & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $bin 'AionUiPortal.exe') ./cmd/aionui-portal
        if ($LASTEXITCODE -ne 0) { throw "AionUiPortal build failed" }
        & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $bin 'AionUiUserHost.exe') ./cmd/aionui-userhost
        if ($LASTEXITCODE -ne 0) { throw "AionUiUserHost build failed" }
        & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $bin 'portal.exe') ./cmd/portal
        if ($LASTEXITCODE -ne 0) { throw "Portal administrator CLI build failed" }
        & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $bin 'AionAgentCli.exe') ./cmd/aion-agent-cli
        if ($LASTEXITCODE -ne 0) { throw "Shared agent CLI launcher build failed" }
    } else {
        $previousManifestPath = Join-Path $projectRoot 'artifacts\build-manifest.json'
        if (-not (Test-Path -LiteralPath $previousManifestPath -PathType Leaf)) {
            throw 'Cannot reuse Portal binaries without the previous hash-recorded build manifest.'
        }
        $previousManifest = Get-Content -LiteralPath $previousManifestPath -Raw | ConvertFrom-Json
        foreach ($name in @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionAgentCli.exe')) {
            $path = Join-Path $bin $name
            $expectedHash = [string]$previousManifest.binaries.$name.sha256
            $actualBinaryHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if (-not $expectedHash -or $actualBinaryHash -cne $expectedHash) {
                throw "Reusable Portal binary does not match the previous manifest: $name"
            }
        }
        Write-Host 'Web-only release: reusing hash-recorded Portal binaries.'
    }

    foreach ($temporary in @(Get-ChildItem -LiteralPath $bin -File -Filter '*.exe~')) {
        Remove-Item -LiteralPath $temporary.FullName -Force
    }
    $binaryNames = @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionAgentCli.exe')
    $unexpected = @(Get-ChildItem -LiteralPath $bin -File | Where-Object { $_.Name -notin $binaryNames })
    if ($unexpected.Count -ne 0) { throw "Unexpected build artifact: $($unexpected[0].FullName)" }
    $files = [ordered]@{}
    foreach ($name in $binaryNames) {
        $path = Join-Path $bin $name
        $item = Get-Item -LiteralPath $path -Force
        $files[$name] = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            size = $item.Length
        }
    }
    $manifest = [ordered]@{
        format_version = 1
        built_at_utc = [DateTime]::UtcNow.ToString('o')
        go_version = (& $GoExe version | Out-String).Trim()
        aionui_version = $version
        aioncore_version = $coreVersion
        aionui_archive = $archive
        aionui_archive_sha256 = $actualHash
        aionui_packed_directory = $packedDirectory
        aionui_packed_files = $packedFiles
        binaries = $files
    }
    $manifestJson = ($manifest | ConvertTo-Json -Depth 5).Replace("`r`n", "`n") + "`n"
    [IO.File]::WriteAllText((Join-Path $projectRoot 'artifacts\build-manifest.json'), $manifestJson, [Text.UTF8Encoding]::new($false))
}
finally {
    Pop-Location
}

Write-Host "Build complete: AionUi $version / AionCore $coreVersion"
Write-Host "Packed directory: $packedDirectory"

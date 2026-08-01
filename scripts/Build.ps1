[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9._-]{2,79}$')][string]$ReleaseId,
    [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
    [string[]]$IncludedComponents,
    [string]$AionUiSource = (Join-Path $PSScriptRoot '..\..\AionUi'),
    [string]$GoExe = 'go',
    [string]$UpgradeBaselinePath,
    [switch]$FreshInstall,
    [switch]$SkipAionUiPack,
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\artifacts\releases')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

if ($FreshInstall -and -not [string]::IsNullOrWhiteSpace($UpgradeBaselinePath)) {
    throw 'FreshInstall and UpgradeBaselinePath are mutually exclusive.'
}
if (-not $FreshInstall -and [string]::IsNullOrWhiteSpace($UpgradeBaselinePath)) {
    throw 'Upgrade builds require a production preflight baseline. Use New-UpgradeBaseline.ps1, or pass FreshInstall for a new machine.'
}
if ($null -eq $IncludedComponents -or $IncludedComponents.Count -eq 0) {
    $IncludedComponents = switch ($ReleaseScope) {
        'web-only' { @('web') }
        'runtime-only' { @('AionAgentCli.exe') }
        'combined' { @('web', 'AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe') }
        default { throw 'backend-only builds require an explicit IncludedComponents list.' }
    }
}
$IncludedComponents = @($IncludedComponents | ForEach-Object { [string]$_ })
Assert-ReleaseScopeContract -ReleaseScope $ReleaseScope -IncludedComponents $IncludedComponents
$declaredBinaryComponents = @($IncludedComponents | Where-Object { $_ -cne 'web' })
if ($declaredBinaryComponents.Count -ne 0) {
    $goCommand = Get-Command $GoExe -ErrorAction Stop
    $GoExe = $goCommand.Source
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tarExe = if ($env:OS -eq 'Windows_NT') {
    Join-Path $env:SystemRoot 'System32\tar.exe'
} else {
    (Get-Command tar -ErrorAction Stop).Source
}
if (-not (Test-Path -LiteralPath $tarExe -PathType Leaf)) { throw "Native tar executable is missing: $tarExe" }
$resolvedOutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $resolvedOutputRoot -Force | Out-Null
$outputRootItem = Get-Item -LiteralPath $resolvedOutputRoot -Force
if (($outputRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Release output root must not be a reparse point: $resolvedOutputRoot"
}
$releaseRoot = Join-Path $resolvedOutputRoot $ReleaseId
if (Test-Path -LiteralPath $releaseRoot) { throw "Immutable release output already exists: $releaseRoot" }
$stagingRoot = Join-Path $resolvedOutputRoot ('.staging-' + $ReleaseId + '-' + [Guid]::NewGuid().ToString('N'))
$outputPrefix = $resolvedOutputRoot.TrimEnd('\') + '\'
if (-not $stagingRoot.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($stagingRoot)).StartsWith('.staging-' + $ReleaseId + '-', [StringComparison]::Ordinal)) {
    throw 'Computed release staging path escaped the output root.'
}
New-Item -ItemType Directory -Path $stagingRoot -ErrorAction Stop | Out-Null
$published = $false
try {

$baseline = $null
$baselineCapturedAtUtc = $null
if (-not $FreshInstall) {
    if (-not (Test-Path -LiteralPath $UpgradeBaselinePath -PathType Leaf)) { throw "Upgrade baseline is missing: $UpgradeBaselinePath" }
    $baseline = Get-Content -LiteralPath $UpgradeBaselinePath -Raw | ConvertFrom-Json
    if ($baseline.format_version -ne 1 -or $null -eq $baseline.components) { throw 'Upgrade baseline format is invalid.' }
    $capturedValue = $baseline.captured_at_utc
    if ($capturedValue -is [DateTime]) {
        $baselineCapturedAtUtc = $capturedValue.ToUniversalTime().ToString('o')
    } else {
        $parsedCapturedAt = [DateTimeOffset]::ParseExact(
            [string]$capturedValue,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $baselineCapturedAtUtc = $parsedCapturedAt.UtcDateTime.ToString('o')
    }
}

$webManifest = $null
if ('web' -cin $IncludedComponents) {
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
            & bun run package
            if ($LASTEXITCODE -ne 0) { throw "AionUi renderer build failed with exit code $LASTEXITCODE" }
            $env:PACK_PLATFORM = 'win32'
            $env:PACK_ARCH = 'x64'
            & node 'scripts\pack-web-cli.js'
            if ($LASTEXITCODE -ne 0) { throw "AionUi pack-web-cli.js failed with exit code $LASTEXITCODE" }
        } finally {
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
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required Web build output is missing: $path" }
    }

    $managedResourcesRoot = Join-Path $packedDirectory 'bundled-aioncore\win32-x64\managed-resources'
    & (Join-Path $PSScriptRoot 'Patch-CodexAcpSessionFork.ps1') -ManagedResourcesRoot $managedResourcesRoot
    & $tarExe -czf $archive -C (Join-Path $dist 'staging') 'aionui-web'
    if ($LASTEXITCODE -ne 0) { throw "Repack patched AionUi archive failed with exit code $LASTEXITCODE" }
    $actualArchiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        "$archive.sha256",
        "$actualArchiveHash  $([IO.Path]::GetFileName($archive))`n",
        [Text.UTF8Encoding]::new($false)
    )
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
    $webManifest = [ordered]@{
        aionui_version = $version
        aioncore_version = $coreVersion
        archive = $archive
        archive_sha256 = $actualArchiveHash
        packed_directory = $packedDirectory
        packed_files = $packedFiles
    }
}

$binaryComponents = $declaredBinaryComponents
$binaryManifest = [ordered]@{}
$bin = $null
if ($binaryComponents.Count -ne 0) {
    $bin = Join-Path $stagingRoot 'bin'
    New-Item -ItemType Directory -Path $bin -ErrorAction Stop | Out-Null
    $buildTargets = [ordered]@{
        'AionUiPortal.exe' = './cmd/aionui-portal'
        'AionUiUserHost.exe' = './cmd/aionui-userhost'
        'portal.exe' = './cmd/portal'
        'AionAgentCli.exe' = './cmd/aion-agent-cli'
    }
    $env:GOTOOLCHAIN = 'local'
    $env:CGO_ENABLED = '0'
    Push-Location $projectRoot
    try {
        & $GoExe test -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw 'Go behavior tests failed.' }
        & $GoExe vet -unsafeptr=false ./...
        if ($LASTEXITCODE -ne 0) { throw 'Go vet failed.' }
        foreach ($name in $binaryComponents) {
            & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $bin $name) $buildTargets[$name]
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $name" }
        }
    } finally {
        Pop-Location
    }
    foreach ($name in $binaryComponents) {
        $path = Join-Path $bin $name
        $item = Get-Item -LiteralPath $path -Force
        $binaryManifest[$name] = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            size = $item.Length
        }
    }
}

$upgradeContract = $null
if (-not $FreshInstall) {
    $expected = [ordered]@{}
    foreach ($component in $IncludedComponents) {
        $entry = $baseline.components.PSObject.Properties[$component].Value
        if ($null -eq $entry) { throw "Production baseline is missing component: $component" }
        $hash = ([string]$entry.sha256).ToLowerInvariant()
        Assert-Sha256String -Value $hash -Description "$component production baseline"
        $expected[$component] = $hash
    }
    $upgradeContract = [ordered]@{
        baseline_id = [string]$baseline.baseline_id
        captured_at_utc = $baselineCapturedAtUtc
        expected_installed_sha256 = $expected
    }
}

$goVersion = ''
if ($binaryComponents.Count -ne 0) { $goVersion = (& $GoExe version | Out-String).Trim() }
$manifest = [ordered]@{
    format_version = 2
    release_id = $ReleaseId
    release_scope = $ReleaseScope
    included_components = $IncludedComponents
    built_at_utc = [DateTime]::UtcNow.ToString('o')
    go_version = $goVersion
    web = $webManifest
    binaries = $binaryManifest
    upgrade_contract = $upgradeContract
}
$manifestPath = Join-Path $stagingRoot 'build-manifest.json'
$manifestJson = ($manifest | ConvertTo-Json -Depth 8).Replace("`r`n", "`n") + "`n"
[IO.File]::WriteAllText($manifestPath, $manifestJson, [Text.UTF8Encoding]::new($false))

$testArguments = @{
    BuildManifestPath = $manifestPath
    ReleaseScope = $ReleaseScope
}
if ($null -ne $bin) { $testArguments.BinariesDirectory = $bin }
if ($null -ne $webManifest) {
    $testArguments.AionUiPackedDirectory = $webManifest.packed_directory
    $testArguments.AionUiVersion = $webManifest.aionui_version
    $testArguments.AionCoreVersion = $webManifest.aioncore_version
}
if (-not $FreshInstall) { $testArguments.RequireUpgradeContract = $true }
& (Join-Path $PSScriptRoot 'Test-BuildArtifacts.ps1') @testArguments

Move-Item -LiteralPath $stagingRoot -Destination $releaseRoot -ErrorAction Stop
$published = $true
$manifestPath = Join-Path $releaseRoot 'build-manifest.json'
Write-Host "Immutable $ReleaseScope release built at $releaseRoot"
Write-Host "Manifest: $manifestPath"
} finally {
    if (-not $published -and (Test-Path -LiteralPath $stagingRoot)) {
        $resolvedStaging = [IO.Path]::GetFullPath($stagingRoot)
        if (-not $resolvedStaging.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($resolvedStaging)).StartsWith('.staging-' + $ReleaseId + '-', [StringComparison]::Ordinal)) {
            throw 'Refusing to clean an unexpected release staging path.'
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}

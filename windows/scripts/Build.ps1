[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9._-]{2,79}$')][string]$ReleaseId,
    [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
    [string[]]$IncludedComponents,
    [string]$AionUiSource = (Join-Path $PSScriptRoot '..\..\AionUi'),
    [string]$AionCoreSource = (Join-Path $PSScriptRoot '..\.tools\AionCore-src'),
    [string]$AionCorePackagedDirectory,
    [string]$AionCoreBinarySha256,
    [string]$AionCoreBundleManifestSha256,
    [string]$GoExe = 'go',
    [string]$UpgradeBaselinePath,
    [switch]$FreshInstall,
    [switch]$SkipAionUiPack,
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\artifacts\releases')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

if ($SkipAionUiPack) {
    throw 'SkipAionUiPack is not permitted for immutable releases because it cannot prove renderer freshness.'
}

function Get-CleanGitProvenance {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $commit = (& git -C $resolved rev-parse HEAD 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') {
        throw "$Label source is not a readable Git checkout."
    }
    $tree = (& git -C $resolved rev-parse 'HEAD^{tree}' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $tree -cnotmatch '^[0-9a-f]{40}$') {
        throw "$Label source tree could not be resolved."
    }
    $dirty = @(& git -C $resolved status --porcelain=v1 --untracked-files=all 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "$Label source status could not be read." }
    if ($dirty.Count -ne 0) {
        throw "$Label source must be clean before an immutable release; first change: $($dirty[0])"
    }
    [ordered]@{ commit = $commit; tree = $tree; dirty = $false }
}

function Assert-GitProvenanceUnchanged {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Expected, [Parameter(Mandatory)][string]$Label)
    $actual = Get-CleanGitProvenance -Path $Path -Label $Label
    if ($actual.commit -cne $Expected.commit -or $actual.tree -cne $Expected.tree) {
        throw "$Label source changed during the build."
    }
}

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
        'combined' { @('web', 'AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionKimiDatasourceBroker.exe') }
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
$sourceProvenance = [ordered]@{
    workagent2 = Get-CleanGitProvenance -Path $projectRoot -Label 'WorkAgent2 source and release tooling'
    release_tooling = [ordered]@{
        build_ps1_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        test_build_artifacts_ps1_sha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Test-BuildArtifacts.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
        patch_codex_acp_ps1_sha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Patch-CodexAcpSessionFork.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
if ('web' -cin $IncludedComponents) {
    $aionRoot = (Resolve-Path $AionUiSource).Path
    if ([string]::IsNullOrWhiteSpace($AionCorePackagedDirectory) -or [string]::IsNullOrWhiteSpace($AionCoreBinarySha256) -or
        [string]::IsNullOrWhiteSpace($AionCoreBundleManifestSha256)) {
        throw 'Web releases require the packaged Core directory plus binary and bundle-manifest SHA-256 values from the clean recorded Core build.'
    }
    Assert-Sha256String -Value $AionCoreBinarySha256 -Description 'recorded AionCore binary'
    Assert-Sha256String -Value $AionCoreBundleManifestSha256 -Description 'recorded AionCore bundle manifest'
    $resolvedCoreBundle = (Resolve-Path -LiteralPath $AionCorePackagedDirectory).Path
    $coreBundleBinary = Join-Path $resolvedCoreBundle 'aioncore.exe'
    $coreBundleManifestPath = Join-Path $resolvedCoreBundle 'manifest.json'
    if (-not (Test-Path -LiteralPath $coreBundleBinary -PathType Leaf)) { throw "Recorded AionCore bundle is missing: $coreBundleBinary" }
    if (-not (Test-Path -LiteralPath $coreBundleManifestPath -PathType Leaf)) { throw "Recorded AionCore bundle manifest is missing: $coreBundleManifestPath" }
    if ((Get-FileHash -LiteralPath $coreBundleManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $AionCoreBundleManifestSha256.ToLowerInvariant()) {
        throw 'Recorded AionCore bundle manifest hash does not match AionCoreBundleManifestSha256.'
    }
    $inputCoreHash = (Get-FileHash -LiteralPath $coreBundleBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($inputCoreHash -cne $AionCoreBinarySha256.ToLowerInvariant()) { throw 'Recorded AionCore bundle binary hash does not match AionCoreBinarySha256.' }
    $sourceProvenance['aionui'] = Get-CleanGitProvenance -Path $aionRoot -Label 'AionUi'
    $sourceProvenance['aioncore'] = Get-CleanGitProvenance -Path $AionCoreSource -Label 'AionCore'
    $coreBundleManifest = Get-Content -LiteralPath $coreBundleManifestPath -Raw | ConvertFrom-Json
    if ($coreBundleManifest.format_version -ne 2 -or [string]$coreBundleManifest.source.commit -cne $sourceProvenance['aioncore'].commit -or
        [string]$coreBundleManifest.source.tree -cne $sourceProvenance['aioncore'].tree -or [bool]$coreBundleManifest.source.dirty -or
        [string]$coreBundleManifest.aioncore_sha256 -cne $inputCoreHash) {
        throw 'AionCore bundle manifest does not bind the binary to the selected clean Core commit/tree.'
    }
    $sourceProvenance['aioncore']['binary_sha256'] = $inputCoreHash
    $sourceProvenance['aioncore']['bundle_manifest_sha256'] = $AionCoreBundleManifestSha256.ToLowerInvariant()
    $sourceProvenance['aioncore']['managed_resources_aggregate_sha256'] = [string]$coreBundleManifest.managed_resources_aggregate_sha256
    $package = Get-Content -Raw (Join-Path $aionRoot 'package.json') | ConvertFrom-Json
    $version = [string]$package.version
    $coreVersion = [string]$package.aioncoreVersion
    $dist = Join-Path $aionRoot 'dist-web-cli'
    $archive = Join-Path $dist "aionui-web-$version-win-x86_64.tar.gz"
    $packedDirectory = Join-Path $dist 'staging\aionui-web'

    if (-not $SkipAionUiPack) {
        $previousPackagedCore = $env:AIONUI_PACKAGED_AIONCORE_DIRECTORY
        $env:AIONUI_PACKAGED_AIONCORE_DIRECTORY = $resolvedCoreBundle
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
            $env:AIONUI_PACKAGED_AIONCORE_DIRECTORY = $previousPackagedCore
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
    $packedCoreHash = (Get-FileHash -LiteralPath (Join-Path $packedDirectory 'bundled-aioncore\win32-x64\aioncore.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($packedCoreHash -cne $inputCoreHash) { throw 'Packed AionCore binary differs from the recorded clean Core build.' }
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
        'AionKimiDatasourceBroker.exe' = './cmd/kimi-datasource-broker'
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
        if ($hash -ceq 'absent' -and $component -ceq 'AionKimiDatasourceBroker.exe') {
            $expected[$component] = $hash
            continue
        }
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
Assert-GitProvenanceUnchanged -Path $projectRoot -Expected $sourceProvenance.workagent2 -Label 'WorkAgent2 source and release tooling'
if ('web' -cin $IncludedComponents) {
    Assert-GitProvenanceUnchanged -Path $aionRoot -Expected $sourceProvenance.aionui -Label 'AionUi'
    Assert-GitProvenanceUnchanged -Path $AionCoreSource -Expected $sourceProvenance.aioncore -Label 'AionCore'
}
$manifest = [ordered]@{
    format_version = 2
    release_id = $ReleaseId
    release_scope = $ReleaseScope
    included_components = $IncludedComponents
    built_at_utc = [DateTime]::UtcNow.ToString('o')
    go_version = $goVersion
    source_provenance = $sourceProvenance
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

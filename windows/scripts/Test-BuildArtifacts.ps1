[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildManifestPath,
    [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
    [string]$AionUiPackedDirectory,
    [string]$AionUiVersion,
    [string]$AionCoreVersion,
    [string]$BinariesDirectory,
    [switch]$RequireUpgradeContract
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

function Test-FileContainsAsciiMarker {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Marker)
    $needle = [Text.Encoding]::ASCII.GetBytes($Marker)
    if ($needle.Length -eq 0) { return $true }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $buffer = [byte[]]::new(1024 * 1024)
        $tail = [byte[]]::new(0)
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $combined = [byte[]]::new($tail.Length + $count)
            if ($tail.Length -gt 0) { [Array]::Copy($tail, 0, $combined, 0, $tail.Length) }
            [Array]::Copy($buffer, 0, $combined, $tail.Length, $count)
            for ($start = 0; $start -le $combined.Length - $needle.Length; $start++) {
                $matches = $true
                for ($offset = 0; $offset -lt $needle.Length; $offset++) {
                    if ($combined[$start + $offset] -ne $needle[$offset]) {
                        $matches = $false
                        break
                    }
                }
                if ($matches) { return $true }
            }
            $tailLength = [Math]::Min($needle.Length - 1, $combined.Length)
            $tail = [byte[]]::new($tailLength)
            if ($tailLength -gt 0) {
                [Array]::Copy($combined, $combined.Length - $tailLength, $tail, 0, $tailLength)
            }
        }
        return $false
    } finally {
        $stream.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $BuildManifestPath -PathType Leaf)) {
    throw "Required build manifest is missing: $BuildManifestPath"
}
$manifestRaw = Get-Content -LiteralPath $BuildManifestPath -Raw
$manifest = $manifestRaw | ConvertFrom-Json
if ($manifest.format_version -ne 2) { throw 'Only component-scoped build manifest format 2 is accepted.' }
if ([string]$manifest.release_scope -cne $ReleaseScope) {
    throw "Build manifest release_scope '$($manifest.release_scope)' does not match requested scope '$ReleaseScope'."
}
if ([string]::IsNullOrWhiteSpace([string]$manifest.release_id)) { throw 'Build manifest release_id is required.' }
$components = @($manifest.included_components | ForEach-Object { [string]$_ })
Assert-ReleaseScopeContract -ReleaseScope $ReleaseScope -IncludedComponents $components

$expectedInstalled = $null
if ($null -ne $manifest.upgrade_contract) {
    $expectedInstalled = $manifest.upgrade_contract.expected_installed_sha256
}
if ($RequireUpgradeContract -and $null -eq $expectedInstalled) {
    throw 'Upgrade manifests require a production preflight baseline contract.'
}

$binaryComponents = @($components | Where-Object { $_ -cne 'web' })
if ($binaryComponents.Count -ne 0) {
    if ([string]::IsNullOrWhiteSpace($BinariesDirectory) -or -not (Test-Path -LiteralPath $BinariesDirectory -PathType Container)) {
        throw 'A binaries directory is required for the declared executable components.'
    }
    $actualBinaryNames = @(Get-ChildItem -LiteralPath $BinariesDirectory -Force -File | ForEach-Object { $_.Name })
    $unexpectedBinaryNames = @($actualBinaryNames | Where-Object { $_ -cnotin $binaryComponents })
    $missingBinaryNames = @($binaryComponents | Where-Object { $_ -cnotin $actualBinaryNames })
    if ($unexpectedBinaryNames.Count -ne 0 -or $missingBinaryNames.Count -ne 0 -or $actualBinaryNames.Count -ne $binaryComponents.Count) {
        throw "Binaries directory must contain exactly the declared executable components. Declared: $($binaryComponents -join ', '); found: $($actualBinaryNames -join ', ')"
    }
    foreach ($name in $binaryComponents) {
        $path = Join-Path $BinariesDirectory $name
        $entry = $manifest.binaries.PSObject.Properties[$name].Value
        if ($null -eq $entry) { throw "Build manifest is missing binary $name" }
        $item = Get-Item -LiteralPath $path -Force
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Sha256String -Value ([string]$entry.sha256) -Description "$name target hash"
        if ($item.Length -ne [int64]$entry.size -or $hash -cne [string]$entry.sha256) {
            throw "Built binary failed size/SHA-256 verification: $name"
        }
        if ($name -ceq 'AionUiPortal.exe' -and -not (Test-FileContainsAsciiMarker -Path $path -Marker '/api/portal/me/restart-service')) {
            throw 'AionUiPortal.exe is missing the per-user restart-service route marker.'
        }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($BinariesDirectory)) {
    throw 'BinariesDirectory must be omitted when the release declares no executable component.'
}

foreach ($sourceName in @('workagent2')) {
    $source = $manifest.source_provenance.PSObject.Properties[$sourceName].Value
    if ($null -eq $source -or [string]$source.commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$source.tree -cnotmatch '^[0-9a-f]{40}$' -or [bool]$source.dirty) {
        throw "Build manifest is missing clean $sourceName source provenance."
    }
}
foreach ($hashName in @('build_ps1_sha256', 'test_build_artifacts_ps1_sha256', 'patch_codex_acp_ps1_sha256')) {
    Assert-Sha256String -Value ([string]$manifest.source_provenance.release_tooling.PSObject.Properties[$hashName].Value) `
        -Description "$hashName release-tooling hash"
}

if ('web' -cin $components) {
    foreach ($sourceName in @('aionui', 'aioncore')) {
        $source = $manifest.source_provenance.PSObject.Properties[$sourceName].Value
        if ($null -eq $source -or [string]$source.commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$source.tree -cnotmatch '^[0-9a-f]{40}$' -or [bool]$source.dirty) {
            throw "Build manifest is missing clean $sourceName source provenance."
        }
    }
    $archivePath = [string]$manifest.web.archive
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) { throw "Packed AionUi archive is missing: $archivePath" }
    Assert-Sha256String -Value ([string]$manifest.web.archive_sha256) -Description 'AionUi archive hash'
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($archiveHash -cne [string]$manifest.web.archive_sha256) {
        throw 'Packed AionUi archive failed SHA-256 verification.'
    }
    foreach ($value in @($AionUiPackedDirectory, $AionUiVersion, $AionCoreVersion)) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'Web releases require AionUiPackedDirectory, AionUiVersion, and AionCoreVersion.' }
    }
    foreach ($path in @(
        (Join-Path $AionUiPackedDirectory 'aionui-web.exe'),
        (Join-Path $AionUiPackedDirectory 'package.json'),
        (Join-Path $AionUiPackedDirectory 'static\index.html'),
        (Join-Path $AionUiPackedDirectory 'bundled-aioncore\win32-x64\aioncore.exe')
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required Web artifact is missing: $path" }
    }
    if ([string]$manifest.web.aionui_version -cne $AionUiVersion -or [string]$manifest.web.aioncore_version -cne $AionCoreVersion) {
        throw 'Build manifest AionUi/AionCore version does not match the requested deployment.'
    }
    $reparsePoints = @(Get-ChildItem -LiteralPath $AionUiPackedDirectory -Force -Recurse | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($reparsePoints.Count -ne 0) { throw "Packed AionUi contains a reparse point: $($reparsePoints[0].FullName)" }
    $files = @(Get-ChildItem -LiteralPath $AionUiPackedDirectory -Force -File -Recurse)
    $expectedFiles = @($manifest.web.packed_files.PSObject.Properties)
    if ($expectedFiles.Count -eq 0 -or $files.Count -ne $expectedFiles.Count) {
        throw "Packed AionUi file count $($files.Count) does not match build manifest count $($expectedFiles.Count)."
    }
    $root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AionUiPackedDirectory).Path).TrimEnd('\') + '\'
    foreach ($file in $files) {
        $full = [IO.Path]::GetFullPath($file.FullName)
        if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "Packed file escaped its root: $full" }
        $relative = $full.Substring($root.Length).Replace('\', '/')
        $entry = $manifest.web.packed_files.PSObject.Properties[$relative].Value
        if ($null -eq $entry) { throw "Packed file is absent from build manifest: $relative" }
        $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($file.Length -ne [int64]$entry.size -or $hash -cne [string]$entry.sha256) {
            throw "Packed AionUi file failed size/SHA-256 verification: $relative"
        }
    }
    # These literals are release invariants for the WorkAgent2 Web client. Checking
    # the immutable bundle prevents an older AionUi worktree from silently
    # reintroducing memory-heavy downloads or dropping tenant-facing controls.
    $requiredWebFeatureMarkers = [ordered]@{
        '/api/fs/download'                    = 'native streaming file downloads'
        '/api/portal/me/restart-service'      = 'per-user service restart'
        '/api/portal/shared-invites'          = 'shared project invitations'
        'COLLABORATION_DISABLED'              = 'private-history collaboration fallback'
        'OFFICE_PREVIEW_RESOURCE_LIMIT'       = 'Office preview resource-limit errors'
        'USER_AGENT_RESOURCE_EXHAUSTED'       = 'Agent resource-exhaustion errors'
    }
    $webJavaScriptFiles = @($files | Where-Object {
        $_.Extension -ceq '.js' -and $_.FullName.StartsWith((Join-Path $AionUiPackedDirectory 'static'), [StringComparison]::OrdinalIgnoreCase)
    })
    foreach ($marker in $requiredWebFeatureMarkers.GetEnumerator()) {
        $found = $false
        foreach ($javaScriptFile in $webJavaScriptFiles) {
            if (Select-String -LiteralPath $javaScriptFile.FullName -SimpleMatch -Quiet -Pattern $marker.Key) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            throw "Packed AionUi is missing required feature '$($marker.Value)' (marker: $($marker.Key)). Refusing an older/regressed Web source."
        }
    }
    $webVersion = (& (Join-Path $AionUiPackedDirectory 'aionui-web.exe') version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $webVersion -cne $AionUiVersion) { throw "Packed aionui-web reports unexpected version: $webVersion" }
    $coreVersionOutput = (& (Join-Path $AionUiPackedDirectory 'bundled-aioncore\win32-x64\aioncore.exe') --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $coreVersionOutput -cne ('aioncore ' + $AionCoreVersion.TrimStart('v'))) {
        throw "Packed aioncore reports unexpected version: $coreVersionOutput"
    }
    $packedCorePath = Join-Path $AionUiPackedDirectory 'bundled-aioncore\win32-x64\aioncore.exe'
    Assert-Sha256String -Value ([string]$manifest.source_provenance.aioncore.binary_sha256) -Description 'recorded AionCore binary'
    Assert-Sha256String -Value ([string]$manifest.source_provenance.aioncore.bundle_manifest_sha256) -Description 'recorded AionCore bundle manifest'
    Assert-Sha256String -Value ([string]$manifest.source_provenance.aioncore.managed_resources_aggregate_sha256) -Description 'recorded AionCore managed resources aggregate'
    $packedCoreHash = (Get-FileHash -LiteralPath $packedCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($packedCoreHash -cne [string]$manifest.source_provenance.aioncore.binary_sha256) {
        throw 'Packed aioncore does not match the clean Core build recorded in source provenance.'
    }
    foreach ($coreMarker in @('x-aionui-streaming-download', 'OFFICE_PREVIEW_RESOURCE_LIMIT', 'USER_AGENT_RESOURCE_EXHAUSTED')) {
        if (-not (Test-FileContainsAsciiMarker -Path $packedCorePath -Marker $coreMarker)) {
            throw "Packed aioncore is missing required runtime marker: $coreMarker"
        }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($AionUiPackedDirectory) -or -not [string]::IsNullOrWhiteSpace($AionUiVersion) -or
    -not [string]::IsNullOrWhiteSpace($AionCoreVersion)) {
    throw 'Web artifact arguments must be omitted when web is outside the release scope.'
}

if ($RequireUpgradeContract) {
    if ($manifestRaw -cnotmatch '"captured_at_utc"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"') {
        throw 'Upgrade manifest captured_at_utc must preserve its UTC ISO-8601 lexical form.'
    }
    foreach ($component in $components) {
        $baseline = [string]$expectedInstalled.PSObject.Properties[$component].Value
        if ($baseline -ceq 'absent' -and $component -ceq 'AionKimiDatasourceBroker.exe') { continue }
        Assert-Sha256String -Value $baseline -Description "$component production baseline"
    }
}

Write-Host "Verified component-scoped $ReleaseScope release '$($manifest.release_id)' for: $($components -join ', ')."

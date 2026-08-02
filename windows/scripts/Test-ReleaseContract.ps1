[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Expected error matching '$Pattern', got: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected an error matching '$Pattern'."
}

$a = 'a' * 64
$b = 'b' * 64
$c = 'c' * 64

Assert-ReleaseScopeContract -ReleaseScope 'web-only' -IncludedComponents @('web')
Assert-ReleaseScopeContract -ReleaseScope 'runtime-only' -IncludedComponents @('AionAgentCli.exe')
Assert-ReleaseScopeContract -ReleaseScope 'backend-only' -IncludedComponents @('AionUiUserHost.exe')
Assert-ReleaseScopeContract -ReleaseScope 'combined' -IncludedComponents @('web', 'AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe')
Assert-Throws { Assert-ReleaseScopeContract -ReleaseScope 'web-only' -IncludedComponents @('web', 'AionUiUserHost.exe') } 'exactly the web component'
Assert-Throws { Assert-ReleaseScopeContract -ReleaseScope 'backend-only' -IncludedComponents @('AionAgentCli.exe') } 'Portal backend executables'

if (-not (Test-UpgradeComponentTransition -Component 'AionUiUserHost.exe' -CurrentSha256 $a -TargetSha256 $b -ExpectedInstalledSha256 $a)) {
    throw 'A baseline-to-target transition was incorrectly treated as a no-op.'
}
if (Test-UpgradeComponentTransition -Component 'AionUiUserHost.exe' -CurrentSha256 $b -TargetSha256 $b -ExpectedInstalledSha256 $a) {
    throw 'An already-installed target was incorrectly treated as needing replacement.'
}
Assert-Throws {
    Test-UpgradeComponentTransition -Component 'AionUiUserHost.exe' -CurrentSha256 $c -TargetSha256 $b -ExpectedInstalledSha256 $a
} 'Stale release refused'

Assert-PreservedComponentHashes -Before ([ordered]@{ portal = $a; web = $b }) -After ([ordered]@{ portal = $a; web = $b })
Assert-Throws {
    Assert-PreservedComponentHashes -Before ([ordered]@{ portal = $a }) -After ([ordered]@{ portal = $c })
} 'outside its declared scope'

$agentCliPublisher = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Publish-SharedAgentClis.ps1') -Raw
if ($agentCliPublisher -notmatch 'Stop-PortalUserHosts\s+& \$launcher release activate') {
    throw 'Agent CLI publisher must stop every Portal UserHost immediately before activating current.json.'
}

$upgrade = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Upgrade.ps1') -Raw
foreach ($required in @(
    "if (`$updatesUserHostBinary)",
    "Wait-AllInstancesIdle.ps1",
    "if (-not `$updatesUserHostBinary) { `$releaseInstallArguments += '--allow-running' }",
    "if (`$portalServiceStoppedForUpgrade)"
)) {
    if (-not $upgrade.Contains($required)) { throw "Upgrade script is missing the non-interrupting cutover contract: $required" }
}
$stopAllInstancesCalls = ([regex]::Matches($upgrade, [regex]::Escape("'Stop-AllInstances.ps1'"))).Count
if ($stopAllInstancesCalls -ne 1) {
    throw "Upgrade script must stop all instances only in the UserHost-binary drain path; calls=$stopAllInstancesCalls."
}

Write-Host 'Release scope, optimistic baseline, idempotence, preserved-component, CLI cutover, and non-interrupting Web cutover tests passed.'

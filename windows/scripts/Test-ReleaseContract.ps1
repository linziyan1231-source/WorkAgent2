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
Assert-ReleaseScopeContract -ReleaseScope 'combined' -IncludedComponents @('web', 'AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionKimiDatasourceBroker.exe')
Assert-Throws { Assert-ReleaseScopeContract -ReleaseScope 'web-only' -IncludedComponents @('web', 'AionUiUserHost.exe') } 'exactly the web component'
Assert-Throws { Assert-ReleaseScopeContract -ReleaseScope 'backend-only' -IncludedComponents @('AionAgentCli.exe') } 'Portal backend executables'

$refreshMessage = '系统正在升级，页面可能需要刷新，但正在进行的任务不会中断'
$interruptionMessage = '系统正在升级，正在进行的任务可能会中断'
foreach ($safeRelease in @(
    @{ Scope = 'web-only'; Components = @('web') },
    @{ Scope = 'backend-only'; Components = @('AionUiPortal.exe') },
    @{ Scope = 'backend-only'; Components = @('portal.exe') },
    @{ Scope = 'combined'; Components = @('web', 'AionUiPortal.exe', 'portal.exe') }
)) {
    if ((Get-UpgradeInterruptionClass -ReleaseScope $safeRelease.Scope -IncludedComponents $safeRelease.Components) -cne 'refresh-only') {
        throw "Safe release was not classified as refresh-only: $($safeRelease.Components -join ',')"
    }
    if ((Get-UpgradeNotificationMessage -ReleaseScope $safeRelease.Scope -IncludedComponents $safeRelease.Components) -cne $refreshMessage) {
        throw "Safe release received the wrong notification: $($safeRelease.Components -join ',')"
    }
}
foreach ($interruptingRelease in @(
    @{ Scope = 'runtime-only'; Components = @('AionAgentCli.exe') },
    @{ Scope = 'backend-only'; Components = @('AionUiUserHost.exe') },
    @{ Scope = 'combined'; Components = @('web', 'AionUiUserHost.exe') }
)) {
    if ((Get-UpgradeInterruptionClass -ReleaseScope $interruptingRelease.Scope -IncludedComponents $interruptingRelease.Components) -cne 'task-interruption-possible') {
        throw "Interrupting release was not classified correctly: $($interruptingRelease.Components -join ',')"
    }
    if ((Get-UpgradeNotificationMessage -ReleaseScope $interruptingRelease.Scope -IncludedComponents $interruptingRelease.Components) -cne $interruptionMessage) {
        throw "Interrupting release received the wrong notification: $($interruptingRelease.Components -join ',')"
    }
}

$notificationNow = [DateTime]::Parse('2026-08-07T08:02:00Z').ToUniversalTime()
$published = '{"notifications":[{"id":"upgrade-safe-1","message":"系统正在升级，页面可能需要刷新，但正在进行的任务不会中断","published_at":"2026-08-07T08:00:00Z"}]}' | ConvertFrom-Json
Assert-PublishedUpgradeNotification -Payload $published -ExpectedId 'upgrade-safe-1' -ExpectedMessage $refreshMessage -NowUtc $notificationNow
Assert-Throws {
    Assert-PublishedUpgradeNotification -Payload $published -ExpectedId 'upgrade-safe-1' -ExpectedMessage $interruptionMessage -NowUtc $notificationNow
} 'wrong interruption message'
$tooRecent = '{"notifications":[{"id":"upgrade-safe-1","message":"系统正在升级，页面可能需要刷新，但正在进行的任务不会中断","published_at":"2026-08-07T08:01:30Z"}]}' | ConvertFrom-Json
Assert-Throws {
    Assert-PublishedUpgradeNotification -Payload $tooRecent -ExpectedId 'upgrade-safe-1' -ExpectedMessage $refreshMessage -NowUtc $notificationNow
} 'at least 60 seconds'
$missingPublishedAt = '{"notifications":[{"id":"upgrade-safe-1","message":"系统正在升级，页面可能需要刷新，但正在进行的任务不会中断"}]}' | ConvertFrom-Json
Assert-Throws {
    Assert-PublishedUpgradeNotification -Payload $missingPublishedAt -ExpectedId 'upgrade-safe-1' -ExpectedMessage $refreshMessage -NowUtc $notificationNow
} 'missing published_at'
$duplicate = '{"notifications":[{"id":"upgrade-safe-1","message":"系统正在升级，页面可能需要刷新，但正在进行的任务不会中断","published_at":"2026-08-07T08:00:00Z"},{"id":"upgrade-safe-1","message":"系统正在升级，页面可能需要刷新，但正在进行的任务不会中断","published_at":"2026-08-07T08:00:00Z"}]}' | ConvertFrom-Json
Assert-Throws {
    Assert-PublishedUpgradeNotification -Payload $duplicate -ExpectedId 'upgrade-safe-1' -ExpectedMessage $refreshMessage -NowUtc $notificationNow
} 'exactly one notification'

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

$install = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install.ps1') -Raw
$upgrade = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Upgrade.ps1') -Raw
foreach ($requiredNotificationScript in @('ReleaseContract.ps1', 'Publish-UpgradeNotification.ps1')) {
    if (-not $install.Contains("'$requiredNotificationScript'")) {
        throw "Install script does not preserve the notification publisher dependency: $requiredNotificationScript"
    }
    if (-not $upgrade.Contains("'$requiredNotificationScript'")) {
        throw "Upgrade script does not preserve the notification publisher dependency: $requiredNotificationScript"
    }
}

foreach ($required in @(
    "if (`$updatesUserHostBinary)",
    "Wait-AllInstancesIdle.ps1",
    "if (-not `$updatesUserHostBinary) { `$releaseInstallArguments += '--allow-running' }",
    "if (`$portalServiceStoppedForUpgrade -or (Get-Service -Name AionUiPortal).Status -eq 'Stopped')",
    "Get-UpgradeNotificationMessage",
    "Assert-PublishedUpgradeNotification"
)) {
    if (-not $upgrade.Contains($required)) { throw "Upgrade script is missing the non-interrupting cutover contract: $required" }
}
if ($upgrade -notmatch "portalServiceStoppedForUpgrade\s+-or\s+\(Get-Service -Name AionUiPortal\)\.Status -eq 'Stopped'") {
    throw 'Upgrade script must restart Portal after a prior interrupted invocation left it stopped.'
}
$build = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Build.ps1') -Raw
foreach ($requiredBuildContract in @(
    'SkipAionUiPack is not permitted for immutable releases',
    'Get-CleanGitProvenance',
    'source_provenance'
)) {
    if (-not $build.Contains($requiredBuildContract)) {
        throw "Build script is missing immutable source-provenance contract: $requiredBuildContract"
    }
}
$stopAllInstancesCalls = ([regex]::Matches($upgrade, [regex]::Escape("'Stop-AllInstances.ps1'"))).Count
if ($stopAllInstancesCalls -ne 1) {
    throw "Upgrade script must stop all instances only in the UserHost-binary drain path; calls=$stopAllInstancesCalls."
}

Write-Host 'Release scope, notification classification, optimistic baseline, idempotence, preserved-component, CLI cutover, and non-interrupting Web cutover tests passed.'

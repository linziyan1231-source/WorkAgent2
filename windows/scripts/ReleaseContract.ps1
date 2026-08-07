Set-StrictMode -Version Latest

$script:KnownReleaseComponents = @(
    'web',
    'AionUiPortal.exe',
    'AionUiUserHost.exe',
    'portal.exe',
    'AionKimiDatasourceBroker.exe',
    'AionAgentCli.exe'
)

$script:RefreshOnlyUpgradeMessage = '系统正在升级，页面可能需要刷新，但正在进行的任务不会中断'
$script:TaskInterruptionUpgradeMessage = '系统正在升级，正在进行的任务可能会中断'

function Assert-ReleaseScopeContract {
    param(
        [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
        [Parameter(Mandatory)][string[]]$IncludedComponents
    )

    $components = @($IncludedComponents | ForEach-Object { [string]$_ })
    if ($components.Count -eq 0) { throw 'Release manifest must include at least one component.' }
    if (@($components | Select-Object -Unique).Count -ne $components.Count) {
        throw 'Release manifest contains a duplicate component.'
    }
    $unknown = @($components | Where-Object { $_ -cnotin $script:KnownReleaseComponents })
    if ($unknown.Count -ne 0) { throw "Release manifest contains an unknown component: $($unknown[0])" }

    $hasWeb = 'web' -cin $components
    $hasRuntime = 'AionAgentCli.exe' -cin $components
    $backend = @($components | Where-Object { $_ -cin @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionKimiDatasourceBroker.exe') })
    switch ($ReleaseScope) {
        'web-only' {
            if ($components.Count -ne 1 -or -not $hasWeb) { throw 'web-only releases must contain exactly the web component.' }
        }
        'runtime-only' {
            if ($components.Count -ne 1 -or -not $hasRuntime) { throw 'runtime-only releases must contain exactly AionAgentCli.exe.' }
        }
        'backend-only' {
            if ($hasWeb -or $hasRuntime -or $backend.Count -ne $components.Count) {
                throw 'backend-only releases may contain only Portal backend executables.'
            }
        }
        'combined' {
            if (-not $hasWeb -or ($backend.Count -eq 0 -and -not $hasRuntime)) {
                throw 'combined releases must contain web and at least one backend or runtime component.'
            }
        }
    }
}

function Get-UpgradeInterruptionClass {
    param(
        [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
        [Parameter(Mandatory)][string[]]$IncludedComponents
    )

    Assert-ReleaseScopeContract -ReleaseScope $ReleaseScope -IncludedComponents $IncludedComponents
    if ('AionUiUserHost.exe' -cin $IncludedComponents -or 'AionAgentCli.exe' -cin $IncludedComponents) {
        return 'task-interruption-possible'
    }
    return 'refresh-only'
}

function Get-UpgradeNotificationMessage {
    param(
        [Parameter(Mandatory)][ValidateSet('web-only', 'runtime-only', 'backend-only', 'combined')][string]$ReleaseScope,
        [Parameter(Mandatory)][string[]]$IncludedComponents
    )

    $class = Get-UpgradeInterruptionClass -ReleaseScope $ReleaseScope -IncludedComponents $IncludedComponents
    if ($class -ceq 'task-interruption-possible') { return $script:TaskInterruptionUpgradeMessage }
    return $script:RefreshOnlyUpgradeMessage
}

function Assert-PublishedUpgradeNotification {
    param(
        [Parameter(Mandatory)][object]$Payload,
        [Parameter(Mandatory)][string]$ExpectedId,
        [Parameter(Mandatory)][string]$ExpectedMessage
    )

    $notificationsProperty = $Payload.PSObject.Properties['notifications']
    if ($null -eq $notificationsProperty) { throw 'Upgrade notification source did not return a notifications collection.' }
    $matches = @($notificationsProperty.Value | Where-Object {
        $idProperty = $_.PSObject.Properties['id']
        $null -ne $idProperty -and [string]$idProperty.Value -ceq $ExpectedId
    })
    if ($matches.Count -ne 1) {
        throw "Upgrade notification source must return exactly one notification with id $ExpectedId; matches=$($matches.Count)."
    }
    $messageProperty = $matches[0].PSObject.Properties['message']
    $actualMessage = if ($null -eq $messageProperty) { '' } else { [string]$messageProperty.Value }
    if ($actualMessage -cne $ExpectedMessage) {
        throw "Upgrade notification $ExpectedId has the wrong interruption message."
    }
}

function Assert-Sha256String {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description
    )
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Description is not a lowercase SHA-256 value." }
}

function Test-UpgradeComponentTransition {
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$CurrentSha256,
        [Parameter(Mandatory)][string]$TargetSha256,
        [Parameter(Mandatory)][string]$ExpectedInstalledSha256
    )

    foreach ($entry in @(
        @{ Value = $CurrentSha256; Description = "$Component current hash" },
        @{ Value = $TargetSha256; Description = "$Component target hash" },
        @{ Value = $ExpectedInstalledSha256; Description = "$Component expected installed hash" }
    )) {
        Assert-Sha256String -Value ([string]$entry.Value).ToLowerInvariant() -Description ([string]$entry.Description)
    }

    if ($CurrentSha256 -ceq $TargetSha256) { return $false }
    if ($CurrentSha256 -cne $ExpectedInstalledSha256) {
        throw "Stale release refused for ${Component}: installed SHA-256 $CurrentSha256 is neither the target nor the production baseline $ExpectedInstalledSha256. Rebuild from a fresh preflight snapshot instead of overwriting an independently upgraded component."
    }
    return $true
}

function Assert-PreservedComponentHashes {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Before,
        [Parameter(Mandatory)][System.Collections.IDictionary]$After
    )

    foreach ($entry in $Before.GetEnumerator()) {
        if (-not $After.Contains($entry.Key)) { throw "Preserved component disappeared during upgrade: $($entry.Key)" }
        if ([string]$After[$entry.Key] -cne [string]$entry.Value) {
            throw "Upgrade modified a component outside its declared scope: $($entry.Key)"
        }
    }
}

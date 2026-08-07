[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('web-only', 'backend-only', 'combined')][string]$ReleaseScope,
    [Parameter(Mandatory)][string]$BuildManifestPath,
    [string]$AionUiPackedDirectory,
    [string]$AionUiVersion,
    [string]$AionCoreVersion,
    [string]$BinariesDirectory,
    [string]$ConfigPath = 'C:\ProgramData\AionUiPortal\portal.json',
    [string]$InstallRoot = 'C:\Program Files\AionUiPortal',
    [string]$AgentCurrentFile = 'C:\Program Files\AionAgentCliShared\current.json',
    [string]$UsageManagementURL = 'http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy',
    [string]$UsageManagementKeyFile = 'C:\ProgramData\CLIProxyAPI\.management-key',
    [string]$ChatForwardURL = 'http://127.0.0.1:3210',
    [string]$ChatForwardSecretFile = 'C:\ProgramData\AionUiPortal\chatforward.key',
    [string]$NotificationSourceURL = 'http://203.0.113.79:25888/notification',
    [string]$ExpectedNotificationId,
    [AllowEmptyString()][string]$OutboundProxyURL,
    [ValidateRange(1, 86400)][int]$UserHostDrainTimeoutSeconds = 7200,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseContract.ps1')

function Invoke-ServiceControl([string]$operation, [string[]]$arguments) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command sc.exe -ErrorAction Stop).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $arguments) { $startInfo.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($startInfo)
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult().Trim()
        $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
        if ($process.ExitCode -ne 0) {
            throw "$operation failed with exit code $($process.ExitCode): $stdout $stderr".Trim()
        }
    } finally {
        $process.Dispose()
    }
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}
$usageManagementUri = [Uri]$UsageManagementURL
if (-not $usageManagementUri.IsAbsoluteUri -or $usageManagementUri.Scheme -ne 'http' -or $usageManagementUri.Host -ne '127.0.0.1' -or
    $usageManagementUri.AbsolutePath -ne '/v0/management/plugins/cpa-key-policy' -or $usageManagementUri.UserInfo -or $usageManagementUri.Query -or $usageManagementUri.Fragment) {
    throw 'UsageManagementURL must be the exact local cpa-key-policy Management API URL.'
}
if (-not [IO.Path]::IsPathFullyQualified($UsageManagementKeyFile) -or
    -not ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($UsageManagementKeyFile))).Equals('C:\ProgramData\CLIProxyAPI', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'UsageManagementKeyFile must be a direct child of C:\ProgramData\CLIProxyAPI.'
}
$portalDataRoot = 'C:\ProgramData\AionUiPortal'
$chatForwardUri = [Uri]$ChatForwardURL
if (-not $chatForwardUri.IsAbsoluteUri -or $chatForwardUri.Scheme -ne 'http' -or $chatForwardUri.Authority -notmatch '^127\.0\.0\.1:[0-9]{1,5}$' -or
    $chatForwardUri.AbsolutePath -ne '/' -or $chatForwardUri.UserInfo -or $chatForwardUri.Query -or $chatForwardUri.Fragment) {
    throw 'ChatForwardURL must be an exact 127.0.0.1 HTTP origin.'
}
$notificationSourceUri = [Uri]$NotificationSourceURL
if (-not $notificationSourceUri.IsAbsoluteUri -or $notificationSourceUri.Scheme -notin @('http', 'https') -or
    $notificationSourceUri.AbsolutePath -ne '/notification' -or $notificationSourceUri.UserInfo -or $notificationSourceUri.Query -or $notificationSourceUri.Fragment) {
    throw 'NotificationSourceURL must be an absolute HTTP or HTTPS /notification URL without credentials, query, or fragment.'
}
if (-not [IO.Path]::IsPathFullyQualified($ChatForwardSecretFile) -or
    -not ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ChatForwardSecretFile))).Equals($portalDataRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ChatForwardSecretFile must be a direct child of C:\ProgramData\AionUiPortal.'
}
if ($PSBoundParameters.ContainsKey('OutboundProxyURL') -and $OutboundProxyURL) {
    $proxyUri = [Uri]$OutboundProxyURL
    if (-not $proxyUri.IsAbsoluteUri -or $proxyUri.Scheme -notin @('http', 'https') -or $proxyUri.UserInfo -or
        ($proxyUri.AbsolutePath -notin @('', '/')) -or $proxyUri.Query -or $proxyUri.Fragment) {
        throw 'OutboundProxyURL must be an absolute HTTP or HTTPS proxy URL without credentials, path, query, or fragment.'
    }
}
$portalCli = Join-Path $InstallRoot 'portal.exe'
foreach ($path in @($ConfigPath, $portalCli)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Upgrade prerequisite is missing: $path" }
}
$portalConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$publicUri = [Uri][string]$portalConfig.public_base_url
if (-not $publicUri.IsAbsoluteUri -or $publicUri.Scheme -notin @('http', 'https')) { throw 'Portal public_base_url has an unsupported scheme.' }
$healthUri = ('{0}://127.0.0.1:25808/healthz' -f $publicUri.Scheme)
$artifactTestArguments = @{
    BuildManifestPath = $BuildManifestPath
    ReleaseScope = $ReleaseScope
    RequireUpgradeContract = $true
}
if (-not [string]::IsNullOrWhiteSpace($BinariesDirectory)) { $artifactTestArguments.BinariesDirectory = $BinariesDirectory }
if (-not [string]::IsNullOrWhiteSpace($AionUiPackedDirectory)) { $artifactTestArguments.AionUiPackedDirectory = $AionUiPackedDirectory }
if (-not [string]::IsNullOrWhiteSpace($AionUiVersion)) { $artifactTestArguments.AionUiVersion = $AionUiVersion }
if (-not [string]::IsNullOrWhiteSpace($AionCoreVersion)) { $artifactTestArguments.AionCoreVersion = $AionCoreVersion }
& (Join-Path $PSScriptRoot 'Test-BuildArtifacts.ps1') @artifactTestArguments

$buildManifest = Get-Content -LiteralPath $BuildManifestPath -Raw | ConvertFrom-Json
$includedComponents = @($buildManifest.included_components | ForEach-Object { [string]$_ })
$unsupportedUpgradeComponents = @($includedComponents | Where-Object { $_ -cnotin @('web', 'AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionKimiDatasourceBroker.exe') })
if ($unsupportedUpgradeComponents.Count -ne 0) {
    throw "Upgrade.ps1 does not publish runtime component $($unsupportedUpgradeComponents[0]); use the dedicated immutable runtime publisher."
}
$includesWeb = 'web' -cin $includedComponents
$includedBackend = @($includedComponents | Where-Object { $_ -cne 'web' })
$installedComponentPaths = [ordered]@{
    'web' = [string]$portalConfig.current_release_file
    'AionUiPortal.exe' = (Join-Path $InstallRoot 'AionUiPortal.exe')
    'AionUiUserHost.exe' = (Join-Path $InstallRoot 'AionUiUserHost.exe')
    'portal.exe' = (Join-Path $InstallRoot 'portal.exe')
    'AionKimiDatasourceBroker.exe' = (Join-Path $InstallRoot 'AionKimiDatasourceBroker.exe')
    'AionAgentCli.exe' = $AgentCurrentFile
}
$copyRequired = [ordered]@{}
foreach ($name in $includedBackend) {
    $installedPath = [string]$installedComponentPaths[$name]
    $targetHash = [string]$buildManifest.binaries.PSObject.Properties[$name].Value.sha256
    $baselineHash = [string]$buildManifest.upgrade_contract.expected_installed_sha256.PSObject.Properties[$name].Value
    if ($baselineHash -ceq 'absent' -and $name -ceq 'AionKimiDatasourceBroker.exe') {
        if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
            $copyRequired[$name] = $true
            continue
        }
        $currentHash = (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($currentHash -cne $targetHash) { throw 'Stale release refused for newly introduced AionKimiDatasourceBroker.exe: an unexpected binary is already installed.' }
        $copyRequired[$name] = $false
        continue
    }
    $currentHash = (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $copyRequired[$name] = Test-UpgradeComponentTransition -Component $name -CurrentSha256 $currentHash `
        -TargetSha256 $targetHash -ExpectedInstalledSha256 $baselineHash
}
if ($includesWeb) {
    $currentWebHash = (Get-FileHash -LiteralPath $installedComponentPaths['web'] -Algorithm SHA256).Hash.ToLowerInvariant()
    $baselineWebHash = [string]$buildManifest.upgrade_contract.expected_installed_sha256.web
    Assert-Sha256String -Value $baselineWebHash -Description 'web production baseline'
    if ($currentWebHash -cne $baselineWebHash) {
        $currentPointer = Get-Content -LiteralPath $installedComponentPaths['web'] -Raw | ConvertFrom-Json
        if ([string]$currentPointer.version -cne $AionUiVersion) {
            throw "Stale release refused for web: current pointer SHA-256 $currentWebHash differs from baseline $baselineWebHash and does not already select $AionUiVersion."
        }
    }
}
$preservedBefore = [ordered]@{}
foreach ($entry in $installedComponentPaths.GetEnumerator()) {
    if ($entry.Key -cnotin $includedComponents -and (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
        $preservedBefore[$entry.Key] = (Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
if ($PreflightOnly) {
    Write-Host "Upgrade preflight passed for component-scoped $ReleaseScope release $($buildManifest.release_id). No production state was changed."
    return
}
if ([string]::IsNullOrWhiteSpace($ExpectedNotificationId)) {
    throw 'ExpectedNotificationId is required for a production cutover. Publish the manifest-classified notice first.'
}
$expectedNotificationMessage = Get-UpgradeNotificationMessage -ReleaseScope ([string]$buildManifest.release_scope) -IncludedComponents $includedComponents
try {
    $notificationPayload = Invoke-RestMethod -Method Get -Uri $NotificationSourceURL -TimeoutSec 15 -ErrorAction Stop
} catch {
    throw "Read published upgrade notification before cutover: $($_.Exception.Message)"
}
Assert-PublishedUpgradeNotification -Payload $notificationPayload -ExpectedId $ExpectedNotificationId -ExpectedMessage $expectedNotificationMessage
Write-Host "Verified manifest-classified upgrade notification before cutover: id=$ExpectedNotificationId message=$expectedNotificationMessage"
$instanceLines = @(& $portalCli --config $ConfigPath instance list 2>&1)
if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate Portal Windows accounts before upgrade: $($instanceLines -join [Environment]::NewLine)" }
$windowsAccounts = @()
foreach ($line in $instanceLines) {
    if ([string]$line -match '^user=\S+\s+windows=(?<account>\S+)\s+sid=S-[0-9-]+\s') {
        $windowsAccounts += $Matches.account
    }
}
$updatesPortalBackend = 'AionUiPortal.exe' -cin $includedComponents
$updatesPortalCli = 'portal.exe' -cin $includedComponents
$updatesUserHostBinary = 'AionUiUserHost.exe' -cin $includedComponents
$updatesKimiDatasourceBroker = 'AionKimiDatasourceBroker.exe' -cin $includedComponents
if ($updatesPortalBackend) {
    $fsrmFeature = Get-WindowsFeature FS-Resource-Manager
    if (-not $fsrmFeature.Installed) {
        $fsrmInstall = Install-WindowsFeature FS-Resource-Manager -IncludeManagementTools
        if (-not $fsrmInstall.Success -or $fsrmInstall.RestartNeeded -eq 'Yes') {
            throw "File Server Resource Manager installation did not complete without a restart: success=$($fsrmInstall.Success) restart=$($fsrmInstall.RestartNeeded)."
        }
    }
    Import-Module FileServerResourceManager -ErrorAction Stop
	$userDataRoot = ''
	if ($portalConfig.PSObject.Properties.Name -contains 'user_data_root') {
		$userDataRoot = [string]$portalConfig.user_data_root
	}
    foreach ($account in $windowsAccounts) {
        & (Join-Path $PSScriptRoot 'Set-UserDiskQuota.ps1') -WindowsAccount $account -DataRootBase $userDataRoot -LimitGiB 60 -SharedLimitGiB 20
    }
}
$adminService = Get-Service -Name AionUiPortalAdmin -ErrorAction SilentlyContinue
$adminServiceStoppedForUpgrade = $false
$portalService = Get-Service -Name AionUiPortal -ErrorAction Stop
$portalServiceStoppedForUpgrade = $false
$kimiDatasourceService = Get-Service -Name AionKimiDatasourceBroker -ErrorAction SilentlyContinue
$kimiDatasourceServiceStoppedForUpgrade = $false
if ($updatesUserHostBinary) {
    & (Join-Path $PSScriptRoot 'Wait-AllInstancesIdle.ps1') -PortalCli $portalCli -ConfigPath $ConfigPath -TimeoutSeconds $UserHostDrainTimeoutSeconds
}
if ($updatesPortalCli -and $adminService -and $adminService.Status -ne 'Stopped') {
    Stop-Service -Name AionUiPortalAdmin -Force -ErrorAction Stop
    $adminService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $adminServiceStoppedForUpgrade = $true
}
if (($updatesPortalBackend -or $updatesUserHostBinary) -and $portalService.Status -ne 'Stopped') {
    Stop-Service -Name AionUiPortal -Force -ErrorAction Stop
    $portalService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $portalServiceStoppedForUpgrade = $true
}
if ($updatesKimiDatasourceBroker -and $kimiDatasourceService -and $kimiDatasourceService.Status -ne 'Stopped') {
    Stop-Service -Name AionKimiDatasourceBroker -Force -ErrorAction Stop
    $kimiDatasourceService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $kimiDatasourceServiceStoppedForUpgrade = $true
}
if ($updatesUserHostBinary) {
    try {
        # Portal is stopped, so no browser request can start new work between
        # this final fail-closed activity check and instance shutdown.
        & (Join-Path $PSScriptRoot 'Wait-AllInstancesIdle.ps1') -PortalCli $portalCli -ConfigPath $ConfigPath -TimeoutSeconds 10 -PollMilliseconds 250
        & (Join-Path $PSScriptRoot 'Stop-AllInstances.ps1') -PortalCli $portalCli -ConfigPath $ConfigPath
    } catch {
        if ($portalServiceStoppedForUpgrade) {
            Start-Service -Name AionUiPortal
            (Get-Service AionUiPortal).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            $portalServiceStoppedForUpgrade = $false
        }
        if ($adminServiceStoppedForUpgrade) {
            Start-Service -Name AionUiPortalAdmin
            (Get-Service AionUiPortalAdmin).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            $adminServiceStoppedForUpgrade = $false
        }
        throw
    }
}
if ($updatesPortalBackend -and $windowsAccounts.Count -ne 0) {
    & (Join-Path $PSScriptRoot 'Remove-CodexSandboxGroupMembership.ps1') -WindowsAccount $windowsAccounts
}
if ($includedBackend.Count -ne 0) {
    foreach ($name in $includedBackend) {
        if (-not [bool]$copyRequired[$name]) {
            Write-Host "Backend component already matches target; preserving in place: $name"
            continue
        }
        $source = Join-Path $BinariesDirectory $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Upgrade binary is missing: $source" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $InstallRoot $name) -Force
    }
}
if ($updatesPortalCli) {
    $adminScripts = Join-Path $InstallRoot 'admin-scripts'
    New-Item -ItemType Directory -Force -Path $adminScripts | Out-Null
    foreach ($name in @('Remove-CodexSandboxGroupMembership.ps1', 'Set-UserHostRights.ps1', 'Set-UserDiskQuota.ps1', 'ReleaseContract.ps1', 'Publish-UpgradeNotification.ps1', 'Configure-KimiDatasourceBroker.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $adminScripts $name) -Force
    }
    if (-not $adminService) {
        $adminImagePath = '"' + $portalCli + '" --config "' + $ConfigPath + '" service --scripts "' + $adminScripts + '"'
        Invoke-ServiceControl 'Create Portal administration service' @('create', 'AionUiPortalAdmin', 'binPath=', $adminImagePath, 'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=', 'AionUi Portal Account Administration')
        Invoke-ServiceControl 'Configure Portal administration service startup' @('config', 'AionUiPortalAdmin', 'start=', 'delayed-auto')
        Invoke-ServiceControl 'Configure Portal administration service recovery' @('failure', 'AionUiPortalAdmin', 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/none/0')
        $adminService = Get-Service -Name AionUiPortalAdmin -ErrorAction Stop
    }
}
if ($updatesPortalBackend) {
    $legacyChatForwardSecretFile = Join-Path $portalDataRoot 'chatgpt-forwarder.key'
    if (-not (Test-Path -LiteralPath $ChatForwardSecretFile) -and (Test-Path -LiteralPath $legacyChatForwardSecretFile -PathType Leaf)) {
        Copy-Item -LiteralPath $legacyChatForwardSecretFile -Destination $ChatForwardSecretFile
    }
    if (-not (Test-Path -LiteralPath $ChatForwardSecretFile)) {
        $chatForwardSecretBytes = [byte[]]::new(48)
        [Security.Cryptography.RandomNumberGenerator]::Fill($chatForwardSecretBytes)
        [IO.File]::WriteAllText($ChatForwardSecretFile, [Convert]::ToBase64String($chatForwardSecretBytes) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        [Array]::Clear($chatForwardSecretBytes, 0, $chatForwardSecretBytes.Length)
    }
    $chatForwardSecretItem = Get-Item -LiteralPath $ChatForwardSecretFile -Force
    if (($chatForwardSecretItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $chatForwardSecretItem.PSIsContainer -or $chatForwardSecretItem.Length -lt 32) {
        throw 'ChatForward secret must be a regular non-reparse file containing at least 32 bytes.'
    }
}
$portalConfigTable = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
$requiredUsageSettings = [ordered]@{
    usage_management_url = $UsageManagementURL
    usage_management_key_file = [IO.Path]::GetFullPath($UsageManagementKeyFile)
}
$configurationChanged = $false
if ($includesWeb) {
    $supportedAionCoreVersions = @($portalConfigTable['supported_aioncore_versions'] | ForEach-Object { [string]$_ })
    if ($AionCoreVersion -cnotin $supportedAionCoreVersions) {
        $portalConfigTable['supported_aioncore_versions'] = @($supportedAionCoreVersions + $AionCoreVersion)
        $configurationChanged = $true
    }
}
if ($updatesPortalBackend) {
    foreach ($legacyName in @('usage_ssh_target', 'usage_ssh_port', 'usage_ssh_helper_path', 'usage_ssh_identity_file', 'usage_ssh_known_hosts_file')) {
        if ($portalConfigTable.Remove($legacyName)) { $configurationChanged = $true }
    }
    foreach ($legacyName in @('chatgpt_forwarder_url', 'chatgpt_forwarder_secret_file', 'chatgpt_maintenance_mode')) {
        if ($portalConfigTable.Remove($legacyName)) { $configurationChanged = $true }
    }
    foreach ($entry in $requiredUsageSettings.GetEnumerator()) {
        if ($portalConfigTable.ContainsKey($entry.Key)) {
            if ([string]$portalConfigTable[$entry.Key] -cne [string]$entry.Value) {
                throw "Existing Portal setting $($entry.Key) does not match the requested usage configuration; Portal remains stopped."
            }
        } else {
            $portalConfigTable[$entry.Key] = $entry.Value
            $configurationChanged = $true
        }
    }
    foreach ($entry in ([ordered]@{ usage_query_timeout_seconds = 25; usage_cache_seconds = 30 }).GetEnumerator()) {
        if (-not $portalConfigTable.ContainsKey($entry.Key)) {
            $portalConfigTable[$entry.Key] = $entry.Value
            $configurationChanged = $true
        }
    }
    foreach ($entry in ([ordered]@{
        chatforward_url = $ChatForwardURL
        chatforward_secret_file = [IO.Path]::GetFullPath($ChatForwardSecretFile)
        chatgpt_pro_models = @('gpt-5-4-pro', 'gpt-5-5-pro', 'gpt-5-6-pro')
        notification_source_url = $NotificationSourceURL
        kimi_datasource_broker_url = 'http://127.0.0.1:3211/mcp'
    }).GetEnumerator()) {
        if (-not $portalConfigTable.ContainsKey($entry.Key) -or [string]$portalConfigTable[$entry.Key] -cne [string]$entry.Value) {
            $portalConfigTable[$entry.Key] = $entry.Value
            $configurationChanged = $true
        }
    }
}
if ($PSBoundParameters.ContainsKey('OutboundProxyURL')) {
    $portalConfigTable['outbound_proxy_url'] = $OutboundProxyURL
    $configurationChanged = $true
}
if ($configurationChanged) {
    $temporaryConfig = Join-Path (Split-Path -Parent $ConfigPath) ('.' + (Split-Path -Leaf $ConfigPath) + '.usage-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $updatedJson = $portalConfigTable | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($temporaryConfig, $updatedJson + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryConfig -Destination $ConfigPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryConfig) { Remove-Item -LiteralPath $temporaryConfig -Force }
    }
}
# A running Portal keeps its parsed configuration in memory. Restart only the
# Portal boundary when the on-disk configuration changed; UserHosts and their
# Agent CLI process trees remain alive and reconnect through the same origin.
if ($configurationChanged -and -not $portalServiceStoppedForUpgrade -and $portalService.Status -ne 'Stopped') {
    Stop-Service -Name AionUiPortal -Force -ErrorAction Stop
    $portalService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    $portalServiceStoppedForUpgrade = $true
}
$updatesUserHostConfiguration = $includesWeb -or ('AionUiUserHost.exe' -cin $includedComponents) -or $PSBoundParameters.ContainsKey('OutboundProxyURL')
if ($updatesUserHostConfiguration) {
    $userConfigRoot = [string]$portalConfigTable['user_config_root']
    foreach ($directory in @(Get-ChildItem -LiteralPath $userConfigRoot -Directory -Force -ErrorAction Stop)) {
        if ($directory.Name -notmatch '^S-1-[0-9-]+$') { throw "Unexpected non-SID directory in UserHost config root: $($directory.FullName)" }
        $userConfigPath = Join-Path $directory.FullName 'userhost.json'
        if (-not (Test-Path -LiteralPath $userConfigPath -PathType Leaf)) { throw "UserHost configuration is missing: $userConfigPath" }
        $userConfig = Get-Content -LiteralPath $userConfigPath -Raw | ConvertFrom-Json -AsHashtable
        if ([string]$userConfig['windows_sid'] -cne $directory.Name) { throw "UserHost configuration SID does not match its directory: $userConfigPath" }
        $userConfigChanged = $false
        if ($includesWeb) {
            $userSupportedVersions = @($userConfig['supported_aioncore_versions'] | ForEach-Object { [string]$_ })
            if ($AionCoreVersion -cnotin $userSupportedVersions) {
                $userConfig['supported_aioncore_versions'] = @($userSupportedVersions + $AionCoreVersion)
                $userConfigChanged = $true
            }
        }
        if ($PSBoundParameters.ContainsKey('OutboundProxyURL')) {
            $userConfig['outbound_proxy_url'] = $OutboundProxyURL
            $userConfigChanged = $true
        }
        if ($userConfigChanged) {
            $temporaryUserConfig = Join-Path $directory.FullName ('.userhost.upgrade-' + [Guid]::NewGuid().ToString('N') + '.tmp')
            try {
                $updatedUserJson = $userConfig | ConvertTo-Json -Depth 8
                [IO.File]::WriteAllText($temporaryUserConfig, $updatedUserJson + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
                Move-Item -LiteralPath $temporaryUserConfig -Destination $userConfigPath -Force
            } finally {
                if (Test-Path -LiteralPath $temporaryUserConfig) { Remove-Item -LiteralPath $temporaryUserConfig -Force }
            }
        }
    }
}
if ($includesWeb) {
    $releaseInstallArguments = @('--config', $ConfigPath, 'release', 'install', '--source', (Resolve-Path $AionUiPackedDirectory).Path,
        '--version', $AionUiVersion, '--aioncore-version', $AionCoreVersion)
    if (-not $updatesUserHostBinary) { $releaseInstallArguments += '--allow-running' }
    & $portalCli @releaseInstallArguments
    if ($LASTEXITCODE -ne 0) { throw 'Release install/switch failed; service state was preserved for this release scope.' }
}
& $portalCli --config $ConfigPath acl apply
if ($LASTEXITCODE -ne 0) { throw 'ACL reapplication failed; service state was preserved for this release scope.' }
& $portalCli --config $ConfigPath acl verify
if ($LASTEXITCODE -ne 0) { throw 'Post-upgrade integrity/ACL verification failed; service state was preserved for this release scope.' }
if ($portalServiceStoppedForUpgrade) {
    Start-Service -Name AionUiPortal
    (Get-Service AionUiPortal).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
if ($adminService -and ($adminServiceStoppedForUpgrade -or (Get-Service -Name AionUiPortalAdmin).Status -eq 'Stopped')) {
    Start-Service -Name AionUiPortalAdmin
    (Get-Service AionUiPortalAdmin).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
if ($kimiDatasourceService -and ($kimiDatasourceServiceStoppedForUpgrade -or (Get-Service -Name AionKimiDatasourceBroker).Status -eq 'Stopped')) {
    Start-Service -Name AionKimiDatasourceBroker
    (Get-Service AionKimiDatasourceBroker).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
$deadline = [DateTime]::UtcNow.AddSeconds(120)
$healthy = $false
$lastHealthError = "no $($publicUri.Scheme.ToUpperInvariant()) response was received"
do {
    $handler = $null
    $client = $null
    $response = $null
    try {
        $handler = New-Object Net.Http.HttpClientHandler
        $handler.UseProxy = $false
        if ($publicUri.Scheme -eq 'https') {
            $handler.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        }
        $client = [Net.Http.HttpClient]::new($handler)
        $response = $client.GetAsync($healthUri).GetAwaiter().GetResult()
        $healthy = $response.IsSuccessStatusCode
        if (-not $healthy) { $lastHealthError = "HTTP $([int]$response.StatusCode)" }
    } catch {
        $lastHealthError = $_.Exception.Message
    } finally {
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
    }
    if (-not $healthy) { Start-Sleep -Milliseconds 500 }
} while (-not $healthy -and [DateTime]::UtcNow -lt $deadline)
if (-not $healthy) { throw "Portal did not pass its local $($publicUri.Scheme.ToUpperInvariant()) health check. Last error: $lastHealthError" }
foreach ($name in $includedBackend) {
    $actualHash = (Get-FileHash -LiteralPath $installedComponentPaths[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
    $targetHash = [string]$buildManifest.binaries.PSObject.Properties[$name].Value.sha256
    if ($actualHash -cne $targetHash) { throw "Activated backend component hash mismatch: $name" }
}
if ($includesWeb) {
    $activatedPointer = Get-Content -LiteralPath $installedComponentPaths['web'] -Raw | ConvertFrom-Json
    if ([string]$activatedPointer.version -cne $AionUiVersion) { throw "Activated Web pointer does not select $AionUiVersion." }
}
$preservedAfter = [ordered]@{}
foreach ($entry in $preservedBefore.GetEnumerator()) {
    if (Test-Path -LiteralPath $installedComponentPaths[$entry.Key] -PathType Leaf) {
        $preservedAfter[$entry.Key] = (Get-FileHash -LiteralPath $installedComponentPaths[$entry.Key] -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
Assert-PreservedComponentHashes -Before $preservedBefore -After $preservedAfter
Write-Host "Upgrade activated component-scoped $ReleaseScope release $($buildManifest.release_id). User databases were backed up and components outside scope were hash-preserved."

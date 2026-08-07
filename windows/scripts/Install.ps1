[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublicBaseUrl,
    [string]$CertificateFile,
    [string]$PrivateKeyFile,
    [Parameter(Mandatory)][string]$BinariesDirectory,
    [Parameter(Mandatory)][string]$BuildManifestPath,
    [string]$AionUiPackedDirectory = (Join-Path $PSScriptRoot '..\..\AionUi\dist-web-cli\staging\aionui-web'),
    [string]$AionUiVersion = '2.1.0-beta',
    [string]$AionCoreVersion = 'v0.1.42',
    [string]$CodexVersion,
    [string]$KimiVersion,
    [string]$AgentCliPythonVersion,
    [string]$UsageManagementURL = 'http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy',
    [string]$UsageManagementKeyFile = 'C:\ProgramData\CLIProxyAPI\.management-key',
    [string]$ChatForwardURL = 'http://127.0.0.1:3210',
    [string]$ChatForwardSecretFile = 'C:\ProgramData\AionUiPortal\chatforward.key',
    [string]$NotificationSourceURL = 'http://203.0.113.79:25888/notification',
    [AllowEmptyString()][string]$OutboundProxyURL = ''
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AionUiPortal'
$adminServiceName = 'AionUiPortalAdmin'
$installRoot = 'C:\Program Files\AionUiPortal'
$sharedRoot = 'C:\Program Files\AionUiWebShared'
$programData = 'C:\ProgramData\AionUiPortal'
$configPath = Join-Path $programData 'portal.json'
$portalExe = Join-Path $installRoot 'AionUiPortal.exe'
$portalCli = Join-Path $installRoot 'portal.exe'
$adminScripts = Join-Path $installRoot 'admin-scripts'
if ($OutboundProxyURL) {
    $proxyUri = [Uri]$OutboundProxyURL
    if (-not $proxyUri.IsAbsoluteUri -or $proxyUri.Scheme -notin @('http', 'https') -or $proxyUri.UserInfo -or
        ($proxyUri.AbsolutePath -notin @('', '/')) -or $proxyUri.Query -or $proxyUri.Fragment) {
        throw 'OutboundProxyURL must be an absolute HTTP or HTTPS proxy URL without credentials, path, query, or fragment.'
    }
}
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
    -not ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ChatForwardSecretFile))).Equals($programData, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ChatForwardSecretFile must be a direct child of C:\ProgramData\AionUiPortal.'
}

function Assert-Exit([string]$operation) {
    if ($LASTEXITCODE -ne 0) { throw "$operation failed with exit code $LASTEXITCODE" }
}

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
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1 -or -not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows Server is required.' }
if (-not (Test-Path -LiteralPath 'C:\Users' -PathType Container)) {
    throw 'The fixed Windows profiles root C:\Users is missing.'
}
$systemVolume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
if ($null -eq $systemVolume -or $systemVolume.DriveType -ne 3 -or $systemVolume.FileSystem -ne 'NTFS') {
    throw 'C: must be a fixed NTFS volume for per-user AionUi data.'
}
$publicUri = [Uri]$PublicBaseUrl
if (-not $publicUri.IsAbsoluteUri -or $publicUri.Scheme -notin @('http', 'https') -or $publicUri.Port -ne 25808 -or $publicUri.AbsolutePath -ne '/' -or
    -not [string]::IsNullOrEmpty($publicUri.UserInfo) -or -not [string]::IsNullOrEmpty($publicUri.Query) -or -not [string]::IsNullOrEmpty($publicUri.Fragment)) {
    throw 'PublicBaseUrl must be an absolute HTTP or HTTPS origin on port 25808 without a path.'
}
$useTls = $publicUri.Scheme -eq 'https'
if ($useTls) {
    if ([string]::IsNullOrWhiteSpace($CertificateFile) -or [string]::IsNullOrWhiteSpace($PrivateKeyFile)) {
        throw 'CertificateFile and PrivateKeyFile are required for an HTTPS PublicBaseUrl.'
    }
    foreach ($path in @($CertificateFile, $PrivateKeyFile)) {
        $resolved = Resolve-Path -LiteralPath $path -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) { throw "TLS input is missing: $path" }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($CertificateFile) -or -not [string]::IsNullOrWhiteSpace($PrivateKeyFile)) {
    throw 'CertificateFile and PrivateKeyFile must be omitted for an HTTP PublicBaseUrl.'
}
foreach ($name in @('AionUiPortal.exe', 'AionUiUserHost.exe', 'portal.exe', 'AionAgentCli.exe', 'AionKimiDatasourceBroker.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $BinariesDirectory $name) -PathType Leaf)) { throw "Built binary is missing: $name" }
}
foreach ($relative in @('aionui-web.exe', 'package.json', 'static\index.html', 'bundled-aioncore\win32-x64\aioncore.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $AionUiPackedDirectory $relative) -PathType Leaf)) { throw "Packed AionUi critical file is missing: $relative" }
}
& (Join-Path $PSScriptRoot 'Test-BuildArtifacts.ps1') -BuildManifestPath $BuildManifestPath -ReleaseScope 'combined' -BinariesDirectory $BinariesDirectory `
    -AionUiPackedDirectory $AionUiPackedDirectory -AionUiVersion $AionUiVersion -AionCoreVersion $AionCoreVersion

$fsrmFeature = Get-WindowsFeature FS-Resource-Manager
if (-not $fsrmFeature.Installed) {
    $fsrmInstall = Install-WindowsFeature FS-Resource-Manager -IncludeManagementTools
    if (-not $fsrmInstall.Success -or $fsrmInstall.RestartNeeded -eq 'Yes') {
        throw "File Server Resource Manager installation did not complete without a restart: success=$($fsrmInstall.Success) restart=$($fsrmInstall.RestartNeeded)."
    }
}
Import-Module FileServerResourceManager -ErrorAction Stop

$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$existingAdminService = Get-Service -Name $adminServiceName -ErrorAction SilentlyContinue
if ($existingAdminService -and $existingAdminService.Status -ne 'Stopped') {
    Stop-Service -Name $adminServiceName -Force
    $existingAdminService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
if ($existingService) {
    if ((Test-Path -LiteralPath $portalCli -PathType Leaf) -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        if ($existingService.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force; $existingService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        & (Join-Path $PSScriptRoot 'Stop-AllInstances.ps1') -PortalCli $portalCli -ConfigPath $configPath
    } elseif ($existingService.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
    }
}

$directories = @($installRoot, $adminScripts, $sharedRoot, $programData, (Join-Path $programData 'logs'), (Join-Path $programData 'users'))
if ($useTls) { $directories += (Join-Path $programData 'tls') }
New-Item -ItemType Directory -Force -Path $directories | Out-Null
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
Copy-Item -LiteralPath (Join-Path $BinariesDirectory 'AionUiPortal.exe') -Destination $portalExe -Force
Copy-Item -LiteralPath (Join-Path $BinariesDirectory 'AionUiUserHost.exe') -Destination (Join-Path $installRoot 'AionUiUserHost.exe') -Force
Copy-Item -LiteralPath (Join-Path $BinariesDirectory 'portal.exe') -Destination $portalCli -Force
Copy-Item -LiteralPath (Join-Path $BinariesDirectory 'AionKimiDatasourceBroker.exe') -Destination (Join-Path $installRoot 'AionKimiDatasourceBroker.exe') -Force
foreach ($name in @('Remove-CodexSandboxGroupMembership.ps1', 'Set-UserHostRights.ps1', 'Set-UserDiskQuota.ps1', 'ReleaseContract.ps1', 'Publish-UpgradeNotification.ps1', 'Configure-KimiDatasourceBroker.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $adminScripts $name) -Force
}
$agentCliArguments = @{
    LauncherPath = (Join-Path $BinariesDirectory 'AionAgentCli.exe')
}
if (-not [string]::IsNullOrWhiteSpace($CodexVersion)) { $agentCliArguments.CodexVersion = $CodexVersion }
if (-not [string]::IsNullOrWhiteSpace($KimiVersion)) { $agentCliArguments.KimiVersion = $KimiVersion }
if (-not [string]::IsNullOrWhiteSpace($AgentCliPythonVersion)) { $agentCliArguments.PythonVersion = $AgentCliPythonVersion }
& (Join-Path $PSScriptRoot 'Publish-SharedAgentClis.ps1') @agentCliArguments
$certificateDestination = ''
$privateKeyDestination = ''
if ($useTls) {
    $certificateDestination = Join-Path $programData 'tls\portal-cert.pem'
    $privateKeyDestination = Join-Path $programData 'tls\portal-key.pem'
    Copy-Item -LiteralPath (Resolve-Path $CertificateFile).Path -Destination $certificateDestination -Force
    Copy-Item -LiteralPath (Resolve-Path $PrivateKeyFile).Path -Destination $privateKeyDestination -Force
}

$imagePath = '"' + $portalExe + '" service --config "' + $configPath + '"'
if (-not $existingService) {
    Invoke-ServiceControl 'Create Portal service' @('create', $serviceName, 'binPath=', $imagePath, 'start=', 'auto', 'obj=', "NT SERVICE\$serviceName", 'DisplayName=', 'AionUi Multi-user Portal')
} else {
    Invoke-ServiceControl 'Update Portal service' @('config', $serviceName, 'binPath=', $imagePath, 'start=', 'auto', 'obj=', "NT SERVICE\$serviceName", 'DisplayName=', 'AionUi Multi-user Portal')
}
Invoke-ServiceControl 'Enable delayed automatic Portal startup' @('config', $serviceName, 'start=', 'delayed-auto')
Invoke-ServiceControl 'Enable Portal service SID' @('sidtype', $serviceName, 'unrestricted')
Invoke-ServiceControl 'Configure Portal service recovery' @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/none/0')

$adminImagePath = '"' + $portalCli + '" --config "' + $configPath + '" service --scripts "' + $adminScripts + '"'
if (-not $existingAdminService) {
    Invoke-ServiceControl 'Create Portal administration service' @('create', $adminServiceName, 'binPath=', $adminImagePath, 'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=', 'AionUi Portal Account Administration')
} else {
    Invoke-ServiceControl 'Update Portal administration service' @('config', $adminServiceName, 'binPath=', $adminImagePath, 'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=', 'AionUi Portal Account Administration')
}
Invoke-ServiceControl 'Enable delayed automatic administration startup' @('config', $adminServiceName, 'start=', 'delayed-auto')
Invoke-ServiceControl 'Configure administration service recovery' @('failure', $adminServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/none/0')

$serviceAccount = New-Object Security.Principal.NTAccount("NT SERVICE\$serviceName")
$serviceSid = $serviceAccount.Translate([Security.Principal.SecurityIdentifier]).Value
if ($serviceSid -notmatch '^S-1-5-80-') { throw "Unexpected Portal service SID: $serviceSid" }

$configuration = [ordered]@{
    mode = 'production'
    listen_address = '0.0.0.0:25808'
    public_base_url = $publicUri.GetLeftPart([UriPartial]::Authority)
    tls_certificate_file = $certificateDestination
    tls_private_key_file = $privateKeyDestination
    database_path = (Join-Path $programData 'portal.db')
    audit_log_path = (Join-Path $programData 'logs\audit.jsonl')
    portal_log_path = (Join-Path $programData 'logs\portal.log')
    releases_root = (Join-Path $sharedRoot 'releases')
    current_release_file = (Join-Path $sharedRoot 'current.json')
    user_config_root = (Join-Path $programData 'users')
    user_profiles_root = 'C:\Users'
    user_host_executable = (Join-Path $installRoot 'AionUiUserHost.exe')
    portal_service_sid = $serviceSid
    session_ttl_seconds = 43200
    session_idle_seconds = 3600
    instance_startup_seconds = 120
    idle_reap_seconds = 1800
    max_running_instances = 20
    login_window_seconds = 900
    login_block_seconds = 900
    login_account_failures = 5
    login_ip_failures = 20
    usage_management_url = $UsageManagementURL
    usage_management_key_file = [IO.Path]::GetFullPath($UsageManagementKeyFile)
    usage_query_timeout_seconds = 25
    usage_cache_seconds = 30
    chatforward_url = $ChatForwardURL
    chatforward_secret_file = [IO.Path]::GetFullPath($ChatForwardSecretFile)
    chatgpt_pro_models = @('gpt-5-4-pro', 'gpt-5-5-pro', 'gpt-5-6-pro')
    notification_source_url = $NotificationSourceURL
    outbound_proxy_url = $OutboundProxyURL
    kimi_datasource_broker_url = 'http://127.0.0.1:3211/mcp'
    supported_aioncore_versions = @($AionCoreVersion)
}
$json = $configuration | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($configPath, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))

& $portalCli --config $configPath release install --source (Resolve-Path $AionUiPackedDirectory).Path --version $AionUiVersion --aioncore-version $AionCoreVersion
Assert-Exit 'Install immutable AionUi Web release'
& $portalCli --config $configPath acl apply
Assert-Exit 'Apply production ACLs'
& $portalCli --config $configPath acl verify
Assert-Exit 'Verify production ACLs'
& (Join-Path $PSScriptRoot 'Configure-PortalFirewall.ps1') -PortalExecutable $portalExe

Start-Service -Name $adminServiceName
(Get-Service -Name $adminServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$deadline = [DateTime]::UtcNow.AddSeconds(30)
$healthy = $false
$healthUri = ('{0}://127.0.0.1:25808/healthz' -f $publicUri.Scheme)
$lastHealthError = "no $($publicUri.Scheme.ToUpperInvariant()) response was received"
do {
    $handler = $null
    $client = $null
    $response = $null
    try {
        $handler = New-Object Net.Http.HttpClientHandler
        $handler.UseProxy = $false
        if ($useTls) {
            $handler.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        }
        $client = [Net.Http.HttpClient]::new($handler)
        $response = $client.GetAsync($healthUri).GetAwaiter().GetResult()
        $healthy = $response.IsSuccessStatusCode
        if (-not $healthy) { $lastHealthError = "HTTP $([int]$response.StatusCode)" }
    } catch {
        $lastHealthError = $_.Exception.Message
        Start-Sleep -Milliseconds 500
    } finally {
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
    }
} while (-not $healthy -and [DateTime]::UtcNow -lt $deadline)
if (-not $healthy) { throw "Portal did not pass its local $($publicUri.Scheme.ToUpperInvariant()) health check. Last error: $lastHealthError" }

$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($service.StartName -ne "NT SERVICE\$serviceName" -or $service.ProcessId -eq 0) { throw 'Portal service identity or PID verification failed.' }
$listener = @(Get-NetTCPConnection -State Listen -LocalPort 25808 | Where-Object { $_.LocalAddress -eq '0.0.0.0' -and $_.OwningProcess -eq $service.ProcessId })
if ($listener.Count -ne 1) { throw 'Portal is not listening exactly once on 0.0.0.0:25808 under the service PID.' }
$adminService = Get-CimInstance Win32_Service -Filter "Name='$adminServiceName'"
if ($adminService.StartName -ne 'LocalSystem' -or $adminService.ProcessId -eq 0) { throw 'Portal administration service identity or PID verification failed.' }
& $portalCli --config $configPath acl verify
Assert-Exit 'Verify production ACLs after service startup'

Write-Host "Installed AionUi Portal service as NT SERVICE\$serviceName ($serviceSid)."
Write-Host "$($publicUri.Scheme.ToUpperInvariant()) health check passed at $($configuration.public_base_url)."
Write-Host 'Each employee data root will be created at C:\Users\<Windows profile>\AionUiPortal only when that user is installed.'
Write-Host 'The administrator Portal can now create employee accounts without exposing their generated Windows passwords.'
